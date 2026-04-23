/// High-level WhatsApp client.
///
/// `Client::new()` → `client.connect().await` → `Session`
///
/// `Session` owns the background receive loop and reconnects automatically.
/// Subscribe to events with `session.events()`.
use crate::auth::{AuthManager, AuthState, FileStore};
use crate::contacts::ContactStore;
use crate::message_store::MessageStore;
use crate::messages::{MessageEvent, MessageKey, MessageManager, MessageStatus};
use crate::outbox::OutboxStore;
use crate::poll_store::PollStore;
use crate::error::{Result, WaError};
use crate::signal::SignalRepository;
use crate::socket;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, info, warn};

// ── Client ────────────────────────────────────────────────────────────────────

pub struct Client {
    store: Arc<FileStore>,
}

impl Client {
    /// Create a client backed by the default file store (`~/.wacli/`).
    pub fn new() -> Result<Self> {
        Ok(Self { store: Arc::new(FileStore::new()?) })
    }

    #[allow(dead_code)]
    pub fn is_authenticated(&self) -> bool {
        AuthManager::new(self.store.clone())
            .map(|m| *m.state() == AuthState::Authenticated)
            .unwrap_or(false)
    }

    /// Link by phone number instead of QR scan.
    ///
    /// Prints an 8-character code; user enters it in WhatsApp →
    /// Settings → Linked Devices → Link a Device → "Link with phone number".
    /// Blocks until paired, then returns a live `Session`.
    pub async fn connect_with_phone(&self, phone: &str) -> Result<Session> {
        let mut auth_mgr = AuthManager::new(self.store.clone())?;

        if *auth_mgr.state() != AuthState::Authenticated {
            self.run_pairing_code(phone, &mut auth_mgr).await?;
        }

        // same post-auth setup as `connect`
        self.start_session(auth_mgr).await.map_err(Into::into)
    }

    /// Connect and return a live `Session`.
    ///
    /// On first run: prints QR to stdout, blocks until scanned.
    /// On subsequent runs: reconnects immediately.
    /// The session auto-reconnects in the background on any disconnect.
    pub async fn connect(&self) -> Result<Session> {
        let mut auth_mgr = AuthManager::new(self.store.clone())?;

        if *auth_mgr.state() != AuthState::Authenticated {
            self.run_pairing(&mut auth_mgr).await?;
        }

        self.start_session(auth_mgr).await.map_err(Into::into)
    }

    async fn start_session(&self, auth_mgr: AuthManager) -> Result<Session> {
        let our_jid = auth_mgr.creds().me.as_ref().map(|c| c.id.clone()).unwrap_or_default();
        let our_lid = auth_mgr.creds().me.as_ref().and_then(|c| c.lid.clone());

        // Shared state — survives reconnects
        let base = self.store.base_dir();
        let (event_tx, _) = broadcast::channel::<MessageEvent>(512);
        let contacts   = Arc::new(ContactStore::new(base)?);
        let msg_store  = Arc::new(MessageStore::new(base)?);
        let poll_store = Arc::new(PollStore::new(base)?);
        let outbox     = Arc::new(OutboxStore::new(base)?);
        let app_state_keys    = crate::app_state::AppStateKeyStore::new(base)?;
        let app_state_colls   = crate::app_state::CollectionStore::new(base)?;

        // Initial connection. Do NOT send any IQ yet — server hasn't authenticated us
        // until it emits <success>. Pre-key upload / passive-active happen in the recv
        // loop when that node arrives.
        let (sender, receiver) =
            socket::connect(auth_mgr.creds()).await.map_err(|e| anyhow::anyhow!("connect: {e}"))?;
        let sender = Arc::new(sender);

        let creds: SharedCreds = Arc::new(tokio::sync::Mutex::new(auth_mgr.creds().clone()));
        let signal = Arc::new(SignalRepository::new(&*creds.lock().await, self.store.clone()));

        let app_state_sync = Arc::new(crate::app_state::AppStateSync {
            sender: sender.clone(),
            keys: app_state_keys.clone(),
            collections: app_state_colls.clone(),
            event_tx: event_tx.clone(),
        });

        let mgr = Arc::new(
            MessageManager::with_stores(
                sender, signal, our_jid.clone(), event_tx.clone(),
                contacts.clone(), msg_store.clone(), poll_store.clone(), outbox.clone(),
            )
            .with_our_lid(our_lid.clone())
            .with_app_state(app_state_keys.clone(), app_state_sync.clone()),
        );
        let current_mgr: Arc<RwLock<Arc<MessageManager>>> = Arc::new(RwLock::new(mgr.clone()));

        info!("connected as {our_jid}");

        // Retry any messages that were left in the outbox from a previous run.
        // Purge expired entries first — a 24h-old send is almost never still
        // relevant and would just retry-loop forever against a bad jid.
        let expired = outbox.purge_expired();
        if expired > 0 {
            info!("outbox: purged {expired} expired entries (>24h)");
        }
        let pending = outbox.pending();
        if !pending.is_empty() {
            info!("{} outbox entries pending from previous session, retrying", pending.len());
            let mgr_retry = mgr.clone();
            tokio::spawn(async move {
                for (jid, msg) in pending {
                    mgr_retry.retry_outbox_entry(&jid, msg).await;
                }
            });
        }

        // Spawn background loop: recv nodes + keepalive + auto-reconnect + pre-key rotation
        let bg_store    = self.store.clone();
        let bg_creds    = creds.clone();
        let bg_mgr      = current_mgr.clone();
        let bg_tx       = event_tx.clone();
        let bg_jid      = our_jid.clone();
        let bg_contacts = contacts.clone();
        let bg_msgs     = msg_store.clone();
        let bg_polls    = poll_store.clone();
        let bg_outbox   = outbox.clone();
        // Subscribe before spawning so we don't miss the Connected event
        // emitted from inside run_session_loop.
        let mut ready_rx = event_tx.subscribe();

        let bg_handle = tokio::spawn(async move {
            run_session_loop(
                receiver, mgr, bg_mgr, bg_tx, bg_creds, bg_store, bg_jid,
                our_lid.clone(), bg_contacts, bg_msgs, bg_polls, bg_outbox,
            ).await;
        });

        // Wait up to 10 s for <success>. `Connected` is emitted immediately
        // after the server sends <success>; passive-active and OTK upload
        // run in the background and don't block the send path.
        let saw_connected = tokio::time::timeout(Duration::from_secs(10), async {
            while let Ok(ev) = ready_rx.recv().await {
                if matches!(ev, MessageEvent::Connected) {
                    return true;
                }
            }
            false
        }).await.unwrap_or(false);

        let connected = Arc::new(std::sync::atomic::AtomicBool::new(saw_connected));
        let chat_meta = Arc::new(crate::chat_meta::ChatMetaStore::new(base)?);

        // Mirror connection state + app-state updates from the event bus.
        // Single subscriber drives both so ordering is preserved (you'll
        // never get an AppStateUpdate before the matching Connected).
        {
            let connected = connected.clone();
            let chat_meta = chat_meta.clone();
            let mut rx = event_tx.subscribe();
            tokio::spawn(async move {
                use std::sync::atomic::Ordering;
                while let Ok(ev) = rx.recv().await {
                    match ev {
                        MessageEvent::Connected => connected.store(true, Ordering::SeqCst),
                        MessageEvent::Disconnected { .. }
                        | MessageEvent::Reconnecting { .. } => {
                            connected.store(false, Ordering::SeqCst);
                        }
                        MessageEvent::AppStateUpdate { ref action, .. } => {
                            chat_meta.apply(action);
                        }
                        _ => {}
                    }
                }
            });
        }

        Ok(Session {
            mgr: current_mgr, event_tx, our_jid, contacts, msg_store, poll_store,
            creds: creds.clone(),
            store: self.store.clone(),
            bg_handle: bg_handle.abort_handle(),
            connected,
            chat_meta,
        })
    }

    // ── Pairing ───────────────────────────────────────────────────────────────

    async fn run_pairing(&self, auth_mgr: &mut AuthManager) -> Result<()> {
        use crate::binary::{BinaryNode, NodeContent};
        use crate::qr;
        use base64::{engine::general_purpose::STANDARD as B64, Engine};

        loop {
            let (sender, mut receiver) = socket::connect(auth_mgr.creds()).await?;

            // Keepalive task: server closes after 30s without ping during pairing.
            let ping_sender = sender.clone();
            let keepalive = tokio::spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_secs(25));
                tick.tick().await; // discard immediate tick
                loop {
                    tick.tick().await;
                    let id = ping_sender.next_id();
                    let ping = BinaryNode {
                        tag: "iq".into(),
                        attrs: vec![
                            ("id".into(), id),
                            ("to".into(), "s.whatsapp.net".into()),
                            ("type".into(), "get".into()),
                            ("xmlns".into(), "w:p".into()),
                        ],
                        content: NodeContent::List(vec![BinaryNode {
                            tag: "ping".into(),
                            attrs: vec![],
                            content: NodeContent::None,
                        }]),
                    };
                    if ping_sender.send_node(&ping).await.is_err() { break; }
                }
            });

            let result: Result<()> = async {
            loop {
                let node = match receiver.recv_node().await? {
                    Some(n) => n,
                    None => break,
                };
                let content_kind = match &node.content {
                    NodeContent::None => "none".to_string(),
                    NodeContent::Text(t) => format!("text(len={})", t.len()),
                    NodeContent::Bytes(b) => format!("bytes(len={})", b.len()),
                    NodeContent::List(c) => format!("list(n={})", c.len()),
                };
                info!("pairing ← node tag={} content={} attrs={:?}", node.tag, content_kind, node.attrs);

                // Auto-ACK any iq that is not pair-device/pair-success (commerce_experience, pings, etc).
                // Those two cases send their own iq result inside the match arms below.
                let is_pair_iq = node.tag == "iq" && matches!(&node.content, NodeContent::List(c) if c.iter().any(|x| x.tag == "pair-device" || x.tag == "pair-success"));
                if node.tag == "iq" && !is_pair_iq {
                    let id = node.attr("id").unwrap_or("").to_string();
                    let from = node.attr("from").unwrap_or("s.whatsapp.net").to_string();
                    match sender.send_iq_result(&id, &from).await {
                        Ok(_)  => info!("pairing → ack iq id={id} to={from}"),
                        Err(e) => warn!("pairing → ack failed: {e}"),
                    }
                }

                if let NodeContent::List(children) = &node.content {
                    let child_tags: Vec<&str> = children.iter().map(|c| c.tag.as_str()).collect();
                    info!("pairing ← children={:?}", child_tags);
                    for child in children.clone() {
                        match child.tag.as_str() {
                            "pair-device" => {
                                let refs: Vec<String> =
                                    if let NodeContent::List(gc) = &child.content {
                                        gc.iter()
                                            .filter(|n| n.tag == "ref")
                                            .filter_map(|n| match &n.content {
                                                NodeContent::Text(s) => Some(s.clone()),
                                                NodeContent::Bytes(b) => {
                                                    String::from_utf8(b.clone()).ok()
                                                }
                                                _ => None,
                                            })
                                            .collect()
                                    } else {
                                        vec![]
                                    };
                                if refs.is_empty() {
                                    continue;
                                }
                                let c = auth_mgr.creds();
                                let qr_data = format!(
                                    "{},{},{},{}",
                                    refs[0],
                                    B64.encode(c.noise_key.public),
                                    B64.encode(c.signed_identity_key.public),
                                    B64.encode(&c.adv_secret_key)
                                );
                                println!("\n{}", qr::ascii::render_qr(qr_data.as_bytes()));
                                println!("Scan with WhatsApp on your phone\n");
                                let id = node.attr("id").unwrap_or("").to_string();
                                let from =
                                    node.attr("from").unwrap_or("s.whatsapp.net").to_string();
                                sender.send_iq_result(&id, &from).await?;
                            }
                            "pair-success" => {
                                use crate::auth::{Contact, pair_success::process_pair_success};
                                match process_pair_success(&node, auth_mgr.creds()) {
                                    Ok((outcome, reply)) => {
                                        // Persist identity + account-identity blob + save creds
                                        // before replying, so a crash after the reply still
                                        // leaves us paired and able to build pkmsg later.
                                        auth_mgr.set_me(Contact {
                                            id:   outcome.jid.clone(),
                                            name: outcome.business_name.clone(),
                                            lid:  outcome.lid.clone(),
                                        });
                                        auth_mgr.creds_mut().account_enc = outcome.account_enc.clone();
                                        auth_mgr.set_auth_state(AuthState::Authenticated);
                                        if let Err(e) = auth_mgr.save() {
                                            warn!("save creds after pair-success: {e}");
                                        }

                                        if let Err(e) = sender.send_node(&reply).await {
                                            warn!("send pair-device-sign reply: {e}");
                                        }
                                        info!(
                                            "paired! jid={} lid={:?} platform={:?} key_index={}",
                                            outcome.jid, outcome.lid,
                                            outcome.platform, outcome.key_index,
                                        );
                                        // Note: pre-key upload is skipped here —
                                        // server will disconnect after pair-success and we
                                        // reconnect in `start_session` where we upload then.
                                    }
                                    Err(e) => {
                                        warn!("pair-success processing failed: {e}");
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                // Once paired, do NOT reconnect immediately — the server still
                // needs to validate our pair-device-sign reply. Keep reading on
                // this socket until the server tears it down (xmlstreamend /
                // recv returns None). Reconnecting too early gives a 401.
            }
            Ok(())
            }.await;

            keepalive.abort();

            // Any exit path counts as success once the state flipped to Authenticated
            // (the server typically closes the socket after we send pair-device-sign,
            // which propagates up as Err from recv_node).
            if *auth_mgr.state() == AuthState::Authenticated {
                let _ = result; // ignore the connection-close error
                return Ok(());
            }
            info!("connection dropped during pairing, retrying in 3s…");
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    }

    // ── Pairing-by-phone-number ───────────────────────────────────────────────

    async fn run_pairing_code(&self, phone: &str, auth_mgr: &mut AuthManager) -> Result<()> {
        use crate::binary::NodeContent;

        // Set provisional JID so the server knows which account to link
        {
            let c = auth_mgr.creds_mut();
            c.me = Some(crate::auth::Contact {
                id: format!("{}@s.whatsapp.net", phone.trim_start_matches('+')),
                name: None,
                lid: None,
            });
        }

        let mut pairing_code: Option<String> = None;

        loop {
            let (sender, mut receiver) = socket::connect(auth_mgr.creds()).await?;

            loop {
                let node = match receiver.recv_node().await? {
                    Some(n) => n,
                    None => break,
                };

                // pair-device: send companion_hello and display code
                if let NodeContent::List(children) = &node.content {
                    for child in children.clone() {
                        if child.tag == "pair-device" {
                            let code = pairing_code_send_hello(&sender, auth_mgr).await?;
                            println!("\nEnter this code in WhatsApp → Settings → Linked Devices → Link a Device → \"Link with phone number instead\":\n");
                            println!("  {}-{}\n", &code[..4], &code[4..]);
                            pairing_code = Some(code);
                        }
                        if child.tag == "pair-success" {
                            let jid = if let NodeContent::List(gc) = &child.content {
                                gc.iter()
                                    .find(|n| n.tag == "device")
                                    .and_then(|n| n.attr("jid"))
                                    .map(|s| s.to_string())
                            } else {
                                None
                            };
                            if let Some(jid) = jid {
                                auth_mgr.set_me(crate::auth::Contact {
                                    id: jid.clone(),
                                    name: None,
                                    lid: None,
                                });
                                auth_mgr.set_auth_state(AuthState::Authenticated);
                                auth_mgr.save()?;
                                let id = node.attr("id").unwrap_or("").to_string();
                                let from = node.attr("from").unwrap_or("s.whatsapp.net").to_string();
                                sender.send_iq_result(&id, &from).await?;
                                if let Err(e) = socket::prekey::upload_pre_keys(
                                    &sender, auth_mgr.creds_mut(), self.store.as_ref(),
                                ).await {
                                    warn!("pre-key upload: {e}");
                                }
                                info!("paired via phone code! JID={jid}");
                            }
                        }
                    }
                }

                // link_code_companion_reg notification from phone → do companion_finish
                if node.tag == "notification" && node.attr("type") == Some("link_code_companion_reg") {
                    if let Some(ref code) = pairing_code {
                        if let Err(e) = pairing_code_send_finish(&sender, auth_mgr, &node, code).await {
                            warn!("companion_finish failed: {e}");
                        }
                    }
                }

                if *auth_mgr.state() == AuthState::Authenticated {
                    return Ok(());
                }
            }

            info!("connection dropped during pairing, retrying in 3s…");
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    }
}

// ── Pairing code crypto ───────────────────────────────────────────────────────
// All helpers live in auth::pairing_crypto for testability.

use crate::auth::pairing_crypto::{
    aes256_gcm_encrypt, decipher_link_public_key,
    generate_pairing_code, hkdf_sha256, make_wrapped_companion_ephemeral, x25519_dh,
};

/// Send the companion_hello IQ; returns the 8-char pairing code.
async fn pairing_code_send_hello(
    sender: &crate::socket::SocketSender,
    auth_mgr: &mut AuthManager,
) -> Result<String> {
    use crate::binary::{BinaryNode, NodeContent};

    let code = generate_pairing_code();
    auth_mgr.creds_mut().pairing_code = Some(code.clone());

    let ephemeral_pub = auth_mgr.creds().pairing_ephemeral_key.public;
    let noise_pub     = auth_mgr.creds().noise_key.public;
    let our_jid       = auth_mgr.creds().me.as_ref()
        .map(|m| m.id.clone())
        .unwrap_or_default();

    let wrapped = make_wrapped_companion_ephemeral(&code, &ephemeral_pub);

    let id = sender.next_id();
    let node = BinaryNode {
        tag: "iq".to_string(),
        attrs: vec![
            ("id".to_string(), id),
            ("to".to_string(), "s.whatsapp.net".to_string()),
            ("type".to_string(), "set".to_string()),
            ("xmlns".to_string(), "md".to_string()),
        ],
        content: NodeContent::List(vec![BinaryNode {
            tag: "link_code_companion_reg".to_string(),
            attrs: vec![
                ("jid".to_string(), our_jid),
                ("stage".to_string(), "companion_hello".to_string()),
                ("should_show_push_notification".to_string(), "true".to_string()),
            ],
            content: NodeContent::List(vec![
                BinaryNode {
                    tag: "link_code_pairing_wrapped_companion_ephemeral_pub".to_string(),
                    attrs: vec![],
                    content: NodeContent::Bytes(wrapped),
                },
                BinaryNode {
                    tag: "companion_server_auth_key_pub".to_string(),
                    attrs: vec![],
                    content: NodeContent::Bytes(noise_pub.to_vec()),
                },
                BinaryNode {
                    tag: "companion_platform_id".to_string(),
                    attrs: vec![],
                    content: NodeContent::Text("1".to_string()), // Chrome
                },
                BinaryNode {
                    tag: "companion_platform_display".to_string(),
                    attrs: vec![],
                    content: NodeContent::Text("Chrome (WhatsApp)".to_string()),
                },
                BinaryNode {
                    tag: "link_code_pairing_nonce".to_string(),
                    attrs: vec![],
                    content: NodeContent::Text("0".to_string()),
                },
            ]),
        }]),
    };

    sender.send_node(&node).await?;
    Ok(code)
}

/// Process the phone's `link_code_companion_reg` notification and send companion_finish.
async fn pairing_code_send_finish(
    sender: &crate::socket::SocketSender,
    auth_mgr: &mut AuthManager,
    notification: &crate::binary::BinaryNode,
    pairing_code: &str,
) -> Result<()> {
    use crate::binary::{BinaryNode, NodeContent};
    use rand::RngCore;

    // Find the inner link_code_companion_reg child
    let inner = match &notification.content {
        NodeContent::List(ch) => ch.iter().find(|n| n.tag == "link_code_companion_reg").cloned(),
        _ => None,
    }.ok_or_else(|| anyhow::anyhow!("no link_code_companion_reg in notification"))?;

    let get_bytes = |tag: &str| -> anyhow::Result<Vec<u8>> {
        match &inner.content {
            NodeContent::List(ch) => ch.iter()
                .find(|n| n.tag == tag)
                .and_then(|n| match &n.content {
                    NodeContent::Bytes(b) => Some(b.clone()),
                    NodeContent::Text(t) => Some(t.as_bytes().to_vec()),
                    _ => None,
                })
                .ok_or_else(|| anyhow::anyhow!("missing {} in link_code_companion_reg", tag)),
            _ => Err(anyhow::anyhow!("empty link_code_companion_reg")),
        }
    };

    let link_ref          = get_bytes("link_code_pairing_ref")?;
    let primary_id_pub    = get_bytes("primary_identity_pub")?;
    let wrapped_primary   = get_bytes("link_code_pairing_wrapped_primary_ephemeral_pub")?;

    // Decipher phone's ephemeral public key
    let code_pairing_pub  = decipher_link_public_key(pairing_code, &wrapped_primary)?;

    let pairing_priv      = auth_mgr.creds().pairing_ephemeral_key.private;
    let identity_priv     = auth_mgr.creds().signed_identity_key.private;
    let identity_pub      = auth_mgr.creds().signed_identity_key.public;

    let companion_shared  = x25519_dh(&pairing_priv, &code_pairing_pub);

    let mut random_bytes  = [0u8; 32];
    let mut link_salt     = [0u8; 32];
    let mut encrypt_iv    = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut random_bytes);
    rand::rngs::OsRng.fill_bytes(&mut link_salt);
    rand::rngs::OsRng.fill_bytes(&mut encrypt_iv);

    let link_key = hkdf_sha256(
        &companion_shared,
        Some(&link_salt),
        b"link_code_pairing_key_bundle_encryption_key",
        32,
    );
    let link_key_arr: [u8; 32] = link_key.try_into().unwrap();

    let primary_id_pub_arr: [u8; 32] = primary_id_pub.as_slice().try_into()
        .map_err(|_| anyhow::anyhow!("primary_identity_pub wrong length"))?;

    let mut encrypt_payload = Vec::with_capacity(96);
    encrypt_payload.extend_from_slice(&identity_pub);
    encrypt_payload.extend_from_slice(&primary_id_pub_arr);
    encrypt_payload.extend_from_slice(&random_bytes);

    let encrypted = aes256_gcm_encrypt(&encrypt_payload, &link_key_arr, &encrypt_iv);

    let mut encrypted_bundle = Vec::with_capacity(156);
    encrypted_bundle.extend_from_slice(&link_salt);
    encrypted_bundle.extend_from_slice(&encrypt_iv);
    encrypted_bundle.extend_from_slice(&encrypted);

    // Derive new adv_secret_key
    let identity_shared = x25519_dh(&identity_priv, &primary_id_pub_arr);
    let mut identity_payload = Vec::with_capacity(96);
    identity_payload.extend_from_slice(&companion_shared);
    identity_payload.extend_from_slice(&identity_shared);
    identity_payload.extend_from_slice(&random_bytes);
    let new_adv = hkdf_sha256(&identity_payload, None, b"adv_secret", 32);
    auth_mgr.creds_mut().adv_secret_key = new_adv;

    let our_jid = auth_mgr.creds().me.as_ref()
        .map(|m| m.id.clone())
        .unwrap_or_default();

    let id = sender.next_id();
    let node = BinaryNode {
        tag: "iq".to_string(),
        attrs: vec![
            ("id".to_string(), id),
            ("to".to_string(), "s.whatsapp.net".to_string()),
            ("type".to_string(), "set".to_string()),
            ("xmlns".to_string(), "md".to_string()),
        ],
        content: NodeContent::List(vec![BinaryNode {
            tag: "link_code_companion_reg".to_string(),
            attrs: vec![
                ("jid".to_string(), our_jid),
                ("stage".to_string(), "companion_finish".to_string()),
            ],
            content: NodeContent::List(vec![
                BinaryNode {
                    tag: "link_code_pairing_wrapped_key_bundle".to_string(),
                    attrs: vec![],
                    content: NodeContent::Bytes(encrypted_bundle),
                },
                BinaryNode {
                    tag: "companion_identity_public".to_string(),
                    attrs: vec![],
                    content: NodeContent::Bytes(identity_pub.to_vec()),
                },
                BinaryNode {
                    tag: "link_code_pairing_ref".to_string(),
                    attrs: vec![],
                    content: NodeContent::Bytes(link_ref),
                },
            ]),
        }]),
    };

    sender.send_node(&node).await?;
    Ok(())
}

// ── Background session loop ───────────────────────────────────────────────────

type SharedCreds = Arc<tokio::sync::Mutex<crate::auth::credentials::AuthCredentials>>;

/// Runs recv + keepalive for the current connection, then reconnects on drop.
async fn run_session_loop(
    receiver: socket::SocketReceiver,
    initial_mgr: Arc<MessageManager>,
    current_mgr: Arc<RwLock<Arc<MessageManager>>>,
    event_tx: broadcast::Sender<MessageEvent>,
    creds: SharedCreds,
    store: Arc<FileStore>,
    our_jid: String,
    our_lid: Option<String>,
    contacts: Arc<ContactStore>,
    msg_store: Arc<MessageStore>,
    poll_store: Arc<PollStore>,
    outbox: Arc<OutboxStore>,
) {
    if !run_one_connection(receiver, initial_mgr, creds.clone(), store.clone(), event_tx.clone()).await {
        return; // permanent failure — don't reconnect
    }

    // Reconnect loop: exponential backoff with jitter, capped at 60s. Each
    // retry emits a `Reconnecting` event so UIs / metrics can surface the
    // delay. `attempt` resets once a fresh connection holds long enough to
    // yield a successful <success>.
    let mut backoff = Duration::from_secs(2);
    let mut attempt: u32 = 0;
    loop {
        attempt = attempt.saturating_add(1);
        crate::metrics::inc_reconnect();
        let delay = with_jitter(backoff);
        info!("reconnecting in {delay:?} (attempt {attempt})");
        let _ = event_tx.send(MessageEvent::Reconnecting { attempt, delay });
        tokio::time::sleep(delay).await;
        backoff = (backoff * 2).min(Duration::from_secs(60));

        let (sender, receiver) = {
            let c = creds.lock().await;
            match socket::connect(&*c).await {
                Ok(pair) => {
                    backoff = Duration::from_secs(2);
                    attempt = 0;
                    pair
                }
                Err(e) => { warn!("reconnect failed: {e}"); continue; }
            }
        };
        let sender = Arc::new(sender);
        // Pre-key upload deferred to <success> handler (session not authenticated yet).

        let signal = {
            let c = creds.lock().await;
            Arc::new(SignalRepository::new(&*c, store.clone()))
        };
        let base = store.base_dir();
        let app_state_keys  = crate::app_state::AppStateKeyStore::new(base).expect("app-state keys");
        let app_state_colls = crate::app_state::CollectionStore::new(base).expect("app-state colls");
        let app_state_sync = Arc::new(crate::app_state::AppStateSync {
            sender: sender.clone(),
            keys: app_state_keys.clone(),
            collections: app_state_colls.clone(),
            event_tx: event_tx.clone(),
        });
        let mgr = Arc::new(
            MessageManager::with_stores(
                sender, signal, our_jid.clone(), event_tx.clone(),
                contacts.clone(), msg_store.clone(), poll_store.clone(), outbox.clone(),
            )
            .with_our_lid(our_lid.clone())
            .with_app_state(app_state_keys, app_state_sync),
        );

        *current_mgr.write().await = mgr.clone();
        info!("reconnected as {our_jid}");

        // Retry any messages that failed during the previous connection
        let pending = outbox.pending();
        if !pending.is_empty() {
            info!("{} outbox entries, retrying after reconnect", pending.len());
            let mgr_retry = mgr.clone();
            tokio::spawn(async move {
                for (jid, msg) in pending {
                    mgr_retry.retry_outbox_entry(&jid, msg).await;
                }
            });
        }

        if !run_one_connection(receiver, mgr, creds.clone(), store.clone(), event_tx.clone()).await {
            warn!("permanent disconnect — stopping reconnect loop");
            return;
        }
    }
}

/// Add ±20% random jitter to `base` to avoid thundering-herd reconnects.
///
/// Clamped to a floor of 500 ms so we never burst-dial after a flap.
fn with_jitter(base: Duration) -> Duration {
    use rand::Rng;
    let ms = base.as_millis() as u64;
    let jitter_ms = (ms / 5).max(100);
    let offset: i64 = rand::thread_rng().gen_range(-(jitter_ms as i64)..=(jitter_ms as i64));
    let adjusted = (ms as i64).saturating_add(offset).max(500) as u64;
    Duration::from_millis(adjusted)
}

/// Drive a single connection to completion (recv loop + keepalive + pre-key rotation).
/// Returns `true` if the caller should reconnect, `false` if a permanent failure occurred.
async fn run_one_connection(
    mut receiver: socket::SocketReceiver,
    mgr: Arc<MessageManager>,
    creds: SharedCreds,
    store: Arc<FileStore>,
    event_tx: broadcast::Sender<MessageEvent>,
) -> bool {
    // Shared liveness marker — updated every time we accept a node from the
    // wire. The liveness watchdog tears the connection down if it goes
    // stale, which is our only signal for "silent" WebSocket stalls where
    // the kernel never surfaces a RST.
    let last_rx = Arc::new(tokio::sync::Mutex::new(tokio::time::Instant::now()));

    let ping_socket = mgr.socket.clone();
    let keepalive = tokio::spawn(async move {
        use crate::binary::{BinaryNode, NodeContent};
        let mut interval = tokio::time::interval(Duration::from_secs(25));
        interval.tick().await;
        loop {
            interval.tick().await;
            let id = ping_socket.next_id();
            let ping = BinaryNode {
                tag: "iq".to_string(),
                attrs: vec![
                    ("id".to_string(), id),
                    ("xmlns".to_string(), "w:p".to_string()),
                    ("type".to_string(), "get".to_string()),
                    ("to".to_string(), "s.whatsapp.net".to_string()),
                ],
                content: NodeContent::List(vec![BinaryNode {
                    tag: "ping".to_string(),
                    attrs: vec![],
                    content: NodeContent::None,
                }]),
            };
            if ping_socket.send_node(&ping).await.is_err() {
                break;
            }
        }
    });

    // Liveness watchdog: if no node has arrived in 75 s the socket is
    // effectively dead. Disconnect it so the recv loop breaks and the
    // outer reconnect loop dials again. 75 s > 3× the 25 s keepalive
    // interval so transient jitter won't trip it.
    const STALE_AFTER: Duration = Duration::from_secs(75);
    let watchdog_rx = last_rx.clone();
    let watchdog_sock = mgr.socket.clone();
    let watchdog_ev  = event_tx.clone();
    let watchdog = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        interval.tick().await;
        loop {
            interval.tick().await;
            let since = {
                let t = watchdog_rx.lock().await;
                tokio::time::Instant::now().saturating_duration_since(*t)
            };
            if since > STALE_AFTER {
                warn!("liveness watchdog: no nodes in {since:?}, forcing reconnect");
                let _ = watchdog_ev.send(MessageEvent::Disconnected {
                    reason: format!("watchdog stale ({since:?})"),
                    reconnect: true,
                });
                // Closing the underlying socket causes recv_node to
                // return Err and the select!-loop to break.
                watchdog_sock.close().await;
                return;
            }
        }
    });

    // Proactive key rotation: every 6 hours check OTK count; every 7 days rotate SPK.
    let rot_socket = mgr.socket.clone();
    let rot_creds  = creds.clone();
    let rot_store  = store.clone();
    let rotation = tokio::spawn(async move {
        const OTK_THRESHOLD: u32    = 10;
        const SPK_INTERVAL_SECS: u64 = 7 * 24 * 3600;

        let mut interval = tokio::time::interval(Duration::from_secs(6 * 3600));
        interval.tick().await; // discard the immediate first tick
        loop {
            interval.tick().await;

            // ── OTK check ────────────────────────────────────────────────────
            match socket::prekey::query_pre_key_count(&rot_socket).await {
                Ok(count) if count < OTK_THRESHOLD => {
                    info!("proactive OTK rotation: {count} keys left, uploading batch");
                    let mut c = rot_creds.lock().await;
                    if let Err(e) = socket::prekey::upload_pre_keys(&rot_socket, &mut *c, rot_store.as_ref()).await {
                        warn!("OTK upload failed: {e}");
                    }
                }
                Ok(count) => debug!("OTK count OK: {count}"),
                Err(e) => {
                    warn!("OTK count query failed: {e}");
                    break; // connection dead; stop the task
                }
            }

            // ── SPK rotation ─────────────────────────────────────────────────
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let spk_age = {
                let c = rot_creds.lock().await;
                if c.spk_last_rotated == 0 { SPK_INTERVAL_SECS + 1 } // never rotated
                else { now.saturating_sub(c.spk_last_rotated) }
            };
            if spk_age >= SPK_INTERVAL_SECS {
                info!("SPK age {spk_age}s ≥ 7 days, rotating signed pre-key");
                let mut c = rot_creds.lock().await;
                if let Err(e) = socket::prekey::rotate_signed_pre_key(&rot_socket, &mut *c, rot_store.as_ref()).await {
                    warn!("SPK rotation failed: {e}");
                }
            }
        }
    });

    let mut event_rx = mgr.subscribe();
    let mut should_reconnect = true;

    loop {
        tokio::select! {
            // Drain event bus to watch for permanent disconnects
            ev = event_rx.recv() => {
                if let Ok(MessageEvent::Disconnected { reconnect, .. }) = ev {
                    should_reconnect = reconnect;
                    if !reconnect {
                        break;
                    }
                }
            }
            node_result = receiver.recv_node() => {
                match node_result {
                    Ok(Some(node)) => {
                        *last_rx.lock().await = tokio::time::Instant::now();
                        tracing::debug!(tag = %node.tag, attrs = ?node.attrs, "← node");
                        if node.tag == "message" {
                            info!(
                                from = %node.attr("from").unwrap_or(""),
                                id = %node.attr("id").unwrap_or(""),
                                participant = %node.attr("participant").unwrap_or(""),
                                kind = %node.attr("type").unwrap_or(""),
                                offline = %node.attr("offline").unwrap_or(""),
                                "client received message node",
                            );
                        }

                        // Login confirmation — session is authenticated and
                        // usable NOW. Emit Connected immediately so send-path
                        // code can unblock; background tasks (OTK upload +
                        // passive-active) finish asynchronously and WA won't
                        // reject messages while they run.
                        if node.tag == "success" {
                            info!("login success ({})", node.attr("lid").unwrap_or("no lid"));
                            let _ = mgr.event_tx.send(MessageEvent::Connected);

                            // Fire-and-forget app-state resync if we already have keys.
                            // Fresh installs won't: the primary will push them via
                            // `appStateSyncKeyShare` and we'll resync from there.
                            if let Some(sync) = mgr.app_state_sync.clone() {
                                if let Some(keys) = mgr.app_state_keys.as_ref() {
                                    if !keys.is_empty() {
                                        tokio::spawn(async move {
                                            let _ = sync.resync(crate::app_state::ALL_COLLECTIONS, true).await;
                                        });
                                    }
                                }
                            }

                            let sock = mgr.socket.clone();
                            let cr   = creds.clone();
                            let st   = store.clone();
                            tokio::spawn(async move {
                                let need = socket::prekey::query_pre_key_count(&sock).await
                                    .map(|c| c < 10)
                                    .unwrap_or(true);
                                if need {
                                    let mut c = cr.lock().await;
                                    if let Err(e) = socket::prekey::upload_pre_keys(
                                        &sock, &mut *c, st.as_ref(),
                                    ).await {
                                        warn!("pre-key upload after success: {e}");
                                    }
                                }
                                if let Err(e) = sock.send_passive_active().await {
                                    warn!("passive active iq failed: {e}");
                                }
                            });

                            // Announce presence=available with a name — without this,
                            // the server keeps us in passive mode and only delivers
                            // offline-queued messages, never live fan-out.
                            let pres_mgr = mgr.clone();
                            tokio::spawn(async move {
                                match pres_mgr.send_presence(true).await {
                                    Ok(()) => info!("→ presence type=available name=WhatsApp-rs"),
                                    Err(e) => warn!("presence available failed: {e}"),
                                }
                            });
                        }

                        if let Some(count) = crate::messages::recv::extract_encrypt_count(&node) {
                            if count < 5 {
                                info!("server OTK count low ({count}), uploading new batch");
                                let mut c = creds.lock().await;
                                if let Err(e) = socket::prekey::upload_pre_keys(&mgr.socket, &mut *c, store.as_ref()).await {
                                    warn!("pre-key upload on low count: {e}");
                                }
                            }
                        }
                        if let Err(e) = mgr.handle_node(&node).await {
                            warn!(tag = %node.tag, from = %node.attr("from").unwrap_or(""), id = %node.attr("id").unwrap_or(""), "handle_node failed: {e}");
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        debug!("recv: {e}");
                        break;
                    }
                }
            }
        }
    }
    keepalive.abort();
    rotation.abort();
    watchdog.abort();
    should_reconnect
}

// ── Session ───────────────────────────────────────────────────────────────────

/// A live authenticated session.
///
/// All methods are cheap — they read-lock the current `MessageManager` which
/// is swapped atomically on each reconnect.
pub struct Session {
    mgr: Arc<RwLock<Arc<MessageManager>>>,
    event_tx: broadcast::Sender<MessageEvent>,
    pub our_jid: String,
    contacts: Arc<ContactStore>,
    msg_store: Arc<MessageStore>,
    #[allow(dead_code)]
    poll_store: Arc<PollStore>,
    creds: SharedCreds,
    store: Arc<FileStore>,
    bg_handle: tokio::task::AbortHandle,
    /// Mirrored from `MessageEvent::Connected` / `Disconnected` so callers
    /// can cheaply check liveness without subscribing to the event bus.
    connected: Arc<std::sync::atomic::AtomicBool>,
    /// Per-JID metadata index projected from app-state sync. Kept in
    /// sync by the background event subscriber.
    chat_meta: Arc<crate::chat_meta::ChatMetaStore>,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.bg_handle.abort();
    }
}

/// RAII handle for a typing heartbeat. See [`Session::typing_heartbeat`].
///
/// Dropping the handle aborts the refresher task and fires one last
/// `typing=off` in a background task (Drop can't be async). The off send
/// is best-effort — it may race with the task-executor being torn down
/// but normally lands well under 100 ms.
pub struct TypingHandle {
    abort: tokio::task::AbortHandle,
    mgr: Arc<RwLock<Arc<MessageManager>>>,
    jid: String,
}

impl Drop for TypingHandle {
    fn drop(&mut self) {
        self.abort.abort();
        let mgr = self.mgr.clone();
        let jid = std::mem::take(&mut self.jid);
        tokio::spawn(async move {
            let m = mgr.read().await;
            let _ = m.send_typing(&jid, false).await;
        });
    }
}

#[allow(dead_code)]
impl Session {
    // ── Events ────────────────────────────────────────────────────────────────

    /// Subscribe to all incoming events.
    /// The same channel is reused across reconnects so no events are missed.
    pub fn events(&self) -> broadcast::Receiver<MessageEvent> {
        self.event_tx.subscribe()
    }

    /// Cheap, non-blocking check: was the last lifecycle event `Connected`?
    ///
    /// Transitions to `false` on `Disconnected` or `Reconnecting`. Flips back
    /// to `true` once the recv loop sees `<success>` from the server. No IPC
    /// or event-bus poll — just an atomic load, safe to call in a hot path.
    pub fn is_connected(&self) -> bool {
        self.connected.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Block until [`is_connected`](Self::is_connected) turns `true`, or the
    /// `timeout` elapses. Returns `true` if we observed a live connection
    /// during the wait, `false` on timeout.
    ///
    /// If already connected, returns immediately.
    pub async fn wait_connected(&self, timeout: std::time::Duration) -> bool {
        if self.is_connected() { return true; }
        let mut rx = self.event_tx.subscribe();
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            // Fast-path re-check in case the flag flipped between the
            // guard above and the subscribe above.
            if self.is_connected() { return true; }
            let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
            if rem.is_zero() { return false; }
            match tokio::time::timeout(rem, rx.recv()).await {
                Err(_) => return false,
                Ok(Err(_)) => return false, // event bus closed
                Ok(Ok(MessageEvent::Connected)) => return true,
                Ok(Ok(_)) => continue,
            }
        }
    }

    // ── Sending ───────────────────────────────────────────────────────────────

    pub async fn send_text(&self, jid: &str, text: &str) -> Result<String> {
        self.mgr.read().await.send_text(jid, text).await.map_err(Into::into)
    }

    pub async fn send_reply(&self, jid: &str, reply_to_id: &str, text: &str) -> Result<String> {
        self.mgr.read().await.send_reply(jid, reply_to_id, text).await.map_err(Into::into)
    }

    pub async fn send_reaction(&self, jid: &str, target_id: &str, emoji: &str) -> Result<()> {
        self.mgr.read().await.send_reaction(jid, target_id, emoji).await.map_err(Into::into)
    }

    pub async fn send_mention(
        &self,
        jid: &str,
        text: &str,
        mention_jids: &[&str],
    ) -> Result<String> {
        self.mgr.read().await.send_mention(jid, text, mention_jids).await.map_err(Into::into)
    }

    pub async fn send_revoke(&self, jid: &str, msg_id: &str) -> Result<()> {
        self.mgr.read().await.send_revoke(jid, msg_id).await.map_err(Into::into)
    }

    pub async fn send_edit(&self, jid: &str, msg_id: &str, new_text: &str) -> Result<()> {
        self.mgr.read().await.send_edit(jid, msg_id, new_text).await.map_err(Into::into)
    }

    pub async fn send_poll_vote(
        &self,
        jid: &str,
        poll_msg_id: &str,
        selected_options: &[&str],
    ) -> Result<()> {
        self.mgr.read().await.send_poll_vote(jid, poll_msg_id, selected_options).await.map_err(Into::into)
    }

    pub async fn send_image(
        &self, jid: &str, data: &[u8], caption: Option<&str>,
    ) -> Result<String> {
        self.mgr.read().await.send_image(jid, data, caption).await.map_err(Into::into)
    }

    /// Send a "view once" image — receiver's WA client wipes it after open.
    pub async fn send_view_once_image(
        &self, jid: &str, data: &[u8], caption: Option<&str>,
    ) -> Result<String> {
        self.mgr.read().await.send_view_once_image(jid, data, caption).await.map_err(Into::into)
    }

    pub async fn send_video(
        &self, jid: &str, data: &[u8], caption: Option<&str>,
    ) -> Result<String> {
        self.mgr.read().await.send_video(jid, data, caption).await.map_err(Into::into)
    }

    /// Send a "view once" video.
    pub async fn send_view_once_video(
        &self, jid: &str, data: &[u8], caption: Option<&str>,
    ) -> Result<String> {
        self.mgr.read().await.send_view_once_video(jid, data, caption).await.map_err(Into::into)
    }

    pub async fn send_audio(&self, jid: &str, data: &[u8], mimetype: &str) -> Result<String> {
        self.mgr.read().await.send_audio(jid, data, mimetype).await.map_err(Into::into)
    }

    /// Voice note (push-to-talk): audio with the `ptt` flag set so peer
    /// clients show the waveform/play-bar UI.
    pub async fn send_voice_note(&self, jid: &str, data: &[u8], mimetype: &str) -> Result<String> {
        self.mgr.read().await.send_voice_note(jid, data, mimetype).await.map_err(Into::into)
    }

    pub async fn send_document(
        &self, jid: &str, data: &[u8], mimetype: &str, file_name: &str,
    ) -> Result<String> {
        self.mgr.read().await.send_document(jid, data, mimetype, file_name).await.map_err(Into::into)
    }

    pub async fn send_sticker(&self, jid: &str, data: &[u8]) -> Result<String> {
        self.mgr.read().await.send_sticker(jid, data).await.map_err(Into::into)
    }

    pub async fn send_poll(
        &self,
        jid: &str,
        question: &str,
        options: &[&str],
        selectable_count: u32,
    ) -> Result<String> {
        self.mgr.read().await.send_poll(jid, question, options, selectable_count).await.map_err(Into::into)
    }

    pub async fn send_location(
        &self, jid: &str,
        latitude: f64, longitude: f64,
        name: Option<&str>, address: Option<&str>,
    ) -> Result<String> {
        self.mgr.read().await.send_location(jid, latitude, longitude, name, address).await.map_err(Into::into)
    }

    /// Send a contact card built from a name + E.164 phone (e.g.
    /// `+573001234567`). Generates a minimal vCard automatically.
    pub async fn send_contact(
        &self, jid: &str, display_name: &str, phone_e164: &str,
    ) -> Result<String> {
        let vcard = crate::messages::MessageContent::contact_vcard(display_name, phone_e164);
        self.mgr.read().await.send_contact(jid, display_name, &vcard).await.map_err(Into::into)
    }

    /// Send a contact card with a pre-built vCard string. Use when you
    /// need something richer than the single-phone helper
    /// ([`Self::send_contact`]) — multiple TEL lines, email, address, etc.
    pub async fn send_contact_vcard(
        &self, jid: &str, display_name: &str, vcard: &str,
    ) -> Result<String> {
        self.mgr.read().await.send_contact(jid, display_name, vcard).await.map_err(Into::into)
    }

    pub async fn send_link_preview(
        &self,
        jid: &str,
        text: &str,
        url: &str,
        title: &str,
        description: &str,
        thumbnail_jpeg: Option<Vec<u8>>,
    ) -> Result<String> {
        self.mgr.read().await
            .send_link_preview(jid, text, url, title, description, thumbnail_jpeg)
            .await.map_err(Into::into)
    }

    /// Send an inline-buttons message (up to 3 buttons; consumer WA may
    /// render only the fallback text).
    pub async fn send_buttons(
        &self, jid: &str, text: &str, footer: Option<&str>,
        buttons: &[(String, String)],
    ) -> Result<String> {
        self.mgr.read().await.send_buttons(jid, text, footer, buttons).await.map_err(Into::into)
    }

    /// Send a list (tap-to-open) with sections of rows.
    pub async fn send_list(
        &self, jid: &str,
        title: &str, description: &str, button_text: &str,
        footer: Option<&str>,
        sections: Vec<crate::messages::ListSection>,
    ) -> Result<String> {
        self.mgr.read().await
            .send_list(jid, title, description, button_text, footer, sections)
            .await.map_err(Into::into)
    }

    /// Send text and auto-attach a link preview if the body contains a URL.
    /// Fetches OG metadata + thumbnail with a short timeout; degrades to
    /// plain text on fetch failure.
    pub async fn send_text_with_preview(&self, jid: &str, text: &str) -> Result<String> {
        self.mgr.read().await.send_text_with_auto_preview(jid, text).await.map_err(Into::into)
    }

    pub async fn send_group_text(&self, group_jid: &str, text: &str) -> Result<String> {
        self.mgr.read().await.send_group_text(group_jid, text).await.map_err(Into::into)
    }

    /// Post a text status update visible to all contacts.
    pub async fn send_status_text(&self, text: &str) -> Result<String> {
        self.mgr.read().await.send_status_text(text).await.map_err(Into::into)
    }

    pub async fn send_status_image(&self, data: &[u8], caption: Option<&str>) -> Result<String> {
        self.mgr.read().await.send_status_image(data, caption).await.map_err(Into::into)
    }

    pub async fn send_status_video(&self, data: &[u8], caption: Option<&str>) -> Result<String> {
        self.mgr.read().await.send_status_video(data, caption).await.map_err(Into::into)
    }

    pub async fn forward_message(
        &self,
        to_jid: &str,
        from_jid: &str,
        msg_id: &str,
    ) -> Result<String> {
        self.mgr.read().await.forward_message(to_jid, from_jid, msg_id).await.map_err(Into::into)
    }

    pub async fn set_ephemeral_duration(&self, jid: &str, expiration_secs: u32) -> Result<()> {
        self.mgr.read().await.set_ephemeral_duration(jid, expiration_secs).await.map_err(Into::into)
    }

    pub async fn group_info(
        &self,
        group_jid: &str,
    ) -> Result<crate::socket::group::GroupInfo> {
        self.mgr.read().await.group_info(group_jid).await.map_err(Into::into)
    }

    // ── Privacy settings ─────────────────────────────────────────────────────

    /// Fetch current privacy settings from the server.
    pub async fn fetch_privacy(
        &self,
    ) -> Result<crate::socket::privacy::PrivacySettings> {
        let socket = self.mgr.read().await.socket.clone();
        crate::socket::privacy::fetch_privacy(&socket).await.map_err(Into::into)
    }

    /// Update privacy settings.  Only fields set to `Some(...)` are changed.
    /// Use `PrivacyPatch::default()` as the base and override only what you need.
    pub async fn set_privacy(
        &self,
        patch: crate::socket::privacy::PrivacyPatch,
    ) -> Result<()> {
        let socket = self.mgr.read().await.socket.clone();
        crate::socket::privacy::set_privacy(&socket, &patch).await.map_err(Into::into)
    }

    // ── Key management ───────────────────────────────────────────────────────

    /// Manually rotate the signed pre-key now (normally done automatically every 7 days).
    pub async fn rotate_signed_pre_key(&self) -> Result<()> {
        let socket = self.mgr.read().await.socket.clone();
        let mut c = self.creds.lock().await;
        socket::prekey::rotate_signed_pre_key(&socket, &mut *c, self.store.as_ref()).await.map_err(Into::into)
    }

    // ── Receipts & presence ───────────────────────────────────────────────────

    pub async fn mark_read(&self, keys: &[MessageKey]) -> Result<()> {
        self.mgr.read().await.read_messages(keys).await.map_err(Into::into)
    }

    pub async fn send_typing(&self, jid: &str, composing: bool) -> Result<()> {
        self.mgr.read().await.send_typing(jid, composing).await.map_err(Into::into)
    }

    /// Start a "typing…" heartbeat on `jid`. WA expires the indicator after
    /// ~15 s of silence, so a long-running agent must refresh it. Returns a
    /// [`TypingHandle`] that loops `typing=on` every 10 s until dropped; at
    /// drop the handle sends `typing=off` once and aborts the refresher.
    ///
    /// Use when an agent spends >15 s preparing a reply (LLM round-trip,
    /// media rendering, external API call).
    ///
    /// ```ignore
    /// let _typing = session.typing_heartbeat(&jid);
    /// let reply = my_agent.think(msg).await;  // slow
    /// session.send_text(&jid, &reply).await?;  // drop here → typing=off
    /// ```
    /// Internal accessor: hands out a clone of the current-manager Arc so
    /// crate-local helpers (agent runtime, metrics, etc.) can spawn tasks
    /// that use the live manager across reconnects.
    pub(crate) fn mgr_handle(&self) -> Arc<RwLock<Arc<MessageManager>>> {
        self.mgr.clone()
    }

    pub fn typing_heartbeat(&self, jid: &str) -> TypingHandle {
        let mgr = self.mgr.clone();
        let jid_owned = jid.to_string();
        let refresh_mgr = mgr.clone();
        let refresh_jid = jid_owned.clone();
        let task = tokio::spawn(async move {
            // Send the initial on immediately (interval's first tick fires instantly).
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
            loop {
                interval.tick().await;
                let m = refresh_mgr.read().await;
                let _ = m.send_typing(&refresh_jid, true).await;
            }
        });
        TypingHandle { abort: task.abort_handle(), mgr, jid: jid_owned }
    }

    pub async fn send_presence(&self, available: bool) -> Result<()> {
        self.mgr.read().await.send_presence(available).await.map_err(Into::into)
    }

    /// Subscribe to presence updates for a contact (online/offline notifications).
    pub async fn subscribe_contact_presence(&self, jid: &str) -> Result<()> {
        self.mgr.read().await.subscribe_contact_presence(jid).await.map_err(Into::into)
    }

    /// Mark a WhatsApp Status (story) as viewed.
    pub async fn mark_status_viewed(&self, sender_jid: &str, msg_id: &str) -> Result<()> {
        self.mgr.read().await.mark_status_viewed(sender_jid, msg_id).await.map_err(Into::into)
    }

    /// Fetch the list of JIDs you have blocked.
    pub async fn fetch_blocklist(&self) -> Result<Vec<String>> {
        self.mgr.read().await.fetch_blocklist().await.map_err(Into::into)
    }

    /// Block a contact.
    pub async fn block_contact(&self, jid: &str) -> Result<()> {
        self.mgr.read().await.block_contact(jid).await.map_err(Into::into)
    }

    /// Unblock a contact.
    pub async fn unblock_contact(&self, jid: &str) -> Result<()> {
        self.mgr.read().await.unblock_contact(jid).await.map_err(Into::into)
    }

    // ── Contacts ──────────────────────────────────────────────────────────────

    /// Look up a cached display name for a JID.
    pub fn contact_name(&self, jid: &str) -> Option<String> {
        self.contacts.get(jid)
    }

    /// Snapshot of all known contacts.
    pub fn contacts_snapshot(&self) -> std::collections::HashMap<String, String> {
        self.contacts.snapshot()
    }

    /// Flush contact cache to disk.
    pub fn save_contacts(&self) {
        self.contacts.save();
    }

    /// Last `n` stored messages for a JID (oldest first, most-recent last).
    /// Per-chat metadata projection from app-state sync (pin, mute,
    /// archive, lock, labels). Returns a default-populated [`ChatMeta`]
    /// for JIDs we haven't seen events for.
    ///
    /// Agents can gate on `meta.agent_should_skip()` to stay silent on
    /// muted / archived / locked chats.
    pub fn chat_meta(&self, jid: &str) -> crate::chat_meta::ChatMeta {
        self.chat_meta.get(jid)
    }

    /// Current outbox depth — messages written to disk as Pending that
    /// haven't yet been ACK'd by the server. Handy for `/metrics` + CLI.
    pub async fn outbox_pending_count(&self) -> usize {
        self.mgr.read().await.outbox.len()
    }

    /// Snapshot of all pending outbox entries as `(jid, message)` tuples,
    /// oldest first. Use for the `outbox` CLI subcommand.
    pub async fn outbox_pending(&self) -> Vec<(String, crate::messages::WAMessage)> {
        self.mgr.read().await.outbox.pending()
    }

    pub fn message_history(&self, jid: &str, n: usize) -> Vec<crate::message_store::StoredMessage> {
        self.msg_store.recent(jid, n)
    }

    /// All JIDs that have at least one stored message.
    pub fn known_chats(&self) -> Vec<String> {
        self.msg_store.known_jids()
    }

    // ── Media ─────────────────────────────────────────────────────────────────

    pub async fn download_media(
        &self,
        info: &crate::messages::MediaInfo,
        media_type: crate::media::MediaType,
    ) -> Result<Vec<u8>> {
        self.mgr.read().await.download_media(info, media_type).await.map_err(Into::into)
    }

    /// Download media for a stored message by JID + message ID.
    /// Returns the raw decrypted bytes, or an error if the message is not found,
    /// is not a media message, or the download fails.
    pub async fn download_media_by_id(&self, jid: &str, msg_id: &str) -> Result<Vec<u8>> {
        let stored = self.msg_store.lookup(jid, msg_id)
            .ok_or_else(|| WaError::message_not_found(format!("{msg_id} in {jid}")))?;
        let info = stored.media_info
            .ok_or_else(|| WaError::invalid_input(format!("{msg_id} is not a media message")))?;
        let media_type = match stored.media_type.as_deref() {
            Some("image")    => crate::media::MediaType::Image,
            Some("video")    => crate::media::MediaType::Video,
            Some("audio")    => crate::media::MediaType::Audio,
            Some("sticker")  => crate::media::MediaType::Sticker,
            _                => crate::media::MediaType::Document,
        };
        self.download_media(&info, media_type).await.map_err(Into::into)
    }

    // ── Contact / usync ───────────────────────────────────────────────────────

    /// Check if phone numbers are registered on WhatsApp.
    /// `phones` — E.164 digits without `+`, e.g. `["5491112345678"]`.
    pub async fn on_whatsapp(
        &self, phones: &[&str],
    ) -> Result<Vec<crate::socket::usync::ContactInfo>> {
        self.mgr.read().await.on_whatsapp(phones).await.map_err(Into::into)
    }

    /// Resolve JIDs to `ContactInfo` (on_whatsapp + status text).
    /// Results are cached in `ContactStore` for future use.
    pub async fn resolve_contacts(
        &self, jids: &[&str],
    ) -> Result<std::collections::HashMap<String, crate::socket::usync::ContactInfo>> {
        let result = self.mgr.read().await.resolve_contacts(jids).await?;
        // Cache display names from usync results
        let entries: Vec<(String, String)> = result
            .iter()
            .filter_map(|(jid, info)| {
                // Use the JID itself as a fallback name only when the contact is registered
                if info.on_whatsapp { Some((jid.clone(), jid.clone())) } else { None }
            })
            .collect();
        if !entries.is_empty() {
            self.contacts.bulk_upsert(&entries);
            self.contacts.save();
        }
        Ok(result)
    }

    /// Like `resolve_contacts` but skips the network for JIDs already in the contact cache.
    pub async fn resolve_contacts_cached(
        &self,
        jids: &[&str],
    ) -> Result<std::collections::HashMap<String, crate::socket::usync::ContactInfo>> {
        use crate::socket::usync::ContactInfo;
        let mut result = std::collections::HashMap::new();
        let mut unknown: Vec<&str> = Vec::new();

        for &jid in jids {
            if let Some(name) = self.contacts.get(jid) {
                result.insert(jid.to_string(), ContactInfo {
                    jid: jid.to_string(),
                    on_whatsapp: true,
                    status: None,
                });
                let _ = name; // name is in the cache but ContactInfo doesn't carry it
            } else {
                unknown.push(jid);
            }
        }

        if !unknown.is_empty() {
            let fresh = self.resolve_contacts(&unknown).await?;
            result.extend(fresh);
        }
        Ok(result)
    }

    /// Fetch status text for a list of JIDs.
    pub async fn fetch_status(
        &self, jids: &[&str],
    ) -> Result<std::collections::HashMap<String, String>> {
        self.mgr.read().await.fetch_status(jids).await.map_err(Into::into)
    }

    // ── Group management ──────────────────────────────────────────────────────

    pub async fn create_group(
        &self,
        subject: &str,
        participant_jids: &[&str],
    ) -> Result<crate::socket::group::GroupInfo> {
        self.mgr.read().await.create_group(subject, participant_jids).await.map_err(Into::into)
    }

    pub async fn add_participants(
        &self,
        group_jid: &str,
        jids: &[&str],
    ) -> Result<Vec<crate::socket::group::ParticipantResult>> {
        self.mgr.read().await.add_participants(group_jid, jids).await.map_err(Into::into)
    }

    pub async fn remove_participants(
        &self,
        group_jid: &str,
        jids: &[&str],
    ) -> Result<Vec<crate::socket::group::ParticipantResult>> {
        self.mgr.read().await.remove_participants(group_jid, jids).await.map_err(Into::into)
    }

    pub async fn promote_to_admin(
        &self,
        group_jid: &str,
        jids: &[&str],
    ) -> Result<Vec<crate::socket::group::ParticipantResult>> {
        self.mgr.read().await.promote_to_admin(group_jid, jids).await.map_err(Into::into)
    }

    pub async fn demote_from_admin(
        &self,
        group_jid: &str,
        jids: &[&str],
    ) -> Result<Vec<crate::socket::group::ParticipantResult>> {
        self.mgr.read().await.demote_from_admin(group_jid, jids).await.map_err(Into::into)
    }

    pub async fn leave_group(&self, group_jid: &str) -> Result<()> {
        self.mgr.read().await.leave_group(group_jid).await.map_err(Into::into)
    }

    pub async fn set_group_subject(&self, group_jid: &str, subject: &str) -> Result<()> {
        self.mgr.read().await.set_group_subject(group_jid, subject).await.map_err(Into::into)
    }

    pub async fn set_group_description(&self, group_jid: &str, description: &str) -> Result<()> {
        self.mgr.read().await.set_group_description(group_jid, description).await.map_err(Into::into)
    }

    pub async fn subscribe_group_presence(&self, group_jid: &str) -> Result<()> {
        self.mgr.read().await.subscribe_group_presence(group_jid).await.map_err(Into::into)
    }

    // ── Profile pictures ──────────────────────────────────────────────────────

    pub async fn get_profile_picture(
        &self,
        jid: &str,
        high_res: bool,
    ) -> Result<Option<String>> {
        self.mgr.read().await.get_profile_picture(jid, high_res).await.map_err(Into::into)
    }

    pub async fn set_profile_picture(&self, jpeg_data: &[u8]) -> Result<()> {
        self.mgr.read().await.set_profile_picture(jpeg_data).await.map_err(Into::into)
    }

    // ── Chat handle ───────────────────────────────────────────────────────────

    /// Return a handle scoped to a single chat (user or group).
    ///
    /// Lets agent-style callers skip repeating the JID:
    /// `session.chat(jid).text("hi").await?;`
    /// `session.chat(jid).react(msg_id, "👍").await?;`
    pub fn chat(&self, jid: impl Into<String>) -> Chat<'_> {
        Chat { session: self, jid: jid.into() }
    }

    /// Register a LID↔PN equivalence manually. Bidirectional — inserts
    /// both directions into the lookup map and informs the Signal layer so
    /// session lookup falls back across addressings.
    ///
    /// Useful when the mapping isn't auto-discoverable from stanza attrs
    /// (e.g. 1:1 DMs where the peer addresses you via LID and `sender_pn`
    /// isn't emitted). Group stanzas do carry `participant_pn` and
    /// populate this map automatically.
    pub async fn set_jid_alias(&self, lid: &str, pn: &str) {
        let lid_bare = bare_user_jid(lid);
        let pn_bare = bare_user_jid(pn);
        let mgr = self.mgr.read().await;
        mgr.signal.set_jid_alias(&lid_bare, &pn_bare);
    }

    /// Return the LID↔PN counterpart of `jid` if one has been learned from
    /// an incoming stanza (`sender_pn` / `participant_pn`). Both identities
    /// route to the same user — handy when you track a peer by PN but they
    /// start addressing you via LID or vice versa.
    pub async fn equivalent_jid(&self, jid: &str) -> Option<String> {
        let at = jid.find('@')?;
        let (user, server) = (&jid[..at], &jid[at..]);
        let bare_user = user.split(':').next().unwrap_or(user);
        let bare = format!("{bare_user}{server}");
        let mgr = self.mgr.read().await;
        mgr.signal.alias_of(&bare)
    }
}

/// Ergonomic wrapper over [`Session`] scoped to one chat JID. Mirrors the
/// send/receipt-style APIs on `Session` but removes the repeated JID arg.
/// Obtain via [`Session::chat`].
#[allow(dead_code)]
pub struct Chat<'a> {
    session: &'a Session,
    jid: String,
}

#[allow(dead_code)]
impl<'a> Chat<'a> {
    pub fn jid(&self) -> &str { &self.jid }

    pub fn name(&self) -> Option<String> {
        self.session.contact_name(&self.jid)
    }

    pub async fn text(&self, text: &str) -> Result<String> {
        self.session.send_text(&self.jid, text).await.map_err(Into::into)
    }

    pub async fn reply(&self, reply_to_id: &str, text: &str) -> Result<String> {
        self.session.send_reply(&self.jid, reply_to_id, text).await.map_err(Into::into)
    }

    pub async fn react(&self, target_id: &str, emoji: &str) -> Result<()> {
        self.session.send_reaction(&self.jid, target_id, emoji).await.map_err(Into::into)
    }

    pub async fn mention(&self, text: &str, mention_jids: &[&str]) -> Result<String> {
        self.session.send_mention(&self.jid, text, mention_jids).await.map_err(Into::into)
    }

    pub async fn revoke(&self, msg_id: &str) -> Result<()> {
        self.session.send_revoke(&self.jid, msg_id).await.map_err(Into::into)
    }

    pub async fn edit(&self, msg_id: &str, new_text: &str) -> Result<()> {
        self.session.send_edit(&self.jid, msg_id, new_text).await.map_err(Into::into)
    }

    pub async fn image(&self, data: &[u8], caption: Option<&str>) -> Result<String> {
        self.session.send_image(&self.jid, data, caption).await.map_err(Into::into)
    }

    /// Image that receiver's WA wipes after first open.
    pub async fn view_once_image(&self, data: &[u8], caption: Option<&str>) -> Result<String> {
        self.session.send_view_once_image(&self.jid, data, caption).await
    }

    pub async fn video(&self, data: &[u8], caption: Option<&str>) -> Result<String> {
        self.session.send_video(&self.jid, data, caption).await.map_err(Into::into)
    }

    /// Video that receiver's WA wipes after first open.
    pub async fn view_once_video(&self, data: &[u8], caption: Option<&str>) -> Result<String> {
        self.session.send_view_once_video(&self.jid, data, caption).await
    }

    pub async fn audio(&self, data: &[u8], mimetype: &str) -> Result<String> {
        self.session.send_audio(&self.jid, data, mimetype).await.map_err(Into::into)
    }

    pub async fn voice_note(&self, data: &[u8], mimetype: &str) -> Result<String> {
        self.session.send_voice_note(&self.jid, data, mimetype).await.map_err(Into::into)
    }

    pub async fn document(&self, data: &[u8], mimetype: &str, file_name: &str) -> Result<String> {
        self.session.send_document(&self.jid, data, mimetype, file_name).await.map_err(Into::into)
    }

    pub async fn sticker(&self, data: &[u8]) -> Result<String> {
        self.session.send_sticker(&self.jid, data).await.map_err(Into::into)
    }

    pub async fn poll(
        &self, question: &str, options: &[&str], selectable_count: u32,
    ) -> Result<String> {
        self.session.send_poll(&self.jid, question, options, selectable_count).await.map_err(Into::into)
    }

    pub async fn poll_vote(&self, poll_msg_id: &str, selected: &[&str]) -> Result<()> {
        self.session.send_poll_vote(&self.jid, poll_msg_id, selected).await.map_err(Into::into)
    }

    pub async fn location(
        &self,
        latitude: f64, longitude: f64,
        name: Option<&str>, address: Option<&str>,
    ) -> Result<String> {
        self.session.send_location(&self.jid, latitude, longitude, name, address).await.map_err(Into::into)
    }

    pub async fn contact(&self, display_name: &str, phone_e164: &str) -> Result<String> {
        self.session.send_contact(&self.jid, display_name, phone_e164).await.map_err(Into::into)
    }

    pub async fn link_preview(
        &self,
        text: &str,
        url: &str,
        title: &str,
        description: &str,
        thumbnail_jpeg: Option<Vec<u8>>,
    ) -> Result<String> {
        self.session
            .send_link_preview(&self.jid, text, url, title, description, thumbnail_jpeg)
            .await.map_err(Into::into)
    }

    /// Send text with an auto-fetched link preview. Falls back to plain text
    /// when the URL fetch fails or no URL is present.
    pub async fn text_with_preview(&self, text: &str) -> Result<String> {
        self.session.send_text_with_preview(&self.jid, text).await.map_err(Into::into)
    }

    pub async fn typing(&self, composing: bool) -> Result<()> {
        self.session.send_typing(&self.jid, composing).await.map_err(Into::into)
    }

    /// RAII "typing…" indicator that refreshes every 10 s so WA doesn't
    /// expire it. See [`Session::typing_heartbeat`].
    pub fn typing_heartbeat(&self) -> TypingHandle {
        self.session.typing_heartbeat(&self.jid)
    }

    pub async fn mark_read(&self, keys: &[MessageKey]) -> Result<()> {
        self.session.mark_read(keys).await.map_err(Into::into)
    }

    pub async fn forward_from(&self, from_jid: &str, msg_id: &str) -> Result<String> {
        self.session.forward_message(&self.jid, from_jid, msg_id).await.map_err(Into::into)
    }

    pub async fn set_ephemeral(&self, expiration_secs: u32) -> Result<()> {
        self.session.set_ephemeral_duration(&self.jid, expiration_secs).await.map_err(Into::into)
    }

    pub fn history(&self, n: usize) -> Vec<crate::message_store::StoredMessage> {
        self.session.message_history(&self.jid, n)
    }

    /// Send a text and block until its status reaches `min_status`
    /// (typically [`MessageStatus::Delivered`] or [`MessageStatus::Read`]),
    /// or until `timeout` elapses.
    ///
    /// Subscribes to events *before* sending so no update is missed in a
    /// race with a fast ack. Returns `(msg_id, final_observed_status)`.
    /// On timeout the status reflects the last update seen (defaults to
    /// [`MessageStatus::Sent`] when no update arrived).
    pub async fn text_and_wait(
        &self,
        text: &str,
        min_status: MessageStatus,
        timeout: std::time::Duration,
    ) -> Result<(String, MessageStatus)> {
        let mut rx = self.session.events();
        let id = self.text(text).await?;
        let status = wait_for_status(&mut rx, &id, min_status, timeout).await;
        Ok((id, status))
    }

    /// Block until a specific message id's status reaches `min_status`, or
    /// `timeout` elapses. Use when you already have the id from a prior
    /// send. Note there is a race window between send and subscribe — prefer
    /// [`Self::text_and_wait`] for send-then-wait flows.
    pub async fn wait_status(
        &self,
        msg_id: &str,
        min_status: MessageStatus,
        timeout: std::time::Duration,
    ) -> MessageStatus {
        let mut rx = self.session.events();
        wait_for_status(&mut rx, msg_id, min_status, timeout).await
    }

    /// Start listening for the next incoming reply **now**, and return a
    /// handle that can be awaited later. Use this when you want to send
    /// something and then wait for a reply without racing the subscription:
    ///
    /// ```ignore
    /// let waiter = chat.listen_for_reply(Duration::from_secs(60));
    /// chat.text("hola").await?;
    /// if let Some(msg) = waiter.await { … }
    /// ```
    ///
    /// Internally spawns a task that subscribes to events immediately, so
    /// replies that arrive before/during your send are not missed.
    pub fn listen_for_reply(
        &self,
        timeout: std::time::Duration,
    ) -> tokio::task::JoinHandle<Option<crate::messages::WAMessage>> {
        // Capture what we need for the background task.
        let event_tx = self.session.event_tx.clone();
        let target_jid = self.jid.clone();
        let mgr = self.session.mgr.clone();
        tokio::spawn(async move {
            let mut rx = event_tx.subscribe();
            let target_bare = bare_user_jid(&target_jid);
            let deadline = tokio::time::Instant::now() + timeout;
            loop {
                let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
                if rem.is_zero() { return None; }
                match tokio::time::timeout(rem, rx.recv()).await {
                    Err(_) => return None,
                    Ok(Err(_)) => return None,
                    Ok(Ok(MessageEvent::NewMessage { msg })) if !msg.key.from_me => {
                        if matches!(
                            &msg.message,
                            Some(crate::messages::MessageContent::Text { text, .. })
                                if text == "<decrypt failed>" || text == "<skmsg decrypt failed>"
                        ) {
                            continue;
                        }
                        let remote_bare = bare_user_jid(&msg.key.remote_jid);
                        if remote_bare == target_bare {
                            return Some(msg);
                        }
                        // Re-query mapping in case it was just learned.
                        let alt = {
                            let m = mgr.read().await;
                            m.signal.alias_of(&target_bare)
                        };
                        if let Some(alt) = alt {
                            if bare_user_jid(&alt) == remote_bare {
                                return Some(msg);
                            }
                        }
                    }
                    _ => {}
                }
            }
        })
    }

    /// Send a question and wait for the peer's text reply. Sugar for
    /// bots: pre-arms the reply listener *before* sending to avoid the
    /// race where a fast answer lands before we subscribe, then drops
    /// anything that's not plain text (reactions, delivery receipts,
    /// decrypt-failed placeholders).
    ///
    /// Returns the reply text on success, `None` on timeout.
    pub async fn ask(
        &self,
        question: &str,
        timeout: std::time::Duration,
    ) -> Result<Option<String>> {
        let waiter = self.listen_for_reply(timeout);
        self.text(question).await?;
        let msg = match waiter.await.ok().flatten() {
            Some(m) => m,
            None => return Ok(None),
        };
        let text = match &msg.message {
            Some(crate::messages::MessageContent::Text { text, .. }) => Some(text.clone()),
            Some(crate::messages::MessageContent::Reply { text, .. }) => Some(text.clone()),
            Some(crate::messages::MessageContent::LinkPreview { text, .. }) => Some(text.clone()),
            _ => None,
        };
        Ok(text)
    }

    /// Block until the next incoming (non-self) message in this chat, or
    /// until `timeout`. For Q&A-style bots.
    ///
    /// Matches incoming messages whose `remote_jid` equals `self.jid` OR
    /// whose LID↔PN counterpart (learned from earlier stanzas) equals it —
    /// so a Chat tracked by PN still catches replies addressed via LID and
    /// vice versa.
    ///
    /// Beware: this subscribes only when you call it. If you intend to send
    /// first and then wait for a reply, use [`Self::listen_for_reply`]
    /// instead — it subscribes up-front so fast replies aren't missed.
    pub async fn wait_for_reply(
        &self,
        timeout: std::time::Duration,
    ) -> Option<crate::messages::WAMessage> {
        let mut rx = self.session.events();
        let target_bare = bare_user_jid(&self.jid);
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
            if rem.is_zero() { return None; }
            match tokio::time::timeout(rem, rx.recv()).await {
                Err(_) => return None,
                Ok(Err(_)) => return None,
                Ok(Ok(MessageEvent::NewMessage { msg })) if !msg.key.from_me => {
                    // Skip decrypt-failed placeholders — not a real reply.
                    if matches!(
                        &msg.message,
                        Some(crate::messages::MessageContent::Text { text, .. })
                            if text == "<decrypt failed>" || text == "<skmsg decrypt failed>"
                    ) {
                        continue;
                    }
                    let remote_bare = bare_user_jid(&msg.key.remote_jid);
                    if remote_bare == target_bare {
                        return Some(msg);
                    }
                    // Re-query on each event so newly-learned LID↔PN mappings
                    // (populated by recv.rs when the stanza carries sender_pn)
                    // take effect without restarting the waiter.
                    if let Some(alt) = self.session.equivalent_jid(&self.jid).await {
                        if bare_user_jid(&alt) == remote_bare {
                            return Some(msg);
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

/// Strip any `:device` suffix from a JID to get the bare user form.
fn bare_user_jid(jid: &str) -> String {
    let at = match jid.find('@') {
        Some(i) => i,
        None => return jid.to_string(),
    };
    let (before, server) = (&jid[..at], &jid[at..]);
    let user = before.split(':').next().unwrap_or(before);
    format!("{user}{server}")
}

fn status_rank(s: MessageStatus) -> u8 {
    match s {
        MessageStatus::Pending   => 0,
        MessageStatus::Sent      => 1,
        MessageStatus::Delivered => 2,
        MessageStatus::Read      => 3,
        MessageStatus::Played    => 4,
    }
}

async fn wait_for_status(
    rx: &mut broadcast::Receiver<MessageEvent>,
    msg_id: &str,
    min: MessageStatus,
    timeout: std::time::Duration,
) -> MessageStatus {
    let mut current = MessageStatus::Sent;
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
        if rem.is_zero() { return current; }
        match tokio::time::timeout(rem, rx.recv()).await {
            Err(_) => return current,
            Ok(Err(_)) => return current,
            Ok(Ok(MessageEvent::MessageUpdate { key, status })) if key.id == msg_id => {
                if status_rank(status) > status_rank(current) {
                    current = status;
                }
                if status_rank(current) >= status_rank(min) {
                    return current;
                }
            }
            _ => {}
        }
    }
}
