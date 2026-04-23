use crate::binary::{BinaryNode, NodeContent};

/// Append `:0` (primary device) to a bare user JID like `573144...@s.whatsapp.net`.
/// If the JID already carries a `:device` part it's returned unchanged.
fn ensure_device(jid: &str) -> String {
    let at = match jid.find('@') { Some(i) => i, None => return jid.to_string() };
    let before = &jid[..at];
    let server = &jid[at..];
    if before.contains(':') {
        jid.to_string()
    } else {
        format!("{}:0{}", before, server)
    }
}

/// Drop the `:0` primary-device suffix from a JID — matches Baileys'
/// `jidEncode` which omits device=0 on the wire. Other `:N` suffixes stay.
fn strip_zero_device(jid: &str) -> String {
    let at = match jid.find('@') { Some(i) => i, None => return jid.to_string() };
    let (left, server) = (&jid[..at], &jid[at..]);
    match left.split_once(':') {
        Some((user, "0")) => format!("{}{}", user, server),
        _ => jid.to_string(),
    }
}

/// Strip any `:device` suffix from a JID, leaving the bare user form.
fn bare_user_jid(jid: &str) -> String {
    let at = match jid.find('@') { Some(i) => i, None => return jid.to_string() };
    let before = &jid[..at];
    let server = &jid[at..];
    let user = before.split(':').next().unwrap_or(before);
    format!("{}{}", user, server)
}

/// WhatsApp-specific random padding applied to the OUTERMOST Message bytes
/// before they hit AES-CBC encrypt. Matches Baileys' `writeRandomPadMax16`:
/// pad length = (rand & 0x0f) + 1, each byte = pad length. Receiver's
/// `unpadRandomMax16` reads the last byte as padLength and trims.
fn pad_wa(bytes: &[u8]) -> Vec<u8> {
    use rand::RngCore;
    let mut r = [0u8; 1];
    rand::rngs::OsRng.fill_bytes(&mut r);
    let pad_len = ((r[0] & 0x0f) as usize) + 1;
    let mut out = Vec::with_capacity(bytes.len() + pad_len);
    out.extend_from_slice(bytes);
    out.extend(std::iter::repeat(pad_len as u8).take(pad_len));
    out
}

/// Parse the `<keys>` child of an incoming retry-receipt into a `PreKeyBundle`.
/// Layout: `<keys><type/><identity/><key>(id,value)</key><skey>(id,value,signature)</skey><device-identity/></keys>`.
/// `registration_id` comes from the sibling `<registration>` node at receipt level.
fn parse_retry_keys_bundle(
    keys: &BinaryNode,
    registration_id: u32,
) -> Result<crate::signal::x3dh::PreKeyBundle> {
    let kc: &[BinaryNode] = match &keys.content {
        NodeContent::List(v) => v.as_slice(),
        _ => anyhow::bail!("keys node without children"),
    };
    let bytes_of = |n: &BinaryNode| -> Option<Vec<u8>> {
        match &n.content {
            NodeContent::Bytes(b) => Some(b.clone()),
            _ => None,
        }
    };
    let child = |tag: &str| -> Option<&BinaryNode> { kc.iter().find(|n| n.tag == tag) };
    let sub_bytes = |parent: &BinaryNode, tag: &str| -> Option<Vec<u8>> {
        match &parent.content {
            NodeContent::List(v) => v.iter().find(|n| n.tag == tag).and_then(bytes_of),
            _ => None,
        }
    };
    let u24_or_u32 = |b: &[u8]| -> Result<u32> {
        Ok(match b.len() {
            3 => ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32),
            4 => u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
            n => anyhow::bail!("prekey id wrong length: {n}"),
        })
    };

    let id_pub = child("identity").and_then(bytes_of)
        .ok_or_else(|| anyhow::anyhow!("retry keys missing identity"))?;
    if id_pub.len() != 32 { anyhow::bail!("identity wrong length: {}", id_pub.len()); }
    let mut identity_key = [0u8; 32];
    identity_key.copy_from_slice(&id_pub);

    let skey = child("skey").ok_or_else(|| anyhow::anyhow!("retry keys missing skey"))?;
    let skid = sub_bytes(skey, "id").ok_or_else(|| anyhow::anyhow!("skey.id missing"))?;
    let signed_pre_key_id = u24_or_u32(&skid)?;
    let skval = sub_bytes(skey, "value").ok_or_else(|| anyhow::anyhow!("skey.value missing"))?;
    if skval.len() != 32 { anyhow::bail!("skey.value wrong length: {}", skval.len()); }
    let mut signed_pre_key = [0u8; 32];
    signed_pre_key.copy_from_slice(&skval);
    let sksig = sub_bytes(skey, "signature").ok_or_else(|| anyhow::anyhow!("skey.signature missing"))?;
    if sksig.len() != 64 { anyhow::bail!("skey.signature wrong length: {}", sksig.len()); }
    let mut signed_pre_key_sig = [0u8; 64];
    signed_pre_key_sig.copy_from_slice(&sksig);

    let (one_time_pre_key_id, one_time_pre_key) = if let Some(key) = child("key") {
        let kid = sub_bytes(key, "id").ok_or_else(|| anyhow::anyhow!("key.id missing"))?;
        let id = u24_or_u32(&kid)?;
        let kv = sub_bytes(key, "value").ok_or_else(|| anyhow::anyhow!("key.value missing"))?;
        if kv.len() != 32 { anyhow::bail!("key.value wrong length: {}", kv.len()); }
        let mut p = [0u8; 32];
        p.copy_from_slice(&kv);
        (Some(id), Some(p))
    } else {
        (None, None)
    };

    Ok(crate::signal::x3dh::PreKeyBundle {
        registration_id,
        device_id: 0,
        identity_key,
        signed_pre_key_id,
        signed_pre_key,
        signed_pre_key_sig,
        one_time_pre_key_id,
        one_time_pre_key,
    })
}

/// Wrap a serialized `WAMessage` inside `Message.deviceSentMessage` so our
/// own other devices can display the message as "sent by me". Matches
/// Baileys `encodeWAMessage({ deviceSentMessage: { destinationJid, message } })`.
fn wrap_device_sent_message(destination_jid: &str, inner_msg_bytes: &[u8]) -> Vec<u8> {
    use crate::signal::wa_proto::{proto_bytes, proto_varint as _};
    // DeviceSentMessage body: field 1 = destinationJid, field 2 = message.
    let mut body = Vec::new();
    body.extend(proto_bytes(1, destination_jid.as_bytes()));
    body.extend(proto_bytes(2, inner_msg_bytes));
    // Outer Message: field 31 = deviceSentMessage.
    proto_bytes(31, &body)
}
use crate::messages::{
    generate_message_id, unix_now, MessageContent, MessageEvent, MessageKey, MessageManager,
    MessageStatus, ReceiptType, WAMessage,
};
use anyhow::Result;
use std::sync::Arc;

/// Free-function form of `send_placeholder_resend` so callers can `tokio::spawn`
/// it without needing an `Arc<MessageManager>` handle. Takes cloned handles.
pub async fn placeholder_resend_send(
    socket: Arc<crate::socket::SocketSender>,
    signal: Arc<crate::signal::SignalRepository>,
    our_jid: String,
    key: MessageKey,
) -> Result<String> {
    use crate::signal::wa_proto::{proto_bytes, proto_varint};

    let mut mk = Vec::new();
    mk.extend(proto_bytes(1, key.remote_jid.as_bytes()));
    mk.extend(proto_varint(2, if key.from_me { 1 } else { 0 }));
    mk.extend(proto_bytes(3, key.id.as_bytes()));
    if let Some(p) = &key.participant {
        mk.extend(proto_bytes(4, p.as_bytes()));
    }
    tracing::info!(
        "PDO request key: remote_jid={} from_me={} id={} participant={:?}",
        key.remote_jid,
        key.from_me,
        key.id,
        key.participant,
    );
    let pmrr = proto_bytes(1, &mk);
    let mut pdo = Vec::new();
    pdo.extend(proto_varint(1, 4));
    pdo.extend(proto_bytes(5, &pmrr));
    let mut pm = Vec::new();
    pm.extend(proto_varint(2, 16));
    pm.extend(proto_bytes(16, &pdo));
    let message_bytes = proto_bytes(12, &pm);

    // Session key = bare user JID, because incoming peer msgs from our phone
    // arrive with `from=bare`. Always create a FRESH session via a new prekey
    // fetch: any pre-existing bare session may be out of sync with the phone
    // (they may have a different derivation from an earlier X3DH). A fresh
    // pkmsg forces both sides onto the same root.
    let our_user = bare_user_jid(&our_jid);
    let phone_jid_for_prekey = ensure_device(&our_user);
    let session_jid = our_user.clone();

    let bundle = crate::socket::prekey::fetch_pre_key_bundle(&socket, &phone_jid_for_prekey).await?;
    tracing::info!(
        "PDO: fetched bundle for {} (spk_id={}, otk={})",
        phone_jid_for_prekey, bundle.signed_pre_key_id,
        bundle.one_time_pre_key_id.map(|v| v.to_string()).unwrap_or_else(|| "none".into()),
    );
    signal.create_sender_session(&session_jid, &bundle)?;

    let plaintext = pad_wa(&message_bytes);
    let enc = signal.encrypt_message(&session_jid, &plaintext).await?;
    tracing::info!(
        "PDO: encrypted {}B plaintext → {}B {} (session key={})",
        plaintext.len(), enc.ciphertext.len(), enc.msg_type, session_jid,
    );

    let mut children = vec![BinaryNode {
        tag: "enc".to_string(),
        attrs: vec![
            ("v".to_string(), "2".to_string()),
            ("type".to_string(), enc.msg_type.to_string()),
        ],
        content: NodeContent::Bytes(enc.ciphertext),
    }];
    if enc.msg_type == "pkmsg" {
        let account_id = signal.account_identity_bytes().to_vec();
        if !account_id.is_empty() {
            children.push(BinaryNode {
                tag: "device-identity".to_string(),
                attrs: vec![],
                content: NodeContent::Bytes(account_id),
            });
        }
    }
    children.push(BinaryNode {
        tag: "meta".to_string(),
        attrs: vec![("appdata".to_string(), "default".to_string())],
        content: NodeContent::None,
    });

    let request_id = generate_message_id();
    let stanza = BinaryNode {
        tag: "message".to_string(),
        attrs: vec![
            ("to".to_string(), our_user),
            ("id".to_string(), request_id.clone()),
            ("type".to_string(), "text".to_string()),
            ("category".to_string(), "peer".to_string()),
            ("push_priority".to_string(), "high_force".to_string()),
            ("t".to_string(), unix_now().to_string()),
        ],
        content: NodeContent::List(children),
    };
    socket.send_node(&stanza).await?;
    Ok(request_id)
}

#[allow(dead_code)]
impl MessageManager {
    /// Send a PeerDataOperationRequestMessage (PLACEHOLDER_MESSAGE_RESEND) to
    /// our own user JID. This is what Baileys does alongside retry-receipts
    /// when an incoming group message fails to decrypt: it asks the primary
    /// phone to re-ship the missing SKDM/message for this new device slot.
    ///
    /// WA server reuses the category=peer routing to deliver the PDO to the
    /// primary phone only. The phone's protocolMessage handler sees the
    /// PLACEHOLDER_MESSAGE_RESEND request and re-broadcasts the referenced
    /// message with SKDM bundled, so future skmsg from that sender decrypt.
    pub async fn send_placeholder_resend(&self, key: &MessageKey) -> Result<String> {
        placeholder_resend_send(
            self.socket.clone(),
            self.signal.clone(),
            self.our_jid.clone(),
            key.clone(),
        ).await
    }

    pub async fn send_text(&self, jid: &str, text: &str) -> Result<String> {
        let id = generate_message_id();
        let content = MessageContent::Text { text: text.to_string(), mentioned_jids: Vec::new() };
        self.send_message(jid, id.clone(), content).await?;
        Ok(id)
    }

    pub async fn send_reaction(&self, jid: &str, target_id: &str, emoji: &str) -> Result<()> {
        let id = generate_message_id();
        self.send_message(jid, id, MessageContent::Reaction {
            target_id: target_id.to_string(),
            emoji: emoji.to_string(),
        }).await
    }

    pub async fn send_reply(&self, jid: &str, reply_to_id: &str, text: &str) -> Result<String> {
        let id = generate_message_id();
        let content = MessageContent::Reply {
            reply_to_id: reply_to_id.to_string(),
            text: text.to_string(),
        };
        self.send_message(jid, id.clone(), content).await?;
        Ok(id)
    }

    /// Send a text message with @mention JIDs so the recipient app highlights them.
    pub async fn send_mention(
        &self,
        jid: &str,
        text: &str,
        mention_jids: &[&str],
    ) -> Result<String> {
        let id = generate_message_id();
        let wa_bytes = crate::signal::wa_proto::encode_wa_text_with_mentions(text, mention_jids);
        self.send_encrypted_bytes(jid, &id, wa_bytes).await?;
        Ok(id)
    }

    /// Send composing/paused typing indicator to a JID.
    pub async fn send_typing(&self, jid: &str, composing: bool) -> Result<()> {
        let state = if composing { "composing" } else { "paused" };
        let node = BinaryNode {
            tag: "chatstate".to_string(),
            attrs: vec![("to".to_string(), jid.to_string())],
            content: NodeContent::List(vec![BinaryNode {
                tag: state.to_string(),
                attrs: vec![],
                content: NodeContent::None,
            }]),
        };
        self.socket.send_node(&node).await
    }

    /// Broadcast presence (available/unavailable).
    ///
    /// WhatsApp needs a `name=` attribute on the first `available` presence
    /// or it keeps us flagged as passive and won't fan out incoming messages.
    /// We use the push name stored in creds (set via `Client::set_push_name`,
    /// defaults to "WhatsApp-rs" if unset).
    pub async fn send_presence(&self, available: bool) -> Result<()> {
        let pres_type = if available { "available" } else { "unavailable" };
        let mut attrs = vec![("type".to_string(), pres_type.to_string())];
        if available {
            attrs.push(("name".to_string(), "WhatsApp-rs".to_string()));
        }
        let node = BinaryNode {
            tag: "presence".to_string(),
            attrs,
            content: NodeContent::None,
        };
        self.socket.send_node(&node).await
    }

    /// Subscribe to presence updates for a specific contact JID.
    /// The server will send presence notifications whenever they come online/offline.
    pub async fn subscribe_contact_presence(&self, jid: &str) -> Result<()> {
        let node = BinaryNode {
            tag: "presence".to_string(),
            attrs: vec![
                ("type".to_string(), "subscribe".to_string()),
                ("to".to_string(), jid.to_string()),
            ],
            content: NodeContent::None,
        };
        self.socket.send_node(&node).await
    }

    /// Mark a WhatsApp Status (story) as viewed.
    /// `sender_jid` is the JID of the status author; `msg_id` is the status message ID.
    pub async fn mark_status_viewed(&self, sender_jid: &str, msg_id: &str) -> Result<()> {
        let node = BinaryNode {
            tag: "receipt".to_string(),
            attrs: vec![
                ("id".to_string(), msg_id.to_string()),
                ("to".to_string(), "status@broadcast".to_string()),
                ("participant".to_string(), sender_jid.to_string()),
                ("type".to_string(), "read".to_string()),
            ],
            content: NodeContent::None,
        };
        self.socket.send_node(&node).await
    }

    /// Fetch the current blocklist (JIDs you have blocked).
    pub async fn fetch_blocklist(&self) -> Result<Vec<String>> {
        let id = self.socket.next_id();
        let node = BinaryNode {
            tag: "iq".to_string(),
            attrs: vec![
                ("id".to_string(), id),
                ("xmlns".to_string(), "blocklist".to_string()),
                ("to".to_string(), "s.whatsapp.net".to_string()),
                ("type".to_string(), "get".to_string()),
            ],
            content: NodeContent::None,
        };
        let response = self.socket.send_iq_await(node).await?;
        let jids = match &response.content {
            NodeContent::List(ch) => {
                let list = ch.iter().find(|n| n.tag == "list");
                match list {
                    Some(l) => match &l.content {
                        NodeContent::List(items) => items
                            .iter()
                            .filter(|n| n.tag == "item")
                            .filter_map(|n| n.attr("jid").map(|s| s.to_string()))
                            .collect(),
                        _ => vec![],
                    },
                    None => vec![],
                }
            }
            _ => vec![],
        };
        Ok(jids)
    }

    /// Block a contact JID.
    pub async fn block_contact(&self, jid: &str) -> Result<()> {
        self.update_block_status(jid, "block").await
    }

    /// Unblock a contact JID.
    pub async fn unblock_contact(&self, jid: &str) -> Result<()> {
        self.update_block_status(jid, "unblock").await
    }

    async fn update_block_status(&self, jid: &str, action: &str) -> Result<()> {
        let id = self.socket.next_id();
        let node = BinaryNode {
            tag: "iq".to_string(),
            attrs: vec![
                ("id".to_string(), id),
                ("xmlns".to_string(), "blocklist".to_string()),
                ("to".to_string(), "s.whatsapp.net".to_string()),
                ("type".to_string(), "set".to_string()),
            ],
            content: NodeContent::List(vec![BinaryNode {
                tag: "item".to_string(),
                attrs: vec![
                    ("action".to_string(), action.to_string()),
                    ("jid".to_string(), jid.to_string()),
                ],
                content: NodeContent::None,
            }]),
        };
        self.socket.send_iq_await(node).await?;
        Ok(())
    }

    pub async fn send_receipt(
        &self,
        jid: &str,
        ids: &[String],
        receipt: ReceiptType,
    ) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let extra = if ids.len() > 1 {
            NodeContent::List(
                ids[1..]
                    .iter()
                    .map(|id| BinaryNode {
                        tag: "item".to_string(),
                        attrs: vec![("id".to_string(), id.clone())],
                        content: NodeContent::None,
                    })
                    .collect(),
            )
        } else {
            NodeContent::None
        };
        // WA convention: delivery receipts have NO `type` attribute;
        // any other receipt flavour does.
        let mut attrs = vec![
            ("id".to_string(), ids[0].clone()),
            ("to".to_string(), jid.to_string()),
        ];
        if !matches!(receipt, ReceiptType::Delivered) {
            attrs.push(("type".to_string(), receipt.as_str().to_string()));
        }
        let node = BinaryNode {
            tag: "receipt".to_string(),
            attrs,
            content: extra,
        };
        self.socket.send_node(&node).await
    }

    pub async fn read_messages(&self, keys: &[MessageKey]) -> Result<()> {
        let mut by_jid: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        for key in keys {
            by_jid
                .entry(key.remote_jid.clone())
                .or_default()
                .push(key.id.clone());
        }
        for (jid, ids) in by_jid {
            self.send_receipt(&jid, &ids, ReceiptType::Read).await?;
        }
        Ok(())
    }

    async fn send_message(
        &self,
        jid: &str,
        id: String,
        content: MessageContent,
    ) -> Result<()> {
        let msg = WAMessage {
            key: MessageKey {
                remote_jid: jid.to_string(),
                from_me: true,
                id: id.clone(),
                participant: None,
            },
            message: Some(content),
            message_timestamp: unix_now(),
            status: MessageStatus::Pending,
            push_name: None,
        };

        // Persist as Pending before touching the network so we can retry on reconnect
        self.msg_store.push(&msg);
        self.outbox.push(jid, &msg);

        let wa_bytes = self.encode_content(&msg)?;
        match self.send_encrypted_bytes(jid, &id, wa_bytes).await {
            Ok(()) => {
                // Cache for incoming retry-receipts from peer devices that
                // missed this send (new device, session churn). Key by bare
                // chat jid + id to match how retry receipts identify the msg.
                self.recent_sends.insert(jid, &id, msg.clone());
                // Socket write succeeded; remove from outbox and advance status to Sent
                self.outbox.remove(&id);
                self.msg_store.update_status(jid, &id, MessageStatus::Sent);
                let _ = self.event_tx.send(MessageEvent::MessageUpdate {
                    key: msg.key,
                    status: MessageStatus::Sent,
                });
                Ok(())
            }
            Err(e) => Err(e), // stays in outbox → retried on next reconnect
        }
    }

    /// Respond to an incoming `<receipt type="retry">` from a peer device that
    /// missed our original send (new device added post-send, session churn).
    /// Looks up the cached plaintext, re-encrypts for the requesting device
    /// using the prekey bundle carried in the retry receipt (or our cached
    /// session if present), and ships a fresh `<message>` to that device only.
    ///
    /// 1:1 only for now — group retries also need SKDM re-distribution which
    /// is not implemented in this path yet.
    pub(crate) async fn handle_incoming_retry_receipt(&self, node: &BinaryNode) -> Result<()> {
        let from = match node.attr("from") {
            Some(v) => v.to_string(),
            None => anyhow::bail!("retry receipt without from"),
        };
        let msg_id = match node.attr("id") {
            Some(v) => v.to_string(),
            None => anyhow::bail!("retry receipt without id"),
        };

        // Group retries need SKDM re-ship — skip here, handled elsewhere.
        if from.ends_with("@g.us") {
            tracing::debug!(
                "incoming retry-receipt for group {from}/{msg_id} — skipping (no group resend yet)",
            );
            return Ok(());
        }

        let children: &[BinaryNode] = match &node.content {
            NodeContent::List(v) => v.as_slice(),
            _ => &[],
        };

        let retry_count: u32 = children
            .iter()
            .find(|n| n.tag == "retry")
            .and_then(|n| n.attr("count"))
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);

        let bare_chat = bare_user_jid(&from);
        let Some(cached) = self.recent_sends.get(&bare_chat, &msg_id) else {
            tracing::debug!(
                "incoming retry-receipt for {from}/{msg_id}: no cached send (cache miss or too old)",
            );
            return Ok(());
        };

        // Target the specific device. Drop `:0` to match wire convention.
        let device_jid = strip_zero_device(&from);

        let keys_node = children.iter().find(|n| n.tag == "keys");
        if let Some(keys) = keys_node {
            let registration_id = children
                .iter()
                .find(|n| n.tag == "registration")
                .and_then(|n| match &n.content {
                    NodeContent::Bytes(b) if b.len() >= 4 => {
                        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
                    }
                    _ => None,
                })
                .unwrap_or(0);
            match parse_retry_keys_bundle(keys, registration_id) {
                Ok(bundle) => {
                    if let Err(e) = self.signal.create_sender_session(&device_jid, &bundle) {
                        tracing::warn!("create_sender_session for retry {device_jid}: {e}");
                    }
                }
                Err(e) => tracing::warn!("parse retry keys bundle: {e}"),
            }
        } else if !self.signal.has_session(&device_jid) {
            match crate::socket::prekey::fetch_pre_key_bundle(&self.socket, &device_jid).await {
                Ok(bundle) => {
                    if let Err(e) = self.signal.create_sender_session(&device_jid, &bundle) {
                        tracing::warn!(
                            "create_sender_session (fetched) for retry {device_jid}: {e}",
                        );
                        return Ok(());
                    }
                }
                Err(e) => {
                    tracing::warn!("fetch_pre_key_bundle for retry {device_jid}: {e}");
                    return Ok(());
                }
            }
        }

        let wa_bytes = self.encode_content(&cached)?;
        let padded = pad_wa(&wa_bytes);
        let enc = self.signal.encrypt_message(&device_jid, &padded).await?;
        let is_pkmsg = enc.msg_type == "pkmsg";

        let mut out_children = vec![BinaryNode {
            tag: "enc".to_string(),
            attrs: vec![
                ("v".to_string(), "2".to_string()),
                ("type".to_string(), enc.msg_type.to_string()),
                ("count".to_string(), retry_count.to_string()),
            ],
            content: NodeContent::Bytes(enc.ciphertext),
        }];
        if is_pkmsg {
            let account_id = self.signal.account_identity_bytes().to_vec();
            if !account_id.is_empty() {
                out_children.push(BinaryNode {
                    tag: "device-identity".to_string(),
                    attrs: vec![],
                    content: NodeContent::Bytes(account_id),
                });
            }
        }

        let mut attrs = vec![
            ("to".to_string(), device_jid.clone()),
            ("id".to_string(), msg_id.clone()),
            ("type".to_string(), "text".to_string()),
            ("t".to_string(), unix_now().to_string()),
        ];
        if let Some(p) = node.attr("participant") {
            attrs.push(("participant".into(), p.to_string()));
        }
        if let Some(r) = node.attr("recipient") {
            attrs.push(("recipient".into(), r.to_string()));
        }
        let stanza = BinaryNode {
            tag: "message".to_string(),
            attrs,
            content: NodeContent::List(out_children),
        };
        tracing::info!(
            "→ retry-resend id={msg_id} to={device_jid} pkmsg={is_pkmsg} count={retry_count}",
        );
        self.socket.send_node(&stanza).await?;
        Ok(())
    }

    /// Retry a single outbox entry (re-encodes + re-encrypts with fresh ratchet step).
    /// Called from the reconnect loop for every entry still in the outbox.
    pub(crate) async fn retry_outbox_entry(&self, jid: &str, msg: WAMessage) {
        let id = msg.key.id.clone();
        let wa_bytes = match self.encode_content(&msg) {
            Ok(b) => b,
            Err(e) => { tracing::warn!("retry encode failed for {id}: {e}"); return; }
        };
        match self.send_encrypted_bytes(jid, &id, wa_bytes).await {
            Ok(()) => {
                self.recent_sends.insert(jid, &id, msg.clone());
                self.outbox.remove(&id);
                self.msg_store.update_status(jid, &id, MessageStatus::Sent);
                let _ = self.event_tx.send(MessageEvent::MessageUpdate {
                    key: msg.key,
                    status: MessageStatus::Sent,
                });
                tracing::info!("retried {id} → Sent");
            }
            Err(e) => tracing::warn!("retry send failed for {id}: {e}"),
        }
    }

    /// Encode any MessageContent variant to WAProto bytes.
    /// Side-effects: registers poll enc_key in PollStore when encoding a Poll.
    fn encode_content(&self, msg: &WAMessage) -> Result<Vec<u8>> {
        use crate::signal::wa_proto::{
            encode_wa_audio_message, encode_wa_document_message, encode_wa_image_message,
            encode_wa_link_preview_message, encode_wa_reaction_message, encode_wa_reply_message,
            encode_wa_sticker_message, encode_wa_text_message, encode_wa_video_message,
        };
        let bytes = match &msg.message {
            Some(MessageContent::Text { text, mentioned_jids }) => {
                if mentioned_jids.is_empty() {
                    encode_wa_text_message(text)
                } else {
                    let refs: Vec<&str> = mentioned_jids.iter().map(String::as_str).collect();
                    crate::signal::wa_proto::encode_wa_text_with_mentions(text, &refs)
                }
            }
            Some(MessageContent::Reply { reply_to_id, text }) => {
                // Look up the quoted message by id under the current chat jid
                // first. Incoming msgs from a LID-addressed peer are stored
                // under the LID jid while the reply goes out under PN, so
                // also try the aliased counterpart (learned in recv from
                // sender_pn/participant_pn) and any stored jid ending with
                // the peer's user id — that covers LID↔PN and device-suffix
                // variants without requiring an exact match.
                let stored = self.msg_store.lookup(&msg.key.remote_jid, reply_to_id)
                    .or_else(|| {
                        let alt = self.lid_pn_map.lock().ok()?
                            .get(&bare_user_jid(&msg.key.remote_jid)).cloned()?;
                        self.msg_store.lookup(&alt, reply_to_id)
                    })
                    .or_else(|| {
                        // Last resort: scan every known chat for this id.
                        self.msg_store.known_jids().into_iter()
                            .find_map(|j| self.msg_store.lookup(&j, reply_to_id))
                    });
                let quoted_text = stored.as_ref().and_then(|m| m.text.clone()).unwrap_or_default();
                let quoted_sender_owned = stored.map(|m| if m.from_me {
                    self.our_jid.clone()
                } else {
                    m.participant.unwrap_or_else(|| m.remote_jid.clone())
                });
                let participant = quoted_sender_owned.as_deref()
                    .or(msg.key.participant.as_deref());
                encode_wa_reply_message(text, reply_to_id, participant, &quoted_text)
            }
            Some(MessageContent::Image { info, caption }) =>
                encode_wa_image_message(info, caption.as_deref()),
            Some(MessageContent::Video { info, caption }) =>
                encode_wa_video_message(info, caption.as_deref()),
            Some(MessageContent::Audio { info }) => encode_wa_audio_message(info),
            Some(MessageContent::Document { info, file_name }) =>
                encode_wa_document_message(info, file_name),
            Some(MessageContent::Sticker { info }) => encode_wa_sticker_message(info),
            Some(MessageContent::Reaction { target_id, emoji }) => {
                // The target msg's `fromMe` flag in the reaction key must
                // match the peer's record, otherwise they can't locate the
                // target and drop the reaction silently. Look it up in our
                // message store; default to fromMe=false when unknown (most
                // common case: reacting to a received msg).
                let target_from_me = self
                    .msg_store
                    .lookup(&msg.key.remote_jid, target_id)
                    .map(|m| m.from_me)
                    .unwrap_or(false);
                encode_wa_reaction_message(
                    &msg.key.remote_jid,
                    target_id,
                    emoji,
                    target_from_me,
                )
            }
            Some(MessageContent::Poll { question, options, selectable_count }) => {
                let opts: Vec<&str> = options.iter().map(|s| s.as_str()).collect();
                let (bytes, enc_key) = crate::signal::wa_proto::encode_wa_poll_message(
                    question, &opts, *selectable_count,
                );
                self.poll_store.register(&msg.key.id, enc_key.to_vec(), question, options);
                bytes
            }
            Some(MessageContent::LinkPreview { text, url, title, description, thumbnail_jpeg }) =>
                encode_wa_link_preview_message(text, url, title, description, thumbnail_jpeg.as_deref()),
            None => anyhow::bail!("send_message called with no content"),
        };
        Ok(bytes)
    }

    /// Encrypt `wa_bytes` and send to `jid` — automatically routes 1:1 vs group.
    ///
    /// Groups (`@g.us`): fetches participants, distributes SenderKey, encrypts as skmsg.
    /// 1:1: establishes Signal session if needed, encrypts as msg/pkmsg.
    async fn send_encrypted_bytes(&self, jid: &str, id: &str, wa_bytes: Vec<u8>) -> Result<()> {
        // Do NOT pad `wa_bytes` here — padding must be applied to the
        // *outermost* Message bytes handed to encrypt. For DSM (own-device
        // copy) the outer Message is `deviceSentMessage{destinationJid,message}`
        // with an UNPADDED inner. Helper `pad_wa` does per-target padding
        // right before `signal.encrypt_message`.
        let (message_content, any_pkmsg, skdm_distributed) = if jid.ends_with("@g.us") {
            let participants =
                crate::socket::group::fetch_group_participants(&self.socket, jid).await?;
            let (sender_key_nodes, distributed, sender_key_pkmsg) =
                self.build_group_sender_key_distribution(jid, &participants).await?;
            let skmsg = self.signal.encrypt_group_message(jid, &pad_wa(&wa_bytes)).await?;
            let mut children = vec![BinaryNode {
                tag: "enc".to_string(),
                attrs: vec![
                    ("v".to_string(), "2".to_string()),
                    ("type".to_string(), "skmsg".to_string()),
                ],
                content: NodeContent::Bytes(skmsg),
            }];
            if !sender_key_nodes.is_empty() {
                children.push(BinaryNode {
                    tag: "participants".to_string(),
                    attrs: vec![],
                    content: NodeContent::List(sender_key_nodes),
                });
            }
            if sender_key_pkmsg {
                let account_id = self.signal.account_identity_bytes().to_vec();
                if !account_id.is_empty() {
                    children.push(BinaryNode {
                        tag: "device-identity".to_string(),
                        attrs: vec![],
                        content: NodeContent::Bytes(account_id),
                    });
                }
            }
            (NodeContent::List(children), sender_key_pkmsg, distributed)
        } else {
            // 1:1 flow — send to recipient's devices AND our own other
            // devices so the message also shows up as "sent" in our phone
            // (DeviceSentMessage).
            let own_address_jid = if jid.ends_with("@lid") {
                self.our_lid.as_deref().unwrap_or(&self.our_jid)
            } else {
                &self.our_jid
            };
            let our_user_jid = bare_user_jid(own_address_jid);
            let our_device_jid = own_address_jid.to_string();

            let cache = crate::device_cache::DeviceCache::new(std::path::Path::new("."));

            // Recipient devices (cached)
            let recipient_devs = if let Some(d) = cache.get(jid) { d } else {
                match crate::socket::usync::get_user_devices(&self.socket, &[jid]).await {
                    Ok(d) if !d.is_empty() => { cache.put(jid, &d); d }
                    _ => vec![ensure_device(jid)],
                }
            };
            // Our own devices (cached, minus the one we're running on)
            let own_devs = if let Some(d) = cache.get(&our_user_jid) { d } else {
                match crate::socket::usync::get_user_devices(&self.socket, &[&our_user_jid]).await {
                    Ok(d) if !d.is_empty() => { cache.put(&our_user_jid, &d); d }
                    _ => vec![],
                }
            };
            let own_other_devs: Vec<String> = own_devs
                .into_iter()
                .filter(|d| d != &our_device_jid)
                .collect();

            tracing::info!(
                "→ send 1:1 to={} other_devs={:?} own_devs={:?}",
                jid, recipient_devs, own_other_devs,
            );

            // DSM-wrapped plaintext for our own other devices. Note we wrap
            // the UNPADDED `wa_bytes` and apply padding to the outer DSM
            // bytes below, mirroring Baileys' `encodeWAMessage(dsmMessage)`.
            let dsm_bytes = wrap_device_sent_message(jid, &wa_bytes);

            let mut to_nodes: Vec<BinaryNode> = Vec::new();
            let mut any_pkmsg = false;

            // Each target gets the same outermost Message padded fresh per
            // encrypt to match the peer's `unpadRandomMax16` trim.
            // Baileys' `jidEncode` drops `:0` from the wire JID (primary
            // device), so `<to jid="X@lid">` is semantically the same as
            // `<to jid="X:0@lid">`. We strip `:0` to match — keeping the
            // explicit `:0` form triggers retry receipts from the primary
            // device even when our session state is correct.
            for (dev_jid, plaintext) in recipient_devs.iter().map(|d| (strip_zero_device(d), pad_wa(&wa_bytes)))
                .chain(own_other_devs.iter().map(|d| (strip_zero_device(d), pad_wa(&dsm_bytes))))
            {
                if !self.signal.has_session(&dev_jid) {
                    match crate::socket::prekey::fetch_pre_key_bundle(&self.socket, &dev_jid).await {
                        Ok(bundle) => {
                            if let Err(e) = self.signal.create_sender_session(&dev_jid, &bundle) {
                                tracing::warn!("create_sender_session {dev_jid}: {e}");
                                continue;
                            }
                        }
                        Err(e) => {
                            tracing::warn!("fetch_pre_key_bundle {dev_jid}: {e}");
                            continue;
                        }
                    }
                }
                let enc = match self.signal.encrypt_message(&dev_jid, &plaintext).await {
                    Ok(e) => e,
                    Err(e) => { tracing::warn!("encrypt {dev_jid}: {e}"); continue; }
                };
                if enc.msg_type == "pkmsg" { any_pkmsg = true; }
                to_nodes.push(BinaryNode {
                    tag: "to".to_string(),
                    attrs: vec![("jid".to_string(), dev_jid)],
                    content: NodeContent::List(vec![BinaryNode {
                        tag: "enc".to_string(),
                        attrs: vec![
                            ("v".to_string(), "2".to_string()),
                            ("type".to_string(), enc.msg_type.to_string()),
                        ],
                        content: NodeContent::Bytes(enc.ciphertext),
                    }]),
                });
            }

            if to_nodes.is_empty() {
                anyhow::bail!("no devices available for {jid}");
            }

            let mut children = vec![BinaryNode {
                tag: "participants".to_string(),
                attrs: vec![],
                content: NodeContent::List(to_nodes),
            }];
            if any_pkmsg {
                let account_id = self.signal.account_identity_bytes().to_vec();
                if !account_id.is_empty() {
                    children.push(BinaryNode {
                        tag: "device-identity".to_string(),
                        attrs: vec![],
                        content: NodeContent::Bytes(account_id),
                    });
                }
            }
            (NodeContent::List(children), any_pkmsg, Vec::new())
        };

        let is_pkmsg = any_pkmsg;

        let stanza = BinaryNode {
            tag: "message".to_string(),
            attrs: vec![
                ("to".to_string(), jid.to_string()),
                ("id".to_string(), id.to_string()),
                ("type".to_string(), "text".to_string()),
                ("t".to_string(), unix_now().to_string()),
            ],
            content: message_content,
        };
        tracing::info!(
            "→ send message id={} to={} pkmsg={} children={}",
            id, jid, is_pkmsg,
            match &stanza.content {
                NodeContent::List(c) => c.iter().map(|n| n.tag.as_str()).collect::<Vec<_>>().join(","),
                _ => String::new(),
            },
        );
        self.socket.send_node(&stanza).await?;
        if jid.ends_with("@g.us") {
            for dev_jid in skdm_distributed {
                self.signal.mark_skdm_distributed(jid, &dev_jid);
            }
        }
        Ok(())
    }

    /// Encrypt and upload media, returning a filled-in `MediaInfo`.
    pub async fn upload_media(
        &self,
        plaintext: &[u8],
        media_type: crate::media::MediaType,
        mimetype: &str,
    ) -> Result<crate::messages::MediaInfo> {
        use crate::media::{encrypt_media_blob};
        use crate::socket::media_upload::{request_upload_url, upload_to_cdn};

        let (blob, media_key, enc_sha256, sha256) = encrypt_media_blob(plaintext, media_type)?;
        let size = blob.len() as u64;
        let up = request_upload_url(&self.socket, &enc_sha256, media_type, size).await?;
        upload_to_cdn(&up.url, &blob).await?;

        Ok(crate::messages::MediaInfo {
            url: up.url,
            direct_path: up.direct_path,
            media_key,
            file_enc_sha256: enc_sha256,
            file_sha256: sha256,
            file_length: size,
            mimetype: mimetype.to_string(),
        })
    }

    pub async fn send_image(&self, jid: &str, data: &[u8], caption: Option<&str>) -> Result<String> {
        let info = self.upload_media(data, crate::media::MediaType::Image, "image/jpeg").await?;
        let id = generate_message_id();
        self.send_message(jid, id.clone(), MessageContent::Image {
            info,
            caption: caption.map(|s| s.to_string()),
        }).await?;
        Ok(id)
    }

    pub async fn send_video(&self, jid: &str, data: &[u8], caption: Option<&str>) -> Result<String> {
        let info = self.upload_media(data, crate::media::MediaType::Video, "video/mp4").await?;
        let id = generate_message_id();
        self.send_message(jid, id.clone(), MessageContent::Video {
            info,
            caption: caption.map(|s| s.to_string()),
        }).await?;
        Ok(id)
    }

    pub async fn send_audio(&self, jid: &str, data: &[u8], mimetype: &str) -> Result<String> {
        let info = self.upload_media(data, crate::media::MediaType::Audio, mimetype).await?;
        let id = generate_message_id();
        self.send_message(jid, id.clone(), MessageContent::Audio { info }).await?;
        Ok(id)
    }

    pub async fn send_document(
        &self,
        jid: &str,
        data: &[u8],
        mimetype: &str,
        file_name: &str,
    ) -> Result<String> {
        let info = self.upload_media(data, crate::media::MediaType::Document, mimetype).await?;
        let id = generate_message_id();
        self.send_message(jid, id.clone(), MessageContent::Document {
            info,
            file_name: file_name.to_string(),
        }).await?;
        Ok(id)
    }

    /// Post a text status update (WhatsApp Stories equivalent).
    pub async fn send_status_text(&self, text: &str) -> Result<String> {
        let wa_bytes = crate::signal::wa_proto::encode_wa_text_message(text);
        self.send_status_bytes(wa_bytes).await
    }

    /// Post an image status update (WhatsApp Stories).
    pub async fn send_status_image(&self, data: &[u8], caption: Option<&str>) -> Result<String> {
        let info = self.upload_media(data, crate::media::MediaType::Image, "image/jpeg").await?;
        let wa_bytes = crate::signal::wa_proto::encode_wa_image_message(&info, caption);
        self.send_status_bytes(wa_bytes).await
    }

    /// Post a video status update (WhatsApp Stories).
    pub async fn send_status_video(&self, data: &[u8], caption: Option<&str>) -> Result<String> {
        let info = self.upload_media(data, crate::media::MediaType::Video, "video/mp4").await?;
        let wa_bytes = crate::signal::wa_proto::encode_wa_video_message(&info, caption);
        self.send_status_bytes(wa_bytes).await
    }

    /// Core: encrypt wa_bytes as skmsg and send to status@broadcast.
    async fn send_status_bytes(&self, wa_bytes: Vec<u8>) -> Result<String> {
        const STATUS_JID: &str = "status@broadcast";

        let contacts: Vec<String> = self.contacts.snapshot().into_keys().collect();
        let (sender_key_nodes, distributed, sender_key_pkmsg) =
            self.build_group_sender_key_distribution(STATUS_JID, &contacts).await?;

        let skmsg = self.signal.encrypt_group_message(STATUS_JID, &wa_bytes).await?;
        let id = generate_message_id();

        let mut content_nodes = vec![BinaryNode {
            tag: "enc".to_string(),
            attrs: vec![
                ("v".to_string(), "2".to_string()),
                ("type".to_string(), "skmsg".to_string()),
            ],
            content: NodeContent::Bytes(skmsg),
        }];
        if !sender_key_nodes.is_empty() {
            content_nodes.push(BinaryNode {
                tag: "participants".to_string(),
                attrs: vec![],
                content: NodeContent::List(sender_key_nodes),
            });
        }
        if sender_key_pkmsg {
            let account_id = self.signal.account_identity_bytes().to_vec();
            if !account_id.is_empty() {
                content_nodes.push(BinaryNode {
                    tag: "device-identity".to_string(),
                    attrs: vec![],
                    content: NodeContent::Bytes(account_id),
                });
            }
        }

        self.socket.send_node(&BinaryNode {
            tag: "message".to_string(),
            attrs: vec![
                ("to".to_string(), STATUS_JID.to_string()),
                ("id".to_string(), id.clone()),
                ("type".to_string(), "text".to_string()),
                ("t".to_string(), unix_now().to_string()),
            ],
            content: NodeContent::List(content_nodes),
        }).await?;
        for dev_jid in distributed {
            self.signal.mark_skdm_distributed(STATUS_JID, &dev_jid);
        }
        Ok(id)
    }

    /// Send a text message to a group. Uses the SenderKey path automatically.
    pub async fn send_group_text(&self, group_jid: &str, text: &str) -> Result<String> {
        self.send_text(group_jid, text).await
    }

    /// Build `<participants><to><enc/></to>...` nodes that distribute our
    /// SenderKey to every group device missing it. This must ride on the same
    /// group stanza as the `skmsg`; sending separate 1:1 stanzas can leave
    /// other devices without the key, which is exactly how official clients
    /// end up stuck on "esperando mensaje".
    async fn build_group_sender_key_distribution(
        &self,
        group_jid: &str,
        participants: &[String],
    ) -> Result<(Vec<BinaryNode>, Vec<String>, bool)> {
        use std::collections::{HashMap, HashSet};

        let cache = crate::device_cache::DeviceCache::new(std::path::Path::new("."));
        let mut participant_devices = Vec::new();
        let mut uncached = Vec::new();

        for jid in participants {
            let bare = bare_user_jid(jid);
            if let Some(devs) = cache.get(&bare) {
                participant_devices.extend(devs);
            } else {
                uncached.push(bare);
            }
        }

        let uncached_user_count = uncached.len();
        if !uncached.is_empty() {
            let uncached_refs: Vec<&str> = uncached.iter().map(String::as_str).collect();
            let fetched = crate::socket::usync::get_user_devices(&self.socket, &uncached_refs).await?;
            let mut fetched_by_user: HashMap<String, Vec<String>> = HashMap::new();
            for dev in fetched {
                fetched_by_user.entry(bare_user_jid(&dev)).or_default().push(dev);
            }
            for bare in uncached {
                let devices = fetched_by_user
                    .remove(&bare)
                    .unwrap_or_else(|| vec![ensure_device(&bare)]);
                cache.put(&bare, &devices);
                participant_devices.extend(devices);
            }
        }

        let skdm_proto = self.signal.get_skdm_proto(group_jid);
        tracing::info!(
            "SKDM plan: group={} participants={} candidate_devices={} uncached_users={} proto_len={}",
            group_jid,
            participants.len(),
            participant_devices.len(),
            uncached_user_count,
            skdm_proto.len(),
        );
        tracing::debug!(
            "SKDM candidate devices for {} => {:?}",
            group_jid,
            participant_devices,
        );
        let mut our_devices = HashSet::from([strip_zero_device(&self.our_jid)]);
        if let Some(our_lid) = &self.our_lid {
            our_devices.insert(strip_zero_device(our_lid));
        }
        let mut seen = HashSet::new();
        let mut to_nodes = Vec::new();
        let mut distributed = Vec::new();
        let mut any_pkmsg = false;

        for device_jid in participant_devices {
            let jid = strip_zero_device(&device_jid);
            if !seen.insert(jid.clone()) {
                continue;
            }
            if our_devices.contains(&jid) {
                tracing::debug!("SKDM: skipping own device {jid}");
                continue;
            }
            if self.signal.is_skdm_distributed(group_jid, &jid) {
                continue;
            }
            tracing::debug!(
                "SKDM: refreshing pairwise session for {} (had_session={})",
                jid,
                self.signal.has_session(&jid),
            );
            match crate::socket::prekey::fetch_pre_key_bundle(&self.socket, &jid).await {
                Ok(bundle) => {
                    if let Err(e) = self.signal.create_sender_session(&jid, &bundle) {
                        tracing::warn!("SKDM: session refresh for {jid} failed: {e}");
                        continue;
                    }
                }
                Err(e) => {
                    tracing::warn!("SKDM: pre-keys for {jid} failed: {e}");
                    continue;
                }
            }
            let padded = pad_wa(&skdm_proto);
            match self.signal.encrypt_message(&jid, &padded).await {
                Ok(enc) => {
                    if enc.msg_type == "pkmsg" {
                        any_pkmsg = true;
                    }
                    tracing::debug!(
                        "SKDM target: group={} jid={} enc_type={} padded_len={} cipher_len={}",
                        group_jid,
                        jid,
                        enc.msg_type,
                        padded.len(),
                        enc.ciphertext.len(),
                    );
                    to_nodes.push(BinaryNode {
                        tag: "to".to_string(),
                        attrs: vec![("jid".to_string(), jid.clone())],
                        content: NodeContent::List(vec![BinaryNode {
                            tag: "enc".to_string(),
                            attrs: vec![
                                ("v".to_string(), "2".to_string()),
                                ("type".to_string(), enc.msg_type.to_string()),
                            ],
                            content: NodeContent::Bytes(enc.ciphertext),
                        }]),
                    });
                    distributed.push(jid);
                }
                Err(e) => tracing::warn!("SKDM encrypt for {jid} failed: {e}"),
            }
        }
        tracing::info!(
            "SKDM built: group={} targets={} pkmsg={} distributed={:?}",
            group_jid,
            to_nodes.len(),
            any_pkmsg,
            distributed,
        );
        Ok((to_nodes, distributed, any_pkmsg))
    }

    /// Send a text message with a link preview card.
    /// The caller is responsible for fetching OG metadata (title, description, thumbnail).
    pub async fn send_link_preview(
        &self,
        jid: &str,
        text: &str,
        url: &str,
        title: &str,
        description: &str,
        thumbnail_jpeg: Option<Vec<u8>>,
    ) -> Result<String> {
        let id = generate_message_id();
        self.send_message(jid, id.clone(), MessageContent::LinkPreview {
            text: text.to_string(),
            url: url.to_string(),
            title: title.to_string(),
            description: description.to_string(),
            thumbnail_jpeg,
        }).await?;
        Ok(id)
    }

    /// Send a poll to a 1:1 or group JID.
    /// `selectable_count` = max options a voter can pick (0 = unlimited).
    pub async fn send_poll(
        &self,
        jid: &str,
        question: &str,
        options: &[&str],
        selectable_count: u32,
    ) -> Result<String> {
        let id = generate_message_id();
        self.send_message(jid, id.clone(), MessageContent::Poll {
            question: question.to_string(),
            options: options.iter().map(|s| s.to_string()).collect(),
            selectable_count,
        }).await?;
        Ok(id)
    }

    /// Delete (revoke) a message we sent.
    pub async fn send_revoke(&self, jid: &str, msg_id: &str) -> Result<()> {
        let wa_bytes = crate::signal::wa_proto::encode_wa_revoke_message(jid, msg_id, true);
        self.send_encrypted_bytes(jid, &generate_message_id(), wa_bytes).await
    }

    /// Edit a message we sent.
    pub async fn send_edit(&self, jid: &str, msg_id: &str, new_text: &str) -> Result<()> {
        let wa_bytes = crate::signal::wa_proto::encode_wa_edit_message(jid, msg_id, new_text);
        self.send_encrypted_bytes(jid, &generate_message_id(), wa_bytes).await
    }

    /// Vote on a poll (`selected_options` empty = deselect all).
    pub async fn send_poll_vote(
        &self,
        jid: &str,
        poll_msg_id: &str,
        selected_options: &[&str],
    ) -> Result<()> {
        let enc_key = self.poll_store.enc_key(poll_msg_id)
            .ok_or_else(|| anyhow::anyhow!("poll {poll_msg_id} not found in store"))?;
        let wa_bytes = crate::signal::wa_proto::encode_wa_poll_vote(
            poll_msg_id, jid, &enc_key, &self.our_jid, selected_options,
        );
        self.send_encrypted_bytes(jid, &generate_message_id(), wa_bytes).await
    }

    pub async fn send_sticker(&self, jid: &str, data: &[u8]) -> Result<String> {
        let info = self.upload_media(data, crate::media::MediaType::Sticker, "image/webp").await?;
        let id = generate_message_id();
        self.send_message(jid, id.clone(), MessageContent::Sticker { info }).await?;
        Ok(id)
    }

    // ── Forward ───────────────────────────────────────────────────────────────

    /// Forward a stored message to a new JID.
    /// Looks up the message in the local store; fails if not found.
    pub async fn forward_message(
        &self,
        to_jid: &str,
        from_jid: &str,
        msg_id: &str,
    ) -> Result<String> {
        use crate::signal::wa_proto::{
            encode_wa_forward_audio, encode_wa_forward_document,
            encode_wa_forward_image, encode_wa_forward_text, encode_wa_forward_video,
        };

        let stored = self.msg_store.lookup(from_jid, msg_id)
            .ok_or_else(|| anyhow::anyhow!("message {msg_id} not found in {from_jid}"))?;

        // Re-download media if needed, then re-upload to get fresh CDN URLs
        let wa_bytes = match (&stored.text, &stored.media_type, &stored.media_info) {
            (Some(text), _, _) => encode_wa_forward_text(text),
            (_, Some(mt), Some(info)) if mt.starts_with("image") => {
                let data = crate::media::download_media(
                    &info.url, &info.media_key, crate::media::MediaType::Image,
                ).await?;
                let new_info = self.upload_media(&data, crate::media::MediaType::Image, &info.mimetype).await?;
                encode_wa_forward_image(&new_info, None)
            }
            (_, Some(mt), Some(info)) if mt.starts_with("video") => {
                let data = crate::media::download_media(
                    &info.url, &info.media_key, crate::media::MediaType::Video,
                ).await?;
                let new_info = self.upload_media(&data, crate::media::MediaType::Video, &info.mimetype).await?;
                encode_wa_forward_video(&new_info, None)
            }
            (_, Some(mt), Some(info)) if mt.starts_with("audio") => {
                let data = crate::media::download_media(
                    &info.url, &info.media_key, crate::media::MediaType::Audio,
                ).await?;
                let new_info = self.upload_media(&data, crate::media::MediaType::Audio, &info.mimetype).await?;
                encode_wa_forward_audio(&new_info)
            }
            (_, Some(mt), Some(info)) if mt.starts_with("document") => {
                let file_name = msg_id;
                let data = crate::media::download_media(
                    &info.url, &info.media_key, crate::media::MediaType::Document,
                ).await?;
                let new_info = self.upload_media(&data, crate::media::MediaType::Document, &info.mimetype).await?;
                encode_wa_forward_document(&new_info, file_name)
            }
            _ => anyhow::bail!("message {msg_id} has no forwardable content"),
        };

        let id = generate_message_id();
        self.send_encrypted_bytes(to_jid, &id, wa_bytes).await?;
        Ok(id)
    }

    // ── Ephemeral ─────────────────────────────────────────────────────────────

    /// Set the ephemeral (disappearing) message timer for a chat.
    ///
    /// `expiration_secs`: 0 = off, 86400 = 24h, 604800 = 7d, 7776000 = 90d.
    ///
    /// For groups, sends an IQ to the group. For 1:1 chats, sends a ProtocolMessage.
    pub async fn set_ephemeral_duration(&self, jid: &str, expiration_secs: u32) -> Result<()> {
        if jid.ends_with("@g.us") {
            // Group: use IQ
            let id = self.socket.next_id();
            self.socket.send_iq_await(crate::binary::BinaryNode {
                tag: "iq".to_string(),
                attrs: vec![
                    ("id".to_string(), id),
                    ("type".to_string(), "set".to_string()),
                    ("xmlns".to_string(), "w:g2".to_string()),
                    ("to".to_string(), jid.to_string()),
                ],
                content: crate::binary::NodeContent::List(vec![crate::binary::BinaryNode {
                    tag: "ephemeral".to_string(),
                    attrs: vec![("period".to_string(), expiration_secs.to_string())],
                    content: crate::binary::NodeContent::None,
                }]),
            }).await?;
        } else {
            // 1:1: send ProtocolMessage
            let wa_bytes = crate::signal::wa_proto::encode_wa_ephemeral_setting(expiration_secs);
            let id = generate_message_id();
            self.send_encrypted_bytes(jid, &id, wa_bytes).await?;
        }
        Ok(())
    }

    /// Download and decrypt media referenced by a received message.
    pub async fn download_media(
        &self,
        info: &crate::messages::MediaInfo,
        media_type: crate::media::MediaType,
    ) -> Result<Vec<u8>> {
        crate::media::download_media(&info.url, &info.media_key, media_type).await
    }

    /// Fetch full group info (name, description, participants).
    pub async fn group_info(
        &self,
        group_jid: &str,
    ) -> Result<crate::socket::group::GroupInfo> {
        crate::socket::group::fetch_group_info(&self.socket, group_jid).await
    }

    /// Check whether phone numbers are registered on WhatsApp.
    /// `phones` — E.164 digits without '+', e.g. `["5491112345678"]`.
    pub async fn on_whatsapp(
        &self,
        phones: &[&str],
    ) -> Result<Vec<crate::socket::usync::ContactInfo>> {
        crate::socket::usync::on_whatsapp(&self.socket, phones).await
    }

    /// Resolve JIDs to ContactInfo (on_whatsapp + status text).
    pub async fn resolve_contacts(
        &self,
        jids: &[&str],
    ) -> Result<std::collections::HashMap<String, crate::socket::usync::ContactInfo>> {
        crate::socket::usync::resolve_contacts(&self.socket, jids).await
    }

    /// Fetch the status text for a list of JIDs.
    pub async fn fetch_status(
        &self,
        jids: &[&str],
    ) -> Result<std::collections::HashMap<String, String>> {
        crate::socket::usync::fetch_status(&self.socket, jids).await
    }

    // ── Group management ──────────────────────────────────────────────────────

    pub async fn create_group(
        &self,
        subject: &str,
        participant_jids: &[&str],
    ) -> Result<crate::socket::group::GroupInfo> {
        crate::socket::group::create_group(&self.socket, subject, participant_jids).await
    }

    pub async fn add_participants(
        &self,
        group_jid: &str,
        jids: &[&str],
    ) -> Result<Vec<crate::socket::group::ParticipantResult>> {
        crate::socket::group::add_participants(&self.socket, group_jid, jids).await
    }

    pub async fn remove_participants(
        &self,
        group_jid: &str,
        jids: &[&str],
    ) -> Result<Vec<crate::socket::group::ParticipantResult>> {
        crate::socket::group::remove_participants(&self.socket, group_jid, jids).await
    }

    pub async fn promote_to_admin(
        &self,
        group_jid: &str,
        jids: &[&str],
    ) -> Result<Vec<crate::socket::group::ParticipantResult>> {
        crate::socket::group::promote_to_admin(&self.socket, group_jid, jids).await
    }

    pub async fn demote_from_admin(
        &self,
        group_jid: &str,
        jids: &[&str],
    ) -> Result<Vec<crate::socket::group::ParticipantResult>> {
        crate::socket::group::demote_from_admin(&self.socket, group_jid, jids).await
    }

    pub async fn leave_group(&self, group_jid: &str) -> Result<()> {
        crate::socket::group::leave_group(&self.socket, group_jid).await
    }

    pub async fn set_group_subject(&self, group_jid: &str, subject: &str) -> Result<()> {
        crate::socket::group::set_group_subject(&self.socket, group_jid, subject).await
    }

    pub async fn set_group_description(&self, group_jid: &str, description: &str) -> Result<()> {
        crate::socket::group::set_group_description(&self.socket, group_jid, description).await
    }

    pub async fn subscribe_group_presence(&self, group_jid: &str) -> Result<()> {
        crate::socket::group::subscribe_group_presence(&self.socket, group_jid).await
    }

    // ── Profile pictures ──────────────────────────────────────────────────────

    pub async fn get_profile_picture(
        &self,
        jid: &str,
        high_res: bool,
    ) -> Result<Option<String>> {
        crate::socket::group::get_profile_picture(&self.socket, jid, high_res).await
    }

    pub async fn set_profile_picture(&self, jpeg_data: &[u8]) -> Result<()> {
        crate::socket::group::set_profile_picture(&self.socket, &self.our_jid, jpeg_data).await
    }

}
