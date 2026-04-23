//! Persistent-connection daemon + thin IPC client.
//!
//! The daemon keeps a single WhatsApp session alive and accepts JSON
//! commands over a TCP loopback socket. The CLI one-shot commands fall
//! back to transparently proxying through the daemon when it's running,
//! which drops per-command latency from ~2.5 s (fresh connect + offline
//! drain) to <100 ms (one local round-trip).
//!
//! Portability: loopback TCP works identically on Linux, macOS and
//! Windows. A short-lived random token is written to the handle file so
//! only a process with read access to the user's config dir can connect.
//!
//! IPC wire format: newline-delimited JSON. First line from the client
//! is always `{"token":"…"}`; after that, any of the `Request` variants
//! below. Each request gets one `Response` line back.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use crate::client::{Client, Session};
use crate::MessageEvent;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    Ping,
    Status,
    SendText { jid: String, text: String },
    History { jid: String, n: Option<usize> },
    Contacts,
    /// Stream incoming messages + status updates as JSON lines until the
    /// client disconnects. Designed for long-running consumers (eg. an AI
    /// agent) that want to react to messages in real time.
    Subscribe,
    SendTyping { jid: String, composing: bool },
    MarkRead { jid: String, id: String, participant: Option<String> },
    /// Download media for a previously-received message by (jid, msg id).
    /// Response: `{"data_b64": "..."}` with the decrypted media bytes.
    DownloadMedia { jid: String, id: String },
    SendImage { jid: String, data_b64: String, caption: Option<String> },
    SendVideo { jid: String, data_b64: String, caption: Option<String> },
    SendAudio { jid: String, data_b64: String, mimetype: String },
    SendVoiceNote { jid: String, data_b64: String, mimetype: String },
    SendDocument { jid: String, data_b64: String, mimetype: String, file_name: String },
    SendLocation { jid: String, latitude: f64, longitude: f64, name: Option<String>, address: Option<String> },
    SendContact { jid: String, display_name: String, phone_e164: String },
    /// Send text that auto-attaches a link preview if the body contains a URL.
    SendTextPreview { jid: String, text: String },
    Shutdown,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "ok")]
pub enum Response {
    #[serde(rename = "true")]
    Ok(serde_json::Value),
    #[serde(rename = "false")]
    Err { error: String },
}

/// Where we persist port + token so CLI clients can discover the daemon.
fn handle_path() -> Result<PathBuf> {
    let base = dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".whatsapp-rs");
    std::fs::create_dir_all(&base)?;
    Ok(base.join("daemon.json"))
}

#[derive(Serialize, Deserialize)]
struct Handle {
    port: u16,
    token: String,
    pid: u32,
}

fn load_handle() -> Result<Handle> {
    let p = handle_path()?;
    let data = std::fs::read(&p)
        .with_context(|| format!("reading {}", p.display()))?;
    Ok(serde_json::from_slice(&data)?)
}

fn save_handle(h: &Handle) -> Result<()> {
    let p = handle_path()?;
    // Atomic write via tempfile rename so partial writes aren't picked up.
    let tmp = p.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec(h)?)?;
    std::fs::rename(&tmp, &p)?;
    Ok(())
}

fn random_token() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

/// Start the daemon: connect to WhatsApp, then serve the IPC socket.
/// Runs until a `shutdown` request or Ctrl+C.
pub async fn run_daemon() -> Result<()> {
    // Refuse to start if another daemon is already alive on its advertised port.
    if let Ok(h) = load_handle() {
        if tokio::time::timeout(
            Duration::from_millis(300),
            TcpStream::connect(("127.0.0.1", h.port)),
        ).await.ok().and_then(|r| r.ok()).is_some() {
            bail!("daemon already running on port {} (pid {})", h.port, h.pid);
        }
    }

    // Refuse to start without pre-existing credentials. The daemon has no
    // stdin/stdout under systemd/launchd, so QR pairing would silently hang
    // forever. Tell the user to pair interactively first.
    {
        use crate::auth::{AuthManager, AuthState, FileStore};
        let store = std::sync::Arc::new(FileStore::new()?);
        let mgr = AuthManager::new(store)?;
        if *mgr.state() != AuthState::Authenticated {
            bail!(
                "daemon: not paired yet. Run `whatsapp-rs listen` once in a \
                 terminal and scan the QR, then restart the daemon."
            );
        }
    }

    let client = Client::new()?;
    let session = Arc::new(client.connect().await?);
    tracing::info!("daemon: connected as {}", session.our_jid);

    // Print every event to stdout so `journalctl --user -u whatsapp-rs -f`
    // works as a live monitor while the daemon is running.
    let print_sess = session.clone();
    let mut print_rx = session.events();
    tokio::spawn(async move {
        loop {
            match print_rx.recv().await {
                Ok(ev) => crate::event_print::print_event(&print_sess, ev).await,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!("daemon: dropped {n} events");
                }
                Err(_) => break,
            }
        }
    });

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let token = random_token();

    save_handle(&Handle { port, token: token.clone(), pid: std::process::id() })?;
    tracing::info!("daemon: listening on 127.0.0.1:{port}");

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);

    let accept_session = session.clone();
    let accept_token = token.clone();
    let accept_task = tokio::spawn(async move {
        loop {
            let (sock, _addr) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => { tracing::warn!("daemon: accept: {e}"); continue; }
            };
            let sess = accept_session.clone();
            let tok = accept_token.clone();
            let sd = shutdown_tx.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_client(sock, sess, tok, sd).await {
                    tracing::debug!("daemon: client error: {e}");
                }
            });
        }
    });

    tokio::select! {
        _ = shutdown_rx.recv() => { tracing::info!("daemon: shutdown requested"); }
        _ = tokio::signal::ctrl_c() => { tracing::info!("daemon: ctrl-c"); }
    }

    accept_task.abort();
    let _ = std::fs::remove_file(handle_path()?);
    Ok(())
}

async fn handle_client(
    stream: TcpStream,
    session: Arc<Session>,
    expected_token: String,
    shutdown_tx: tokio::sync::mpsc::Sender<()>,
) -> Result<()> {
    let (rx, mut tx) = stream.into_split();
    let mut rx = BufReader::new(rx);

    // First line must be the auth envelope.
    let mut line = String::new();
    rx.read_line(&mut line).await?;
    #[derive(Deserialize)] struct Auth { token: String }
    let auth: Auth = serde_json::from_str(line.trim())?;
    if auth.token != expected_token {
        let r = Response::Err { error: "bad token".into() };
        tx.write_all(serde_json::to_vec(&r)?.as_slice()).await?;
        tx.write_all(b"\n").await?;
        return Ok(());
    }

    loop {
        line.clear();
        let n = rx.read_line(&mut line).await?;
        if n == 0 { break; }

        let req: Request = match serde_json::from_str(line.trim()) {
            Ok(r) => r,
            Err(e) => {
                let r = Response::Err { error: format!("bad request: {e}") };
                tx.write_all(serde_json::to_vec(&r)?.as_slice()).await?;
                tx.write_all(b"\n").await?;
                continue;
            }
        };

        // `Subscribe` is a long-lived request: ack once, then stream events
        // until the client disconnects. No further requests honoured on this
        // connection after that.
        if matches!(req, Request::Subscribe) {
            let ok = Response::Ok(serde_json::json!({"subscribed": true}));
            tx.write_all(serde_json::to_vec(&ok)?.as_slice()).await?;
            tx.write_all(b"\n").await?;
            stream_events(&session, &mut tx).await;
            break;
        }

        let resp = dispatch(&session, req, &shutdown_tx).await;
        tx.write_all(serde_json::to_vec(&resp)?.as_slice()).await?;
        tx.write_all(b"\n").await?;
    }
    Ok(())
}

/// Pump `session.events()` onto `tx` as JSON lines. One line per event.
/// Loops until the peer disconnects or the event channel closes.
async fn stream_events(session: &Session, tx: &mut tokio::net::tcp::OwnedWriteHalf) {
    let mut rx = session.events();
    loop {
        match rx.recv().await {
            Ok(ev) => {
                let Some(json) = event_to_json(session, &ev) else { continue };
                let mut line = match serde_json::to_vec(&json) { Ok(b) => b, Err(_) => continue };
                line.push(b'\n');
                if tx.write_all(&line).await.is_err() { return; }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            Err(_) => return,
        }
    }
}

fn event_to_json(session: &Session, ev: &MessageEvent) -> Option<serde_json::Value> {
    use crate::MessageContent;
    match ev {
        MessageEvent::NewMessage { msg } => {
            let name = msg.push_name.clone()
                .or_else(|| session.contact_name(
                    msg.key.participant.as_deref().unwrap_or(&msg.key.remote_jid)
                ));
            let content = msg.message.as_ref().map(|c| match c {
                MessageContent::Text { text, mentioned_jids } =>
                    serde_json::json!({"type": "text", "text": text, "mentions": mentioned_jids}),
                MessageContent::Image { info, caption } =>
                    serde_json::json!({"type": "image", "caption": caption, "media": info}),
                MessageContent::Video { info, caption } =>
                    serde_json::json!({"type": "video", "caption": caption, "media": info}),
                MessageContent::Audio { info, .. } =>
                    serde_json::json!({"type": "audio", "media": info}),
                MessageContent::Document { info, file_name } =>
                    serde_json::json!({"type": "document", "file_name": file_name, "media": info}),
                MessageContent::Sticker { info } =>
                    serde_json::json!({"type": "sticker", "media": info}),
                MessageContent::Reaction { target_id, emoji } =>
                    serde_json::json!({"type": "reaction", "target_id": target_id, "emoji": emoji}),
                MessageContent::Reply { reply_to_id, text } =>
                    serde_json::json!({"type": "reply", "reply_to_id": reply_to_id, "text": text}),
                MessageContent::Poll { question, options, selectable_count } =>
                    serde_json::json!({"type": "poll", "question": question, "options": options, "selectable_count": selectable_count}),
                MessageContent::LinkPreview { text, url, title, description, .. } =>
                    serde_json::json!({"type": "link_preview", "text": text, "url": url, "title": title, "description": description}),
                MessageContent::Location { latitude, longitude, name, address } =>
                    serde_json::json!({"type": "location", "lat": latitude, "lon": longitude, "name": name, "address": address}),
                MessageContent::Contact { display_name, vcard } =>
                    serde_json::json!({"type": "contact", "display_name": display_name, "vcard": vcard}),
            });
            Some(serde_json::json!({
                "event": "message",
                "key": msg.key,
                "push_name": name,
                "timestamp": msg.message_timestamp,
                "content": content,
            }))
        }
        MessageEvent::MessageUpdate { key, status } => Some(serde_json::json!({
            "event": "message_status", "key": key, "status": format!("{status:?}"),
        })),
        MessageEvent::MessageRevoke { key } => Some(serde_json::json!({
            "event": "message_revoke", "key": key,
        })),
        MessageEvent::MessageEdit { key, new_text } => Some(serde_json::json!({
            "event": "message_edit", "key": key, "text": new_text,
        })),
        MessageEvent::Typing { jid, composing } => Some(serde_json::json!({
            "event": "typing", "jid": jid, "composing": composing,
        })),
        MessageEvent::Presence { jid, available } => Some(serde_json::json!({
            "event": "presence", "jid": jid, "available": available,
        })),
        MessageEvent::Disconnected { reason, reconnect } => Some(serde_json::json!({
            "event": "disconnected", "reason": reason, "reconnect": reconnect,
        })),
        // Ignore connection lifecycle, history sync, app-state, etc — not
        // useful to agents. Add more if needed.
        _ => None,
    }
}

async fn dispatch(
    session: &Session,
    req: Request,
    shutdown_tx: &tokio::sync::mpsc::Sender<()>,
) -> Response {
    match req {
        Request::Ping => Response::Ok(serde_json::json!({"pong": true})),
        Request::Status => Response::Ok(serde_json::json!({
            "jid": session.our_jid,
        })),
        Request::SendText { jid, text } => {
            match session.send_text(&jid, &text).await {
                Ok(id) => Response::Ok(serde_json::json!({"id": id})),
                Err(e) => Response::Err { error: e.to_string() },
            }
        }
        Request::History { jid, n } => {
            let msgs = session.message_history(&jid, n.unwrap_or(20));
            Response::Ok(serde_json::json!({"messages": msgs}))
        }
        Request::Contacts => {
            Response::Ok(serde_json::json!({"contacts": session.contacts_snapshot()}))
        }
        Request::SendTyping { jid, composing } => {
            match session.send_typing(&jid, composing).await {
                Ok(()) => Response::Ok(serde_json::json!({"ok": true})),
                Err(e) => Response::Err { error: e.to_string() },
            }
        }
        Request::MarkRead { jid, id, participant } => {
            let key = crate::messages::MessageKey {
                remote_jid: jid,
                from_me: false,
                id,
                participant,
            };
            match session.mark_read(&[key]).await {
                Ok(()) => Response::Ok(serde_json::json!({"ok": true})),
                Err(e) => Response::Err { error: e.to_string() },
            }
        }
        Request::DownloadMedia { jid, id } => {
            use base64::{Engine as _, engine::general_purpose::STANDARD};
            match session.download_media_by_id(&jid, &id).await {
                Ok(bytes) => Response::Ok(serde_json::json!({"data_b64": STANDARD.encode(&bytes)})),
                Err(e) => Response::Err { error: e.to_string() },
            }
        }
        Request::SendImage { jid, data_b64, caption } => {
            use base64::{Engine as _, engine::general_purpose::STANDARD};
            let data = match STANDARD.decode(&data_b64) {
                Ok(b) => b,
                Err(e) => return Response::Err { error: format!("bad base64: {e}") },
            };
            match session.send_image(&jid, &data, caption.as_deref()).await {
                Ok(id) => Response::Ok(serde_json::json!({"id": id})),
                Err(e) => Response::Err { error: e.to_string() },
            }
        }
        Request::SendVideo { jid, data_b64, caption } => {
            use base64::{Engine as _, engine::general_purpose::STANDARD};
            let data = match STANDARD.decode(&data_b64) {
                Ok(b) => b,
                Err(e) => return Response::Err { error: format!("bad base64: {e}") },
            };
            match session.send_video(&jid, &data, caption.as_deref()).await {
                Ok(id) => Response::Ok(serde_json::json!({"id": id})),
                Err(e) => Response::Err { error: e.to_string() },
            }
        }
        Request::SendAudio { jid, data_b64, mimetype } => {
            use base64::{Engine as _, engine::general_purpose::STANDARD};
            let data = match STANDARD.decode(&data_b64) {
                Ok(b) => b,
                Err(e) => return Response::Err { error: format!("bad base64: {e}") },
            };
            match session.send_audio(&jid, &data, &mimetype).await {
                Ok(id) => Response::Ok(serde_json::json!({"id": id})),
                Err(e) => Response::Err { error: e.to_string() },
            }
        }
        Request::SendVoiceNote { jid, data_b64, mimetype } => {
            use base64::{Engine as _, engine::general_purpose::STANDARD};
            let data = match STANDARD.decode(&data_b64) {
                Ok(b) => b,
                Err(e) => return Response::Err { error: format!("bad base64: {e}") },
            };
            match session.send_voice_note(&jid, &data, &mimetype).await {
                Ok(id) => Response::Ok(serde_json::json!({"id": id})),
                Err(e) => Response::Err { error: e.to_string() },
            }
        }
        Request::SendLocation { jid, latitude, longitude, name, address } => {
            match session.send_location(&jid, latitude, longitude, name.as_deref(), address.as_deref()).await {
                Ok(id) => Response::Ok(serde_json::json!({"id": id})),
                Err(e) => Response::Err { error: e.to_string() },
            }
        }
        Request::SendContact { jid, display_name, phone_e164 } => {
            match session.send_contact(&jid, &display_name, &phone_e164).await {
                Ok(id) => Response::Ok(serde_json::json!({"id": id})),
                Err(e) => Response::Err { error: e.to_string() },
            }
        }
        Request::SendTextPreview { jid, text } => {
            match session.send_text_with_preview(&jid, &text).await {
                Ok(id) => Response::Ok(serde_json::json!({"id": id})),
                Err(e) => Response::Err { error: e.to_string() },
            }
        }
        Request::SendDocument { jid, data_b64, mimetype, file_name } => {
            use base64::{Engine as _, engine::general_purpose::STANDARD};
            let data = match STANDARD.decode(&data_b64) {
                Ok(b) => b,
                Err(e) => return Response::Err { error: format!("bad base64: {e}") },
            };
            match session.send_document(&jid, &data, &mimetype, &file_name).await {
                Ok(id) => Response::Ok(serde_json::json!({"id": id})),
                Err(e) => Response::Err { error: e.to_string() },
            }
        }
        Request::Subscribe => {
            // Handled earlier in handle_client; unreachable here.
            Response::Err { error: "subscribe handled out-of-band".into() }
        }
        Request::Shutdown => {
            let _ = shutdown_tx.send(()).await;
            Response::Ok(serde_json::json!({"bye": true}))
        }
    }
}

// ── Client-side: check for running daemon and talk to it ─────────────────────

static DAEMON_CLIENT: Mutex<Option<DaemonClient>> = Mutex::const_new(None);

pub struct DaemonClient {
    stream: TcpStream,
}

impl DaemonClient {
    /// Connect to the running daemon, if any. Returns `Ok(None)` when no
    /// daemon is advertised (handle file missing or port dead).
    pub async fn try_connect() -> Result<Option<Self>> {
        let h = match load_handle() {
            Ok(h) => h,
            Err(_) => return Ok(None),
        };
        let stream = match tokio::time::timeout(
            Duration::from_millis(500),
            TcpStream::connect(("127.0.0.1", h.port)),
        ).await {
            Ok(Ok(s)) => s,
            _ => return Ok(None),
        };
        let mut client = Self { stream };
        client.write_line(&serde_json::json!({"token": h.token})).await?;
        Ok(Some(client))
    }

    async fn write_line<T: Serialize>(&mut self, v: &T) -> Result<()> {
        let mut buf = serde_json::to_vec(v)?;
        buf.push(b'\n');
        self.stream.write_all(&buf).await?;
        Ok(())
    }

    pub async fn request(&mut self, req: Request) -> Result<serde_json::Value> {
        self.write_line(&req).await?;
        let mut line = String::new();
        BufReader::new(&mut self.stream).read_line(&mut line).await?;
        let resp: Response = serde_json::from_str(line.trim())?;
        match resp {
            Response::Ok(v) => Ok(v),
            Response::Err { error } => Err(anyhow!("{error}")),
        }
    }
}

/// Execute `req` via the daemon if one is up; returns `Ok(None)` if no
/// daemon is available so callers can fall back to one-shot mode.
pub async fn try_daemon_request(req: Request) -> Result<Option<serde_json::Value>> {
    let mut slot = DAEMON_CLIENT.lock().await;
    if slot.is_none() {
        match DaemonClient::try_connect().await? {
            Some(c) => *slot = Some(c),
            None => return Ok(None),
        }
    }
    match slot.as_mut().unwrap().request(req).await {
        Ok(v) => Ok(Some(v)),
        Err(e) => {
            // Drop the dead client so a follow-up call retries.
            *slot = None;
            Err(e)
        }
    }
}
