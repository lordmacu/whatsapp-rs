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

        let resp = dispatch(&session, req, &shutdown_tx).await;
        tx.write_all(serde_json::to_vec(&resp)?.as_slice()).await?;
        tx.write_all(b"\n").await?;
    }
    Ok(())
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
