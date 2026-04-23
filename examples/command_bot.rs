/// Command-routing bot with media download hooks.
///
/// Text commands:
///   /help                 — list commands
///   /echo <text>          — repeat the text back
///   /upper <text>         — repeat uppercased
///   /repeat <n> <text>    — repeat text N times (max 10)
///   /ping                 — replies "pong"
///   /time                 — current unix timestamp
///
/// Media (image / video / audio / document / sticker) is downloaded to
/// `$BOT_MEDIA_DIR` (default `/tmp/wa-bot-media`) and a short summary is
/// sent back. `handle_media` is the hook where you'd plug in an AI
/// description / OCR / upload-to-object-storage / etc.
///
/// Env:
///   BOT_MEDIA_DIR   — folder for downloaded files (created if missing)
///
/// Usage:
///   systemctl --user stop whatsapp-rs
///   cargo run --example command_bot [jid-filter]
///   systemctl --user start whatsapp-rs
use anyhow::Result;
use std::path::{Path, PathBuf};
use whatsapp_rs::{
    client::{Client, Session},
    media::MediaType,
    MessageContent, MessageEvent, MessageKey,
};

fn media_dir() -> PathBuf {
    let p = std::env::var("BOT_MEDIA_DIR").unwrap_or_else(|_| "/tmp/wa-bot-media".to_string());
    let p = PathBuf::from(p);
    let _ = std::fs::create_dir_all(&p);
    p
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    let filter = args.get(1).cloned();
    let dir = media_dir();

    let client = Client::new()?;
    let session = client.connect().await?;
    println!("command_bot running as {}", session.our_jid);
    println!("media dir: {}", dir.display());
    if let Some(j) = &filter { println!("only responding to {j}"); }
    println!("commands: /help /echo /upper /repeat /ping /time\nCtrl+C to quit\n");

    let mut events = session.events();
    loop {
        match events.recv().await {
            Ok(MessageEvent::NewMessage { msg }) if !msg.key.from_me => {
                if let Some(allow) = &filter {
                    if !same_user(allow, &msg.key.remote_jid) { continue; }
                }

                let name = session.contact_name(&msg.key.remote_jid)
                    .unwrap_or_else(|| msg.key.remote_jid.clone());
                let chat = session.chat(&msg.key.remote_jid);

                // Media path: download + hand to `handle_media`. Text
                // path: route through `handle_command`.
                let reply = match &msg.message {
                    Some(MessageContent::Text { text, .. })
                    | Some(MessageContent::Reply { text, .. })
                    | Some(MessageContent::LinkPreview { text, .. }) => {
                        if text.starts_with('<') { continue; } // decrypt-failed placeholder
                        println!("← [{name}] {text}");
                        handle_command(text)
                    }
                    Some(MessageContent::Image { info, caption, view_once }) => {
                        let tag = if *view_once { "imagen, ver-una-vez" } else { "imagen" };
                        println!("← [{name}] [{tag}{}]", fmt_caption(caption.as_deref()));
                        let path = save_media(&session, &msg.key, info, MediaType::Image, "jpg", &dir).await;
                        handle_media(Media::Image { caption: caption.clone(), saved_at: path })
                    }
                    Some(MessageContent::Video { info, caption, view_once }) => {
                        let tag = if *view_once { "video, ver-una-vez" } else { "video" };
                        println!("← [{name}] [{tag}{}]", fmt_caption(caption.as_deref()));
                        let path = save_media(&session, &msg.key, info, MediaType::Video, "mp4", &dir).await;
                        handle_media(Media::Video { caption: caption.clone(), saved_at: path })
                    }
                    Some(MessageContent::Audio { .. }) => {
                        println!("← [{name}] [audio]");
                        let info = match &msg.message { Some(MessageContent::Audio { info, .. }) => info, _ => unreachable!() };
                        let path = save_media(&session, &msg.key, info, MediaType::Audio, "ogg", &dir).await;
                        handle_media(Media::Audio { saved_at: path })
                    }
                    Some(MessageContent::Document { info, file_name }) => {
                        println!("← [{name}] [documento: {file_name}]");
                        let ext = Path::new(file_name).extension().and_then(|s| s.to_str()).unwrap_or("bin");
                        let path = save_media(&session, &msg.key, info, MediaType::Document, ext, &dir).await;
                        handle_media(Media::Document { file_name: file_name.clone(), saved_at: path })
                    }
                    Some(MessageContent::Sticker { info }) => {
                        println!("← [{name}] [sticker]");
                        let path = save_media(&session, &msg.key, info, MediaType::Sticker, "webp", &dir).await;
                        handle_media(Media::Sticker { saved_at: path })
                    }
                    _ => continue,
                };

                match &reply {
                    Reply::Plain(t)   => { let _ = chat.text(t).await; }
                    Reply::Quoted(t)  => { let _ = chat.reply(&msg.key.id, t).await; }
                    Reply::Ignore     => {}
                }
            }
            Ok(_) => {}
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                println!("(events lagged by {n})");
            }
        }
    }
    Ok(())
}

fn fmt_caption(c: Option<&str>) -> String {
    match c {
        Some(s) if !s.is_empty() => format!(" — {s}"),
        _ => String::new(),
    }
}

/// Download an inbound media blob and save to `dir/<msg_id>.<ext>`.
/// Returns `Some(path)` on success, `None` if the download or write fails
/// (the caller surfaces the error by value in the reply).
async fn save_media(
    session: &Session,
    key: &MessageKey,
    info: &whatsapp_rs::MediaInfo,
    media_type: MediaType,
    ext: &str,
    dir: &Path,
) -> Option<PathBuf> {
    let bytes = match session.download_media(info, media_type).await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("download failed for {}: {e}", key.id);
            return None;
        }
    };
    let path = dir.join(format!("{}.{ext}", key.id));
    if let Err(e) = std::fs::write(&path, &bytes) {
        eprintln!("write failed for {}: {e}", path.display());
        return None;
    }
    Some(path)
}

/// Rich media event handed to the user-level handler. Extend with AI
/// describe / OCR / upload-to-S3 / etc. — the file is already on disk at
/// `saved_at` when this is called.
#[allow(dead_code)]
enum Media {
    Image    { caption: Option<String>, saved_at: Option<PathBuf> },
    Video    { caption: Option<String>, saved_at: Option<PathBuf> },
    Audio    { saved_at: Option<PathBuf> },
    Document { file_name: String, saved_at: Option<PathBuf> },
    Sticker  { saved_at: Option<PathBuf> },
}

/// User-editable media handler. Right now it just reports size + local
/// path back to the sender. Replace with your integration:
///   - call Claude vision / OpenAI vision on image/video
///   - transcribe audio via Whisper API
///   - extract text from documents
///   - upload to S3 / GCS and reply with the public URL
/// The inbound file is already on disk at `saved_at` if the download
/// succeeded — no need to re-fetch.
fn handle_media(m: Media) -> Reply {
    fn info(path: &Option<PathBuf>) -> String {
        match path {
            Some(p) => match std::fs::metadata(p) {
                Ok(md) => format!("{} KB — {}", md.len() / 1024, p.display()),
                Err(_) => format!("saved at {}", p.display()),
            },
            None => "(descarga falló)".to_string(),
        }
    }
    match m {
        Media::Image { caption, saved_at }    => Reply::Plain(format!(
            "imagen recibida ({}){}", info(&saved_at),
            caption.filter(|c| !c.is_empty()).map(|c| format!("\ncaption: {c}")).unwrap_or_default()
        )),
        Media::Video { caption, saved_at }    => Reply::Plain(format!(
            "video recibido ({}){}", info(&saved_at),
            caption.filter(|c| !c.is_empty()).map(|c| format!("\ncaption: {c}")).unwrap_or_default()
        )),
        Media::Audio { saved_at }             => Reply::Plain(format!("audio recibido ({})", info(&saved_at))),
        Media::Document { file_name, saved_at } => Reply::Plain(format!(
            "documento recibido: {file_name} ({})", info(&saved_at)
        )),
        Media::Sticker { saved_at }           => Reply::Plain(format!("sticker recibido ({})", info(&saved_at))),
    }
}

enum Reply {
    Plain(String),
    Quoted(String),
    #[allow(dead_code)]
    Ignore,
}

fn handle_command(input: &str) -> Reply {
    let trimmed = input.trim();
    let (cmd, rest) = match trimmed.split_once(char::is_whitespace) {
        Some((c, r)) => (c, r.trim()),
        None => (trimmed, ""),
    };
    match cmd {
        "/help" => Reply::Plain(
            "comandos:\n\
             /echo <texto>\n\
             /upper <texto>\n\
             /repeat <n> <texto>\n\
             /ping\n\
             /time\n\
             (envía cualquier imagen/video/audio/doc/sticker — se descarga a disco)".to_string()
        ),
        "/echo" => {
            if rest.is_empty() { Reply::Plain("uso: /echo <texto>".into()) }
            else { Reply::Plain(rest.to_string()) }
        }
        "/upper" => {
            if rest.is_empty() { Reply::Plain("uso: /upper <texto>".into()) }
            else { Reply::Plain(rest.to_uppercase()) }
        }
        "/repeat" => {
            let (n_str, body) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
            let n: usize = match n_str.parse() {
                Ok(v) if v <= 10 => v,
                Ok(_) => return Reply::Plain("límite 10".into()),
                Err(_) => return Reply::Plain("uso: /repeat <n> <texto>".into()),
            };
            if body.is_empty() { return Reply::Plain("uso: /repeat <n> <texto>".into()); }
            Reply::Plain((0..n).map(|_| body).collect::<Vec<_>>().join("\n"))
        }
        "/ping" => Reply::Plain("pong".into()),
        "/time" => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            Reply::Plain(format!("unix: {now}"))
        }
        _ if cmd.starts_with('/') => {
            Reply::Plain(format!("comando desconocido: {cmd}  — usa /help"))
        }
        _ => Reply::Quoted(format!("recibí: {trimmed}")),
    }
}

fn same_user(a: &str, b: &str) -> bool {
    fn bare(j: &str) -> String {
        let at = match j.find('@') { Some(i) => i, None => return j.to_string() };
        let left = &j[..at];
        let user = left.split(':').next().unwrap_or(left);
        format!("{user}@{}", &j[at + 1..])
    }
    let a = bare(a); let b = bare(b);
    if a == b { return true; }
    a.split('@').next() == b.split('@').next()
}
