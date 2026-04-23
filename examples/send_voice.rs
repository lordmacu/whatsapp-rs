/// One-shot: upload an audio file as a push-to-talk voice note.
///
/// Usage:
///   systemctl --user stop whatsapp-rs
///   cargo run --example send_voice -- <jid> <path.mp3>
///   systemctl --user start whatsapp-rs
use anyhow::Result;
use whatsapp_rs::client::Client;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    let jid = args.get(1).cloned().unwrap_or_else(|| {
        eprintln!("usage: send_voice <jid> <path.mp3>");
        std::process::exit(2);
    });
    let path = args.get(2).cloned().unwrap_or_else(|| {
        eprintln!("usage: send_voice <jid> <path.mp3>");
        std::process::exit(2);
    });
    let data = std::fs::read(&path)?;
    let mime = match std::path::Path::new(&path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase()
        .as_str()
    {
        "ogg" | "opus" => "audio/ogg; codecs=opus",
        "mp3" => "audio/mpeg",
        "m4a" => "audio/mp4",
        _ => "audio/mpeg",
    };

    let client = Client::new()?;
    let session = client.connect().await?;
    let id = session.send_voice_note(&jid, &data, mime).await?;
    println!("sent voice note: {id}");
    Ok(())
}
