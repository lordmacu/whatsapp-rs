/// Exercise the new `Chat` ergonomic API + delivery/reply waiters.
///
/// Usage:
///   systemctl --user stop whatsapp-rs   # daemon shares the WA socket
///   cargo run --example chat_demo -- <jid>
///   systemctl --user start whatsapp-rs
///
/// `<jid>` format: `573154645370@s.whatsapp.net` (1:1) or `12345@g.us` (group).
///
/// What it does:
///   1. Connects (reuses existing ~/.local/share/.whatsapp-rs pairing)
///   2. Sends "hola desde chat_demo" via `chat.text_and_wait` and prints
///      the final status (Sent/Delivered/Read) with 30s timeout.
///   3. Reacts to that message with "👋".
///   4. Sets typing=true, then typing=false.
///   5. Waits up to 60s for a reply from that jid via `chat.wait_for_reply`.
///   6. If a reply arrives, echoes it back as a quoted reply.
use std::time::Duration;

use anyhow::{bail, Result};
use whatsapp_rs::{client::Client, MessageStatus};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    let jid = match args.get(1) {
        Some(v) => v.clone(),
        None => bail!("usage: chat_demo <jid>"),
    };

    let client = Client::new()?;
    let session = client.connect().await?;
    println!("connected as {}", session.our_jid);

    let chat = session.chat(&jid);
    println!("chat target: {} (name={:?})", chat.jid(), chat.name());

    // Start listening for a reply *before* we send anything. This catches
    // fast replies that would arrive during the text_and_wait window.
    let reply_waiter = chat.listen_for_reply(Duration::from_secs(20));
    println!("→ reply listener armed (20s window)");

    // 1. Send + wait for delivered (short timeout so demo finishes quickly)
    println!("→ sending and waiting for delivery (10s)…");
    let (id, status) = chat
        .text_and_wait(
            "hola desde chat_demo",
            MessageStatus::Delivered,
            Duration::from_secs(10),
        )
        .await?;
    println!("  id={id} final_status={:?}", status);

    // 2. React
    chat.react(&id, "👋").await?;
    println!("→ reacted 👋");

    // 3. Typing on/off
    chat.typing(true).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    chat.typing(false).await?;
    println!("→ typing pulse sent");

    // 4. Await the pre-armed reply listener
    println!("→ awaiting reply (up to 20s total from listener start)…");
    match reply_waiter.await.ok().flatten() {
        Some(msg) => {
            let preview = match &msg.message {
                Some(whatsapp_rs::MessageContent::Text { text, .. }) => text.clone(),
                Some(other) => format!("{other:?}"),
                None => "<empty>".to_string(),
            };
            println!("  ← reply id={} text={preview}", msg.key.id);

            // 5. Quote-reply to it
            let echo = format!("eco: {preview}");
            let echo_id = chat.reply(&msg.key.id, &echo).await?;
            println!("→ sent quoted echo id={echo_id}");
        }
        None => {
            println!("  (no reply within 60s)");
        }
    }

    println!("done — clean shutdown");
    drop(session);
    Ok(())
}
