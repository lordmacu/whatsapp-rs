/// Minimal agent: echoes every incoming text back as a quoted reply.
///
/// Usage:
///   systemctl --user stop whatsapp-rs   # bot needs exclusive WA socket
///   cargo run --example echo_bot
///   systemctl --user start whatsapp-rs  # when done, restore daemon
///
/// Optional first arg restricts to a single peer jid (PN or LID):
///   cargo run --example echo_bot -- 573154645370@s.whatsapp.net
///
/// From any other WhatsApp device, send this account a text. The bot
/// replies with `eco: <your text>` as a quoted reply. Ctrl+C to exit.
use anyhow::Result;
use whatsapp_rs::{client::Client, MessageContent, MessageEvent};

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

    let client = Client::new()?;
    let session = client.connect().await?;
    println!("echo_bot running as {}", session.our_jid);
    match &filter {
        Some(j) => println!("replying only to messages from {j}"),
        None => println!("replying to every non-self text message"),
    }
    println!("Ctrl+C to quit\n");

    let mut events = session.events();
    loop {
        match events.recv().await {
            Ok(MessageEvent::NewMessage { msg }) if !msg.key.from_me => {
                // Extract something replyable.
                let (text, prefix) = match &msg.message {
                    Some(MessageContent::Text { text, .. }) => (text.clone(), ""),
                    Some(MessageContent::Reply { text, .. }) => (text.clone(), "(reply) "),
                    Some(MessageContent::LinkPreview { text, .. }) => (text.clone(), "(link) "),
                    _ => continue, // ignore media / reactions / system
                };
                // Skip decrypt-failed placeholders.
                if text == "<decrypt failed>" || text == "<skmsg decrypt failed>" {
                    continue;
                }
                // Optional peer filter.
                if let Some(allow) = &filter {
                    if !jid_matches(allow, &msg.key.remote_jid) {
                        continue;
                    }
                }

                let chat_name = session.contact_name(&msg.key.remote_jid)
                    .unwrap_or_else(|| msg.key.remote_jid.clone());
                println!("← [{chat_name}] {prefix}{text}");

                let echo = format!("eco: {text}");
                let chat = session.chat(&msg.key.remote_jid);
                match chat.reply(&msg.key.id, &echo).await {
                    Ok(id) => println!("→ replied id={id}\n"),
                    Err(e) => println!("× reply failed: {e}\n"),
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

/// Loose jid equivalence: matches by bare user portion, ignoring any
/// `:device` slot and the server (so PN ↔ LID on the same contact can be
/// passed as the filter argument). `filter` is the user-supplied jid,
/// `remote` is what came in on the stanza.
fn jid_matches(filter: &str, remote: &str) -> bool {
    let strip = |j: &str| -> String {
        let at = match j.find('@') { Some(i) => i, None => return j.to_string() };
        let left = &j[..at];
        let user = left.split(':').next().unwrap_or(left);
        format!("{user}@{}", &j[at + 1..])
    };
    let a = strip(filter);
    let b = strip(remote);
    if a == b { return true; }
    // Different server (LID vs PN) — compare just the user id.
    let user_of = |j: &str| j.split('@').next().unwrap_or("").to_string();
    user_of(&a) == user_of(&b)
}
