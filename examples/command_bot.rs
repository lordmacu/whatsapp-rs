/// Command-routing bot: dispatches incoming text messages to small
/// handlers keyed by a leading slash command. Useful as a template for
/// real bots.
///
/// Supported commands:
///   /help                 — list commands
///   /echo <text>          — repeat the text back
///   /upper <text>         — repeat uppercased
///   /repeat <n> <text>    — repeat text N times (max 10)
///   /ping                 — replies "pong"
///   /time                 — current unix timestamp + local-style
/// Anything not matching a command is echoed back as a quoted reply so
/// you can see the bot heard it.
///
/// Usage:
///   systemctl --user stop whatsapp-rs
///   cargo run --example command_bot [jid-filter]
///   systemctl --user start whatsapp-rs
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
    println!("command_bot running as {}", session.our_jid);
    if let Some(j) = &filter { println!("only responding to {j}"); }
    println!("commands: /help /echo /upper /repeat /ping /time\nCtrl+C to quit\n");

    let mut events = session.events();
    loop {
        match events.recv().await {
            Ok(MessageEvent::NewMessage { msg }) if !msg.key.from_me => {
                let text = match &msg.message {
                    Some(MessageContent::Text { text, .. }) => text.clone(),
                    Some(MessageContent::Reply { text, .. }) => text.clone(),
                    _ => continue,
                };
                if text.starts_with('<') { continue; } // skip decrypt-failed placeholders
                if let Some(allow) = &filter {
                    if !same_user(allow, &msg.key.remote_jid) { continue; }
                }

                let name = session.contact_name(&msg.key.remote_jid)
                    .unwrap_or_else(|| msg.key.remote_jid.clone());
                println!("← [{name}] {text}");

                let chat = session.chat(&msg.key.remote_jid);
                let reply = handle_command(&text);
                match &reply {
                    Reply::Plain(t) => { let _ = chat.text(t).await; }
                    Reply::Quoted(t) => { let _ = chat.reply(&msg.key.id, t).await; }
                    Reply::Ignore => {}
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

enum Reply {
    Plain(String),
    Quoted(String),
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
             /time".to_string()
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
        _ => {
            // Not a command — echo as a quoted reply so the user sees
            // the bot registered the message.
            Reply::Quoted(format!("recibí: {trimmed}"))
        }
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
    // Fallback: match by user-id only (LID vs PN).
    a.split('@').next() == b.split('@').next()
}
