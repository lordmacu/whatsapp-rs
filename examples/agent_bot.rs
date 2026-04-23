//! Minimal agent-style bot using the Session::run_agent loop.
//!
//! ```
//! cargo run --release --example agent_bot
//! ```
//!
//! Routes:
//!   - `ping`        → text "pong"
//!   - `hora`        → reply with current UTC time
//!   - starts with `!` → quick :ok_hand: reaction + echo back as reply
//!   - everything else → echo as plain text
//!
//! Demonstrates:
//!   - `Response` variants (Text / Reply / React / Multi)
//!   - Handler state captured from outside (atomic counter)
//!   - Typing heartbeat applied automatically per message

use anyhow::Result;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use whatsapp_rs::agent::{AgentCtx, Response};
use whatsapp_rs::Client;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("whatsapp_rs=info")),
        )
        .init();

    let session = Client::new()?.connect().await?;
    tracing::info!("agent ready as {}", session.our_jid);

    let seen = Arc::new(AtomicUsize::new(0));
    let seen_for_handler = seen.clone();

    session.run_agent(move |ctx: AgentCtx| {
        let seen = seen_for_handler.clone();
        async move {
            let n = seen.fetch_add(1, Ordering::Relaxed) + 1;
            let text = match ctx.text.as_deref() {
                Some(t) => t,
                None => return Response::Noop,
            };
            match text {
                "ping" => Response::text("pong"),
                "hora" => Response::reply(format!(
                    "UTC ahora: {}",
                    chrono_like_now()
                )),
                _ if text.starts_with('!') => Response::Multi(vec![
                    Response::react("👌"),
                    Response::reply(format!("({n}) {text}")),
                ]),
                _ => Response::text(format!("({n}) echo: {text}")),
            }
        }
    }).await?;

    Ok(())
}

/// RFC-3339-ish timestamp without pulling in `chrono`.
fn chrono_like_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let hh = (secs / 3600) % 24;
    let mm = (secs / 60) % 60;
    let ss = secs % 60;
    format!("{hh:02}:{mm:02}:{ss:02} UTC")
}
