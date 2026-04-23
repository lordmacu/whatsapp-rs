//! Webhook-driven bot: POSTs each incoming message to an external URL and
//! dispatches whatever `WebhookAction` the server returns. Lets you keep
//! the agent logic in Python / TypeScript / whatever and just use this
//! binary as the WhatsApp transport.
//!
//! ```bash
//! export WA_WEBHOOK_URL=https://your-agent.com/hook
//! export WA_WEBHOOK_SECRET=supersecret          # optional, HMAC-SHA256 over body
//! export WA_AGENT_ALLOW=573XX@s.whatsapp.net    # optional whitelist
//! cargo run --release --example webhook_bot
//! ```
//!
//! Your endpoint gets:
//!   POST /hook                          Content-Type: application/json
//!   X-WhatsApp-Signature: <hex-hmac>    (when secret set)
//!   {
//!     "event": "message",
//!     "msg_id": "…",
//!     "chat_jid": "…@s.whatsapp.net",
//!     "sender":   "…@s.whatsapp.net",
//!     "text":     "hola",
//!     "from_me":  false,
//!     "timestamp": 1712…,
//!     "push_name": "Juan"
//!   }
//!
//! Respond with one of:
//!   {"type": "noop"}
//!   {"type": "text",  "content": "hi"}
//!   {"type": "reply", "content": "ok"}
//!   {"type": "react", "content": "👍"}
//!   {"type": "multi", "items": [{"type":"react","content":"👌"},{"type":"reply","content":"got it"}]}

use anyhow::{bail, Result};
use whatsapp_rs::agent::Acl;
use whatsapp_rs::webhook::WebhookConfig;
use whatsapp_rs::Client;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("whatsapp_rs=info")),
        )
        .init();

    let config = match WebhookConfig::from_env() {
        Some(c) => c,
        None => bail!("set WA_WEBHOOK_URL (and optionally WA_WEBHOOK_SECRET)"),
    };
    let acl = Acl::from_env("WA_AGENT_ALLOW");

    let session = Client::new()?.connect().await?;
    tracing::info!("webhook agent ready as {} → {}", session.our_jid, config.url);

    session.run_webhook_agent(config, acl).await?;
    Ok(())
}
