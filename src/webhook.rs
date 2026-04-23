//! Outbound HTTP webhook agent — POST each incoming message to an external
//! URL and dispatch whatever action the server returns.
//!
//! Perfect for hooking up an LLM backend running elsewhere (Lambda, n8n,
//! Python/FastAPI, a worker on another box) without having to embed it in
//! the Rust binary.
//!
//! Request body (`application/json`):
//! ```json
//! {
//!   "event":      "message",
//!   "msg_id":     "3EB0…",
//!   "chat_jid":   "57300…@s.whatsapp.net",
//!   "sender":     "57300…@s.whatsapp.net",
//!   "text":       "hola",
//!   "from_me":    false,
//!   "timestamp":  1712345678,
//!   "push_name":  "Juan"
//! }
//! ```
//!
//! Expected response (same content-type). Any of:
//! ```json
//! {"type": "noop"}
//! {"type": "text",  "content": "¡hola!"}
//! {"type": "reply", "content": "ok"}
//! {"type": "react", "content": "👍"}
//! {"type": "multi", "items": [
//!     {"type": "react", "content": "👌"},
//!     {"type": "reply", "content": "got it"}
//! ]}
//! ```
//!
//! If `secret` is set, the request carries an `X-WhatsApp-Signature` header
//! with `HMAC-SHA256(secret, body)` hex-encoded so your endpoint can verify
//! the call.

use crate::agent::{Acl, AgentCtx, Response};
use crate::client::Session;
use crate::error::Result;

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Wire shape of a webhook event — what we POST to the user's endpoint.
#[derive(Debug, Clone, Serialize)]
pub struct WebhookEvent<'a> {
    pub event: &'static str,
    pub msg_id: &'a str,
    pub chat_jid: &'a str,
    pub sender: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<&'a str>,
    pub from_me: bool,
    pub timestamp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_name: Option<&'a str>,
}

/// Wire shape of the action the endpoint wants us to take. Mirror of
/// [`Response`] but restricted to JSON-friendly variants (no raw media
/// bytes). Send images via the daemon IPC if you need them.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum WebhookAction {
    Noop,
    Text { content: String },
    Reply { content: String },
    React { content: String },
    Multi { items: Vec<WebhookAction> },
}

impl From<WebhookAction> for Response {
    fn from(a: WebhookAction) -> Self {
        match a {
            WebhookAction::Noop => Response::Noop,
            WebhookAction::Text { content } => Response::Text(content),
            WebhookAction::Reply { content } => Response::Reply(content),
            WebhookAction::React { content } => Response::React(content),
            WebhookAction::Multi { items } =>
                Response::Multi(items.into_iter().map(Into::into).collect()),
        }
    }
}

/// Config for the webhook agent.
pub struct WebhookConfig {
    pub url: String,
    /// If set, sign each request body with HMAC-SHA256 and pass the hex
    /// digest in `X-WhatsApp-Signature`. Your endpoint should reject
    /// requests whose signature doesn't match.
    pub secret: Option<String>,
    /// Per-request timeout. Webhook must respond within this or we treat
    /// it as noop (so a slow LLM doesn't freeze the agent loop).
    pub timeout: Duration,
}

impl WebhookConfig {
    /// Read `WA_WEBHOOK_URL` and `WA_WEBHOOK_SECRET` (optional) from the
    /// environment. Returns `None` if URL is unset.
    pub fn from_env() -> Option<Self> {
        let url = std::env::var("WA_WEBHOOK_URL").ok()?;
        let secret = std::env::var("WA_WEBHOOK_SECRET").ok()
            .filter(|s| !s.is_empty());
        let timeout_secs = std::env::var("WA_WEBHOOK_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);
        Some(Self { url, secret, timeout: Duration::from_secs(timeout_secs) })
    }
}

impl Session {
    /// Run an agent that POSTs each allowed incoming message to `config.url`
    /// and applies the `WebhookAction` returned by the endpoint. Blocks
    /// until the event bus closes.
    ///
    /// A dead / slow / non-200 webhook falls back to `Response::Noop` —
    /// the loop keeps running so one bad turn doesn't kill the bot.
    pub async fn run_webhook_agent(&self, config: WebhookConfig, acl: Acl) -> Result<()> {
        let http = reqwest::Client::builder()
            .timeout(config.timeout)
            .user_agent("whatsapp-rs-webhook/0.1")
            .build()
            .map_err(|e| crate::error::WaError::Other(e.into()))?;

        let url = config.url;
        let secret = config.secret;

        self.run_agent_with(acl, move |ctx: AgentCtx| {
            let http = http.clone();
            let url = url.clone();
            let secret = secret.clone();
            async move {
                match dispatch(&http, &url, secret.as_deref(), &ctx).await {
                    Ok(action) => action.into(),
                    Err(e) => {
                        tracing::warn!("webhook dispatch failed: {e}");
                        Response::Noop
                    }
                }
            }
        }).await
    }
}

async fn dispatch(
    http: &reqwest::Client,
    url: &str,
    secret: Option<&str>,
    ctx: &AgentCtx,
) -> anyhow::Result<WebhookAction> {
    let sender_owned = ctx.sender().to_string();
    let body = WebhookEvent {
        event: "message",
        msg_id: &ctx.msg.key.id,
        chat_jid: &ctx.msg.key.remote_jid,
        sender: &sender_owned,
        text: ctx.text.as_deref(),
        from_me: ctx.msg.key.from_me,
        timestamp: ctx.msg.message_timestamp,
        push_name: ctx.msg.push_name.as_deref(),
    };
    let body_bytes = serde_json::to_vec(&body)?;

    let mut req = http.post(url)
        .header("content-type", "application/json");
    if let Some(s) = secret {
        req = req.header("X-WhatsApp-Signature", hmac_sha256_hex(s.as_bytes(), &body_bytes));
    }
    let resp = req.body(body_bytes).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("webhook returned {}", resp.status());
    }
    let body = resp.bytes().await?;
    let action: WebhookAction = serde_json::from_slice(&body)?;
    Ok(action)
}

fn hmac_sha256_hex(key: &[u8], data: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC key");
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_deserializes_text() {
        let j = r#"{"type":"text","content":"hola"}"#;
        let a: WebhookAction = serde_json::from_str(j).unwrap();
        matches!(a, WebhookAction::Text { .. });
    }

    #[test]
    fn action_deserializes_multi() {
        let j = r#"{"type":"multi","items":[
            {"type":"react","content":"👌"},
            {"type":"reply","content":"ok"}
        ]}"#;
        let a: WebhookAction = serde_json::from_str(j).unwrap();
        match a {
            WebhookAction::Multi { items } => assert_eq!(items.len(), 2),
            _ => panic!("expected Multi"),
        }
    }

    #[test]
    fn hmac_is_deterministic() {
        let sig = hmac_sha256_hex(b"secret", b"hello");
        assert_eq!(sig.len(), 64);
        assert_eq!(sig, hmac_sha256_hex(b"secret", b"hello"));
    }
}
