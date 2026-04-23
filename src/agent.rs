//! Agent runtime: a canonical event-loop that maps incoming messages to
//! replies via a user-supplied handler closure.
//!
//! ```ignore
//! use whatsapp_rs::{agent::{AgentCtx, Response}, Client};
//!
//! let session = Client::new()?.connect().await?;
//! session.run_agent(|ctx| async move {
//!     match ctx.text.as_deref() {
//!         Some("ping") => Response::Text("pong".into()),
//!         Some(t)      => Response::Reply(format!("echo: {t}")),
//!         None         => Response::Noop,
//!     }
//! }).await?;
//! ```
//!
//! Features:
//! - Filters out own messages + decrypt-failure placeholders automatically.
//! - Extracts a `text` convenience string from common message variants
//!   (Text / Reply / LinkPreview) so handlers rarely need to peek inside
//!   the full `MessageContent` enum.
//! - Starts a typing heartbeat for each message while the handler runs;
//!   drops it before sending the reply. Combined with the send-path
//!   rate limiter, agents are ban-safe under burst without extra code.
//! - Handler errors are swallowed with a `warn!` — one misbehaving turn
//!   never kills the loop.

use crate::client::Session;
use crate::messages::{MessageContent, MessageEvent, MessageKey, WAMessage};

/// Context passed to the handler on each incoming message.
#[derive(Debug, Clone)]
pub struct AgentCtx {
    /// The full decoded message. Inspect `ctx.msg.message` to route on
    /// media / poll / reaction variants that don't fit the text channel.
    pub msg: WAMessage,
    /// Best-effort text extracted from Text / Reply / LinkPreview variants.
    /// `None` for media-only messages, reactions, polls, etc.
    pub text: Option<String>,
}

impl AgentCtx {
    /// Shorthand for the chat's JID (where the reply should land).
    pub fn jid(&self) -> &str { &self.msg.key.remote_jid }
    /// Sender JID. Same as `jid()` for 1:1 chats; participant for groups.
    pub fn sender(&self) -> &str {
        self.msg.key.participant.as_deref().unwrap_or(&self.msg.key.remote_jid)
    }
}

/// What the handler wants the runtime to send back. Compose with
/// [`Response::Multi`] for fan-out (e.g. a quick ack then a slow answer).
#[derive(Debug, Clone)]
pub enum Response {
    /// No reply; move on. Use when the message was irrelevant (system
    /// notice, reaction, etc.).
    Noop,
    /// Plain text message.
    Text(String),
    /// Text as a quoted reply to the triggering message.
    Reply(String),
    /// Emoji reaction to the triggering message.
    React(String),
    /// JPEG/PNG image with optional caption.
    Image { data: Vec<u8>, caption: Option<String> },
    /// MP4 video with optional caption.
    Video { data: Vec<u8>, caption: Option<String> },
    /// Multiple responses sent in order.
    Multi(Vec<Response>),
}

impl Response {
    /// Convenience: build a `Reply` from any `Display`.
    pub fn reply(text: impl std::fmt::Display) -> Self { Self::Reply(text.to_string()) }
    /// Convenience: build a `Text` from any `Display`.
    pub fn text(text: impl std::fmt::Display) -> Self { Self::Text(text.to_string()) }
    /// Convenience: build a `React` from any `Display`.
    pub fn react(emoji: impl std::fmt::Display) -> Self { Self::React(emoji.to_string()) }
}

/// Pull a human-readable text out of the message variants that carry one.
/// Returns `None` for media/reaction/poll/etc. Filters decrypt-failure
/// placeholders (`<decrypt failed>`, `<skmsg decrypt failed>`, …) so
/// agents don't respond to noise.
pub fn extract_text(content: Option<&MessageContent>) -> Option<String> {
    let raw = match content? {
        MessageContent::Text { text, .. } => Some(text.clone()),
        MessageContent::Reply { text, .. } => Some(text.clone()),
        MessageContent::LinkPreview { text, .. } => Some(text.clone()),
        _ => None,
    }?;
    if raw.starts_with('<') && raw.ends_with('>') && raw.contains("failed") {
        return None;
    }
    Some(raw)
}

impl Session {
    /// Drive an agent-style event loop.
    ///
    /// Subscribes to the event bus and invokes `handler` for every incoming
    /// message that isn't from us. Each call gets a typing heartbeat while
    /// it's running. The returned future never completes unless the event
    /// bus closes (i.e. the Session drops).
    ///
    /// The handler runs **serially** — one message at a time — so agents
    /// that keep conversational state don't race. If you need parallelism
    /// across chats, spawn tasks inside the handler.
    pub async fn run_agent<F, Fut>(&self, handler: F) -> crate::error::Result<()>
    where
        F: Fn(AgentCtx) -> Fut,
        Fut: std::future::Future<Output = Response>,
    {
        let mut rx = self.events();
        loop {
            let ev = match rx.recv().await {
                Ok(e) => e,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!("agent loop lagged {n} events; continuing");
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    return Ok(());
                }
            };
            let msg = match ev {
                MessageEvent::NewMessage { msg } if !msg.key.from_me => msg,
                _ => continue,
            };
            let text = extract_text(msg.message.as_ref());
            let ctx = AgentCtx { msg: msg.clone(), text };

            let _typing = self.typing_heartbeat(&msg.key.remote_jid);
            let response = handler(ctx).await;
            drop(_typing);

            if let Err(e) = self.apply_response(&msg.key, response).await {
                tracing::warn!("agent response send failed: {e}");
            }
        }
    }

    /// Dispatch one [`Response`] against the chat identified by `trigger`.
    /// Used by [`Self::run_agent`]; exposed so callers can build richer
    /// loops (e.g. middleware, per-chat dispatch) on top.
    pub async fn apply_response(
        &self,
        trigger: &MessageKey,
        response: Response,
    ) -> crate::error::Result<()> {
        match response {
            Response::Noop => Ok(()),
            Response::Text(t) => { self.send_text(&trigger.remote_jid, &t).await?; Ok(()) }
            Response::Reply(t) => {
                self.send_reply(&trigger.remote_jid, &trigger.id, &t).await?;
                Ok(())
            }
            Response::React(emoji) => {
                self.send_reaction(&trigger.remote_jid, &trigger.id, &emoji).await?;
                Ok(())
            }
            Response::Image { data, caption } => {
                self.send_image(&trigger.remote_jid, &data, caption.as_deref()).await?;
                Ok(())
            }
            Response::Video { data, caption } => {
                self.send_video(&trigger.remote_jid, &data, caption.as_deref()).await?;
                Ok(())
            }
            Response::Multi(items) => {
                for r in items {
                    // Boxed recursion because `Response::Multi` is a recursive
                    // variant; otherwise the future's size is unbounded.
                    Box::pin(self.apply_response(trigger, r)).await?;
                }
                Ok(())
            }
        }
    }
}
