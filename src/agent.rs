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

// ── Conversation history (LLM-friendly) ───────────────────────────────────────

/// Role of one turn in a chat, using the standard LLM two-role convention.
///
/// Maps from `from_me`: our outbound messages are `Assistant`, everything
/// received is `User`. In group chats all non-self senders collapse into
/// `User` — if you need per-sender attribution, inspect [`ConvEntry::sender`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role { User, Assistant }

/// One turn of a WhatsApp chat in a shape that drops straight into an LLM
/// prompt (`[{ "role": "user", "content": "…" }, …]`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConvEntry {
    pub role: Role,
    /// Plain text for text variants; bracketed placeholders like
    /// `"[image: caption]"` or `"[audio]"` for media. `None` for
    /// reactions / polls / unknown content.
    pub content: String,
    pub timestamp: u64,
    /// Stanza id — useful for mapping back to [`MessageKey`] for reactions
    /// / replies without re-querying the store.
    pub id: String,
    /// Raw WhatsApp JID of the sender (bare `:device` stripped would be on
    /// caller). Helps disambiguate group participants.
    pub sender: String,
}

impl Session {
    /// Return the last `n` messages in a chat formatted for LLM prompting.
    ///
    /// Media messages are rendered as `[image]`, `[video]`, `[audio]`,
    /// `[document]`, `[sticker]` with captions inline when present. Reactions,
    /// polls and unknown variants are skipped — they'd just pollute the prompt.
    ///
    /// Ordered oldest → newest so you can feed it directly into the LLM's
    /// messages array. De-dups already handled by the underlying store.
    pub fn conversation_history(&self, jid: &str, n: usize) -> Vec<ConvEntry> {
        self.message_history(jid, n)
            .into_iter()
            .filter_map(|m| {
                let content = if let Some(t) = &m.text {
                    if t.starts_with('<') && t.ends_with('>') && t.contains("failed") {
                        return None; // skip decrypt placeholders
                    }
                    t.clone()
                } else if let Some(mt) = &m.media_type {
                    format!("[{mt}]")
                } else {
                    return None;
                };
                Some(ConvEntry {
                    role: if m.from_me { Role::Assistant } else { Role::User },
                    content,
                    timestamp: m.timestamp,
                    id: m.id,
                    sender: m.participant.unwrap_or(m.remote_jid),
                })
            })
            .collect()
    }
}

// ── Audio transcription hook ──────────────────────────────────────────────────

/// Extension point for voice-note → text. When configured, the agent loop
/// downloads each incoming audio / voice-note, calls `transcribe`, and
/// injects the returned string into `ctx.text` so the handler sees it as
/// if it were a regular text message.
///
/// Intended for plugging in Whisper (local or API), Google STT, Deepgram,
/// etc. — the library stays codec-agnostic.
///
/// Impl'd for any `Fn(Vec<u8>, String) -> Future<Output = Option<String>>`
/// so callers usually pass a closure:
///
/// ```ignore
/// session.run_agent_with_transcribe(acl,
///     |audio, mimetype| async move {
///         whisper_api::transcribe(audio, &mimetype).await.ok()
///     },
///     |ctx| async move { Response::reply(format!("heard: {}", ctx.text.unwrap_or_default())) },
/// ).await?;
/// ```
pub trait Transcriber: Send + Sync + 'static {
    fn transcribe(
        &self,
        audio: Vec<u8>,
        mimetype: String,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<String>> + Send>>;
}

impl<F, Fut> Transcriber for F
where
    F: Fn(Vec<u8>, String) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Option<String>> + Send + 'static,
{
    fn transcribe(
        &self,
        audio: Vec<u8>,
        mimetype: String,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<String>> + Send>> {
        Box::pin((self)(audio, mimetype))
    }
}

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

// ── Access control ────────────────────────────────────────────────────────────

/// Gate an agent on a set of allowed JIDs so it only responds to known
/// contacts. Empty allow-list = accept everyone (the default).
///
/// Reads `WA_AGENT_ALLOW` if set: comma-separated JIDs (with or without
/// the device suffix — matched against the bare user JID).
#[derive(Debug, Clone, Default)]
pub struct Acl {
    allow: std::collections::HashSet<String>,
}

impl Acl {
    /// Empty — everyone allowed.
    pub fn open() -> Self { Self::default() }

    /// Seed from a comma-separated env var. Empty or missing = open.
    pub fn from_env(var: &str) -> Self {
        let mut allow = std::collections::HashSet::new();
        if let Ok(s) = std::env::var(var) {
            for j in s.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                allow.insert(bare_jid(j));
            }
        }
        Self { allow }
    }

    /// Add a single JID to the allow-list (bare form — `:device` stripped).
    pub fn allow(mut self, jid: impl AsRef<str>) -> Self {
        self.allow.insert(bare_jid(jid.as_ref()));
        self
    }

    /// `true` if `sender` is allowed to invoke the agent. Open ACL permits
    /// everyone; otherwise we match on the bare form.
    pub fn permits(&self, sender: &str) -> bool {
        self.allow.is_empty() || self.allow.contains(&bare_jid(sender))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_strips_device() {
        assert_eq!(bare_jid("5731:20@s.whatsapp.net"), "5731@s.whatsapp.net");
        assert_eq!(bare_jid("5731@s.whatsapp.net"),    "5731@s.whatsapp.net");
        assert_eq!(bare_jid("group@g.us"),             "group@g.us");
        assert_eq!(bare_jid(""),                       "");
    }

    #[test]
    fn acl_open_permits_everyone() {
        let acl = Acl::open();
        assert!(acl.permits("anyone@s.whatsapp.net"));
    }

    #[test]
    fn acl_whitelist_enforces() {
        let acl = Acl::open().allow("57300@s.whatsapp.net");
        assert!(acl.permits("57300@s.whatsapp.net"));
        assert!(acl.permits("57300:20@s.whatsapp.net")); // device suffix stripped
        assert!(!acl.permits("57999@s.whatsapp.net"));
    }
}

/// Strip a `:device` suffix (`1234:20@s.whatsapp.net` → `1234@s.whatsapp.net`).
fn bare_jid(jid: &str) -> String {
    let at = match jid.find('@') {
        Some(i) => i,
        None => return jid.to_string(),
    };
    let user = &jid[..at];
    let host = &jid[at..];
    match user.find(':') {
        Some(colon) => format!("{}{}", &user[..colon], host),
        None => jid.to_string(),
    }
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
        self.run_agent_with(Acl::from_env("WA_AGENT_ALLOW"), handler).await
    }

    /// Like [`Self::run_agent`] but with an explicit [`Acl`] — only the
    /// JIDs it permits reach the handler. Everything else is silently
    /// dropped (the sender never sees typing / reply, so the bot stays
    /// invisible to unauthorised contacts).
    pub async fn run_agent_with<F, Fut>(
        &self,
        acl: Acl,
        handler: F,
    ) -> crate::error::Result<()>
    where
        F: Fn(AgentCtx) -> Fut,
        Fut: std::future::Future<Output = Response>,
    {
        self.run_agent_full(acl, None, handler).await
    }

    /// Run an agent loop that transcribes incoming voice notes / audio
    /// into text before calling the handler. See [`Transcriber`].
    ///
    /// Identical to [`run_agent_with`] otherwise — ACL, typing heartbeat,
    /// dedup, rate limiter all still apply.
    pub async fn run_agent_with_transcribe<T, F, Fut>(
        &self,
        acl: Acl,
        transcribe: T,
        handler: F,
    ) -> crate::error::Result<()>
    where
        T: Transcriber,
        F: Fn(AgentCtx) -> Fut,
        Fut: std::future::Future<Output = Response>,
    {
        self.run_agent_full(acl, Some(Box::new(transcribe) as Box<dyn Transcriber>), handler).await
    }

    async fn run_agent_full<F, Fut>(
        &self,
        acl: Acl,
        transcribe: Option<Box<dyn Transcriber>>,
        handler: F,
    ) -> crate::error::Result<()>
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

            let sender = msg.key.participant.as_deref()
                .unwrap_or(&msg.key.remote_jid);
            if !acl.permits(sender) {
                tracing::debug!("agent: skipping {sender} (not in ACL)");
                continue;
            }

            let mut text = extract_text(msg.message.as_ref());

            // Voice-note transcription: only runs when configured AND the
            // message is audio with no accompanying text. Failure is silent
            // (handler just sees text=None and can route to Noop).
            if text.is_none() {
                if let Some(t) = transcribe.as_ref() {
                    if let Some(MessageContent::Audio { info, .. }) = msg.message.as_ref() {
                        match self.download_media(info, crate::media::MediaType::Audio).await {
                            Ok(bytes) => {
                                let mime = info.mimetype.clone();
                                match t.transcribe(bytes, mime).await {
                                    Some(s) if !s.trim().is_empty() => {
                                        tracing::info!("transcribed {} bytes → {:?}…",
                                            info.file_length,
                                            s.chars().take(40).collect::<String>());
                                        text = Some(s);
                                    }
                                    _ => tracing::debug!("transcriber returned empty"),
                                }
                            }
                            Err(e) => tracing::warn!("download audio for transcribe: {e}"),
                        }
                    }
                }
            }

            let ctx = AgentCtx { msg: msg.clone(), text };

            let _typing = self.typing_heartbeat(&msg.key.remote_jid);
            let _slow = self.slow_notice(&msg.key.remote_jid);
            let response = handler(ctx).await;
            drop(_slow);
            drop(_typing);

            if let Err(e) = self.apply_response(&msg.key, response).await {
                tracing::warn!("agent response send failed: {e}");
            }
        }
    }

    /// Spawn a task that, if the handler is still running after
    /// `WA_AGENT_SLOW_SECS` seconds, sends `WA_AGENT_SLOW_MSG` once to
    /// keep the user informed. Aborted on drop — normal-speed replies
    /// never trigger it.
    ///
    /// Disabled when `WA_AGENT_SLOW_SECS` is unset. Default message is
    /// "⏳ procesando…". Useful for LLM-backed agents where a single
    /// turn can take 30–60 s.
    fn slow_notice(&self, jid: &str) -> Option<tokio::task::AbortHandle> {
        let secs: u64 = std::env::var("WA_AGENT_SLOW_SECS").ok()?.parse().ok()?;
        if secs == 0 { return None; }
        let msg = std::env::var("WA_AGENT_SLOW_MSG")
            .unwrap_or_else(|_| "⏳ procesando…".to_string());
        let jid = jid.to_string();
        let mgr = self.mgr_handle();
        let task = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
            let m = mgr.read().await;
            if let Err(e) = m.send_text(&jid, &msg).await {
                tracing::debug!("slow notice send failed: {e}");
            }
        });
        Some(task.abort_handle())
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
