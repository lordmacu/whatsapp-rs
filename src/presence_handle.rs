//! RAII handle for a chat-presence heartbeat.
//!
//! Generalises the legacy `TypingHandle` to support the
//! `media="audio"` recording variant + mid-stream switches. The
//! refresher task stores the current [`ChatPresenceMedia`] in an
//! `AtomicU8` it reads before every pulse, so callers can call
//! [`PresenceHandle::switch_media`] from another task without
//! re-spawning the loop.
//!
//! Typical use:
//!
//! ```ignore
//! let handle = session.chat_presence_heartbeat(&jid, ChatPresenceMedia::Text);
//! let response = my_handler(ctx).await;
//! if response.is_voice_note() {
//!     handle.switch_media(ChatPresenceMedia::Audio);
//!     tokio::time::sleep(Duration::from_millis(250)).await;
//! }
//! drop(handle); // emits `<paused/>` best-effort
//! ```
//!
//! Implementation defaults — `keepalive_interval=10s`,
//! `max_duration=60s`, `max_consecutive_failures=2` — were chosen
//! to keep the wire cadence consistent with the existing
//! `Session::typing_heartbeat` semantics while picking up the
//! safety bounds OpenClaw documented in
//! `research/src/channels/typing.ts:14,18`.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use crate::messages::chat_presence::{ChatPresenceMedia, ChatPresenceState};
use crate::messages::MessageManager;

/// Tunables for [`PresenceHandle`]. Defaults match the historical
/// `typing_heartbeat` behaviour (10s pulse) plus safety caps lifted
/// from OpenClaw.
#[derive(Debug, Clone, Copy)]
pub struct PresenceHeartbeatConfig {
    /// How often the refresher task pulses the current presence
    /// state. WhatsApp expires the indicator if no refresh is seen
    /// for ~15s, so anything under that works; 10s leaves margin.
    pub keepalive_interval: Duration,
    /// Hard cap on how long the heartbeat can run before
    /// auto-stopping (safety net against handles that callers
    /// forget to drop). Ported from
    /// `research/src/channels/typing.ts:18`.
    pub max_duration: Duration,
    /// Stop the refresher after this many consecutive `send_node`
    /// errors. Avoids hammering a broken socket. Ported from
    /// `research/src/channels/typing.ts:14`.
    pub max_consecutive_failures: u32,
}

impl Default for PresenceHeartbeatConfig {
    fn default() -> Self {
        Self {
            keepalive_interval: Duration::from_secs(10),
            max_duration: Duration::from_secs(60),
            max_consecutive_failures: 2,
        }
    }
}

/// Encode [`ChatPresenceMedia`] into a single byte for atomic
/// load/store. Step 4 ships only the encoding helpers; the
/// refresher task that actually reads them lands in Step 5.
fn encode_media(m: ChatPresenceMedia) -> u8 {
    match m {
        ChatPresenceMedia::Text => 0,
        ChatPresenceMedia::Audio => 1,
    }
}

fn decode_media(byte: u8) -> ChatPresenceMedia {
    match byte {
        1 => ChatPresenceMedia::Audio,
        _ => ChatPresenceMedia::Text,
    }
}

/// Crate-internal door for the refresher task in
/// [`crate::client::Session::chat_presence_heartbeat_with`] to
/// translate the byte it loads from the shared `AtomicU8` back
/// into a [`ChatPresenceMedia`]. Public-in-crate so the spawn
/// site doesn't have to copy the encoding logic.
#[doc(hidden)]
pub fn __decode_media_byte(byte: u8) -> ChatPresenceMedia {
    decode_media(byte)
}

/// RAII guard for an in-flight chat-presence heartbeat.
///
/// Constructing one (via
/// [`crate::client::Session::chat_presence_heartbeat`] in Step 5)
/// spawns a background task that pulses the chosen media kind
/// every `keepalive_interval`. Dropping the handle aborts the task
/// and best-effort emits a final `<paused/>` so the peer phone
/// stops rendering the indicator.
///
/// Step 4 ships the struct shell + atomic media swap. The
/// pulser-task wiring + drop-side paused emit live in Step 5 so
/// the file landing here is reviewable on its own.
pub struct PresenceHandle {
    /// Aborts the refresher task when the handle drops. `None`
    /// only during the brief window before Step 5 wires up the
    /// real spawn — kept Optional to avoid placeholder `Arc<()>`
    /// fields.
    abort: Option<tokio::task::AbortHandle>,
    /// Current media kind the refresher should pulse with. Stored
    /// as a byte so [`Self::switch_media`] is lock-free.
    media_state: Arc<AtomicU8>,
    /// Manager handle the drop-side paused emit borrows from.
    /// `RwLock<Arc<...>>` mirrors `TypingHandle::mgr` so the field
    /// keeps tracking the live manager across reconnects (Step 5).
    mgr: Arc<RwLock<Arc<MessageManager>>>,
    /// Recipient JID. Owned so drop doesn't borrow from the spawn
    /// scope.
    jid: String,
    /// Config snapshot — exposed for inspection + reused by the
    /// Step 5 task spawn.
    cfg: PresenceHeartbeatConfig,
}

impl PresenceHandle {
    /// Build a handle bound to a fresh atomic media state. Used
    /// internally by the [`crate::client::Session::chat_presence_heartbeat`]
    /// constructor; rarely needed from outside the crate.
    #[doc(hidden)]
    pub fn new(
        mgr: Arc<RwLock<Arc<MessageManager>>>,
        jid: String,
        media: ChatPresenceMedia,
        cfg: PresenceHeartbeatConfig,
    ) -> Self {
        Self {
            abort: None,
            media_state: Arc::new(AtomicU8::new(encode_media(media))),
            mgr,
            jid,
            cfg,
        }
    }

    /// Replace the abort handle once the refresher task has been
    /// spawned. Callable once per handle; subsequent calls
    /// overwrite.
    #[doc(hidden)]
    pub fn set_abort(&mut self, abort: tokio::task::AbortHandle) {
        self.abort = Some(abort);
    }

    /// Atomically swap the media kind the refresher pulses with.
    /// The next pulse sees the new value; in-flight pulses are
    /// unaffected (they finish under the previous kind). Lock-free
    /// — safe to call from any task.
    pub fn switch_media(&self, media: ChatPresenceMedia) {
        self.media_state
            .store(encode_media(media), Ordering::SeqCst);
    }

    /// Read the current media kind. Mostly useful for tests.
    pub fn current_media(&self) -> ChatPresenceMedia {
        decode_media(self.media_state.load(Ordering::SeqCst))
    }

    /// Cloneable handle for the refresher task. The task reads the
    /// shared `AtomicU8` instead of owning a copy of the enum so
    /// `switch_media` propagates without channel plumbing.
    #[doc(hidden)]
    pub fn media_state_handle(&self) -> Arc<AtomicU8> {
        Arc::clone(&self.media_state)
    }

    /// Borrow the config the handle was built with.
    pub fn config(&self) -> PresenceHeartbeatConfig {
        self.cfg
    }
}

impl Drop for PresenceHandle {
    /// Abort the refresher and best-effort emit a final
    /// `<paused/>` (no media). Step 5 wires the manager call; here
    /// we only abort the task so the handle compiles cleanly while
    /// the rest of the implementation lands.
    fn drop(&mut self) {
        if let Some(handle) = self.abort.take() {
            handle.abort();
        }
        let mgr = Arc::clone(&self.mgr);
        let jid = std::mem::take(&mut self.jid);
        if jid.is_empty() {
            return;
        }
        // `Drop` can't be async — fire the paused emit on the
        // current runtime if one is alive. If the runtime is
        // shutting down (test teardown, daemon stop) the spawn
        // simply doesn't run; WhatsApp expires the indicator
        // naturally after ~15s.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let m = mgr.read().await;
                let _ = m
                    .send_chat_presence(&jid, ChatPresenceState::Paused, None)
                    .await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_matches_documented_values() {
        let cfg = PresenceHeartbeatConfig::default();
        assert_eq!(cfg.keepalive_interval, Duration::from_secs(10));
        assert_eq!(cfg.max_duration, Duration::from_secs(60));
        assert_eq!(cfg.max_consecutive_failures, 2);
    }

    #[test]
    fn encode_decode_media_roundtrip() {
        for m in [ChatPresenceMedia::Text, ChatPresenceMedia::Audio] {
            assert_eq!(decode_media(encode_media(m)), m);
        }
    }

    #[test]
    fn unknown_byte_decodes_as_text() {
        assert_eq!(decode_media(99), ChatPresenceMedia::Text);
    }
}
