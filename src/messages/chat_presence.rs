//! Chat-presence stanzas — `<chatstate>` with optional `media`
//! discriminator. Used to drive the "typing…" / "recording audio…"
//! indicator on the peer phone while the bot prepares a reply.
//!
//! Wire shape:
//!
//! ```xml
//! <!-- typing (text) -->
//! <chatstate to="123@s.whatsapp.net"><composing/></chatstate>
//!
//! <!-- recording (audio) -->
//! <chatstate to="123@s.whatsapp.net"><composing media="audio"/></chatstate>
//!
//! <!-- stopped (text or audio) -->
//! <chatstate to="123@s.whatsapp.net"><paused/></chatstate>
//! ```
//!
//! The legacy `MessageManager::send_typing(jid, composing)` API
//! lives on as a wrapper that calls `send_chat_presence` with
//! `media: None`. Callers that need the recording variant call
//! `send_chat_presence(jid, ChatPresenceState::Composing,
//! Some(ChatPresenceMedia::Audio))` directly.

/// State of the inner node inside a `<chatstate>` stanza.
///
/// Maps 1-to-1 to the WhatsApp protocol values. `Paused` clears the
/// indicator regardless of the previously-set media — the peer
/// client doesn't carry state across paused/composing transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatPresenceState {
    /// `<composing/>` — peer renders "typing…" / "recording…"
    /// depending on the [`ChatPresenceMedia`] discriminator.
    Composing,
    /// `<paused/>` — peer stops rendering any indicator. Any
    /// `media` argument supplied alongside is ignored.
    Paused,
}

/// Optional `media` attribute on the `<composing>` inner node.
///
/// `Text` (the default for plain typing) emits no `media` attr —
/// the peer renders "typing…". `Audio` emits `media="audio"` and
/// the peer renders "recording audio…". Other media kinds (image,
/// video, document) exist on paper but are not exposed by this
/// crate yet — Baileys-derived implementations also restrict to
/// audio, which is the only kind WhatsApp Web actually paints
/// distinctly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChatPresenceMedia {
    /// No `media` attr; peer paints "typing…".
    #[default]
    Text,
    /// `media="audio"`; peer paints "recording audio…".
    Audio,
}

impl ChatPresenceMedia {
    /// Wire value when serialised as the `media` attr on
    /// `<composing>`. Returns `None` for [`Self::Text`] so the
    /// emitter can omit the attribute entirely (avoids a `media=""`
    /// byte trip that some older WA clients reject).
    pub fn wire_attr(&self) -> Option<&'static str> {
        match self {
            Self::Text => None,
            Self::Audio => Some("audio"),
        }
    }
}
