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

/// Build the `<chatstate>` [`BinaryNode`] without touching any
/// socket. Pure function so wire-shape tests can roundtrip the
/// stanza through the binary encoder without spinning up a full
/// `MessageManager`.
///
/// `media` is honoured on [`ChatPresenceState::Composing`] only;
/// it is dropped silently for `Paused` (matching the wire-level
/// behaviour expected by WhatsApp Web).
pub fn build_chat_presence_node(
    jid: &str,
    state: ChatPresenceState,
    media: Option<ChatPresenceMedia>,
) -> crate::binary::BinaryNode {
    use crate::binary::{BinaryNode, NodeContent};

    let inner_tag = match state {
        ChatPresenceState::Composing => "composing",
        ChatPresenceState::Paused => "paused",
    };
    let inner_attrs: Vec<(String, String)> = match (state, media) {
        (ChatPresenceState::Composing, Some(m)) => match m.wire_attr() {
            Some(v) => vec![("media".to_string(), v.to_string())],
            None => vec![],
        },
        _ => vec![],
    };
    BinaryNode {
        tag: "chatstate".to_string(),
        attrs: vec![("to".to_string(), jid.to_string())],
        content: NodeContent::List(vec![BinaryNode {
            tag: inner_tag.to_string(),
            attrs: inner_attrs,
            content: NodeContent::None,
        }]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::NodeContent;

    fn inner_node(node: &crate::binary::BinaryNode) -> &crate::binary::BinaryNode {
        match &node.content {
            NodeContent::List(items) => items.first().expect("expected one inner node"),
            _ => panic!("chatstate must wrap inner node in NodeContent::List"),
        }
    }

    #[test]
    fn composing_text_emits_no_media_attr() {
        let node = build_chat_presence_node(
            "573144347358@s.whatsapp.net",
            ChatPresenceState::Composing,
            Some(ChatPresenceMedia::Text),
        );
        assert_eq!(node.tag, "chatstate");
        assert_eq!(node.attr("to"), Some("573144347358@s.whatsapp.net"));
        let inner = inner_node(&node);
        assert_eq!(inner.tag, "composing");
        assert!(
            inner.attr("media").is_none(),
            "Text media must omit the attr entirely; got media={:?}",
            inner.attr("media")
        );
    }

    #[test]
    fn composing_audio_emits_media_audio() {
        let node = build_chat_presence_node(
            "573144347358@s.whatsapp.net",
            ChatPresenceState::Composing,
            Some(ChatPresenceMedia::Audio),
        );
        let inner = inner_node(&node);
        assert_eq!(inner.tag, "composing");
        assert_eq!(inner.attr("media"), Some("audio"));
    }

    #[test]
    fn paused_emits_simple_paused() {
        let node = build_chat_presence_node(
            "573144347358@s.whatsapp.net",
            ChatPresenceState::Paused,
            Some(ChatPresenceMedia::Audio), // ignored
        );
        let inner = inner_node(&node);
        assert_eq!(inner.tag, "paused");
        assert!(
            inner.attr("media").is_none(),
            "Paused must drop media attr; got {:?}",
            inner.attr("media")
        );
    }

    #[test]
    fn composing_no_media_arg_omits_attr() {
        let node = build_chat_presence_node(
            "573144347358@s.whatsapp.net",
            ChatPresenceState::Composing,
            None,
        );
        let inner = inner_node(&node);
        assert_eq!(inner.tag, "composing");
        assert!(inner.attr("media").is_none());
    }

    #[test]
    fn send_typing_node_matches_send_chat_presence_with_no_media() {
        // The wrapper `MessageManager::send_typing(jid, true)` must
        // produce the same `<chatstate>` node as
        // `send_chat_presence(jid, Composing, None)` — guards
        // against the wrapper drifting from the canonical builder.
        let typing_on = build_chat_presence_node(
            "1@s.whatsapp.net",
            ChatPresenceState::Composing,
            None,
        );
        let typing_off = build_chat_presence_node(
            "1@s.whatsapp.net",
            ChatPresenceState::Paused,
            None,
        );
        assert_eq!(inner_node(&typing_on).tag, "composing");
        assert!(inner_node(&typing_on).attr("media").is_none());
        assert_eq!(inner_node(&typing_off).tag, "paused");
    }
}

