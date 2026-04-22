//! Decode `SyncActionValue` protobuf into typed events.
//!
//! Coverage is intentionally partial: only the mutations a desktop/CLI
//! client typically cares about (contact names, chat pin/mute/archive/read,
//! starred messages, chat deletion). Everything else falls through as `Raw`.

use crate::signal::wa_proto::{parse_proto_fields, read_varint_from_bytes};

/// Subset of SyncActionValue variants we decode natively.
#[derive(Debug, Clone)]
pub enum SyncAction {
    /// Contact name update. `id` comes from the mutation index.
    Contact { id: String, full_name: Option<String>, first_name: Option<String>, lid_jid: Option<String>, pn_jid: Option<String> },
    /// Pin/unpin a chat.
    Pin { jid: String, pinned: bool },
    /// Mute a chat until `until_ts_ms` (0 = unmute).
    Mute { jid: String, until_ts_ms: i64 },
    /// Archive/unarchive.
    Archive { jid: String, archived: bool },
    /// Mark a chat read/unread.
    MarkChatAsRead { jid: String, read: bool },
    /// Delete a chat locally.
    DeleteChat { jid: String },
    /// Star or unstar a message.
    Star { jid: String, message_id: String, from_me: bool, starred: bool },
    /// Any action we don't decode. Keeps the collection name + raw bytes
    /// so callers can still see *something* changed.
    Raw { field: u64 },
}

#[derive(Debug, Clone)]
pub struct DecodedAction {
    pub action: SyncAction,
    pub timestamp_ms: i64,
}

/// Decode the `action_value` bytes of one mutation. `index` is the JSON
/// array from the mutation index — usually `[action_name, jid, …]`.
pub fn decode(index: &[String], value_blob: &[u8]) -> Option<DecodedAction> {
    let f = parse_proto_fields(value_blob)?;
    let timestamp_ms = f.get(&1).and_then(|b| read_varint_from_bytes(b)).unwrap_or(0) as i64;

    // Pick the first present subfield that we know about.
    if let Some(b) = f.get(&3) {
        // contactAction (3): firstName(1) fullName(2) lidJid(5) pnJid(12?)...
        let id = index.get(1).cloned().unwrap_or_default();
        let cf = parse_proto_fields(b)?;
        let first_name = cf.get(&1).and_then(|b| String::from_utf8(b.clone()).ok());
        let full_name  = cf.get(&2).and_then(|b| String::from_utf8(b.clone()).ok());
        let lid_jid    = cf.get(&5).and_then(|b| String::from_utf8(b.clone()).ok());
        let pn_jid     = cf.get(&12).and_then(|b| String::from_utf8(b.clone()).ok());
        return Some(DecodedAction {
            action: SyncAction::Contact { id, full_name, first_name, lid_jid, pn_jid },
            timestamp_ms,
        });
    }
    if let Some(b) = f.get(&5) {
        // pinAction (5): pinned(1: bool)
        let cf = parse_proto_fields(b)?;
        let pinned = cf.get(&1).and_then(|b| read_varint_from_bytes(b)).unwrap_or(0) != 0;
        let jid = index.get(1).cloned().unwrap_or_default();
        return Some(DecodedAction { action: SyncAction::Pin { jid, pinned }, timestamp_ms });
    }
    if let Some(b) = f.get(&4) {
        // muteAction (4): muted(1: bool), muteEndTimestamp(2)
        let cf = parse_proto_fields(b)?;
        let until_ts_ms = cf.get(&2).and_then(|b| read_varint_from_bytes(b)).unwrap_or(0) as i64;
        let jid = index.get(1).cloned().unwrap_or_default();
        return Some(DecodedAction { action: SyncAction::Mute { jid, until_ts_ms }, timestamp_ms });
    }
    if let Some(b) = f.get(&17) {
        // archiveChatAction (17): archived(1: bool)
        let cf = parse_proto_fields(b)?;
        let archived = cf.get(&1).and_then(|b| read_varint_from_bytes(b)).unwrap_or(0) != 0;
        let jid = index.get(1).cloned().unwrap_or_default();
        return Some(DecodedAction { action: SyncAction::Archive { jid, archived }, timestamp_ms });
    }
    if let Some(b) = f.get(&20) {
        // markChatAsReadAction (20): read(1: bool)
        let cf = parse_proto_fields(b)?;
        let read = cf.get(&1).and_then(|b| read_varint_from_bytes(b)).unwrap_or(0) != 0;
        let jid = index.get(1).cloned().unwrap_or_default();
        return Some(DecodedAction { action: SyncAction::MarkChatAsRead { jid, read }, timestamp_ms });
    }
    if let Some(_b) = f.get(&22) {
        // deleteChatAction (22): messageRange only — no payload we need here.
        let jid = index.get(1).cloned().unwrap_or_default();
        return Some(DecodedAction { action: SyncAction::DeleteChat { jid }, timestamp_ms });
    }
    if let Some(b) = f.get(&2) {
        // starAction (2): starred(1: bool). Index = ["star", jid, msgId, fromMe, participant]
        let cf = parse_proto_fields(b)?;
        let starred = cf.get(&1).and_then(|b| read_varint_from_bytes(b)).unwrap_or(0) != 0;
        let jid = index.get(1).cloned().unwrap_or_default();
        let message_id = index.get(2).cloned().unwrap_or_default();
        let from_me = matches!(index.get(3).map(|s| s.as_str()), Some("1"));
        return Some(DecodedAction {
            action: SyncAction::Star { jid, message_id, from_me, starred },
            timestamp_ms,
        });
    }

    // Unknown subfield — surface the field number.
    let first = f.keys().copied().find(|k| *k != 1).unwrap_or(0);
    Some(DecodedAction { action: SyncAction::Raw { field: first }, timestamp_ms })
}
