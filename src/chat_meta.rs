//! Per-chat metadata projected from app-state sync events.
//!
//! The app-state layer emits one [`SyncAction`] per change the user makes
//! on the phone — pin, mute, archive, lock, etc. This module folds those
//! events into a stable per-JID snapshot that agents can check before
//! replying:
//!
//! ```ignore
//! let meta = session.chat_meta(&ctx.msg.key.remote_jid);
//! if meta.is_muted_now() || meta.archived { return Response::Noop; }
//! ```
//!
//! Backed by a single JSON file so the view survives daemon restarts;
//! updated in-place as each SyncAction arrives.
//!
//! This is a projection, not a source of truth — whatsmeow/Baileys
//! handle the same way. Re-sync via history-sync rebuilds it.
//!
//! [`SyncAction`]: crate::app_state::SyncAction

use crate::app_state::SyncAction;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Everything we track per JID. Every field defaults to "unset / neutral"
/// so a chat we've never heard an app-state event for still returns a
/// sensible [`ChatMeta::default`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChatMeta {
    /// True if the chat is pinned to the top.
    #[serde(default)]
    pub pinned: bool,
    /// Unix-ms deadline. `0` = not muted; past = expired mute; future = active mute.
    /// Use [`Self::is_muted_now`] to check without doing your own clock math.
    #[serde(default)]
    pub muted_until_ms: i64,
    /// True if archived.
    #[serde(default)]
    pub archived: bool,
    /// True if the chat-lock (biometric) is on.
    #[serde(default)]
    pub locked: bool,
    /// True if the chat has been manually marked unread.
    #[serde(default)]
    pub marked_unread: bool,
    /// Sorted list of label ids currently attached to this chat.
    #[serde(default)]
    pub labels: Vec<String>,
}

impl ChatMeta {
    /// True if the chat is muted right now (mute deadline is in the future).
    pub fn is_muted_now(&self) -> bool {
        if self.muted_until_ms == 0 { return false; }
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis()).unwrap_or(0) as i64;
        self.muted_until_ms > now_ms
    }

    /// `true` when an agent should probably stay quiet: archived, locked,
    /// or currently muted.
    pub fn agent_should_skip(&self) -> bool {
        self.archived || self.locked || self.is_muted_now()
    }
}

/// Thread-safe index of `JID → ChatMeta`, persisted to one JSON file.
pub struct ChatMetaStore {
    path: PathBuf,
    inner: Mutex<HashMap<String, ChatMeta>>,
}

impl ChatMetaStore {
    /// Load the JSON file at `<base>/chat_meta.json` (empty if missing or corrupt).
    pub fn new(base: &Path) -> std::io::Result<Self> {
        let path = base.join("chat_meta.json");
        let inner: HashMap<String, ChatMeta> = std::fs::read(&path).ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        Ok(Self { path, inner: Mutex::new(inner) })
    }

    /// Read-only snapshot for one JID; returns `ChatMeta::default()` if unknown.
    pub fn get(&self, jid: &str) -> ChatMeta {
        self.inner.lock().unwrap().get(jid).cloned().unwrap_or_default()
    }

    /// Apply one SyncAction and persist the change. No-op for actions that
    /// don't affect chat metadata (Contact renames, Star, label edits, etc.).
    pub fn apply(&self, action: &SyncAction) {
        let mut changed = false;
        {
            let mut map = self.inner.lock().unwrap();
            match action {
                SyncAction::Pin { jid, pinned } => {
                    map.entry(jid.clone()).or_default().pinned = *pinned;
                    changed = true;
                }
                SyncAction::Mute { jid, until_ts_ms } => {
                    map.entry(jid.clone()).or_default().muted_until_ms = *until_ts_ms;
                    changed = true;
                }
                SyncAction::Archive { jid, archived } => {
                    map.entry(jid.clone()).or_default().archived = *archived;
                    changed = true;
                }
                SyncAction::MarkChatAsRead { jid, read } => {
                    map.entry(jid.clone()).or_default().marked_unread = !*read;
                    changed = true;
                }
                SyncAction::LockChat { jid, locked } => {
                    map.entry(jid.clone()).or_default().locked = *locked;
                    changed = true;
                }
                SyncAction::DeleteChat { jid } | SyncAction::ClearChat { jid } => {
                    // Wipe to default but keep the entry so future events
                    // update cleanly. Alternative: map.remove(jid) — either
                    // works since get() falls back to default anyway.
                    map.insert(jid.clone(), ChatMeta::default());
                    changed = true;
                }
                SyncAction::LabelAssociation { label_id, jid, labeled } => {
                    let entry = map.entry(jid.clone()).or_default();
                    let present = entry.labels.iter().any(|l| l == label_id);
                    if *labeled && !present {
                        entry.labels.push(label_id.clone());
                        entry.labels.sort();
                        changed = true;
                    } else if !*labeled && present {
                        entry.labels.retain(|l| l != label_id);
                        changed = true;
                    }
                }
                _ => {}
            }
        }
        if changed { self.flush(); }
    }

    /// Snapshot of every known entry — for debugging / CLI dumps.
    pub fn snapshot(&self) -> HashMap<String, ChatMeta> {
        self.inner.lock().unwrap().clone()
    }

    fn flush(&self) {
        let map = self.inner.lock().unwrap().clone();
        let tmp = self.path.with_extension("json.tmp");
        if let Ok(bytes) = serde_json::to_vec_pretty(&map) {
            if std::fs::write(&tmp, &bytes).is_ok() {
                let _ = std::fs::rename(&tmp, &self.path);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir() -> PathBuf {
        let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            .unwrap().subsec_nanos();
        let d = std::env::temp_dir().join(format!("wa-chatmeta-{n:x}"));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn pin_mute_archive_roundtrip() {
        let store = ChatMetaStore::new(&tmp_dir()).unwrap();
        store.apply(&SyncAction::Pin { jid: "a@s".into(), pinned: true });
        store.apply(&SyncAction::Mute { jid: "a@s".into(), until_ts_ms: 9_999_999_999_999 });
        store.apply(&SyncAction::Archive { jid: "a@s".into(), archived: true });
        let m = store.get("a@s");
        assert!(m.pinned && m.archived && m.is_muted_now());
        assert!(m.agent_should_skip());
    }

    #[test]
    fn unset_returns_default() {
        let store = ChatMetaStore::new(&tmp_dir()).unwrap();
        let m = store.get("unknown@s");
        assert!(!m.pinned && !m.archived && !m.locked && m.muted_until_ms == 0);
        assert!(!m.is_muted_now());
        assert!(!m.agent_should_skip());
    }

    #[test]
    fn label_add_remove() {
        let store = ChatMetaStore::new(&tmp_dir()).unwrap();
        store.apply(&SyncAction::LabelAssociation { label_id: "1".into(), jid: "a@s".into(), labeled: true });
        store.apply(&SyncAction::LabelAssociation { label_id: "2".into(), jid: "a@s".into(), labeled: true });
        store.apply(&SyncAction::LabelAssociation { label_id: "1".into(), jid: "a@s".into(), labeled: false });
        assert_eq!(store.get("a@s").labels, vec!["2".to_string()]);
    }

    #[test]
    fn delete_clears_entry() {
        let store = ChatMetaStore::new(&tmp_dir()).unwrap();
        store.apply(&SyncAction::Pin { jid: "a@s".into(), pinned: true });
        store.apply(&SyncAction::DeleteChat { jid: "a@s".into() });
        assert!(!store.get("a@s").pinned);
    }

    #[test]
    fn expired_mute_not_muted_now() {
        let store = ChatMetaStore::new(&tmp_dir()).unwrap();
        store.apply(&SyncAction::Mute { jid: "a@s".into(), until_ts_ms: 1 }); // 1970
        assert!(!store.get("a@s").is_muted_now());
    }

    #[test]
    fn persists_across_reloads() {
        let dir = tmp_dir();
        {
            let store = ChatMetaStore::new(&dir).unwrap();
            store.apply(&SyncAction::Pin { jid: "a@s".into(), pinned: true });
        }
        let store = ChatMetaStore::new(&dir).unwrap();
        assert!(store.get("a@s").pinned);
    }
}
