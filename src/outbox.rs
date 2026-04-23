use crate::messages::WAMessage;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[derive(Serialize, Deserialize, Clone)]
struct OutboxEntry {
    jid: String,
    message: WAMessage,
    /// Unix nanoseconds of the first push attempt. Used for ordering and
    /// for TTL expiry — a stuck message (bad JID, encryption mismatch) would
    /// otherwise retry on every reconnect forever.
    created_at: u64,
    /// Retry counter bumped each time the reconnect loop re-sends this.
    /// Dropped when attempts exceed the cap (default 5) so a poisoned
    /// entry can't block the queue indefinitely.
    #[serde(default)]
    attempts: u32,
}

/// Max retry attempts before we give up on an outbox entry.
const MAX_ATTEMPTS: u32 = 5;
/// Entries older than this (unix nanoseconds worth of seconds) are dropped
/// on next inspection — stale messages are almost never still useful.
const MAX_AGE_SECS: u64 = 24 * 3600;

/// Persists outgoing messages that have not yet been ACK'd by the server.
///
/// On reconnect, call `pending()` to get the list and retry.
/// Messages are removed when the socket write succeeds; if the socket drops
/// before the write completes they remain and are retried automatically.
pub struct OutboxStore {
    path: PathBuf,
    entries: Mutex<HashMap<String, OutboxEntry>>,
}

impl OutboxStore {
    pub fn new(base: &Path) -> std::io::Result<Self> {
        let path = base.join("outbox.jsonl");
        let entries = if path.exists() {
            std::fs::read_to_string(&path)
                .unwrap_or_default()
                .lines()
                .filter_map(|l| serde_json::from_str::<OutboxEntry>(l).ok())
                .map(|e| (e.message.key.id.clone(), e))
                .collect()
        } else {
            HashMap::new()
        };
        Ok(Self { path, entries: Mutex::new(entries) })
    }

    /// Add a message to the outbox before sending.
    pub fn push(&self, jid: &str, msg: &WAMessage) {
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let entry = OutboxEntry {
            jid: jid.to_string(), message: msg.clone(), created_at, attempts: 0,
        };
        let mut guard = self.entries.lock().unwrap();
        guard.insert(msg.key.id.clone(), entry);
        Self::write_file(&self.path, &guard);
    }

    /// Bump the attempt counter on an existing entry. Returns `true` if
    /// the entry stayed under the cap (caller should retry); `false` if
    /// the cap was hit and the entry was dropped.
    pub fn record_attempt(&self, id: &str) -> bool {
        let mut guard = self.entries.lock().unwrap();
        let Some(entry) = guard.get_mut(id) else { return false; };
        entry.attempts += 1;
        if entry.attempts > MAX_ATTEMPTS {
            guard.remove(id);
            Self::write_file(&self.path, &guard);
            return false;
        }
        Self::write_file(&self.path, &guard);
        true
    }

    /// Drop every entry older than [`MAX_AGE_SECS`]. Returns the number
    /// removed so the daemon can log a summary on startup.
    pub fn purge_expired(&self) -> usize {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let cutoff_ns = now_secs.saturating_sub(MAX_AGE_SECS) as u128 * 1_000_000_000;
        let mut guard = self.entries.lock().unwrap();
        let before = guard.len();
        guard.retain(|_, e| (e.created_at as u128) >= cutoff_ns);
        let removed = before - guard.len();
        if removed > 0 { Self::write_file(&self.path, &guard); }
        removed
    }

    /// Count of pending entries — for metrics + `whatsapp-rs outbox` CLI.
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool { self.len() == 0 }

    /// Remove a message from the outbox (called after socket write succeeds).
    pub fn remove(&self, id: &str) {
        let mut guard = self.entries.lock().unwrap();
        if guard.remove(id).is_some() {
            Self::write_file(&self.path, &guard);
        }
    }

    /// All pending (jid, message) pairs — used by reconnect retry logic.
    pub fn pending(&self) -> Vec<(String, WAMessage)> {
        let guard = self.entries.lock().unwrap();
        let mut items: Vec<_> = guard.values()
            .map(|e| (e.jid.clone(), e.message.clone(), e.created_at))
            .collect();
        items.sort_by_key(|(_, _, ts)| *ts);
        items.into_iter().map(|(jid, msg, _)| (jid, msg)).collect()
    }

    fn write_file(path: &Path, entries: &HashMap<String, OutboxEntry>) {
        let mut items: Vec<_> = entries.values().collect();
        items.sort_by_key(|e| e.created_at);
        let content: String = items.iter()
            .filter_map(|e| serde_json::to_string(e).ok())
            .collect::<Vec<_>>()
            .join("\n");
        let content = if content.is_empty() { String::new() } else { content + "\n" };
        let _ = std::fs::write(path, content);
    }
}
