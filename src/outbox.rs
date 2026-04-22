use crate::messages::WAMessage;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[derive(Serialize, Deserialize, Clone)]
struct OutboxEntry {
    jid: String,
    message: WAMessage,
    created_at: u64,
}

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
        let entry = OutboxEntry { jid: jid.to_string(), message: msg.clone(), created_at };
        let mut guard = self.entries.lock().unwrap();
        guard.insert(msg.key.id.clone(), entry);
        Self::write_file(&self.path, &guard);
    }

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
