/// Persistent message store — saves received/sent messages per JID.
///
/// Stored as `~/.whatsapp-rs/messages/<jid-safe>.jsonl` — one JSON line per message.
/// Capped at MAX_PER_CHAT most-recent entries per chat to bound disk use.
use crate::messages::{MediaInfo, MessageContent, MessageStatus, WAMessage};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::collections::{HashMap, HashSet};

const MAX_PER_CHAT: usize = 500;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredMessage {
    pub id: String,
    pub remote_jid: String,
    pub from_me: bool,
    pub participant: Option<String>,
    pub timestamp: u64,
    pub push_name: Option<String>,
    pub text: Option<String>,
    pub media_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_info: Option<MediaInfo>,
    pub status: MessageStatus,
}

impl StoredMessage {
    pub fn from_wa(msg: &WAMessage) -> Self {
        let text = match &msg.message {
            Some(MessageContent::Text { text, .. }) => Some(text.clone()),
            Some(MessageContent::Reply { text, .. }) => Some(text.clone()),
            Some(MessageContent::LinkPreview { text, .. }) => Some(text.clone()),
            _ => None,
        };
        let media_type = match &msg.message {
            Some(MessageContent::Image { .. })    => Some("image".to_string()),
            Some(MessageContent::Video { .. })    => Some("video".to_string()),
            Some(MessageContent::Audio { .. })    => Some("audio".to_string()),
            Some(MessageContent::Document { .. }) => Some("document".to_string()),
            Some(MessageContent::Sticker { .. })  => Some("sticker".to_string()),
            Some(MessageContent::Poll { question, .. }) => Some(format!("poll:{question}")),
            _ => None,
        };
        let media_info = match &msg.message {
            Some(MessageContent::Image { info, .. })    => Some(info.clone()),
            Some(MessageContent::Video { info, .. })    => Some(info.clone()),
            Some(MessageContent::Audio { info })        => Some(info.clone()),
            Some(MessageContent::Document { info, .. }) => Some(info.clone()),
            Some(MessageContent::Sticker { info })      => Some(info.clone()),
            _ => None,
        };
        Self {
            id: msg.key.id.clone(),
            remote_jid: msg.key.remote_jid.clone(),
            from_me: msg.key.from_me,
            participant: msg.key.participant.clone(),
            timestamp: msg.message_timestamp,
            push_name: msg.push_name.clone(),
            text,
            media_type,
            media_info,
            status: msg.status,
        }
    }
}

pub struct MessageStore {
    dir: PathBuf,
    // In-memory ring buffer per JID: jid → Vec<StoredMessage> (oldest first)
    cache: Mutex<HashMap<String, Vec<StoredMessage>>>,
    // JIDs that have in-memory status changes not yet flushed to disk
    dirty: Mutex<HashSet<String>>,
}

impl MessageStore {
    pub fn new(data_dir: &Path) -> Result<Self> {
        let dir = data_dir.join("messages");
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir, cache: Mutex::new(HashMap::new()), dirty: Mutex::new(HashSet::new()) })
    }

    /// Append a message. Returns `true` if stored (not a duplicate).
    pub fn push(&self, msg: &WAMessage) -> bool {
        let jid = &msg.key.remote_jid;
        let stored = StoredMessage::from_wa(msg);
        let mut cache = self.cache.lock().unwrap();
        let entries = cache.entry(jid.clone()).or_default();

        // Skip duplicates
        if entries.iter().any(|e| e.id == stored.id) {
            return false;
        }

        // Append line to JSONL file
        let path = self.chat_path(jid);
        if let Ok(line) = serde_json::to_string(&stored) {
            let _ = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .and_then(|mut f| {
                    use std::io::Write;
                    writeln!(f, "{line}")
                });
        }

        entries.push(stored);
        // Cap in-memory cache
        if entries.len() > MAX_PER_CHAT {
            let excess = entries.len() - MAX_PER_CHAT;
            entries.drain(0..excess);
        }
        true
    }

    /// Last `n` messages for a JID (most-recent last). Loads from disk on first access.
    pub fn recent(&self, jid: &str, n: usize) -> Vec<StoredMessage> {
        let mut cache = self.cache.lock().unwrap();
        if !cache.contains_key(jid) {
            let msgs = self.load_from_disk(jid);
            cache.insert(jid.to_string(), msgs);
        }
        let entries = cache.get(jid).map(|v| v.as_slice()).unwrap_or(&[]);
        let start = entries.len().saturating_sub(n);
        entries[start..].to_vec()
    }

    /// Look up a single message by JID + message ID.
    pub fn lookup(&self, jid: &str, msg_id: &str) -> Option<StoredMessage> {
        let mut cache = self.cache.lock().unwrap();
        if !cache.contains_key(jid) {
            let msgs = self.load_from_disk(jid);
            cache.insert(jid.to_string(), msgs);
        }
        cache.get(jid)?.iter().rev().find(|m| m.id == msg_id).cloned()
    }

    #[allow(dead_code)]
    pub fn known_jids(&self) -> Vec<String> {
        let Ok(rd) = std::fs::read_dir(&self.dir) else { return vec![] };
        rd.filter_map(|e| {
            let name = e.ok()?.file_name().to_string_lossy().to_string();
            if name.ends_with(".jsonl") {
                Some(jid_from_filename(&name))
            } else {
                None
            }
        })
        .collect()
    }

    /// Update the delivery/read status of a stored message.
    /// Only mutates in-memory cache. Call `flush_dirty()` to persist.
    pub fn update_status(&self, jid: &str, msg_id: &str, status: MessageStatus) {
        let mut cache = self.cache.lock().unwrap();
        if !cache.contains_key(jid) {
            let msgs = self.load_from_disk(jid);
            cache.insert(jid.to_string(), msgs);
        }
        if let Some(entries) = cache.get_mut(jid) {
            if let Some(m) = entries.iter_mut().find(|e| e.id == msg_id) {
                if m.status != status {
                    m.status = status;
                    self.dirty.lock().unwrap().insert(jid.to_string());
                }
            }
        }
    }

    /// Flush all in-memory status changes to disk (rewrite dirty JSONL files).
    /// Call after processing a batch of receipts.
    pub fn flush_dirty(&self) {
        let dirty: Vec<String> = {
            let mut d = self.dirty.lock().unwrap();
            d.drain().collect()
        };
        if dirty.is_empty() {
            return;
        }
        let cache = self.cache.lock().unwrap();
        for jid in &dirty {
            if let Some(entries) = cache.get(jid.as_str()) {
                let path = self.chat_path(jid);
                Self::rewrite_file(&path, entries);
            }
        }
    }

    fn rewrite_file(path: &PathBuf, entries: &[StoredMessage]) {
        let mut out = String::new();
        for m in entries {
            if let Ok(line) = serde_json::to_string(m) {
                out.push_str(&line);
                out.push('\n');
            }
        }
        let _ = std::fs::write(path, out);
    }

    fn chat_path(&self, jid: &str) -> PathBuf {
        self.dir.join(format!("{}.jsonl", jid_to_filename(jid)))
    }

    fn load_from_disk(&self, jid: &str) -> Vec<StoredMessage> {
        let path = self.chat_path(jid);
        let Ok(content) = std::fs::read_to_string(&path) else { return vec![] };
        let mut msgs: Vec<StoredMessage> = content
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();
        // Keep only the last MAX_PER_CHAT
        if msgs.len() > MAX_PER_CHAT {
            let excess = msgs.len() - MAX_PER_CHAT;
            msgs.drain(0..excess);
        }
        msgs
    }
}

/// Sanitize a JID for use as a filename component.
fn jid_to_filename(jid: &str) -> String {
    jid.replace('@', "_at_").replace('/', "_sl_")
}

#[allow(dead_code)]
fn jid_from_filename(name: &str) -> String {
    name.trim_end_matches(".jsonl")
        .replace("_at_", "@")
        .replace("_sl_", "/")
        .to_string()
}
