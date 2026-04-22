/// Stores the `encKey` for each sent poll so we can decrypt incoming votes.
///
/// PollCreationMessage embeds a random 32-byte `encKey` (field 1).
/// Each vote is HMAC'd with that key — without it vote decryption is impossible.
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Entry {
    enc_key: Vec<u8>,   // 32 bytes
    question: String,
    options: Vec<String>,
}

pub struct PollStore {
    path: PathBuf,
    polls: Mutex<HashMap<String, Entry>>,  // msg_id → Entry
}

impl PollStore {
    pub fn new(data_dir: &Path) -> Result<Self> {
        let path = data_dir.join("polls.json");
        let polls = if path.exists() {
            let raw = std::fs::read_to_string(&path)?;
            serde_json::from_str(&raw).unwrap_or_default()
        } else {
            HashMap::new()
        };
        Ok(Self { path, polls: Mutex::new(polls) })
    }

    /// Store the encKey for a poll we just sent.
    pub fn register(&self, msg_id: &str, enc_key: Vec<u8>, question: &str, options: &[String]) {
        let mut polls = self.polls.lock().unwrap();
        polls.insert(msg_id.to_string(), Entry {
            enc_key,
            question: question.to_string(),
            options: options.to_vec(),
        });
        self.save_locked(&polls);
    }

    /// Retrieve the encKey for a poll by its message ID.
    pub fn enc_key(&self, msg_id: &str) -> Option<Vec<u8>> {
        self.polls.lock().unwrap().get(msg_id).map(|e| e.enc_key.clone())
    }

    /// Retrieve question and option names for a poll.
    pub fn meta(&self, msg_id: &str) -> Option<(String, Vec<String>)> {
        self.polls.lock().unwrap()
            .get(msg_id)
            .map(|e| (e.question.clone(), e.options.clone()))
    }

    fn save_locked(&self, polls: &HashMap<String, Entry>) {
        if let Ok(json) = serde_json::to_string(polls) {
            let _ = std::fs::write(&self.path, json);
        }
    }
}
