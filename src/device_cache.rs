//! Simple on-disk cache of recipient devices from usync, keyed by bare user JID.
//!
//! Usync queries are synchronous round-trips to the WhatsApp server and can
//! take 20+ s on a cold connect while the server drains offline messages.
//! For CLI use where one process handles a single `send` we'd rather hit the
//! cache on repeat sends to the same recipient. The cache entry is expired
//! after `TTL` so device-list changes (new linked device) still propagate.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Cache freshness in seconds — matches Baileys' default `USER_DEVICES_CACHE_TTL_MS = 5 min`.
const TTL_SECS: u64 = 300;

#[derive(Serialize, Deserialize, Default)]
struct CacheFile {
    entries: HashMap<String, Entry>,
}

#[derive(Serialize, Deserialize, Clone)]
struct Entry {
    devices: Vec<String>,
    stored_at: u64,
}

pub struct DeviceCache {
    path: PathBuf,
}

impl DeviceCache {
    pub fn new(base: &std::path::Path) -> Self {
        Self { path: base.join("device_cache.json") }
    }

    pub fn get(&self, user_jid: &str) -> Option<Vec<String>> {
        let file = self.load().ok()?;
        let entry = file.entries.get(user_jid)?;
        let now = now_secs();
        if now.saturating_sub(entry.stored_at) > TTL_SECS {
            return None;
        }
        Some(entry.devices.clone())
    }

    pub fn put(&self, user_jid: &str, devices: &[String]) {
        let mut file = self.load().unwrap_or_default();
        file.entries.insert(user_jid.to_string(), Entry {
            devices: devices.to_vec(),
            stored_at: now_secs(),
        });
        let _ = self.save(&file);
    }

    fn load(&self) -> Result<CacheFile> {
        let data = std::fs::read(&self.path)?;
        Ok(serde_json::from_slice(&data).unwrap_or_default())
    }

    fn save(&self, file: &CacheFile) -> Result<()> {
        let bytes = serde_json::to_vec(file)?;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.path, bytes)?;
        Ok(())
    }
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
