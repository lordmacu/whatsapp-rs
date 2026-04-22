//! App-state sync key store.
//!
//! Keys are 32-byte blobs, one per `keyId` (arbitrary-length byte identifier,
//! typically 8 bytes). WhatsApp ships them to us via encrypted 1:1 messages
//! carrying a `ProtocolMessage.appStateSyncKeyShare` payload.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppStateSyncKey {
    /// Raw 32-byte `keyData`.
    pub key_data: Vec<u8>,
    /// Timestamp from the share message (ms since epoch). Zero if missing.
    #[serde(default)]
    pub timestamp: i64,
}

/// Persistent store: `keyId (hex) → AppStateSyncKey`.
pub struct AppStateKeyStore {
    path: PathBuf,
    map: RwLock<HashMap<String, AppStateSyncKey>>,
}

impl AppStateKeyStore {
    pub fn new(data_dir: &std::path::Path) -> Result<Arc<Self>> {
        let path = data_dir.join("app-state-keys.json");
        let map = if path.exists() {
            let s = std::fs::read_to_string(&path)
                .with_context(|| format!("read {}", path.display()))?;
            serde_json::from_str(&s).unwrap_or_default()
        } else {
            HashMap::new()
        };
        Ok(Arc::new(Self { path, map: RwLock::new(map) }))
    }

    pub fn put(&self, key_id: &[u8], key_data: Vec<u8>, timestamp: i64) {
        let id = hex::encode(key_id);
        self.map.write().unwrap().insert(id, AppStateSyncKey { key_data, timestamp });
        let _ = self.save();
    }

    pub fn get(&self, key_id: &[u8]) -> Option<AppStateSyncKey> {
        let id = hex::encode(key_id);
        self.map.read().unwrap().get(&id).cloned()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.map.read().unwrap().is_empty()
    }

    fn save(&self) -> Result<()> {
        let map = self.map.read().unwrap();
        let s = serde_json::to_string_pretty(&*map)?;
        std::fs::write(&self.path, s)?;
        Ok(())
    }
}
