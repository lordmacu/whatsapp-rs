//! Per-collection persistent state (LT-Hash + version + indexValueMap).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use super::lt_hash::HASH_LEN;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CollectionState {
    pub version: u64,
    /// 128-byte LT-Hash digest (hex-encoded for JSON).
    #[serde(with = "hex_128")]
    pub hash: [u8; HASH_LEN],
    /// base64(indexMac) → base64(valueMac). Needed to REMOVE old mutations later.
    pub index_value_map: HashMap<String, String>,
}

impl Default for CollectionState {
    fn default() -> Self {
        Self { version: 0, hash: [0u8; HASH_LEN], index_value_map: HashMap::new() }
    }
}

pub struct CollectionStore {
    dir: PathBuf,
    cache: RwLock<HashMap<String, CollectionState>>,
}

impl CollectionStore {
    pub fn new(data_dir: &std::path::Path) -> Result<Arc<Self>> {
        let dir = data_dir.join("app-state");
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("mkdir {}", dir.display()))?;
        Ok(Arc::new(Self { dir, cache: RwLock::new(HashMap::new()) }))
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}.json"))
    }

    pub fn load(&self, name: &str) -> CollectionState {
        if let Some(s) = self.cache.read().unwrap().get(name).cloned() {
            return s;
        }
        let p = self.path(name);
        if !p.exists() { return CollectionState::default(); }
        let s = std::fs::read_to_string(&p).unwrap_or_default();
        let parsed: CollectionState = serde_json::from_str(&s).unwrap_or_default();
        self.cache.write().unwrap().insert(name.to_string(), parsed.clone());
        parsed
    }

    pub fn save(&self, name: &str, state: &CollectionState) -> Result<()> {
        self.cache.write().unwrap().insert(name.to_string(), state.clone());
        let s = serde_json::to_string_pretty(state)?;
        std::fs::write(self.path(name), s)?;
        Ok(())
    }

    /// Drop all state for a collection — forces the next resync to request a snapshot.
    pub fn reset(&self, name: &str) {
        self.cache.write().unwrap().remove(name);
        let _ = std::fs::remove_file(self.path(name));
    }
}

// ── hex serializer for 128-byte array (serde_json can't handle [u8;128]) ──

mod hex_128 {
    use super::HASH_LEN;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; HASH_LEN], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; HASH_LEN], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if v.len() != HASH_LEN {
            return Err(serde::de::Error::custom(format!("bad length {}", v.len())));
        }
        let mut out = [0u8; HASH_LEN];
        out.copy_from_slice(&v);
        Ok(out)
    }
}
