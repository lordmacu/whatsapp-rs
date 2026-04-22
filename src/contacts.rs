/// Contact name cache — maps JID → display name.
///
/// Populated automatically from:
/// - `notify` attr on incoming messages (`push_name`)
/// - `HistorySync::push_names`
/// - usync `resolve_contacts` results
use anyhow::Result;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

pub struct ContactStore {
    names: Mutex<HashMap<String, String>>,
    path: PathBuf,
}

impl ContactStore {
    pub fn new(data_dir: &std::path::Path) -> Result<Self> {
        let path = data_dir.join("contacts.json");
        let names = if path.exists() {
            let raw = std::fs::read_to_string(&path)?;
            serde_json::from_str::<HashMap<String, String>>(&raw).unwrap_or_default()
        } else {
            HashMap::new()
        };
        Ok(Self { names: Mutex::new(names), path })
    }

    /// Insert or update a name. Returns `true` if the value changed.
    pub fn upsert(&self, jid: &str, name: &str) -> bool {
        if name.is_empty() { return false; }
        let mut map = self.names.lock().unwrap();
        let old = map.insert(jid.to_string(), name.to_string());
        old.as_deref() != Some(name)
    }

    pub fn get(&self, jid: &str) -> Option<String> {
        self.names.lock().unwrap().get(jid).cloned()
    }

    /// All known contacts as a snapshot.
    pub fn snapshot(&self) -> HashMap<String, String> {
        self.names.lock().unwrap().clone()
    }

    /// Persist to disk (best-effort, ignores errors).
    pub fn save(&self) {
        let map = self.names.lock().unwrap();
        if let Ok(json) = serde_json::to_string(&*map) {
            let _ = std::fs::write(&self.path, json);
        }
    }

    /// Bulk-upsert from a slice of `(jid, name)` pairs.
    pub fn bulk_upsert(&self, entries: &[(String, String)]) {
        let mut map = self.names.lock().unwrap();
        for (jid, name) in entries {
            if !name.is_empty() {
                map.insert(jid.clone(), name.clone());
            }
        }
    }
}
