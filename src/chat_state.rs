//! Per-JID persistent state for agents that need to remember where a
//! conversation is: step in a form wizard, cached user profile, hit count,
//! booking in progress, whatever. Backed by one JSON file per JID so it
//! survives restarts without a database.
//!
//! ```ignore
//! use serde::{Serialize, Deserialize};
//! use whatsapp_rs::chat_state::StateStore;
//!
//! #[derive(Default, Serialize, Deserialize)]
//! struct MyState { turn: u32, pending_step: Option<String> }
//!
//! let state: StateStore<MyState> = StateStore::open("agent-state")?;
//!
//! session.run_agent(move |ctx| {
//!     let state = state.clone();
//!     async move {
//!         let s = state.update(ctx.jid(), |s| { s.turn += 1; });
//!         Response::reply(format!("turn {}: {:?}", s.turn, ctx.text))
//!     }
//! }).await?;
//! ```
//!
//! Concurrency: a per-JID mutex guards reads / writes within a single
//! process. Cross-process sharing isn't supported — run one agent per state
//! directory.

use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashMap;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Typed per-JID state store. Cheap to clone — internal `Arc`.
pub struct StateStore<T> {
    inner: Arc<Inner>,
    _marker: PhantomData<T>,
}

struct Inner {
    dir: PathBuf,
    /// Per-JID lock so two handler invocations for the same chat serialize.
    /// Within one process only; across processes, nothing stops write
    /// races — don't run two agents against the same dir.
    locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
}

impl<T> Clone for StateStore<T> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone(), _marker: PhantomData }
    }
}

impl<T> StateStore<T>
where
    T: Serialize + DeserializeOwned + Default,
{
    /// Open (and create if missing) a directory for state files.
    pub fn open(dir: impl Into<PathBuf>) -> std::io::Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        Ok(Self {
            inner: Arc::new(Inner { dir, locks: Mutex::new(HashMap::new()) }),
            _marker: PhantomData,
        })
    }

    /// Read the current state for `jid`. Returns `T::default()` if no file
    /// exists yet or the file is corrupt.
    pub fn get(&self, jid: &str) -> T {
        let lock = self.lock_for(jid);
        let _g = lock.lock().unwrap();
        self.read(jid).unwrap_or_default()
    }

    /// Atomic read-modify-write. The closure mutates the state; the new
    /// value is written back to disk before returning. Returns the
    /// post-update value for convenience.
    pub fn update(&self, jid: &str, f: impl FnOnce(&mut T)) -> T {
        let lock = self.lock_for(jid);
        let _g = lock.lock().unwrap();
        let mut state = self.read(jid).unwrap_or_default();
        f(&mut state);
        self.write(jid, &state);
        state
    }

    /// Overwrite the state for `jid`.
    pub fn set(&self, jid: &str, value: &T) {
        let lock = self.lock_for(jid);
        let _g = lock.lock().unwrap();
        self.write(jid, value);
    }

    /// Delete the state file for `jid`. No-op if missing.
    pub fn clear(&self, jid: &str) {
        let lock = self.lock_for(jid);
        let _g = lock.lock().unwrap();
        let _ = std::fs::remove_file(self.path(jid));
    }

    // ── internals ─────────────────────────────────────────────────────────────

    fn lock_for(&self, jid: &str) -> Arc<Mutex<()>> {
        let mut locks = self.inner.locks.lock().unwrap();
        locks.entry(jid.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    fn path(&self, jid: &str) -> PathBuf {
        // Slashes / colons in jids are valid but ugly as filenames. Replace
        // with `_` so we get stable `573XXX@s.whatsapp.net` on every FS.
        let safe: String = jid.chars().map(|c| match c {
            '/' | ':' | '\\' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            other => other,
        }).collect();
        self.inner.dir.join(format!("{safe}.json"))
    }

    fn read(&self, jid: &str) -> Option<T> {
        let path = self.path(jid);
        let bytes = std::fs::read(&path).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    fn write(&self, jid: &str, value: &T) {
        let path = self.path(jid);
        let tmp = path.with_extension("json.tmp");
        if let Ok(bytes) = serde_json::to_vec_pretty(value) {
            if std::fs::write(&tmp, &bytes).is_ok() {
                let _ = std::fs::rename(&tmp, &path);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Default, Serialize, Deserialize, Debug, PartialEq)]
    struct Counter { n: u32, label: Option<String> }

    fn tmp_dir() -> PathBuf {
        let base = std::env::temp_dir().join(format!("wa-state-test-{}", rand_suffix()));
        let _ = std::fs::remove_dir_all(&base);
        base
    }

    fn rand_suffix() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos();
        format!("{nanos:x}")
    }

    #[test]
    fn get_returns_default_for_missing() {
        let s: StateStore<Counter> = StateStore::open(tmp_dir()).unwrap();
        assert_eq!(s.get("jid1"), Counter::default());
    }

    #[test]
    fn update_persists() {
        let dir = tmp_dir();
        {
            let s: StateStore<Counter> = StateStore::open(&dir).unwrap();
            s.update("jid1", |c| { c.n = 42; c.label = Some("hi".into()); });
        }
        let s2: StateStore<Counter> = StateStore::open(&dir).unwrap();
        let c = s2.get("jid1");
        assert_eq!(c.n, 42);
        assert_eq!(c.label.as_deref(), Some("hi"));
    }

    #[test]
    fn per_jid_isolation() {
        let s: StateStore<Counter> = StateStore::open(tmp_dir()).unwrap();
        s.update("a@x", |c| c.n = 1);
        s.update("b@x", |c| c.n = 99);
        assert_eq!(s.get("a@x").n, 1);
        assert_eq!(s.get("b@x").n, 99);
    }

    #[test]
    fn clear_removes_file() {
        let s: StateStore<Counter> = StateStore::open(tmp_dir()).unwrap();
        s.update("j", |c| c.n = 7);
        s.clear("j");
        assert_eq!(s.get("j"), Counter::default());
    }

    #[test]
    fn device_suffix_jids_file_safely() {
        let s: StateStore<Counter> = StateStore::open(tmp_dir()).unwrap();
        s.update("573X:20@s.whatsapp.net", |c| c.n = 1);
        // Should read back cleanly — the colon in the filename is sanitized.
        assert_eq!(s.get("573X:20@s.whatsapp.net").n, 1);
    }
}
