/// In-memory LRU of last ~256 outgoing messages, keyed by `(remote_jid, msg_id)`.
///
/// Used to answer incoming `<receipt type="retry">` from peer devices that
/// never received our original send (new device added post-send, session
/// corruption, queue drop). Mirrors whatsmeow's `recentMessagesMap` ring.
use crate::messages::WAMessage;
use std::collections::HashMap;
use std::sync::Mutex;

const CAPACITY: usize = 256;

type Key = (String, String);

pub struct RecentSends {
    inner: Mutex<Inner>,
}

struct Inner {
    map: HashMap<Key, WAMessage>,
    ring: Vec<Option<Key>>,
    ptr: usize,
}

impl RecentSends {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                map: HashMap::with_capacity(CAPACITY),
                ring: vec![None; CAPACITY],
                ptr: 0,
            }),
        }
    }

    pub fn insert(&self, jid: &str, id: &str, msg: WAMessage) {
        let Ok(mut inner) = self.inner.lock() else { return };
        let key = (jid.to_string(), id.to_string());
        let ptr = inner.ptr;
        if let Some(old) = inner.ring[ptr].take() {
            inner.map.remove(&old);
        }
        inner.map.insert(key.clone(), msg);
        inner.ring[ptr] = Some(key);
        inner.ptr = (ptr + 1) % CAPACITY;
    }

    pub fn get(&self, jid: &str, id: &str) -> Option<WAMessage> {
        let inner = self.inner.lock().ok()?;
        inner.map.get(&(jid.to_string(), id.to_string())).cloned()
    }
}

impl Default for RecentSends {
    fn default() -> Self { Self::new() }
}
