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
        // Normalise the message id to lowercase: we send ids uppercase
        // (`3EB0…`) but WhatsApp echoes them lowercase (`3eb0…`) in
        // ack/receipt/retry stanzas — so cache + lookups must agree.
        let key = (jid.to_string(), id.to_ascii_lowercase());
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
        inner.map.get(&(jid.to_string(), id.to_ascii_lowercase())).cloned()
    }

    /// Look up a cached send by message id ALONE, regardless of the chat it was
    /// sent to. Needed for retry-receipts from our OWN devices (own-device
    /// fanout): the message was cached under the recipient's chat, but the retry
    /// arrives addressed from our own account — so the `(chat, id)` key misses.
    /// O(n) over ≤256 entries; only used as a fallback when `get` misses.
    pub fn get_by_id(&self, id: &str) -> Option<WAMessage> {
        let inner = self.inner.lock().ok()?;
        let id_lc = id.to_ascii_lowercase();
        inner
            .map
            .iter()
            .find(|((_, k_id), _)| *k_id == id_lc)
            .map(|(_, m)| m.clone())
    }
}

impl Default for RecentSends {
    fn default() -> Self { Self::new() }
}
