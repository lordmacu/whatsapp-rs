//! Token-bucket rate limiter for outbound content messages.
//!
//! WA's abuse detection disconnects (and eventually bans) accounts that burst
//! messages too fast. For agent-style use where an LLM might decide to
//! dispatch a flurry of replies, we gate every content send through two
//! buckets — one global, one per-JID — so the library degrades to backpressure
//! instead of dropping the account.
//!
//! Ticks in pure wall-clock; no background task. Callers `await acquire()`
//! which returns once a token is available.
//!
//! Override the defaults via env vars: `WA_RATE_GLOBAL_PER_SEC`,
//! `WA_RATE_PER_JID_PER_SEC`. Values are tokens-per-second (float).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Default sustained rate: 1 msg / 500 ms globally, i.e. 2 per second.
/// Empirically safe across Baileys / whatsmeow deployments.
const DEFAULT_GLOBAL_RATE: f64 = 2.0;
const DEFAULT_GLOBAL_BURST: f64 = 10.0;

/// Default per-JID rate: 1 msg per 2 s per conversation. Agents replying
/// with long explanations shouldn't machine-gun a single chat.
const DEFAULT_PER_JID_RATE: f64 = 0.5;
const DEFAULT_PER_JID_BURST: f64 = 5.0;

#[derive(Debug, Clone)]
struct Bucket {
    tokens: f64,
    capacity: f64,
    rate_per_sec: f64,
    last_refill: Instant,
}

impl Bucket {
    fn new(rate_per_sec: f64, burst: f64) -> Self {
        Self { tokens: burst, capacity: burst, rate_per_sec, last_refill: Instant::now() }
    }

    /// Refill tokens up to capacity based on elapsed time since last refill.
    /// Returns how long to wait for 1 token to be available (zero if ready).
    fn try_consume(&mut self) -> Duration {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate_per_sec).min(self.capacity);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Duration::ZERO
        } else {
            let deficit = 1.0 - self.tokens;
            Duration::from_secs_f64(deficit / self.rate_per_sec)
        }
    }
}

pub struct RateLimiter {
    global: Mutex<Bucket>,
    per_jid: Mutex<HashMap<String, Bucket>>,
    per_jid_rate: f64,
    per_jid_burst: f64,
}

impl RateLimiter {
    pub fn new() -> Self {
        let global_rate = env_float("WA_RATE_GLOBAL_PER_SEC", DEFAULT_GLOBAL_RATE);
        let global_burst = env_float("WA_RATE_GLOBAL_BURST", DEFAULT_GLOBAL_BURST);
        let per_jid_rate = env_float("WA_RATE_PER_JID_PER_SEC", DEFAULT_PER_JID_RATE);
        let per_jid_burst = env_float("WA_RATE_PER_JID_BURST", DEFAULT_PER_JID_BURST);
        Self {
            global: Mutex::new(Bucket::new(global_rate, global_burst)),
            per_jid: Mutex::new(HashMap::new()),
            per_jid_rate,
            per_jid_burst,
        }
    }

    /// Block until a token is available from both the global bucket and the
    /// per-JID bucket. Safe to call from many tasks concurrently; each call
    /// consumes exactly one token from each.
    pub async fn acquire(&self, jid: &str) {
        loop {
            let wait_global = { self.global.lock().unwrap().try_consume() };
            if !wait_global.is_zero() {
                tokio::time::sleep(wait_global).await;
                continue;
            }
            let wait_jid = {
                let mut map = self.per_jid.lock().unwrap();
                let bucket = map.entry(jid.to_string())
                    .or_insert_with(|| Bucket::new(self.per_jid_rate, self.per_jid_burst));
                bucket.try_consume()
            };
            if wait_jid.is_zero() { return; }
            tokio::time::sleep(wait_jid).await;
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self { Self::new() }
}

/// Process-wide singleton — shared across every `Session` created via
/// the old code path. **Deprecated**: new code should pass a per-Session
/// `Arc<RateLimiter>` into `MessageManager` instead, so running multiple
/// WhatsApp accounts in the same process doesn't share one quota
/// pool. Kept for back-compat with `MessageManager::new` and external
/// users that haven't migrated.
#[deprecated(
    since = "0.2.0",
    note = "Use per-Session `Arc<RateLimiter>` via `MessageManager::with_rate_limiter` — this singleton leaks quota across accounts"
)]
pub fn global() -> &'static RateLimiter {
    use std::sync::OnceLock;
    static GLOBAL: OnceLock<RateLimiter> = OnceLock::new();
    GLOBAL.get_or_init(RateLimiter::new)
}

fn env_float(key: &str, default: f64) -> f64 {
    std::env::var(key).ok().and_then(|s| s.parse().ok()).unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_refills_over_time() {
        let mut b = Bucket::new(2.0, 5.0); // 2/s, burst 5
        for _ in 0..5 { assert!(b.try_consume().is_zero()); }
        // Next consume should ask to wait ~500 ms (1 token at 2/s).
        let wait = b.try_consume();
        assert!(wait >= Duration::from_millis(400) && wait <= Duration::from_millis(600));
    }

    #[test]
    fn bucket_caps_at_capacity() {
        let mut b = Bucket::new(10.0, 3.0);
        std::thread::sleep(Duration::from_millis(500));
        assert!(b.try_consume().is_zero());
        assert!(b.try_consume().is_zero());
        assert!(b.try_consume().is_zero());
        // Capacity is 3 — fourth needs to wait.
        assert!(!b.try_consume().is_zero());
    }

    /// Critical multi-account invariant: two separate `RateLimiter`s
    /// must not share tokens. Draining limiter A must leave limiter B
    /// fully stocked — otherwise running two accounts in one process
    /// would serialise their sends through a shared pool.
    ///
    /// We check this at the bucket level (no `acquire().await` so the
    /// test stays sync and doesn't depend on tokio time plumbing).
    /// Each RateLimiter owns its own `global` and `per_jid` mutexes,
    /// so two instances having disjoint state is the structural
    /// guarantee; we verify by exhausting A's global bucket and
    /// observing B's is still at full capacity.
    #[test]
    fn two_limiters_have_disjoint_state() {
        let a = RateLimiter::new();
        let b = RateLimiter::new();
        // Drain A's global bucket. Default burst = 10 → 10 instant
        // consumes, then a non-zero wait.
        let a_global = &a.global;
        for _ in 0..10 {
            assert!(a_global.lock().unwrap().try_consume().is_zero());
        }
        assert!(!a_global.lock().unwrap().try_consume().is_zero(),
            "A must be drained after burst");
        // B's global should still be full.
        let b_global = &b.global;
        for _ in 0..10 {
            assert!(b_global.lock().unwrap().try_consume().is_zero(),
                "B must still have its own full quota");
        }
    }
}
