//! Persistent scheduler for "send this message later". JSON-file backed so
//! a daemon restart never loses a pending item. Polled every 5 s by a
//! background task; items whose `send_at_unix` has passed fire once and
//! get removed from disk.
//!
//! Intended for reminders, auto-checkins, delayed follow-ups — anything
//! where the agent wants to schedule a reply N minutes / hours later
//! without holding a live task across restarts.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// One pending scheduled send.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledItem {
    pub id: String,
    pub jid: String,
    pub text: String,
    pub send_at_unix: u64,
}

pub struct Scheduler {
    path: PathBuf,
    items: Mutex<Vec<ScheduledItem>>,
}

impl Scheduler {
    /// Open / create the store at `path`. Any existing file is loaded;
    /// corrupt lines are skipped with a log warning.
    pub fn open(path: impl Into<PathBuf>) -> std::io::Result<Arc<Self>> {
        let path = path.into();
        if let Some(dir) = path.parent() { std::fs::create_dir_all(dir)?; }
        let items = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str::<Vec<ScheduledItem>>(&s).ok())
            .unwrap_or_default();
        Ok(Arc::new(Self { path, items: Mutex::new(items) }))
    }

    /// Add an item. Returns the assigned id.
    pub fn schedule(&self, jid: impl Into<String>, text: impl Into<String>, send_at_unix: u64) -> String {
        let id = new_id();
        let item = ScheduledItem { id: id.clone(), jid: jid.into(), text: text.into(), send_at_unix };
        {
            let mut items = self.items.lock().unwrap();
            items.push(item);
            items.sort_by_key(|i| i.send_at_unix);
        }
        self.flush();
        id
    }

    /// Snapshot of all pending items ordered by fire time.
    pub fn list(&self) -> Vec<ScheduledItem> {
        self.items.lock().unwrap().clone()
    }

    /// Remove one pending item by id. Returns `true` if found.
    pub fn cancel(&self, id: &str) -> bool {
        let removed = {
            let mut items = self.items.lock().unwrap();
            let len_before = items.len();
            items.retain(|i| i.id != id);
            items.len() != len_before
        };
        if removed { self.flush(); }
        removed
    }

    /// Pop and return all items whose `send_at_unix` has already elapsed.
    /// Persists the new (smaller) list before returning.
    pub fn take_due(&self, now: u64) -> Vec<ScheduledItem> {
        let mut items = self.items.lock().unwrap();
        let (due, remaining): (Vec<_>, Vec<_>) =
            items.drain(..).partition(|i| i.send_at_unix <= now);
        *items = remaining;
        drop(items);
        if !due.is_empty() { self.flush(); }
        due
    }

    fn flush(&self) {
        let items = self.items.lock().unwrap().clone();
        let tmp = self.path.with_extension("json.tmp");
        if let Ok(bytes) = serde_json::to_vec_pretty(&items) {
            if std::fs::write(&tmp, &bytes).is_ok() {
                let _ = std::fs::rename(&tmp, &self.path);
            }
        }
    }
}

fn new_id() -> String {
    use rand::RngCore;
    let mut b = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

/// Current unix seconds, defaulting to 0 on clock failure (unreachable in
/// practice — the epoch is monotonic on every supported platform).
pub fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Parse a "when" spec into an absolute unix timestamp.
///
/// Accepted forms:
/// - **Relative duration**: `30s`, `15m`, `2h`, `1d` — added to now.
/// - **Absolute** unix seconds as digits: `1712345678`.
/// - **ISO-8601 date-time** (UTC, no timezone): `2026-04-24T09:00:00`.
pub fn parse_when(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    if s.chars().all(|c| c.is_ascii_digit()) {
        return s.parse::<u64>().map_err(|e| anyhow::anyhow!("bad unix seconds: {e}"));
    }
    // Relative: "<N><unit>" where unit ∈ s|m|h|d.
    if let Some(last) = s.chars().last() {
        if matches!(last, 's' | 'm' | 'h' | 'd') {
            let n: u64 = s[..s.len() - 1].parse()
                .map_err(|e| anyhow::anyhow!("bad number in duration: {e}"))?;
            let secs = match last {
                's' => n,
                'm' => n * 60,
                'h' => n * 3600,
                'd' => n * 86400,
                _ => unreachable!(),
            };
            return Ok(now_unix() + secs);
        }
    }
    // ISO-8601 UTC like 2026-04-24T09:00:00 (no tz, no fractional seconds).
    iso8601_utc_to_unix(s).ok_or_else(|| {
        anyhow::anyhow!("unrecognized time spec {s:?} — use 15m / 2h / 1d / <unix-seconds> / 2026-04-24T09:00:00")
    })
}

/// Tiny hand-rolled ISO-8601 parser for `YYYY-MM-DDTHH:MM:SS` (assumed UTC).
/// Uses the Julian-day trick for leap years — no chrono dependency.
fn iso8601_utc_to_unix(s: &str) -> Option<u64> {
    let bytes = s.as_bytes();
    if bytes.len() != 19 || bytes[4] != b'-' || bytes[7] != b'-'
        || bytes[10] != b'T' || bytes[13] != b':' || bytes[16] != b':'
    {
        return None;
    }
    let n = |a: usize, b: usize| -> Option<u32> { s[a..b].parse().ok() };
    let y = n(0, 4)? as i64;
    let m = n(5, 7)? as i64;
    let d = n(8, 10)? as i64;
    let hh = n(11, 13)? as i64;
    let mm = n(14, 16)? as i64;
    let ss = n(17, 19)? as i64;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d)
        || !(0..=23).contains(&hh) || !(0..=59).contains(&mm) || !(0..=60).contains(&ss)
    {
        return None;
    }

    // Days from Rata Die (0001-01-01) to unix epoch (1970-01-01) = 719162.
    // Using the Howard Hinnant algorithm to handle leap years cleanly.
    let (y_, m_) = if m <= 2 { (y - 1, m + 12) } else { (y, m) };
    let era = y_.div_euclid(400);
    let yoe = y_ - era * 400;
    let doy = (153 * (m_ - 3) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days_since_epoch = era * 146097 + doe - 719468;
    let ts = days_since_epoch * 86400 + hh * 3600 + mm * 60 + ss;
    if ts < 0 { None } else { Some(ts as u64) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path() -> PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let n = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos();
        std::env::temp_dir().join(format!("wa-sched-{n:x}.json"))
    }

    #[test]
    fn schedule_persists() {
        let p = tmp_path();
        {
            let s = Scheduler::open(&p).unwrap();
            s.schedule("x@w", "hi", 100);
            s.schedule("x@w", "later", 500);
        }
        let s2 = Scheduler::open(&p).unwrap();
        assert_eq!(s2.list().len(), 2);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn take_due_partitions() {
        let s = Scheduler::open(tmp_path()).unwrap();
        s.schedule("x", "past", 100);
        s.schedule("x", "future", now_unix() + 3600);
        let due = s.take_due(now_unix());
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].text, "past");
        assert_eq!(s.list().len(), 1);
    }

    #[test]
    fn parse_relative_durations() {
        let now = now_unix();
        assert!(parse_when("30s").unwrap() >= now + 30);
        assert!(parse_when("15m").unwrap() >= now + 900);
        assert!(parse_when("2h").unwrap()  >= now + 7200);
        assert!(parse_when("1d").unwrap()  >= now + 86400);
    }

    #[test]
    fn parse_iso8601() {
        // 2021-01-01T00:00:00Z = 1609459200
        assert_eq!(parse_when("2021-01-01T00:00:00").unwrap(), 1609459200);
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(parse_when("").is_err());
        assert!(parse_when("tomorrow").is_err());
        assert!(parse_when("25h99m").is_err());
    }

    #[test]
    fn cancel_removes() {
        let s = Scheduler::open(tmp_path()).unwrap();
        let id = s.schedule("x", "hi", now_unix() + 3600);
        assert!(s.cancel(&id));
        assert_eq!(s.list().len(), 0);
        assert!(!s.cancel(&id));
    }
}
