//! Process-wide counters + an HTTP `/health` + `/metrics` surface.
//!
//! Agents running under systemd / Kubernetes / Docker Compose need a
//! liveness probe and basic observability. Rather than haul in prometheus
//! or opentelemetry we expose a tiny JSON endpoint you can scrape from
//! anything that speaks HTTP.
//!
//! Counters are process-global atomics (no locks in the hot path). Hook
//! sites:
//! - [`inc_rx()`]         in the inbound-message pipeline
//! - [`inc_tx()`]         after a successful outbound send
//! - [`inc_decrypt_fail()`] on recurrent MAC / session failures
//! - [`inc_reconnect()`]  at the top of each reconnect attempt
//!
//! Probe endpoints (see [`serve`] below):
//! - `GET /health`   → 200 `{"status":"ok","connected":true}`  if the socket
//!                      is alive, 503 `{"status":"down", …}` otherwise.
//! - `GET /metrics`  → snapshot of all counters + uptime + last_rx/tx.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

struct Counters {
    rx: AtomicU64,
    tx: AtomicU64,
    decrypt_fail: AtomicU64,
    reconnects: AtomicU64,
    last_rx_unix: AtomicU64,
    last_tx_unix: AtomicU64,
    started: Instant,
}

fn counters() -> &'static Counters {
    static C: OnceLock<Counters> = OnceLock::new();
    C.get_or_init(|| Counters {
        rx: AtomicU64::new(0),
        tx: AtomicU64::new(0),
        decrypt_fail: AtomicU64::new(0),
        reconnects: AtomicU64::new(0),
        last_rx_unix: AtomicU64::new(0),
        last_tx_unix: AtomicU64::new(0),
        started: Instant::now(),
    })
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Record one successfully-processed inbound message.
pub fn inc_rx() {
    let c = counters();
    c.rx.fetch_add(1, Ordering::Relaxed);
    c.last_rx_unix.store(now_unix(), Ordering::Relaxed);
}

/// Record one successfully-dispatched outbound message.
pub fn inc_tx() {
    let c = counters();
    c.tx.fetch_add(1, Ordering::Relaxed);
    c.last_tx_unix.store(now_unix(), Ordering::Relaxed);
}

/// Record a decrypt / MAC / session failure — surfaces flakiness.
pub fn inc_decrypt_fail() {
    counters().decrypt_fail.fetch_add(1, Ordering::Relaxed);
}

/// Record a reconnect attempt (the outer loop tick, not each dial).
pub fn inc_reconnect() {
    counters().reconnects.fetch_add(1, Ordering::Relaxed);
}

/// Snapshot serializable to JSON. Cheap; all atomic loads.
#[derive(Debug, serde::Serialize)]
pub struct Snapshot {
    pub uptime_secs: u64,
    pub messages_received: u64,
    pub messages_sent: u64,
    pub decrypt_failures: u64,
    pub reconnects: u64,
    pub last_rx_unix: u64,
    pub last_tx_unix: u64,
}

pub fn snapshot() -> Snapshot {
    let c = counters();
    Snapshot {
        uptime_secs: c.started.elapsed().as_secs(),
        messages_received: c.rx.load(Ordering::Relaxed),
        messages_sent: c.tx.load(Ordering::Relaxed),
        decrypt_failures: c.decrypt_fail.load(Ordering::Relaxed),
        reconnects: c.reconnects.load(Ordering::Relaxed),
        last_rx_unix: c.last_rx_unix.load(Ordering::Relaxed),
        last_tx_unix: c.last_tx_unix.load(Ordering::Relaxed),
    }
}

// ── HTTP probes ───────────────────────────────────────────────────────────────

use crate::client::Session;
use axum::{extract::State, http::StatusCode, response::Json, routing::get, Router};
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Clone)]
struct AppState {
    session: Arc<Session>,
}

/// Spawn a tiny axum server on `addr` that exposes `/health` and `/metrics`.
///
/// Returns the server's task handle so the caller can shut it down on
/// session drop if desired. The session handle is stored as `Arc<Session>`
/// so the server can answer liveness queries independently of the main
/// event loop.
pub async fn serve(addr: SocketAddr, session: Arc<Session>) -> std::io::Result<()> {
    let state = AppState { session };
    let app = Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics_json))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("metrics server on http://{}", addr);
    axum::serve(listener, app)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))
}

async fn health(State(s): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
    if s.session.is_connected() {
        (StatusCode::OK, Json(serde_json::json!({
            "status": "ok",
            "connected": true,
            "jid": s.session.our_jid,
        })))
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({
            "status": "down",
            "connected": false,
            "jid": s.session.our_jid,
        })))
    }
}

async fn metrics_json(State(s): State<AppState>) -> Json<serde_json::Value> {
    let snap = snapshot();
    Json(serde_json::json!({
        "connected": s.session.is_connected(),
        "jid": s.session.our_jid,
        "uptime_secs": snap.uptime_secs,
        "messages_received": snap.messages_received,
        "messages_sent": snap.messages_sent,
        "decrypt_failures": snap.decrypt_failures,
        "reconnects": snap.reconnects,
        "last_rx_unix": snap.last_rx_unix,
        "last_tx_unix": snap.last_tx_unix,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_increment() {
        let before = snapshot();
        inc_rx(); inc_rx();
        inc_tx();
        inc_decrypt_fail();
        inc_reconnect();
        let after = snapshot();
        assert!(after.messages_received >= before.messages_received + 2);
        assert!(after.messages_sent >= before.messages_sent + 1);
        assert!(after.decrypt_failures >= before.decrypt_failures + 1);
        assert!(after.reconnects >= before.reconnects + 1);
        assert!(after.last_rx_unix > 0);
        assert!(after.last_tx_unix > 0);
    }
}
