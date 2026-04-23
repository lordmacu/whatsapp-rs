//! `whatsapp-rs doctor` — self-test that walks each step of the connect path
//! and reports which one failed. Saves a bug-report round-trip when something
//! is off.
//!
//! Checks, in order:
//! 1. **Credentials** — a paired `me` exists on disk.
//! 2. **Daemon** — if one is running, report its pid/port; else note we'll
//!    open a fresh socket for the remaining checks.
//! 3. **WebSocket + Noise handshake** — reach `web.whatsapp.com/ws/chat` and
//!    complete the XX handshake.
//! 4. **`<success>`** — the server actually authenticated us.
//! 5. **Pre-key count IQ** — proves the IQ roundtrip works end-to-end.
//! 6. **media_conn IQ** — proves media upload path is unlocked.
//!
//! Anything red produces an actionable hint (run `listen` to pair, restart
//! daemon, etc.). Exits non-zero on any failure for CI use.

use crate::auth::{AuthManager, AuthState, FileStore};
use crate::daemon;
use crate::socket;

use std::sync::Arc;
use std::time::{Duration, Instant};

/// Result of one check — what failed, what to do.
struct CheckOut {
    name: &'static str,
    ok: bool,
    detail: String,
}

fn pass(name: &'static str, detail: impl Into<String>) -> CheckOut {
    CheckOut { name, ok: true, detail: detail.into() }
}
fn fail(name: &'static str, detail: impl Into<String>) -> CheckOut {
    CheckOut { name, ok: false, detail: detail.into() }
}

/// Run all checks and print a colored summary. Returns `Ok(true)` if every
/// check passed, `Ok(false)` if any failed (caller decides exit code).
pub async fn run_doctor() -> anyhow::Result<bool> {
    let mut results: Vec<CheckOut> = Vec::new();

    // ── 1. Credentials / pairing ──────────────────────────────────────────────
    let store = Arc::new(FileStore::new()?);
    let (paired, our_jid) = match AuthManager::new(store.clone()) {
        Ok(mgr) => {
            let paired = *mgr.state() == AuthState::Authenticated;
            let jid = mgr.creds().me.as_ref().map(|m| m.id.clone()).unwrap_or_default();
            (paired, jid)
        }
        Err(e) => {
            results.push(fail("credentials", format!("load failed: {e}")));
            print_and_return(&results);
            return Ok(false);
        }
    };
    if paired {
        results.push(pass("credentials", format!("paired as {our_jid}")));
    } else {
        results.push(fail("credentials",
            "not paired — run `whatsapp-rs listen` once and scan the QR"));
        print_and_return(&results);
        return Ok(false);
    }

    // ── 2. Daemon status ──────────────────────────────────────────────────────
    match daemon::try_daemon_request(daemon::Request::Status).await {
        Ok(Some(v)) => {
            let jid = v.get("jid").and_then(|x| x.as_str()).unwrap_or("?");
            let connected = v.get("connected").and_then(|x| x.as_bool()).unwrap_or(false);
            results.push(pass("daemon",
                format!("running — jid={jid} connected={connected}")));
            // With a live daemon we can't open a second WA socket (only one
            // primary session per device). Skip connect-based checks.
            results.push(pass("ws handshake",  "skipped (daemon holds the socket)"));
            results.push(pass("<success>",     "skipped (daemon holds the socket)"));
            results.push(pass("prekey count",  "skipped (daemon holds the socket)"));
            results.push(pass("media_conn",    "skipped (daemon holds the socket)"));
            print_and_return(&results);
            return Ok(results.iter().all(|c| c.ok));
        }
        Ok(None) => {
            results.push(pass("daemon", "not running (will open fresh socket)"));
        }
        Err(e) => {
            results.push(pass("daemon",
                format!("IPC check failed ({e}) — assuming not running")));
        }
    }

    // ── 3. WebSocket + Noise handshake ────────────────────────────────────────
    let t0 = Instant::now();
    let (sender, mut receiver) = {
        let mgr = AuthManager::new(store.clone())?;
        match socket::connect(mgr.creds()).await {
            Ok(pair) => pair,
            Err(e) => {
                results.push(fail("ws handshake",
                    format!("connect failed: {e}")));
                print_and_return(&results);
                return Ok(false);
            }
        }
    };
    results.push(pass("ws handshake",
        format!("noise complete in {:?}", t0.elapsed())));
    let sender = Arc::new(sender);

    // ── 4. Wait for <success> ─────────────────────────────────────────────────
    let t0 = Instant::now();
    let mut saw_success = false;
    let success_deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < success_deadline {
        match tokio::time::timeout(
            success_deadline.saturating_duration_since(Instant::now()),
            receiver.recv_node(),
        ).await {
            Ok(Ok(Some(node))) => {
                if node.tag == "success" {
                    saw_success = true;
                    break;
                }
            }
            _ => break,
        }
    }
    if saw_success {
        results.push(pass("<success>", format!("authenticated in {:?}", t0.elapsed())));
    } else {
        results.push(fail("<success>",
            "no success stanza in 10s — credentials may be stale"));
        print_and_return(&results);
        return Ok(false);
    }

    // ── 5. Pre-key count IQ ──────────────────────────────────────────────────
    match socket::prekey::query_pre_key_count(&sender).await {
        Ok(count) => {
            let hint = if count < 10 { " (low — daemon will rotate on next start)" } else { "" };
            results.push(pass("prekey count", format!("{count} keys{hint}")));
        }
        Err(e) => results.push(fail("prekey count", format!("IQ failed: {e}"))),
    }

    // ── 6. Media upload endpoint ─────────────────────────────────────────────
    match socket::media_upload::probe_media_conn(&sender).await {
        Ok(host) => results.push(pass("media_conn", format!("host={host}"))),
        Err(e)   => results.push(fail("media_conn", format!("IQ failed: {e}"))),
    }

    let ok = results.iter().all(|c| c.ok);
    print_and_return(&results);
    Ok(ok)
}

/// Dropping `sender` closes the socket cleanly when the function returns.
/// We intentionally leave that to Drop instead of calling close() — we
/// don't want to flap if the caller later re-runs doctor back-to-back.

fn print_and_return(results: &[CheckOut]) {
    let pad = results.iter().map(|c| c.name.len()).max().unwrap_or(0);
    for c in results {
        let status = if c.ok { "✓ PASS" } else { "✗ FAIL" };
        println!("{status}  {:<pad$}  {}", c.name, c.detail, pad = pad);
    }
    let failed = results.iter().filter(|c| !c.ok).count();
    if failed == 0 {
        println!("\nAll checks passed.");
    } else {
        println!("\n{failed} check(s) failed.");
    }
}
