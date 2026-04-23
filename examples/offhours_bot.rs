//! Auto-reply outside business hours.
//!
//! When someone writes during off-hours, reply once with a configurable
//! message. We throttle per-JID via a persistent StateStore so the same
//! contact doesn't get spammed — only one reply per off-hours window.
//!
//! Config (all UTC, all env):
//! - `WA_OFFHOURS_START` — hour (0–23) when off-hours begin. Default 18.
//! - `WA_OFFHOURS_END`   — hour (0–23) when off-hours end.   Default 9.
//!   If START > END, the window wraps midnight (18→9 = "6pm to 9am").
//! - `WA_OFFHOURS_MSG`   — auto-reply text. Default: gentle Spanish notice.
//! - `WA_OFFHOURS_COOLDOWN_HOURS` — min hours between replies to the same
//!   JID so we don't spam. Default 4.
//!
//! ```bash
//! export WA_OFFHOURS_START=19
//! export WA_OFFHOURS_END=8
//! export WA_OFFHOURS_MSG="Gracias por escribir 🌙 respondo mañana entre 8am y 7pm."
//! cargo run --release --example offhours_bot
//! ```

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use whatsapp_rs::agent::{Acl, Response};
use whatsapp_rs::chat_state::StateStore;
use whatsapp_rs::Client;

#[derive(Default, Serialize, Deserialize)]
struct AutoReplyMark {
    last_reply_unix: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("whatsapp_rs=info")),
        )
        .init();

    let start_hour = env_u32("WA_OFFHOURS_START", 18);
    let end_hour   = env_u32("WA_OFFHOURS_END",   9);
    let cooldown_secs = env_u32("WA_OFFHOURS_COOLDOWN_HOURS", 4) as u64 * 3600;
    let auto_msg = std::env::var("WA_OFFHOURS_MSG").unwrap_or_else(|_|
        "🌙 Gracias por tu mensaje. Respondo en horario de oficina (UTC 9–18).".to_string());

    let session = Client::new()?.connect().await?;
    tracing::info!(
        "off-hours bot ready as {} — window {:02}:00→{:02}:00 UTC, cooldown {}h",
        session.our_jid, start_hour, end_hour, cooldown_secs / 3600,
    );

    let state: StateStore<AutoReplyMark> = StateStore::open("agent-state-offhours")?;

    session.run_agent_with(Acl::from_env("WA_AGENT_ALLOW"), move |ctx| {
        let state = state.clone();
        let auto_msg = auto_msg.clone();
        async move {
            let now = unix_now();
            if !is_offhours(now, start_hour, end_hour) {
                return Response::Noop;
            }
            let mark = state.get(ctx.jid());
            if now.saturating_sub(mark.last_reply_unix) < cooldown_secs {
                tracing::debug!("offhours: cooldown not elapsed for {}", ctx.jid());
                return Response::Noop;
            }
            state.update(ctx.jid(), |m| m.last_reply_unix = now);
            Response::text(&auto_msg)
        }
    }).await?;

    Ok(())
}

/// Wall-clock UTC hour from a unix timestamp. `t / 3600 % 24` is sufficient
/// — leap seconds don't shift the hour bucket.
fn hour_of_day_utc(t: u64) -> u32 {
    ((t / 3600) % 24) as u32
}

/// True if `t` is inside `[start, end)` considering wrap across midnight
/// (e.g. 18→9 = "18, 19, 20, 21, 22, 23, 0, 1, 2, 3, 4, 5, 6, 7, 8").
fn is_offhours(t: u64, start: u32, end: u32) -> bool {
    let h = hour_of_day_utc(t);
    if start == end { return false; }
    if start < end {
        h >= start && h < end
    } else {
        h >= start || h < end
    }
}

fn env_u32(key: &str, default: u32) -> u32 {
    std::env::var(key).ok().and_then(|s| s.parse().ok()).unwrap_or(default)
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
