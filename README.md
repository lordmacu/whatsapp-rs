# whatsapp-rs

A WhatsApp multi-device client library for Rust. Speaks the Signal
protocol, uploads/downloads media, decodes history sync, and ships an
agent runtime that makes LLM / webhook / voice-note bots tiny.

Runs as:
- **Library** — link into your app, drive a `Session` directly.
- **Daemon + CLI** — long-lived connection managed by systemd, scripts
  send via Unix-socket IPC in ~10 ms.
- **Agent** — `Session::run_agent(handler)` with built-in rate limiting,
  typing heartbeat, de-dup, ACL, state store, and chat-meta auto-skip.

Wire-format field numbers verified against [Baileys] and [whatsmeow].

[Baileys]: https://github.com/WhiskeySockets/Baileys
[whatsmeow]: https://github.com/tulir/whatsmeow

## Install

Published on crates.io as **`wa-agent`**; imported in Rust as
**`whatsapp_rs`** (the original lib name, kept stable so upgrades
don't churn imports):

```toml
[dependencies]
wa-agent = "0.1"
tokio    = { version = "1", features = ["full"] }
```

```rust
use whatsapp_rs::{Client, agent::Response};
```

Or pin to the git repo while the API is unstable:

```toml
wa-agent = { git = "https://github.com/lordmacu/whatsapp-rs" }
```

## Quick start

### Pair + listen

First run connects, prints a QR in the terminal, stores device creds,
then tails incoming messages:

```bash
cargo run --release -- listen
```

### Send a text

```bash
cargo run --release -- send 573XXXXXXXXX@s.whatsapp.net "hola"
```

### Run a bot

```rust
use whatsapp_rs::{Client, agent::Response};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let session = Client::new()?.connect().await?;
    session.run_agent(|ctx| async move {
        match ctx.text.as_deref() {
            Some("ping") => Response::text("pong"),
            Some(t)      => Response::reply(format!("echo: {t}")),
            _            => Response::Noop,
        }
    }).await?;
    Ok(())
}
```

## What it does

### Messaging

| Feature | CLI | Library |
|---|---|---|
| Text | `send` | `Session::send_text` |
| Image / Video / Audio / Document / Sticker | `send-file` / `sticker` | `Session::send_image` etc. |
| Voice note PTT | `send-voice` | `Session::send_voice_note` |
| View-once | `send-viewonce` | `Session::send_view_once_image` |
| Reply / react / mention / edit / revoke | `reply` / `react` / `revoke` / `edit` | `Session::send_reply` etc. |
| Link preview (auto-fetch) | `send-text-preview` | `Session::send_text_with_preview` |
| Location / contact | `send-location` / `send-contact` | `Session::send_location` etc. |
| Polls + votes | `poll` / `vote` | `Session::send_poll` |
| Buttons / List | `send-buttons` / `send-list` | `Session::send_buttons` etc. |
| Status stories | `status-post` / `status-image` / `status-video` | `Session::send_status_text` etc. |
| Forward | `forward` | `Session::forward_message` |
| Broadcast to many JIDs | `broadcast <jids\|file> <text>` | N × `send_text` |
| Scheduled (one-shot + recurring) | `schedule` / `schedule-daily` / `schedule-weekly` / `schedule-every` | daemon-side cron |

### Groups

`group-create / group-add / group-remove / group-promote / group-demote /
group-leave / group-subject / group-desc / group <jid>`.

### Agent runtime

- **`run_agent(handler)`** — subscribes to events, extracts text, applies
  ACL, de-dup, rate limit, typing heartbeat, slow-notice heartbeat, and
  chat-meta skip. Hands a closure `AgentCtx` with the message.
- **`Response`** — `Noop / Text / Reply / React / Image / Video / Multi`.
- **`Router`** — dispatch by text prefix, exact match, sender JID or raw
  predicate; first match wins.
- **`Acl`** — allow-list from `WA_AGENT_ALLOW` or builder.
- **`StateStore<T>`** — per-JID persistent JSON state for multi-turn flows.
- **`conversation_history(jid, n)`** — LLM-friendly `[{role, content}]`.
- **`run_webhook_agent(config, acl)`** — POST each event to a URL, apply
  whatever `WebhookAction` comes back (HMAC-SHA256 optional).
- **`run_agent_with_transcribe(acl, stt, handler)`** — voice-note in,
  text out via your STT (Whisper, Deepgram, local).

### Reliability

- Reconnect loop with exponential backoff + ±20% jitter + liveness
  watchdog (force-reconnect after 75 s of silence).
- Outbox: persisted before send, retried on reconnect, 5-attempt cap,
  24 h TTL, inspection via `whatsapp-rs outbox`.
- Token-bucket rate limiter (global + per-JID) on every content send.
  Tunable via `WA_RATE_*` env vars.
- De-dup of incoming `NewMessage` so agents don't double-process
  server-replayed stanzas.

### Ops

- **`whatsapp-rs doctor`** — self-test: creds, daemon, WS handshake,
  `<success>`, pre-keys IQ, media_conn IQ.
- **`whatsapp-rs metrics`** — pretty-print counters.
- **`whatsapp-rs outbox`** — list pending sends.
- **HTTP** `/health` + `/metrics` (JSON) + `/metrics/prometheus` when the
  daemon has `WA_METRICS_ADDR` set.
- **Events** — `MessageEvent::{Connected, Disconnected, Reconnecting,
  NewMessage, Receipt, MessageUpdate, Reaction, Typing, Presence,
  MessageRevoke, MessageEdit, EphemeralSetting, GroupUpdate, PollVote,
  HistorySync, AppStateUpdate}`.

### App-state sync (projected)

Chat metadata (pin / mute / archive / lock / labels / marked-unread)
projects from app-state sync into an on-disk index. Agents auto-skip
chats the user muted or archived from the phone; opt out with
`WA_AGENT_IGNORE_CHAT_META=1`.

## Daemon

```bash
systemctl --user start whatsapp-rs
journalctl --user -u whatsapp-rs -f       # tail events

# Optional observability — in a systemd override:
# [Service]
# Environment=WA_METRICS_ADDR=127.0.0.1:9100
```

Every CLI subcommand prefers the running daemon when one is live so a
second WebSocket isn't opened (WA allows only one primary socket per
device).

## Examples

- `examples/echo_bot.rs` — minimal echo bot.
- `examples/agent_bot.rs` — `Router` + `Response::Multi` + captured state.
- `examples/wizard_bot.rs` — persistent multi-turn form (`StateStore`).
- `examples/offhours_bot.rs` — auto-reply outside business hours.
- `examples/voice_bot.rs` — Whisper transcription via `Transcriber`.
- `examples/webhook_bot.rs` — delegate to an HTTP endpoint.
- `examples/command_bot.rs` — slash-command router + media download hook.

## State

Credentials, sessions and caches live under
`$XDG_DATA_HOME/.whatsapp-rs/` (typically `~/.local/share/.whatsapp-rs/`):

```
creds.json        sessions.json        pre-keys/
messages/         outbox.jsonl         scheduled.json
contacts.json     chat_meta.json       app-state/
```

Delete `creds.json` to force a fresh QR pairing.

## Status

- **0.x** — API can still shift between minor versions.
- No Business-API features (buttons render as plain-text bullets on
  consumer accounts, which is where the server filters them).
- No voice/video calls.
- History-sync decoding covers the actions most bots care about
  (pin / mute / archive / lock / labels); cosmetic settings fall through
  as `SyncAction::Raw`.

## License

MIT OR Apache-2.0. Pick whichever fits your project.
