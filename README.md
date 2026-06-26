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

### Meta AI / `@bot` decryption (experimental, opt-in)

Inbound messages from WhatsApp's built-in **Meta AI** assistant (and
any other `*@bot` JID) arrive on the wire as `enc type="msmsg"` — a
Meta-internal envelope that's distinct from the regular Signal
`pkmsg` / `msg` / `skmsg` types and is **not** part of the Signal
ratchet. By default the library treats `msmsg` as undecryptable
(same behaviour as before). Set the env var `WA_BOT_DECRYPT=1` to
opt into the experimental decryption pipeline:

```bash
WA_BOT_DECRYPT=1 cargo run --release -- listen
```

When the flag is set, two hooks light up:

1. **Capture** — every successfully decrypted Signal plaintext is
   sniffed for `MessageContextInfo.messageSecret` (proto field 35 →
   field 3). When the user's phone sends to a bot, the outbound is
   multi-fanned to every linked device wrapped in a
   `deviceSentMessage` (DSM, field 31). We unwrap the DSM, confirm
   the destination is `*@bot`, and stash the 32-byte secret in an
   in-memory FIFO keyed by `(bot_jid, msg_id)` (case-folded).
2. **Decrypt** — when an `<enc type="msmsg">` arrives from a bot,
   we read `<meta target_id>` to find the original outbound id and
   look the secret up. The reply's AES-GCM key is derived per the
   whatsmeow / WhatsApp Web algorithm:

   ```text
   base   = HKDF-SHA256(messageSecret,    salt=∅, info="Bot Message",   L=32)
   useCase= msgID ∥ ourLID(NonAD) ∥ botJID(NonAD) ∥ ""    // empty modType
   aesKey = HKDF-SHA256(base,             salt=∅, info=useCase,         L=32)
   aad    = msgID ∥ 0x00 ∥ botJID(NonAD)
   pt     = AES-256-GCM(aesKey, encIV, encPayload, aad)
   ```

Two corners that bit us empirically and are now handled:

- **Streamed edits.** Meta AI ships replies as a sequence of
  `<bot edit="first|inner|last" edit_target_id="…">` chunks; each
  chunk REPLACES the previous one. For `inner` and `last` the
  derivation uses `edit_target_id` (the FIRST chunk's id), not the
  per-chunk stanza id. Whatsmeow does the same.
- **Identity for bot keys is the LID, not the PN.** The `<meta>`
  on bot replies usually omits `target_sender_jid`; whatsmeow falls
  back to `cli.getOwnLID()` because the bot family server uses LID
  identities. We pass `Session.our_lid` (NonAD-stripped) into the
  derivation when the meta attr is empty.

After decrypt the plaintext is a `WAProto.Message` wrapped in a
`ProtocolMessage.editedMessage` (field 12 → field 14 — Meta AI
emits `MESSAGE_EDIT` for streaming UX). We unwrap that envelope so
the rest of the pipeline (text extraction, agent dispatch, outbox)
sees the bot reply as an ordinary text message.

Off by default for two reasons: the in-memory secret store costs
RAM (capped at 1024 entries), and the feature touches a Meta-
internal protocol that might shift on any upstream update. Logs
land on the `wa::bot_decrypt` target (`info!` for capture +
decrypt success, `debug!` for derivation inputs).

### Reliability

- Reconnect loop with exponential backoff + ±20% jitter + liveness
  watchdog (force-reconnect after 75 s of silence).
- Outbox: persisted before send, retried on reconnect, 5-attempt cap,
  24 h TTL, inspection via `whatsapp-rs outbox`.
- Token-bucket rate limiter (global + per-JID) on every content send.
  Tunable via `WA_RATE_*` env vars.
- De-dup of incoming `NewMessage` so agents don't double-process
  server-replayed stanzas. Backlog redeliveries (ratchet "counter already
  passed") are classified as benign duplicates — plain-acked, never NACK'd
  into a resend loop, and excluded from the auto-recovery counter.
- Own-account decrypt: `from_me` messages (your phone's fanout, incl. your
  own manual sends) decrypt via an own-account LID↔PN alias; `deviceSentMessage`
  copies are re-attributed to the real recipient chat (not your own account).
- Own-device fanout recovery: outgoing copies are mirrored to your other
  devices so they render as "sent by me"; the primary's retry-receipts are
  honoured (cache lookup by id + DSM re-wrap) so it can decrypt them instead
  of getting stuck on "Waiting for this message".

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
  HistorySync, AppStateUpdate, BotMessage, SessionReset}`. `SessionReset`
  fires when a peer's Signal session is dropped after sustained decrypt
  failures — react by sending the peer an outbound message to force a
  fresh X3DH handshake.

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
