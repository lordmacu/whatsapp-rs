# Changelog

All notable changes to `whatsapp-rs` will be documented in this file.
Format loosely follows [Keep a Changelog]; versions follow semver while
the API stabilizes (0.x may break on minor bumps).

[Keep a Changelog]: https://keepachangelog.com/en/1.1.0/

## [Unreleased]

## [0.1.1] — multi-account isolation

### Added
- `Client::new_in_dir(dir)` — construct a client whose `FileStore`
  lives under `<dir>/.whatsapp-rs/...` without reading or mutating
  `XDG_DATA_HOME`. Unblocks running multiple accounts in a single
  process (each one gets an isolated Signal keystore).
- `MessageManager::with_rate_limiter(rl)` — inject a custom
  `Arc<RateLimiter>` so hosts can share / preconfigure a bucket
  across multiple managers instead of relying on the global
  singleton.

### Changed
- `MessageManager` now owns an `Arc<RateLimiter>` per instance
  (`pub(crate) rate_limiter`). Every `send_encrypted_bytes` call
  acquires through that local bucket, so per-account sends no
  longer share quota with sibling accounts in the same process.
- Test `tests/auth_flow_test.rs::test_client_new_in_dir_roots_are_independent`
  asserts that two `Client::new_in_dir` instances have disjoint
  credential stores.
- Test `messages::rate_limit::tests::two_limiters_have_disjoint_state`
  asserts that draining one `RateLimiter` leaves another untouched.

### Deprecated
- `rate_limit::global()` — the process-wide singleton. New code
  should inject a per-`MessageManager` `Arc<RateLimiter>` via
  `with_rate_limiter`. The singleton remains available for
  back-compat and logs a deprecation warning with a migration hint.

## [0.1.0] — initial release

### Messaging
- Signal 1:1 + group end-to-end (X3DH + Double Ratchet + SenderKey).
- Text, image, video, audio, document, sticker, voice-note (PTT).
- View-once image / video (envelope 55 + content-info secret).
- Reply, react, mention, edit, revoke.
- Link preview with auto-fetched OG metadata and JPEG thumbnail.
- Location + contact share (vCard helper).
- Polls (create + vote decode).
- Buttons / List (consumer-safe plain-text fallback).
- Status stories (text / image / video).
- Forward, broadcast, scheduled (one-shot + daily / weekly / every).

### Groups
- Create, add, remove, promote, demote, leave, subject, description.

### Agent runtime
- `run_agent(handler)` with ACL, de-dup, typing heartbeat, slow-notice,
  chat-meta auto-skip.
- `Response` variants: Noop / Text / Reply / React / Image / Video / Multi.
- `Router` for predicate-based dispatch.
- `Acl` allow-list (env-driven or builder).
- `StateStore<T>` per-JID JSON state.
- `conversation_history(jid, n)` as `[{role, content}]` for LLMs.
- `run_webhook_agent` (POST events, apply returned action, HMAC-SHA256).
- `run_agent_with_transcribe` (voice-note → text plugin).

### Reliability & ops
- Reconnect with exponential backoff + jitter + liveness watchdog.
- Outbox: retry cap, 24 h TTL, inspection IPC.
- Token-bucket rate limiter (global + per-JID, env-tunable).
- `Session::is_connected` / `wait_connected`.
- `whatsapp-rs doctor` self-test.
- HTTP `/health` + `/metrics` (JSON + Prometheus).
- `whatsapp-rs metrics` / `outbox` CLI.

### App-state
- SyncAction decode: Contact, Pin, Mute, Archive, MarkChatAsRead,
  DeleteChat, ClearChat, Star, DeleteMessageForMe, LockChat, LabelEdit,
  LabelAssociation, AvatarUpdated.
- `ChatMetaStore` projects events into per-JID metadata (pin / mute /
  archive / lock / labels).

### Error model
- `WaError` typed enum: NotPaired, NotConnected, InvalidJid, Timeout,
  MessageNotFound, Protocol, Crypto, Media, Io, Http, Other(anyhow).
