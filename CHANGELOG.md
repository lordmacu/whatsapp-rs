# Changelog

All notable changes to `whatsapp-rs` will be documented in this file.
Format loosely follows [Keep a Changelog]; versions follow semver while
the API stabilizes (0.x may break on minor bumps).

[Keep a Changelog]: https://keepachangelog.com/en/1.1.0/

## [Unreleased]

## [0.1.7] — own-account decrypt, DSM re-attribution, retry & decode fixes

### Added
- **`MessageEvent::SessionReset { jid }`** — fired when a peer's Signal
  session is dropped after N consecutive *genuine* decrypt failures.
  Consumers should send the peer an outbound message to force a fresh
  X3DH handshake (the broken state won't heal on its own otherwise).
- **Own-account `from_me` decrypt** — your phone fans its own sent
  messages out to companion devices addressed under your account LID; a
  LID↔PN alias is now registered on `<success>` so those resolve to the
  session held under your PN and decrypt (previously: `no session`).
- **`deviceSentMessage` re-attribution** — own-device fanout is now
  attributed to the *real recipient* chat (`destinationJid`), not your
  own account, so handlers route it to the right conversation.

### Fixed
- **Reply / @mention decoded as Video** — `extendedTextMessage` (proto
  field 6) collided with the legacy media tag; `parse_media_sub` now
  requires `mediaKey` + `fileEncSha256`, so text variants no longer
  decode as media.
- **Duplicate-redelivery handling** — ratchet "counter already passed"
  is classified as a benign duplicate: plain-acked (no NACK→resend loop)
  and excluded from the auto-recovery counter. Genuine success resets it.
- **SessionReset storm on own account** — own-account (`from_me`) decrypt
  failures no longer count toward / trigger SessionReset (re-X3DH with
  yourself is futile and the pkmsg storm trips WhatsApp anti-abuse).
- **SessionReset on stale offline backlog** — `offline=N` decrypt failures
  no longer count toward auto-recovery. Old backlog (e.g. messages from
  before a re-pair, encrypted under a session we no longer hold) can never
  decrypt and re-delivers on every reconnect; counting it fired a futile
  SessionReset that pinged the peer with an empty message. Only LIVE
  failures recover now (a genuinely-broken session still fails — and
  recovers — on the peer's next live send); backlog is just drained.
- **Own-device fanout "Waiting for this message"** — the primary's
  retry-receipt is now resolved (cache lookup by id, since the send was
  cached under the recipient chat) and re-wrapped in `deviceSentMessage`
  before resending, so the primary can finally decrypt. Message ids are
  normalised to lowercase in the recent-sends cache (we send `3EB0…` but
  WhatsApp echoes `3eb0…`).

## [0.1.5] — bot decryption surfaces + discovery API

### Added
- **`MessageEvent::BotMessage`** — fired on every successful
  `msmsg` decrypt instead of swallowing the result. Carries
  `bot_jid`, `msg_id`, `target_id`, `edit` (`first|inner|last`),
  and `text` already flattened from the
  `AIRichResponseMessage.submessages[].messageText` chain. Stays
  separate from `NewMessage` so the agent dispatcher never routes
  bot streams as user input (which would otherwise loop the agent
  back at the bot).
- **`Session::list_bots()`** — discover assigned AI bots
  (Meta AI etc.) via the documented `<iq xmlns="bot"><bot v="2"/></iq>`
  query. Returns `Vec<BotListInfo { jid, persona_id }>` without
  needing to send a single message first.
- **`bot_decrypt::DecryptedBotReply`** + `extract_ai_rich_text` are
  now `pub`, so consumers running their own dispatcher can flatten
  `AIRichResponseMessage` plaintext into a string without
  re-implementing the proto walk.

### Changed
- `WA_BOT_DECRYPT` is now **default ON**. Set
  `WA_BOT_DECRYPT=0` to opt out (legacy "treat msmsg as
  undecryptable" path).
- `/tmp/msmsg_*.bin` plaintext dumps are now off by default.
  Enable with `WA_BOT_DECRYPT_DUMP=1` for offline analysis.

## [0.1.4] — clean build (no warnings)

### Fixed
- Lib now compiles with zero warnings: dropped six unused imports
  (`Arc`, `HASH_LEN`, `proto_varint`, `decode_signal_header`, etc.)
  and tagged five intentionally-kept-but-unused helpers
  (`normalize_device_jid`, `build_candidate_jids`,
  `read_varint_at`, `msg_mac`, `PersistedEntry::ad`) with
  `#[allow(dead_code)]` and a one-line note on why each survives.
- Bin (`whatsapp-rs` CLI) sets `#![allow(dead_code, unused_imports)]`
  at the crate root: it re-`mod`-s the same files the lib publishes,
  so the public API surface trips dead-code lint when checked
  bin-side. The allow keeps the lib's clean status while letting
  the CLI stay terse.

## [0.1.3] — pin xeddsa to 1.0.2 (build fix)

### Fixed
- Pin `xeddsa = "=1.0.2"` so a fresh resolver doesn't pull
  `xeddsa 1.1.0`, which switched the `Sign::sign` bound from
  `rand::CryptoRng` to `rand_core::CryptoRng` and broke
  compilation against `rand::rngs::OsRng`. v0.1.2 (just published)
  builds fine against the locked 1.0.2 but fails on a clean
  CI resolve.

## [0.1.2] — Meta AI / `@bot` decryption + media field-number fix

### Added
- **`messages::bot_decrypt`** (opt-in via `WA_BOT_DECRYPT=1`) —
  decrypt inbound `enc type="msmsg"` envelopes from `*@bot` JIDs
  (Meta AI and friends). Captures `MessageContextInfo.messageSecret`
  off our own outbound DSM, derives the AES-GCM key per the
  whatsmeow algorithm (HKDF-SHA256 with the "Bot Message" tag, our
  LID as origMsgSender, the bot JID as modSender), and unwraps the
  resulting `ProtocolMessage.editedMessage` (Meta AI streams
  replies as a sequence of `<bot edit="…" edit_target_id="…">`
  edits — `inner` and `last` re-key off the FIRST chunk's id).
  Off by default; in-memory FIFO secret store capped at 1024 entries.
- `agent::ctx_has_actionable_text` now also pulses the typing
  heartbeat for inbound audio messages so the user sees an
  "escribiendo…" while STT + LLM run.

### Fixed
- `signal::wa_proto::decode_wa_media` / `parse_media_sub` now
  hand the outer message tag through to the sub-parser. WAProto
  uses different field numbers for `mediaKey` / `fileEncSHA256`
  per media type — the previous version hardcoded the image
  layout and silently broke audio / video / document / sticker
  HMAC verification ("media MAC mismatch" symptom).

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
