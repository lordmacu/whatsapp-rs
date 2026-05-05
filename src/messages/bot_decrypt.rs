//! `msmsg` (Meta Server Message) decryption — Meta AI bot replies.
//!
//! ## Why this is a separate file
//!
//! The Signal Protocol pipeline this crate ships only handles `pkmsg` /
//! `msg` / `skmsg` enc-types. WhatsApp's bot envelopes use a different
//! scheme (`enc type="msmsg"`) that is server-derived, NOT a Signal
//! ratchet. Mixing it into `recv.rs` would tangle the two protocols.
//! Everything bot-specific lives here so the experiment can be ripped
//! out cleanly if it breaks (or if Meta changes the format upstream
//! and we need to revert in a hurry).
//!
//! ## Activation gate
//!
//! Off by default. Set the env var `WA_BOT_DECRYPT=1` before launching
//! the daemon to enable both halves of the pipeline:
//!
//!   1. **Capture**: every successfully decrypted Signal plaintext is
//!      sniffed for `MessageContextInfo.messageSecret` (proto field
//!      35 → field 3). When the user's phone sends to a bot, the
//!      outbound message is multi-fanned to every linked device with
//!      the secret embedded; we cache it keyed by `(chat, msg_id)`.
//!
//!   2. **Decrypt**: when an `<enc type="msmsg">` arrives from a
//!      `@bot` JID, look up the secret stored under the original
//!      outbound `target_id`, derive the AES-GCM key per the
//!      whatsmeow / WhatsApp Web algorithm, and decrypt the payload.
//!
//! ## Algorithm (mirrors `whatsmeow/msgsecret.go`)
//!
//!     base = HKDF-SHA256(messageSecret, salt=[], info="Bot Message", L=32)
//!     useCase = msgID || ourJID(NonAD) || botJID(NonAD) || ""    // empty modType
//!     aesKey  = HKDF-SHA256(base, salt=[], info=useCase, L=32)
//!     aad     = msgID || 0x00 || botJID(NonAD)
//!     plaintext = AES-256-GCM(aesKey, encIV, encPayload, aad)
//!
//! `MessageSecretMessage` proto: field 1 = version (sfixed32), field
//! 2 = encIV, field 3 = encPayload.
//!
//! The decrypted plaintext is a regular `WAProto.Message` blob — feed
//! it into the existing `decode_plaintext` to extract text.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use anyhow::{anyhow, Context, Result};
use hkdf::Hkdf;
use sha2::Sha256;
use tracing::{debug, info, warn};

use crate::binary::BinaryNode;
use crate::signal::wa_proto::parse_proto_fields;

/// Toggle the experiment via env. Cheap, no rebuild, default OFF.
pub fn enabled() -> bool {
    std::env::var("WA_BOT_DECRYPT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Strip `:device` suffix and `@server` from a JID — whatsmeow calls
/// this `ToNonAD().String()`. The HKDF info bytes need the bare
/// `user@server` form so our key derivation matches the bot's.
fn to_non_ad(jid: &str) -> String {
    // user[:device]@server → user@server
    if let Some((before_at, server)) = jid.split_once('@') {
        let user = before_at.split(':').next().unwrap_or(before_at);
        format!("{user}@{server}")
    } else {
        jid.to_string()
    }
}

// ── In-memory secret store ────────────────────────────────────────

/// Map `(chat_jid_non_ad, msg_id)` → 32-byte messageSecret.
///
/// In-memory only — bounded by `MAX_ENTRIES` to keep this experiment
/// from leaking unbounded state. When we exceed the cap we drop the
/// oldest insertions (FIFO via insertion order in a Vec sidekick).
/// A real implementation would persist to sqlite alongside the
/// signal session store.
static STORE: OnceLock<Mutex<MsgSecretStore>> = OnceLock::new();

const MAX_ENTRIES: usize = 1024;

#[derive(Default)]
struct MsgSecretStore {
    map: HashMap<(String, String), Vec<u8>>,
    fifo: Vec<(String, String)>,
}

fn store() -> &'static Mutex<MsgSecretStore> {
    STORE.get_or_init(|| Mutex::new(MsgSecretStore::default()))
}

/// Persist a captured secret keyed by `(chat, msg_id)`. Evicts the
/// oldest entry once `MAX_ENTRIES` is reached.
///
/// Both `chat` and `msg_id` are normalised to uppercase: WhatsApp
/// emits the bot's `<meta target_id="…">` in uppercase but the
/// outbound stanza's own `id` attr lands in lowercase. Without
/// case-folding here every captured secret would miss its lookup.
fn put_secret(chat: &str, msg_id: &str, secret: Vec<u8>) {
    let key = (to_non_ad(chat), msg_id.to_uppercase());
    let mut s = store().lock().unwrap();
    if !s.map.contains_key(&key) {
        s.fifo.push(key.clone());
        if s.fifo.len() > MAX_ENTRIES {
            let evict = s.fifo.remove(0);
            s.map.remove(&evict);
        }
    }
    s.map.insert(key, secret);
}

/// Look up a captured secret. Returns a copy because the underlying
/// HashMap can reshape on insert. Case-folded the same way as
/// `put_secret` so case differences between outbound `id` and
/// `target_id` don't break the join.
fn get_secret(chat: &str, msg_id: &str) -> Option<Vec<u8>> {
    let key = (to_non_ad(chat), msg_id.to_uppercase());
    store().lock().unwrap().map.get(&key).cloned()
}

// ── Plaintext sniffing — capture step ─────────────────────────────

/// Walk a decrypted `WAProto.Message` blob looking for a 32-byte
/// `messageContextInfo.messageSecret`. When found AND the real
/// destination of the message is a `@bot` chat, store it so the
/// bot's reply can decrypt against it.
///
/// The phone's outbound to a bot reaches us wrapped in a
/// `deviceSentMessage` envelope (DSM, field 31): the outer stanza
/// is addressed to our own JID (auto-sync) but the inner message
/// carries `destinationJid` (the bot) and the real message body
/// + `messageContextInfo`. We unwrap DSM transparently here so the
/// caller doesn't need to know about it.
///
/// `outer_chat_jid` — what the recv path saw on the wire (often
/// our own JID for DSM cases).
/// `msg_id` — the outer stanza's `id` attr; matches the `target_id`
/// the bot uses in its reply.
///
/// Idempotent — calling on a non-bot or non-secret-bearing message
/// is a cheap no-op.
pub fn maybe_capture_secret(plaintext: &[u8], outer_chat_jid: &str, msg_id: &str) {
    if !enabled() {
        return;
    }
    // Diagnostic — dump top-level field numbers for any inbound
    // routed through here. Useful when the wire format shifts in a
    // future WA update; downgrade to `debug!` in production so the
    // info channel stays clean.
    if tracing::enabled!(target: "wa::bot_decrypt", tracing::Level::DEBUG) {
        if let Some(fields) = parse_proto_fields(plaintext) {
            let mut top_fields: Vec<u64> = fields.keys().copied().collect();
            top_fields.sort_unstable();
            debug!(
                target: "wa::bot_decrypt",
                outer_chat = %outer_chat_jid,
                msg_id = %msg_id,
                plaintext_len = plaintext.len(),
                top_fields = ?top_fields,
                "top-level proto fields"
            );
            if let Some(dsm) = fields.get(&31) {
                if let Some(dsm_fields) = parse_proto_fields(dsm) {
                    let mut inner_keys: Vec<u64> = dsm_fields.keys().copied().collect();
                    inner_keys.sort_unstable();
                    let dest = dsm_fields
                        .get(&1)
                        .map(|b| String::from_utf8_lossy(b).into_owned())
                        .unwrap_or_default();
                    debug!(
                        target: "wa::bot_decrypt",
                        msg_id = %msg_id,
                        dsm_inner_fields = ?inner_keys,
                        dsm_destination = %dest,
                        "DSM (field 31) detected"
                    );
                }
            }
        }
    }
    let (effective_chat, secret_bytes) = match resolve_bot_destination_and_secret(
        plaintext,
        outer_chat_jid,
    ) {
        Some(v) => v,
        None => return,
    };
    if secret_bytes.len() != 32 {
        debug!(
            "bot_decrypt: messageSecret wrong length ({})",
            secret_bytes.len()
        );
        return;
    }
    info!(
        target: "wa::bot_decrypt",
        chat = %effective_chat,
        outer_chat = %outer_chat_jid,
        msg_id = %msg_id,
        "bot_decrypt: captured outbound messageSecret"
    );
    put_secret(&effective_chat, msg_id, secret_bytes);
}

/// Try the top-level `messageContextInfo`. If absent, unwrap a
/// `deviceSentMessage` (field 31) and recurse. Returns the
/// **effective** chat JID — which is `destinationJid` from the DSM
/// when present, otherwise the outer chat the caller passed in.
///
/// Only returns `Some` when the effective chat is a `@bot`, so the
/// caller can skip non-bot traffic without an extra check.
fn resolve_bot_destination_and_secret(
    plaintext: &[u8],
    outer_chat_jid: &str,
) -> Option<(String, Vec<u8>)> {
    let fields = parse_proto_fields(plaintext)?;

    // Helper: try to read MessageContextInfo.messageSecret out of a
    // proto field map at any nesting level we know about.
    let read_secret = |fields: &std::collections::HashMap<u64, Vec<u8>>| -> Option<Vec<u8>> {
        let mci = fields.get(&35)?;
        let mci_fields = parse_proto_fields(mci)?;
        mci_fields.get(&3).cloned()
    };

    // Path A — DSM wrapper. The phone wraps its own outbound in
    // `deviceSentMessage` (field 31) and fans the wrap out to every
    // linked device. The wrap carries `destinationJid` (field 1) and
    // `message` (field 2). The `messageContextInfo` (field 35) sits
    // at the OUTER level alongside the DSM — NOT inside the inner
    // `message`. Confirmed empirically on iOS WA: outer top-level
    // top_fields = [31, 35].
    //
    // Some clients also (or instead) embed the secret on the inner
    // message — accept both as a defensive measure so we don't break
    // when WA tweaks the layout in a future update.
    if let Some(dsm) = fields.get(&31) {
        let dsm_fields = parse_proto_fields(dsm)?;
        let dest_bytes = dsm_fields.get(&1)?;
        let destination_jid = String::from_utf8_lossy(dest_bytes).into_owned();
        if !destination_jid.contains("@bot") {
            return None;
        }
        if let Some(secret) = read_secret(&fields) {
            return Some((destination_jid, secret));
        }
        if let Some(inner) = dsm_fields.get(&2) {
            if let Some(inner_fields) = parse_proto_fields(inner) {
                if let Some(secret) = read_secret(&inner_fields) {
                    return Some((destination_jid, secret));
                }
            }
        }
        return None;
    }

    // Path B — top-level message addressed directly to a bot. No
    // DSM wrap; the message context info is at the root.
    if !outer_chat_jid.contains("@bot") {
        return None;
    }
    let secret = read_secret(&fields)?;
    Some((outer_chat_jid.to_string(), secret))
}

// ── Bot reply decryption ──────────────────────────────────────────

/// Apply the first HKDF stage. The "Bot Message" info string is
/// hardcoded by WhatsApp — see whatsmeow `applyBotMessageHKDF`.
fn apply_bot_message_hkdf(secret: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, secret);
    let mut out = [0u8; 32];
    hk.expand(b"Bot Message", &mut out)
        .expect("HKDF L=32 always fits");
    out
}

/// Build the AES key + AAD pair for a bot reply.
///
/// `bot_reply_msg_id` — the `id` attr of the inbound `<message>` from
/// the bot.
/// `our_jid` — our `@s.whatsapp.net` or `@lid` JID (NonAD).
/// `bot_jid` — the bot's JID, e.g. `718584497008509@bot`.
/// `derived_key` — output of `apply_bot_message_hkdf`.
fn generate_msg_secret_key(
    bot_reply_msg_id: &str,
    our_jid_non_ad: &str,
    bot_jid_non_ad: &str,
    derived_key: &[u8],
) -> ([u8; 32], Vec<u8>) {
    // useCaseSecret = msg_id || origMsgSender || modSender || modType("")
    // Matches whatsmeow generateMsgSecretKey with empty modType.
    let mut info_bytes = Vec::with_capacity(
        bot_reply_msg_id.len() + our_jid_non_ad.len() + bot_jid_non_ad.len(),
    );
    info_bytes.extend_from_slice(bot_reply_msg_id.as_bytes());
    info_bytes.extend_from_slice(our_jid_non_ad.as_bytes());
    info_bytes.extend_from_slice(bot_jid_non_ad.as_bytes());

    let hk = Hkdf::<Sha256>::new(None, derived_key);
    let mut aes_key = [0u8; 32];
    hk.expand(&info_bytes, &mut aes_key)
        .expect("HKDF L=32 always fits");

    // AAD = msg_id || 0x00 || modSender   (only when modType == "")
    let mut aad = Vec::with_capacity(bot_reply_msg_id.len() + 1 + bot_jid_non_ad.len());
    aad.extend_from_slice(bot_reply_msg_id.as_bytes());
    aad.push(0);
    aad.extend_from_slice(bot_jid_non_ad.as_bytes());

    (aes_key, aad)
}

/// Parse a `MessageSecretMessage` protobuf — fields 2 (encIV) and
/// 3 (encPayload). Returns `(iv, payload)` when both are present.
fn parse_msmsg_envelope(bytes: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let f = parse_proto_fields(bytes)?;
    let iv = f.get(&2)?.clone();
    let payload = f.get(&3)?.clone();
    Some((iv, payload))
}

/// Decrypt an inbound `<enc type="msmsg">` from a bot. The caller
/// passes the `<message>` node so we can pull `<meta target_id="…"
/// target_sender_jid="…">` for the secret lookup.
///
/// Returns the plaintext `WAProto.Message` bytes ready to feed to
/// `decode_plaintext`. Returns `Err` (no panic) on any failure so
/// the existing recv pipeline can fall back to the warn+skip path.
pub fn decrypt_msmsg(
    message_node: &BinaryNode,
    enc_bytes: &[u8],
    our_jid: &str,
) -> Result<Vec<u8>> {
    if !enabled() {
        return Err(anyhow!("bot_decrypt: disabled (set WA_BOT_DECRYPT=1)"));
    }
    let bot_jid = message_node
        .attr("from")
        .ok_or_else(|| anyhow!("msmsg: <message> has no from"))?;
    let stanza_msg_id = message_node
        .attr("id")
        .ok_or_else(|| anyhow!("msmsg: <message> has no id"))?;

    // Pull <meta target_id, target_sender_jid> from message children.
    let (target_id, target_sender_jid) = find_meta_attrs(message_node)
        .ok_or_else(|| anyhow!("msmsg: missing <meta target_id/target_sender_jid>"))?;

    // Meta AI streams replies as multi-part edits — `<bot edit="first|
    // inner|last" edit_target_id="…">`. The first chunk derives keys
    // off the stanza id; every subsequent chunk re-uses the FIRST
    // chunk's id (carried in `edit_target_id`) so each part
    // decrypts under the same secret. Mirrors whatsmeow's
    // `decryptMessageID = info.MsgBotInfo.EditTargetID` branch.
    let bot_edit = find_bot_attrs(message_node);
    let bot_reply_msg_id: String = match bot_edit.as_ref() {
        Some((edit, edit_target_id))
            if (edit == "inner" || edit == "last") && !edit_target_id.is_empty() =>
        {
            edit_target_id.clone()
        }
        _ => stanza_msg_id.to_string(),
    };
    let bot_reply_msg_id = bot_reply_msg_id.as_str();

    // The secret is keyed by the bot CHAT and the OUTBOUND message
    // we sent. `target_id` is exactly that outbound id.
    let secret = get_secret(bot_jid, &target_id).ok_or_else(|| {
        anyhow!(
            "msmsg: no captured messageSecret for bot={} target_id={} (sent before WA_BOT_DECRYPT was enabled?)",
            bot_jid,
            target_id
        )
    })?;

    let (iv, payload) = parse_msmsg_envelope(enc_bytes)
        .ok_or_else(|| anyhow!("msmsg: malformed MessageSecretMessage proto"))?;
    if iv.len() != 12 {
        return Err(anyhow!("msmsg: unexpected IV length {}", iv.len()));
    }

    // Derive: secret → bot-message HKDF → per-message AES key + AAD.
    let derived = apply_bot_message_hkdf(&secret);

    // origMsgSender (us) and modSender (bot) need to be the NonAD form.
    // `target_sender_jid` is whatever the bot tagged — usually our JID
    // already in NonAD form, but normalise to be safe.
    let our_non_ad = if target_sender_jid.is_empty() {
        to_non_ad(our_jid)
    } else {
        to_non_ad(&target_sender_jid)
    };
    let bot_non_ad = to_non_ad(bot_jid);

    let (aes_key, aad) = generate_msg_secret_key(
        bot_reply_msg_id,
        &our_non_ad,
        &bot_non_ad,
        &derived,
    );

    // Verbose key-derivation dump kept at `debug!` — leaks every
    // byte we'd need to re-create the AES key, so production logs
    // shouldn't capture it. Operators chasing a decryption regression
    // can flip the `wa::bot_decrypt` target to debug.
    debug!(
        target: "wa::bot_decrypt",
        bot_reply_msg_id = %bot_reply_msg_id,
        target_id = %target_id,
        our_jid_arg = %our_jid,
        target_sender_jid = %target_sender_jid,
        our_non_ad = %our_non_ad,
        bot_non_ad = %bot_non_ad,
        secret_hex = %hex::encode(&secret),
        derived_hex = %hex::encode(derived),
        aes_key_hex = %hex::encode(aes_key),
        aad_hex = %hex::encode(&aad),
        iv_hex = %hex::encode(&iv),
        payload_len = payload.len(),
        "derivation inputs"
    );

    // AES-GCM decrypt.
    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .context("msmsg: build AES-GCM cipher")?;
    let nonce = Nonce::from_slice(&iv);
    let plaintext = cipher
        .decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: &payload,
                aad: &aad,
            },
        )
        .map_err(|e| anyhow!("msmsg: AES-GCM decrypt: {e}"))?;

    // Meta AI wraps each reply chunk in a `ProtocolMessage` (field
    // 12 of WAProto.Message) with `type = MESSAGE_EDIT (14)` and the
    // actual reply Message in `editedMessage` (field 14 of
    // ProtocolMessage). Each chunk REPLACES the previous one — this
    // is the streaming-token UX you see in the WA app. The recv
    // pipeline's `decode_plaintext` doesn't drill into ProtocolMessage
    // for text, so we unwrap here and return the inner Message bytes
    // to the caller. The recv path then decodes those bytes through
    // its normal text extraction logic.
    let unwrapped = unwrap_protocol_edited_message(&plaintext).unwrap_or(plaintext);

    let pt_top_fields: Vec<u64> = parse_proto_fields(&unwrapped)
        .map(|f| {
            let mut v: Vec<u64> = f.keys().copied().collect();
            v.sort_unstable();
            v
        })
        .unwrap_or_default();
    let pt_preview = if unwrapped.len() > 80 {
        hex::encode(&unwrapped[..80])
    } else {
        hex::encode(&unwrapped)
    };
    info!(
        target: "wa::bot_decrypt",
        bot = %bot_jid,
        bot_reply_msg_id = %bot_reply_msg_id,
        target_id = %target_id,
        plaintext_len = unwrapped.len(),
        "msmsg decrypted ✓"
    );
    debug!(
        target: "wa::bot_decrypt",
        plaintext_top_fields = ?pt_top_fields,
        plaintext_first_80b_hex = %pt_preview,
        "msmsg payload preview"
    );
    Ok(unwrapped)
}

/// If the plaintext is a `Message { protocolMessage { editedMessage }
/// }` envelope (which is how Meta AI streams its replies), return the
/// inner `editedMessage` bytes. Otherwise return `None` so the caller
/// keeps the plaintext as-is.
///
/// Field numbers: outer `Message.protocolMessage = 12`,
/// `ProtocolMessage.editedMessage = 14`.
fn unwrap_protocol_edited_message(plaintext: &[u8]) -> Option<Vec<u8>> {
    let outer_fields = parse_proto_fields(plaintext)?;
    let proto_msg = outer_fields.get(&12)?;
    let proto_fields = parse_proto_fields(proto_msg)?;
    let edited = proto_fields.get(&14)?;
    Some(edited.clone())
}

/// Walk the `<message>` children for the `<bot>` node and pull
/// `edit` + `edit_target_id` attrs. Returns `None` when the node
/// or attrs are missing — the caller falls back to the stanza id.
fn find_bot_attrs(node: &BinaryNode) -> Option<(String, String)> {
    use crate::binary::NodeContent;
    let children = match &node.content {
        NodeContent::List(c) => c,
        _ => return None,
    };
    for c in children {
        if c.tag == "bot" {
            let edit = c.attr("edit").unwrap_or("").to_string();
            let edit_target_id = c.attr("edit_target_id").unwrap_or("").to_string();
            return Some((edit, edit_target_id));
        }
    }
    None
}

/// Walk the `<message>` children for the `<meta>` node and pull
/// `target_id` + `target_sender_jid` attrs. Returns `None` if the
/// node doesn't exist or the attrs are missing.
fn find_meta_attrs(node: &BinaryNode) -> Option<(String, String)> {
    use crate::binary::NodeContent;
    let children = match &node.content {
        NodeContent::List(c) => c,
        _ => return None,
    };
    // Diagnostic — log every child tag + every attr on each child
    // so we can verify the stanza shape against what whatsmeow's
    // parseMsgMetaInfo expects. `debug!` so production logs stay
    // tidy; flip the target to debug when investigating regressions.
    if tracing::enabled!(target: "wa::bot_decrypt", tracing::Level::DEBUG) {
        let mut tags: Vec<String> = Vec::new();
        for c in children {
            tags.push(c.tag.clone());
            if c.tag == "meta" || c.tag == "bot" {
                let attrs_dump: Vec<String> = c
                    .attrs
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect();
                debug!(
                    target: "wa::bot_decrypt",
                    tag = %c.tag,
                    attrs = ?attrs_dump,
                    "stanza child"
                );
            }
        }
        debug!(
            target: "wa::bot_decrypt",
            children_tags = ?tags,
            "top-level children of <message>"
        );
    }
    for c in children {
        if c.tag == "meta" {
            let target_id = c.attr("target_id").unwrap_or("").to_string();
            let target_sender = c.attr("target_sender_jid").unwrap_or("").to_string();
            if !target_id.is_empty() {
                return Some((target_id, target_sender));
            }
        }
    }
    None
}

// ── Diagnostics for the experiment ────────────────────────────────

/// One-shot startup banner so operators see at-a-glance whether the
/// experiment is live. Called once from `MessageReceiver::new`.
pub fn log_state_at_boot() {
    if enabled() {
        warn!(
            target: "wa::bot_decrypt",
            "bot_decrypt: ACTIVE — capturing messageSecret on outbound, decrypting msmsg on inbound from @bot"
        );
    } else {
        debug!(
            target: "wa::bot_decrypt",
            "bot_decrypt: disabled (set WA_BOT_DECRYPT=1 to enable Meta AI msmsg decryption)"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_ad_strips_device_suffix() {
        assert_eq!(to_non_ad("573144347358:46@s.whatsapp.net"), "573144347358@s.whatsapp.net");
        assert_eq!(to_non_ad("718584497008509@bot"), "718584497008509@bot");
        assert_eq!(to_non_ad("plain"), "plain");
    }

    #[test]
    fn store_evicts_oldest_when_full() {
        // Best-effort smoke — global state, run last.
        for i in 0..(MAX_ENTRIES + 5) {
            put_secret(&format!("c{i}@bot"), "m", vec![i as u8; 32]);
        }
        // Earliest entries should have been evicted.
        assert!(get_secret("c0@bot", "m").is_none());
        assert!(get_secret(&format!("c{}@bot", MAX_ENTRIES + 4), "m").is_some());
    }

    #[test]
    fn bot_message_hkdf_deterministic() {
        let secret = [7u8; 32];
        let a = apply_bot_message_hkdf(&secret);
        let b = apply_bot_message_hkdf(&secret);
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn msmsg_proto_round_trip() {
        // Hand-build: field 2 (bytes) = "iv", field 3 (bytes) = "payload".
        let mut buf = Vec::new();
        // tag=2, wire=2 (length-delimited)
        buf.push((2 << 3) | 2);
        buf.push(2); // len
        buf.extend_from_slice(b"iv");
        buf.push((3 << 3) | 2);
        buf.push(7); // len
        buf.extend_from_slice(b"payload");
        let (iv, payload) = parse_msmsg_envelope(&buf).expect("parse");
        assert_eq!(iv, b"iv");
        assert_eq!(payload, b"payload");
    }
}
