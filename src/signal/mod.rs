pub mod ratchet;
pub mod sender_key;
pub mod wa_proto;
pub mod x3dh;

use crate::auth::credentials::{AuthCredentials, KeyPair, SignedKeyPair};
use crate::auth::session_store::SessionStore;
use crate::signal::ratchet::{RatchetMessage, RatchetSession, RatchetSnapshot};
use crate::signal::wa_proto::{
    decode_pre_key_message, decode_signal_header, encode_signal_header,
};
use crate::signal::x3dh::{x3dh_receiver, PreKeyBundle, PreKeyMessage};
use anyhow::{bail, Result};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use tracing::{debug, warn};

/// Signal Protocol message version prefix. High nibble = current, low = minimum.
/// WhatsApp uses Signal v3 → `0x33`.
const SIGNAL_VERSION: u8 = 0x33;

// ── Serde helpers for session persistence ────────────────────────────────────

#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedChain {
    key: Vec<u8>,
    index: u32,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedSkipped {
    rk: Vec<u8>,
    idx: u32,
    mk: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedEntry {
    /// Legacy field — older on-disk sessions stored a 66-byte direction-
    /// specific AD. Ignored on load (we key MAC by `peer_identity` now).
    #[serde(default, skip_serializing)]
    ad: Option<Vec<u8>>,
    /// Peer's identity public key (32 bytes). Added after the direction-aware
    /// MAC fix; sessions persisted before that land with `None` and must be
    /// recreated.
    #[serde(default)]
    peer_identity: Option<Vec<u8>>,
    root_key: Vec<u8>,
    send_chain: PersistedChain,
    recv_chain: Option<PersistedChain>,
    dh_send_pub: Vec<u8>,
    dh_send_priv: Vec<u8>,
    dh_recv: Option<Vec<u8>>,
    prev_send_count: u32,
    skipped: Vec<PersistedSkipped>,
    /// Pre-key info saved on sender-side until the first outgoing encrypt
    /// wraps it into a pkmsg. Persisted so a restart doesn't lose it.
    #[serde(default)]
    pending_pre_key: Option<PersistedPendingPreKey>,
    #[serde(default)]
    init_base_key: Option<Vec<u8>>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedPendingPreKey {
    base_key_pub: Vec<u8>,
    signed_pre_key_id: u32,
    pre_key_id: Option<u32>,
    registration_id: u32,
}

// ── SessionEntry ──────────────────────────────────────────────────────────────

struct SessionEntry {
    session: RatchetSession,
    /// The remote peer's identity key (pub). Kept instead of a pre-baked AD
    /// because libsignal's MAC over `senderIdentity || receiverIdentity || wire`
    /// is direction-aware: the sender's identity comes first, so encrypt and
    /// decrypt must build opposite orderings. A single cached AD can only
    /// serve one direction; bug symptom was the peer-side MAC failing on our
    /// echo even though the ratchet state was correct.
    peer_identity: [u8; 32],
    /// Pre-key data we need to carry until the first outgoing encrypt, after
    /// which the peer knows our session and we can switch to regular Whisper
    /// messages. `None` once the session is established.
    pending_pre_key: Option<PendingPreKey>,
    /// Receiver-side: the peer's X3DH base key (from the pkmsg that created
    /// this session). If a duplicate pkmsg arrives with the same base key —
    /// Signal's canonical "peer didn't see our ack, retrying" path —
    /// re-running X3DH would derive a divergent root and the new session
    /// wouldn't match the peer. Libsignal handles this by indexing session
    /// states by baseKey and reusing the matching one. We do the same.
    init_base_key: Option<[u8; 32]>,
}

#[derive(Clone, Debug)]
struct PendingPreKey {
    /// Our ephemeral key that was used in X3DH. Becomes `baseKey` in
    /// the PreKeySignalMessage the peer needs to reconstruct the session.
    base_key_pub: [u8; 32],
    signed_pre_key_id: u32,
    /// Only set when the peer's one-time pre-key was consumed.
    pre_key_id: Option<u32>,
    /// Our registration id — goes into the PreKeySignalMessage so the peer
    /// can identify our device.
    registration_id: u32,
}

// ── SignalRepository ──────────────────────────────────────────────────────────

pub struct SignalRepository {
    identity: KeyPair,
    signed_pre_key: SignedKeyPair,
    #[allow(dead_code)]
    registration_id: u16,
    /// Server-signed device identity blob. Attached as `<device-identity>`
    /// inside every outgoing pkmsg stanza.
    account_enc: Vec<u8>,
    sessions: Arc<Mutex<HashMap<String, SessionEntry>>>,
    sender_keys: Arc<Mutex<sender_key::SenderKeyStore>>,
    store: Arc<dyn SessionStore>,
    pkmsg_count: Arc<AtomicU32>,
    /// Bidirectional LID↔PN bare-user aliases learned from incoming stanza
    /// attrs. Lets session lookup fall back across LID/PN addressings so a
    /// single actual session state serves both identities and we don't
    /// diverge with the peer.
    ///
    /// Stored bidirectionally keyed by bare user jid (no `:device` slot).
    /// Example entries:
    ///   "168001974309057@lid"          ↔ "573154645370@s.whatsapp.net"
    jid_alias: Arc<Mutex<HashMap<String, String>>>,
}

pub struct EncryptedMessage {
    pub ciphertext: Vec<u8>,
    pub msg_type: &'static str,
}

#[allow(dead_code)]
impl SignalRepository {
    pub fn new(creds: &AuthCredentials, store: Arc<dyn SessionStore>) -> Self {
        let sessions = load_sessions_from_store(store.as_ref());
        let sender_keys = store.load_sender_keys()
            .ok()
            .flatten()
            .map(|b| sender_key::SenderKeyStore::from_bytes(&b))
            .unwrap_or_default();
        // Rehydrate the LID↔PN alias map so a restart doesn't lose the
        // mappings we learned from `sender_pn` stanzas. Critical when the
        // first incoming msg after a restart is from a LID-addressed peer
        // before any fresh stanza teaches us the mapping again.
        let jid_alias = store.load_jid_alias()
            .ok()
            .flatten()
            .and_then(|b| serde_json::from_slice::<HashMap<String, String>>(&b).ok())
            .unwrap_or_default();
        Self {
            identity: creds.signed_identity_key.clone(),
            signed_pre_key: creds.signed_pre_key.clone(),
            registration_id: creds.registration_id,
            account_enc: creds.account_enc.clone(),
            sessions: Arc::new(Mutex::new(sessions)),
            sender_keys: Arc::new(Mutex::new(sender_keys)),
            store,
            pkmsg_count: Arc::new(AtomicU32::new(0)),
            jid_alias: Arc::new(Mutex::new(jid_alias)),
        }
    }

    /// Record a LID↔PN equivalence so session lookups can fall back across
    /// addressings. Bidirectional — inserts both directions. Keyed by bare
    /// user jid (no `:device` slot).
    ///
    /// Also drops any sessions keyed under the LID side (`@lid`). The PN
    /// session is the one our outgoing sends advance, so the peer's
    /// expected `our_dh_send_pub` aligns with PN session state. Any parallel
    /// LID session is by definition divergent — keeping it causes every
    /// incoming LID-addressed message to MAC-fail. Dropping it lets
    /// `resolve_session_key` fall through the alias and decrypt with the
    /// correct PN session. If the peer needs to re-establish, they'll
    /// re-send via pkmsg which lands under PN via `resolve_session_key`.
    pub fn set_jid_alias(&self, a: &str, b: &str) {
        {
            let mut map = match self.jid_alias.lock() { Ok(m) => m, Err(_) => return };
            let existed_a = map.get(a).map(|v| v == b).unwrap_or(false);
            let existed_b = map.get(b).map(|v| v == a).unwrap_or(false);
            map.insert(a.to_string(), b.to_string());
            map.insert(b.to_string(), a.to_string());
            if !existed_a || !existed_b {
                // Persist on real change only — avoids disk I/O on every recv.
                if let Ok(data) = serde_json::to_vec(&*map) {
                    let _ = self.store.save_jid_alias(&data);
                }
            }
        }
        // Determine which side is LID (if any) and drop all its sessions.
        let lid_bare = if a.ends_with("@lid") { Some(a) }
            else if b.ends_with("@lid") { Some(b) }
            else { None };
        if let Some(lid) = lid_bare {
            if let Ok(mut sessions) = self.sessions.lock() {
                let (user, server) = match lid.find('@') {
                    Some(i) => (&lid[..i], &lid[i..]),
                    None => return,
                };
                let victims: Vec<String> = sessions
                    .keys()
                    .filter(|k| {
                        match k.find('@') {
                            Some(i) => {
                                let (left, srv) = (&k[..i], &k[i..]);
                                let ku = left.split(':').next().unwrap_or(left);
                                ku == user && srv == server
                            }
                            None => false,
                        }
                    })
                    .cloned()
                    .collect();
                for v in victims {
                    tracing::info!("set_jid_alias: dropping divergent LID session {v}");
                    sessions.remove(&v);
                }
            }
        }
    }

    /// Return the alias of a bare user jid if known.
    fn aliased_bare(&self, bare_jid: &str) -> Option<String> {
        self.jid_alias.lock().ok()?.get(bare_jid).cloned()
    }

    /// Public accessor: LID↔PN alias of a bare user jid. Returns `None` if
    /// no mapping has been learned yet. Used by higher layers (Chat,
    /// Session) to unify peer identity across addressings.
    pub fn alias_of(&self, bare_jid: &str) -> Option<String> {
        self.aliased_bare(bare_jid)
    }

    /// Translate a canonical session jid into the best-known session key.
    /// Preference order:
    ///   1. the jid as-is if a session exists;
    ///   2. any session under the LID/PN alias (same user, different server);
    ///   3. the jid as-is (caller will get `no session` error).
    fn resolve_session_key(&self, canonical: &str) -> String {
        let sessions = match self.sessions.lock() {
            Ok(m) => m,
            _ => return canonical.to_string(),
        };
        if sessions.contains_key(canonical) {
            return canonical.to_string();
        }
        // Try the aliased bare jid, preserving the device slot.
        let (user, server, device) = split_user_server_device(canonical);
        let bare = format!("{user}{server}");
        drop(sessions);
        if let Some(alt_bare) = self.aliased_bare(&bare) {
            let sessions = match self.sessions.lock() {
                Ok(m) => m,
                _ => return canonical.to_string(),
            };
            // Try exact alt device first, then fall back to any device under alt user.
            let alt_exact = match device {
                Some(d) => format!(
                    "{}:{d}{}",
                    alt_bare.split('@').next().unwrap_or(""),
                    alt_bare.find('@').map(|i| &alt_bare[i..]).unwrap_or(""),
                ),
                None => alt_bare.clone(),
            };
            if sessions.contains_key(&alt_exact) {
                return alt_exact;
            }
            let (alt_user, alt_server) = match alt_bare.find('@') {
                Some(i) => (&alt_bare[..i], &alt_bare[i..]),
                None => return canonical.to_string(),
            };
            for k in sessions.keys() {
                if let Some(at) = k.find('@') {
                    let (left, srv) = (&k[..at], &k[at..]);
                    let ku = left.split(':').next().unwrap_or(left);
                    if ku == alt_user && srv == alt_server {
                        return k.clone();
                    }
                }
            }
        }
        canonical.to_string()
    }

    pub fn account_identity_bytes(&self) -> &[u8] { &self.account_enc }

    pub fn registration_id(&self) -> u16 { self.registration_id }

    pub fn drop_session(&self, jid: &str) {
        self.sessions.lock().unwrap().remove(jid);
    }

    /// Drop every session belonging to a user, across all device slots and
    /// across both LID and PN addressings (via the alias map). Used as a
    /// last-resort auto-recovery when decrypt-retry-with-keys doesn't
    /// unstick the peer: by clearing our local state we force our next
    /// outgoing send to fetch fresh prekeys and X3DH from scratch, and
    /// the peer's next send will no longer match our (empty) session so
    /// our retry-receipt-with-keys path takes over.
    ///
    /// `user_jid` is the bare user jid (no `:device` slot). Both the user
    /// itself and its aliased counterpart are cleared.
    pub fn drop_sessions_for_user(&self, user_jid: &str) -> usize {
        let mut targets: Vec<String> = vec![user_jid.to_string()];
        if let Some(alt) = self.aliased_bare(user_jid) {
            targets.push(alt);
        }
        let mut victims = Vec::new();
        if let Ok(sessions) = self.sessions.lock() {
            for key in sessions.keys() {
                let (user, server, _) = split_user_server_device(key);
                let bare = format!("{user}{server}");
                if targets.iter().any(|t| t == &bare) {
                    victims.push(key.clone());
                }
            }
        }
        if victims.is_empty() {
            return 0;
        }
        if let Ok(mut sessions) = self.sessions.lock() {
            for v in &victims {
                sessions.remove(v);
                tracing::info!("drop_sessions_for_user: removed {v}");
            }
        }
        // Persist the purge so a daemon restart doesn't revive stale state.
        if let Ok(sessions) = self.sessions.lock() {
            let map: HashMap<String, PersistedEntry> = sessions.iter()
                .filter_map(|(jid, e)| {
                    let snap = e.session.snapshot();
                    Some((jid.clone(), PersistedEntry {
                        ad: None,
                        peer_identity: Some(e.peer_identity.to_vec()),
                        root_key: snap.root_key.to_vec(),
                        send_chain: PersistedChain { key: snap.send_chain_key.to_vec(), index: snap.send_chain_index },
                        recv_chain: snap.recv_chain_key.map(|k| PersistedChain { key: k.to_vec(), index: snap.recv_chain_index.unwrap_or(0) }),
                        dh_send_pub: snap.dh_send_pub.to_vec(),
                        dh_send_priv: snap.dh_send_priv.to_vec(),
                        dh_recv: snap.dh_recv.map(|k| k.to_vec()),
                        prev_send_count: snap.prev_send_count,
                        skipped: snap.skipped.iter().map(|(rk, idx, mk)| PersistedSkipped { rk: rk.to_vec(), idx: *idx, mk: mk.to_vec() }).collect(),
                        pending_pre_key: e.pending_pre_key.as_ref().map(|p| PersistedPendingPreKey {
                            base_key_pub: p.base_key_pub.to_vec(),
                            signed_pre_key_id: p.signed_pre_key_id,
                            pre_key_id: p.pre_key_id,
                            registration_id: p.registration_id,
                        }),
                        init_base_key: e.init_base_key.map(|b| b.to_vec()),
                    }))
                })
                .collect();
            if let Ok(data) = serde_json::to_vec(&map) {
                let _ = self.store.save_all_sessions(&data);
            }
        }
        victims.len()
    }

    pub fn identity_public(&self) -> &[u8; 32] { &self.identity.public }

    /// Signed pre-key for retry receipts: (keyId, pub32, signature64).
    pub fn signed_prekey_fields(&self) -> (u32, [u8; 32], Vec<u8>) {
        (
            self.signed_pre_key.key_id,
            self.signed_pre_key.key_pair.public,
            self.signed_pre_key.signature.to_vec(),
        )
    }

    /// Pick any remaining one-time pre-key on disk for a retry receipt.
    /// Returns (keyId, pub32). Does not consume — the sender will trigger
    /// a pkmsg that consumes it via the normal decrypt path. `None` if
    /// no usable OTK is available.
    pub fn pick_unused_prekey(&self) -> Option<(u32, [u8; 32])> {
        // Walk ids downward from the most-recently-generated batch.
        // upload_pre_keys uses ids 1.. in batches of 30, writing zeroed
        // bytes on consumption. Scan a reasonable window.
        for id in (1..=2000u32).rev() {
            if let Ok(Some(bytes)) = self.store.load_prekey(id) {
                if bytes.len() == 64 && bytes[..32] != [0u8; 32] {
                    let mut pub_b = [0u8; 32];
                    pub_b.copy_from_slice(&bytes[32..64]);
                    return Some((id, pub_b));
                }
            }
        }
        None
    }

    pub fn pkmsg_count(&self) -> u32 {
        self.pkmsg_count.load(Ordering::Relaxed)
    }

    /// Build the WAProto.Message bytes (field 35 SKDM) to distribute to a group participant.
    pub fn get_skdm_proto(&self, group_jid: &str) -> Vec<u8> {
        let mut sk = self.sender_keys.lock().expect("sender_keys");
        let own = sk.get_or_create_own(group_jid);
        let axolotl = wa_proto::encode_axolotl_skdm(own.key_id, own.iteration, &own.chain_key, &own.signing_pub);
        let key_id = own.key_id;
        let iteration = own.iteration;
        drop(sk);
        let proto = wa_proto::encode_wa_skdm_message(group_jid, &axolotl);
        debug!(
            "skdm proto: group={} key_id={} iteration={} axolotl_len={} wa_len={}",
            group_jid,
            key_id,
            iteration,
            axolotl.len(),
            proto.len(),
        );
        proto
    }

    /// Encrypt `plaintext` as a SenderKey message for `group_jid`.
    /// Returns the final skmsg wire bytes (version | proto | signature).
    pub async fn encrypt_group_message(&self, group_jid: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        // Derive message keys and encrypt
        let (key_id, iteration, chain_key, signing_priv) = {
            let mut sk = self.sender_keys.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
            sk.encrypt_own(group_jid)
        };

        use crate::signal::sender_key::expand_message_keys_pub;
        let (iv, cipher_key, _mac_key) = expand_message_keys_pub(&chain_key)?;
        use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
        use aes::Aes256;
        let enc = cbc::Encryptor::<Aes256>::new_from_slices(&cipher_key, &iv)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let ciphertext = enc.encrypt_padded_vec_mut::<Pkcs7>(plaintext);
        debug!(
            "group encrypt: group={} key_id={} iteration={} plaintext_len={} ciphertext_len={}",
            group_jid,
            key_id,
            iteration,
            plaintext.len(),
            ciphertext.len(),
        );

        // Persist updated chain
        let bytes = self.sender_keys.lock().map_err(|e| anyhow::anyhow!("{e}"))?.to_bytes();
        if let Err(e) = self.store.save_sender_keys(&bytes) {
            warn!("save_sender_keys: {e}");
        }
        Ok(wa_proto::encode_skmsg_signed(key_id, iteration, &ciphertext, &signing_priv))
    }

    pub fn mark_skdm_distributed(&self, group_jid: &str, participant_jid: &str) {
        let mut sk = self.sender_keys.lock().expect("sender_keys");
        sk.mark_distributed(group_jid, participant_jid);
        let bytes = sk.to_bytes();
        drop(sk);
        let _ = self.store.save_sender_keys(&bytes);
    }

    pub fn is_skdm_distributed(&self, group_jid: &str, participant_jid: &str) -> bool {
        let sk = self.sender_keys.lock().expect("sender_keys");
        sk.is_distributed(group_jid, participant_jid)
    }

    /// Store a SenderKey received via SKDM (call after decrypting the 1:1 wrapper).
    pub fn process_sender_key_distribution(
        &self,
        sender_jid: &str,
        group_jid: &str,
        iteration: u32,
        chain_key: [u8; 32],
    ) {
        let mut sk = self.sender_keys.lock().expect("sender_keys");
        sk.process_skdm(sender_jid, group_jid, iteration, chain_key);
        let bytes = sk.to_bytes();
        drop(sk);
        if let Err(e) = self.store.save_sender_keys(&bytes) {
            warn!("save_sender_keys: {e}");
        }
    }

    /// Decrypt a group SenderKey message.
    pub async fn decrypt_sender_key_message(
        &self,
        sender_jid: &str,
        group_jid: &str,
        iteration: u32,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let mut sk = self.sender_keys.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        let plaintext = sk.decrypt(sender_jid, group_jid, iteration, ciphertext)?;
        let bytes = sk.to_bytes();
        drop(sk);
        if let Err(e) = self.store.save_sender_keys(&bytes) {
            warn!("save_sender_keys: {e}");
        }
        Ok(plaintext)
    }

    pub fn sign(&self, data: &[u8]) -> [u8; 64] {
        use ed25519_dalek::{Signer, SigningKey};
        let sk = SigningKey::from_bytes(&self.identity.private);
        sk.sign(data).to_bytes()
    }

    pub async fn encrypt_message(&self, jid: &str, plaintext: &[u8]) -> Result<EncryptedMessage> {
        let jid = canonical_session_jid(jid);
        let jid = jid.as_str();
        let mut sessions = self.sessions.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        let entry = sessions
            .get_mut(jid)
            .ok_or_else(|| anyhow::anyhow!("no Signal session for {jid}"))?;
        // Encrypt direction: we are sender, peer is receiver.
        let ad_encrypt = make_ad(&self.identity.public, &entry.peer_identity);
        let msg = entry.session.encrypt(plaintext, &ad_encrypt)?;
        let inner_wire = encode_signal_wire(&msg)?;

        // If this is the first outgoing on the session, wrap it in a
        // PreKeySignalMessage so the peer can derive the session; otherwise
        // just use the Whisper ("msg") form.
        let (wire, msg_type) = if let Some(pk) = entry.pending_pre_key.take() {
            let wrapped = encode_pre_key_signal_message(
                &pk,
                &self.identity.public,
                &inner_wire,
            );
            (wrapped, "pkmsg")
        } else {
            (inner_wire, "msg")
        };

        let peer_identity = entry.peer_identity;
        let snap = entry.session.snapshot();
        drop(sessions);
        self.persist_session(jid, &peer_identity, &snap);
        Ok(EncryptedMessage { ciphertext: wire, msg_type })
    }

    pub async fn decrypt_message(
        &self,
        jid: &str,
        ciphertext: &[u8],
        msg_type: &str,
    ) -> Result<Vec<u8>> {
        let jid = canonical_session_jid(jid);
        match msg_type {
            "pkmsg" => self.decrypt_pre_key_message(&jid, ciphertext),
            "msg" => self.decrypt_normal_message(&jid, ciphertext),
            other => bail!("unknown msg type: {other}"),
        }
    }

    pub fn create_sender_session(&self, jid: &str, bundle: &PreKeyBundle) -> Result<Vec<u8>> {
        let jid = canonical_session_jid(jid);
        let jid = jid.as_str();
        let result = x3dh::x3dh_sender(&self.identity, bundle);
        let session = RatchetSession::init_sender(
            result.root_key,
            result.chain_key,
            bundle.signed_pre_key,
        );
        let peer_identity = bundle.identity_key;
        let snap = session.snapshot();
        let pending = PendingPreKey {
            base_key_pub: result.ephemeral_key.public,
            signed_pre_key_id: bundle.signed_pre_key_id,
            pre_key_id: bundle.one_time_pre_key_id,
            registration_id: self.registration_id as u32,
        };
        self.sessions
            .lock()
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .insert(jid.to_string(), SessionEntry {
                session,
                peer_identity,
                pending_pre_key: Some(pending),
                init_base_key: None,
            });
        self.persist_session(jid, &peer_identity, &snap);
        Ok(result.ephemeral_key.public.to_vec())
    }

    pub fn has_session(&self, jid: &str) -> bool {
        let jid = canonical_session_jid(jid);
        self.sessions.lock().map(|s| s.contains_key(&jid)).unwrap_or(false)
    }

    /// Return all session-store JIDs whose user part matches `user_jid`'s
    /// user part, ignoring device slot. Useful for LID resolution: when a
    /// message arrives as `X@lid` and we only have PN-keyed device sessions,
    /// try each candidate.
    pub fn sibling_jids(&self, user_jid: &str) -> Vec<String> {
        let (user, server) = split_user_server(user_jid);
        self.sessions
            .lock()
            .map(|s| {
                s.keys()
                    .filter(|k| {
                        let (u, sv) = split_user_server(k);
                        u == user && sv == server
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Try `decrypt_message` against a list of candidate JIDs and return
    /// the plaintext + the JID that successfully decrypted. Used for LID
    /// addressing where the stanza JID doesn't identify the device that
    /// encrypted the payload.
    pub async fn decrypt_with_candidates(
        &self,
        candidates: &[String],
        ciphertext: &[u8],
        msg_type: &str,
    ) -> Result<(Vec<u8>, String)> {
        let mut last_err: Option<anyhow::Error> = None;
        for jid in candidates {
            match self.decrypt_message(jid, ciphertext, msg_type).await {
                Ok(pt) => return Ok((pt, jid.clone())),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no candidates")))
    }
}

/// `"1234:5@lid" → ("1234", "lid")`, `"1234@s.whatsapp.net" → ("1234", "s.whatsapp.net")`.
fn split_user_server(jid: &str) -> (&str, &str) {
    let (left, server) = jid.split_once('@').unwrap_or((jid, ""));
    let user = left.split_once(':').map(|(u, _)| u).unwrap_or(left);
    (user, server)
}

/// Canonicalize a jid for session keying: device `:0` ≡ bare (Baileys'
/// `jidEncode` omits `:0` because it's the primary device). Keeping them as
/// separate session entries makes pkmsg-from-bare and fanout-to-`:0` use
/// different sessions for the same peer device — the peer accepts only one,
/// so the other diverges and MAC fails on the next round-trip.
fn canonical_session_jid(jid: &str) -> String {
    let Some(at) = jid.find('@') else { return jid.to_string() };
    let (left, server) = (&jid[..at], &jid[at..]);
    match left.split_once(':') {
        Some((user, "0")) => format!("{}{}", user, server),
        _ => jid.to_string(),
    }
}

/// `(user, server, device)` split. `"A:7@lid" → ("A", "@lid", Some(7))`.
/// `"A@s.whatsapp.net" → ("A", "@s.whatsapp.net", None)`.
fn split_user_server_device(jid: &str) -> (String, String, Option<u32>) {
    let Some(at) = jid.find('@') else {
        return (jid.to_string(), String::new(), None);
    };
    let (left, server) = (&jid[..at], &jid[at..]);
    let (user, device) = match left.split_once(':') {
        Some((u, d)) => (u.to_string(), d.parse().ok()),
        None => (left.to_string(), None),
    };
    (user, server.to_string(), device)
}

// ── Decrypt ───────────────────────────────────────────────────────────────────

impl SignalRepository {
    fn decrypt_normal_message(&self, jid: &str, data: &[u8]) -> Result<Vec<u8>> {
        let (msg, _) = decode_signal_wire(data)?;
        // Resolve LID↔PN alias. A LID-addressed stanza doesn't tell us which
        // PN device actually encrypted, so first try the jid we'd normally
        // pick — if MAC fails, walk every session under the alias user and
        // try each. Matches whatsmeow's per-device fallback for migrated
        // sessions.
        let primary = self.resolve_session_key(jid);
        let mut candidates: Vec<String> = vec![primary.clone()];
        // Add sibling sessions under the aliased user (other device slots).
        let (user, server, _) = split_user_server_device(&primary);
        let bare = format!("{user}{server}");
        if let Ok(sessions) = self.sessions.lock() {
            for k in sessions.keys() {
                if k == &primary { continue; }
                let (ku, ks, _) = split_user_server_device(k);
                if format!("{ku}{ks}") == bare {
                    candidates.push(k.clone());
                }
            }
        }
        tracing::info!(
            "decrypt msg: jid={jid} primary={primary} candidates={candidates:?}"
        );
        let mut last_err: Option<anyhow::Error> = None;
        for candidate in &candidates {
            match self.decrypt_normal_for_jid(candidate, &msg, data) {
                Ok(pt) => {
                    if candidate != &primary {
                        tracing::info!(
                            "decrypt msg: primary {primary} MAC-failed, sibling {candidate} decrypted OK"
                        );
                    } else if primary != jid {
                        tracing::debug!("decrypt msg: resolved {jid} → {primary} via alias");
                    }
                    return Ok(pt);
                }
                Err(e) => {
                    tracing::info!(
                        "decrypt msg: candidate {candidate} failed: {e}"
                    );
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no sessions for {jid}")))
    }

    fn decrypt_normal_for_jid(
        &self,
        jid: &str,
        msg: &RatchetMessage,
        _data: &[u8],
    ) -> Result<Vec<u8>> {
        let mut sessions = self.sessions.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        let session_keys: Vec<String> = sessions.keys().cloned().collect();
        let entry = sessions
            .get_mut(jid)
            .ok_or_else(|| anyhow::anyhow!("no session for {jid} (have: {session_keys:?})"))?;
        tracing::debug!(
            "decrypt msg: jid={} ratchet_key_incoming={} counter={} prev_counter={}",
            jid, hex::encode(msg.ratchet_key), msg.counter, msg.prev_counter,
        );

        // Decrypt direction: peer is sender, we are receiver.
        let ad_decrypt = make_ad(&entry.peer_identity, &self.identity.public);
        // Snapshot before MAC check — state mutates before MAC verify.
        let pre_snap = entry.session.snapshot();
        if ratchet_dump_enabled() {
            dump_ratchet_state(
                jid, "pre",
                &entry.peer_identity, &self.identity.public,
                &pre_snap, &msg, &ad_decrypt, None,
            );
        }
        let result = entry.session.decrypt(&msg, &ad_decrypt);
        let plaintext = match result {
            Ok(pt) => pt,
            Err(e) => {
                if ratchet_dump_enabled() {
                    let post_snap = entry.session.snapshot();
                    dump_ratchet_state(
                        jid, "post-fail",
                        &entry.peer_identity, &self.identity.public,
                        &post_snap, &msg, &ad_decrypt, Some(&e.to_string()),
                    );
                }
                entry.session = RatchetSession::from_snapshot(pre_snap);
                return Err(e);
            }
        };
        let peer_identity = entry.peer_identity;
        let snap = entry.session.snapshot();
        if ratchet_dump_enabled() {
            dump_ratchet_state(
                jid, "post-ok",
                &entry.peer_identity, &self.identity.public,
                &snap, &msg, &ad_decrypt, None,
            );
        }
        drop(sessions);
        self.persist_session(jid, &peer_identity, &snap);
        Ok(plaintext)
    }

    fn decrypt_pre_key_message(&self, jid: &str, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() || data[0] != SIGNAL_VERSION {
            bail!("bad pre-key message version");
        }
        let pkm = decode_pre_key_message(&data[1..])
            .ok_or_else(|| anyhow::anyhow!("could not parse pre-key message"))?;

        tracing::info!(
            "decrypt_pkmsg: jid={} base_key={} identity={} signed_pre_key_id={} pre_key_id={:?}",
            jid,
            hex::encode(&pkm.base_key[..8]),
            hex::encode(&pkm.identity_key[..8]),
            pkm.signed_pre_key_id,
            pkm.pre_key_id,
        );

        // libsignal `HasSessionState(version, baseKey)`: if a session for
        // this peer already exists with the exact same X3DH baseKey, the
        // sender is re-delivering (didn't see our ack yet). Re-running X3DH
        // would pick a fresh (or zeroed, if already consumed) OTK and derive
        // a divergent root_key → guaranteed MAC fail. Reuse the existing
        // session: its recv chain has already advanced past counter 0, so
        // the retried message (typically counter ≥ 1) decrypts cleanly.
        {
            let mut sessions = self.sessions.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
            if let Some(entry) = sessions.get_mut(jid) {
                if entry.init_base_key == Some(pkm.base_key) {
                    tracing::info!(
                        "decrypt_pkmsg: reusing session for {jid} (base_key match — peer retry, skipping X3DH + OTK consume)"
                    );
                    let (msg, _) = decode_signal_wire(&pkm.message)?;
                    let ad_decrypt = make_ad(&entry.peer_identity, &self.identity.public);
                    let peer_identity = entry.peer_identity;
                    let pre_snap = entry.session.snapshot();
                    let result = entry.session.decrypt(&msg, &ad_decrypt);
                    let plaintext = match result {
                        Ok(pt) => pt,
                        Err(e) => {
                            entry.session = RatchetSession::from_snapshot(pre_snap);
                            return Err(e);
                        }
                    };
                    let snap = entry.session.snapshot();
                    drop(sessions);
                    self.persist_session(jid, &peer_identity, &snap);
                    return Ok(plaintext);
                }
                if let Some(prev_bk) = entry.init_base_key {
                    tracing::warn!(
                        "decrypt_pkmsg: fresh base_key for {jid} (prev={} new={}) — archiving old session, starting X3DH",
                        hex::encode(&prev_bk[..8]),
                        hex::encode(&pkm.base_key[..8]),
                    );
                }
            }
        }

        // Fresh session: load OTK (priv half must be non-zero to be usable).
        // libsignal only removes the OTK AFTER successful decrypt — we match
        // that so a MAC failure here doesn't leave a dangling zeroed slot.
        let (otk, otk_was_zeroed) = if let Some(kid) = pkm.pre_key_id {
            match self.store.load_prekey(kid) {
                Ok(Some(bytes)) if bytes.len() == 64 && bytes[..32] != [0u8; 32] => {
                    let mut priv_b = [0u8; 32];
                    let mut pub_b = [0u8; 32];
                    priv_b.copy_from_slice(&bytes[..32]);
                    pub_b.copy_from_slice(&bytes[32..64]);
                    (Some(KeyPair { private: priv_b, public: pub_b }), false)
                }
                Ok(Some(bytes)) if bytes.len() == 64 => {
                    // Already consumed (priv zeroed). Fresh baseKey + consumed
                    // OTK means we can't reproduce the peer's X3DH — MAC will
                    // fail. Log loudly; the session will not establish.
                    (None, true)
                }
                _ => {
                    debug!("OTK id={kid} not found");
                    (None, false)
                }
            }
        } else {
            (None, false)
        };

        let pre_msg = PreKeyMessage {
            identity_key: pkm.identity_key,
            ephemeral_key: pkm.base_key,
            signed_pre_key_id: pkm.signed_pre_key_id,
            one_time_pre_key_id: pkm.pre_key_id,
        };
        let (root_key, chain_key) = x3dh_receiver(
            &self.identity,
            &self.signed_pre_key.key_pair,
            otk.as_ref(),
            &pre_msg,
        );

        tracing::info!(
            "decrypt_pkmsg: x3dh_root={} x3dh_chain={} our_spk_pub={} otk_present={} otk_was_zeroed={}",
            hex::encode(&root_key[..8]),
            hex::encode(&chain_key[..8]),
            hex::encode(&self.signed_pre_key.key_pair.public[..8]),
            otk.is_some(),
            otk_was_zeroed,
        );
        let mut session = RatchetSession::init_receiver(
            root_key,
            chain_key,
            self.signed_pre_key.key_pair.clone(),
        );
        let peer_identity = pkm.identity_key;
        let ad_decrypt = make_ad(&peer_identity, &self.identity.public);
        let (msg, _) = decode_signal_wire(&pkm.message)?;
        let plaintext = session.decrypt(&msg, &ad_decrypt)?;

        // Decrypt succeeded — NOW consume the OTK (libsignal semantics).
        if let (Some(kid), true) = (pkm.pre_key_id, otk.is_some()) {
            let _ = self.store.save_prekey(kid, &[0u8; 64]);
        }

        let snap = session.snapshot();
        self.sessions
            .lock()
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .insert(jid.to_string(), SessionEntry {
                session,
                peer_identity,
                pending_pre_key: None,
                init_base_key: Some(pkm.base_key),
            });
        self.persist_session(jid, &peer_identity, &snap);
        self.pkmsg_count.fetch_add(1, Ordering::Relaxed);

        Ok(plaintext)
    }
}

// ── Persistence ───────────────────────────────────────────────────────────────

impl SignalRepository {
    fn persist_session(&self, jid: &str, peer_identity: &[u8; 32], snap: &RatchetSnapshot) {
        // Look up the still-in-memory entry so we can capture any
        // pending_pre_key / init_base_key before flushing to disk.
        let (pending, init_base_key) = self.sessions.lock().ok()
            .map(|m| {
                let e = m.get(jid);
                (
                    e.and_then(|e| e.pending_pre_key.as_ref().cloned()),
                    e.and_then(|e| e.init_base_key.map(|b| b.to_vec())),
                )
            })
            .unwrap_or((None, None));

        let entry = PersistedEntry {
            ad: None,
            peer_identity: Some(peer_identity.to_vec()),
            root_key: snap.root_key.to_vec(),
            send_chain: PersistedChain {
                key: snap.send_chain_key.to_vec(),
                index: snap.send_chain_index,
            },
            recv_chain: snap.recv_chain_key.map(|k| PersistedChain {
                key: k.to_vec(),
                index: snap.recv_chain_index.unwrap_or(0),
            }),
            dh_send_pub: snap.dh_send_pub.to_vec(),
            dh_send_priv: snap.dh_send_priv.to_vec(),
            dh_recv: snap.dh_recv.map(|k| k.to_vec()),
            prev_send_count: snap.prev_send_count,
            skipped: snap
                .skipped
                .iter()
                .map(|(rk, idx, mk)| PersistedSkipped {
                    rk: rk.to_vec(),
                    idx: *idx,
                    mk: mk.to_vec(),
                })
                .collect(),
            pending_pre_key: pending.map(|p| PersistedPendingPreKey {
                base_key_pub: p.base_key_pub.to_vec(),
                signed_pre_key_id: p.signed_pre_key_id,
                pre_key_id: p.pre_key_id,
                registration_id: p.registration_id,
            }),
            init_base_key,
        };

        // Load current bulk map, insert/update this entry, re-save
        let mut map: HashMap<String, PersistedEntry> =
            match self.store.load_all_sessions() {
                Ok(Some(data)) => serde_json::from_slice(&data).unwrap_or_default(),
                _ => HashMap::new(),
            };
        map.insert(jid.to_string(), entry);
        match serde_json::to_vec(&map) {
            Ok(data) => {
                if let Err(e) = self.store.save_all_sessions(&data) {
                    warn!("failed to persist session for {jid}: {e}");
                }
            }
            Err(e) => warn!("failed to serialize sessions: {e}"),
        }
    }
}

fn load_sessions_from_store(store: &dyn SessionStore) -> HashMap<String, SessionEntry> {
    let data = match store.load_all_sessions() {
        Ok(Some(d)) => d,
        _ => return HashMap::new(),
    };
    let map: HashMap<String, PersistedEntry> = match serde_json::from_slice(&data) {
        Ok(m) => m,
        Err(e) => {
            warn!("failed to load sessions: {e}");
            return HashMap::new();
        }
    };

    let mut out = HashMap::new();
    for (jid, p) in map {
        let snap = match persisted_to_snapshot(&p) {
            Some(s) => s,
            None => {
                warn!("skipping malformed session for {jid}");
                continue;
            }
        };
        let session = RatchetSession::from_snapshot(snap);
        let peer_identity: [u8; 32] = match p.peer_identity
            .as_ref()
            .and_then(|b| b.as_slice().try_into().ok())
        {
            Some(id) => id,
            None => {
                warn!("session for {jid} has no peer_identity — skipping (legacy pre-fix format, re-pair required)");
                continue;
            }
        };
        let pending = p.pending_pre_key.as_ref().and_then(|pp| {
            let base: [u8; 32] = pp.base_key_pub.as_slice().try_into().ok()?;
            Some(PendingPreKey {
                base_key_pub: base,
                signed_pre_key_id: pp.signed_pre_key_id,
                pre_key_id: pp.pre_key_id,
                registration_id: pp.registration_id,
            })
        });
        let init_base_key = p.init_base_key.as_ref()
            .and_then(|b| b.as_slice().try_into().ok());
        out.insert(jid, SessionEntry { session, peer_identity, pending_pre_key: pending, init_base_key });
    }
    debug!("loaded {} Signal sessions from disk", out.len());
    out
}

fn persisted_to_snapshot(p: &PersistedEntry) -> Option<RatchetSnapshot> {
    Some(RatchetSnapshot {
        root_key: p.root_key.as_slice().try_into().ok()?,
        send_chain_key: p.send_chain.key.as_slice().try_into().ok()?,
        send_chain_index: p.send_chain.index,
        recv_chain_key: p
            .recv_chain
            .as_ref()
            .and_then(|c| c.key.as_slice().try_into().ok()),
        recv_chain_index: p.recv_chain.as_ref().map(|c| c.index),
        dh_send_pub: p.dh_send_pub.as_slice().try_into().ok()?,
        dh_send_priv: p.dh_send_priv.as_slice().try_into().ok()?,
        dh_recv: p
            .dh_recv
            .as_ref()
            .and_then(|k| k.as_slice().try_into().ok()),
        prev_send_count: p.prev_send_count,
        skipped: p
            .skipped
            .iter()
            .filter_map(|s| {
                let rk: [u8; 32] = s.rk.as_slice().try_into().ok()?;
                let mk: [u8; 32] = s.mk.as_slice().try_into().ok()?;
                Some((rk, s.idx, mk))
            })
            .collect(),
    })
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Dump ratchet state to /tmp when `RATCHET_DUMP=1` is set in env. Used for
/// diagnosing MAC-mismatch cases (ratchet drift). No-op without the env var.
fn ratchet_dump_enabled() -> bool {
    std::env::var("RATCHET_DUMP").ok().as_deref() == Some("1")
}

fn dump_ratchet_state(
    jid: &str,
    label: &str,
    peer_identity: &[u8; 32],
    our_identity: &[u8; 32],
    snap: &RatchetSnapshot,
    msg: &RatchetMessage,
    ad: &[u8],
    err: Option<&str>,
) {
    use serde_json::json;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let jid_safe = jid.replace(['/', ':', '@'], "_");
    let path = format!("/tmp/ratchet-{ts}-{label}-{jid_safe}.json");
    let value = json!({
        "jid": jid,
        "label": label,
        "ts_ms": ts,
        "peer_identity": hex::encode(peer_identity),
        "our_identity": hex::encode(our_identity),
        "ad": hex::encode(ad),
        "root_key": hex::encode(snap.root_key),
        "send_chain_key": hex::encode(snap.send_chain_key),
        "send_chain_index": snap.send_chain_index,
        "recv_chain_key": snap.recv_chain_key.map(hex::encode),
        "recv_chain_index": snap.recv_chain_index,
        "dh_send_pub": hex::encode(snap.dh_send_pub),
        "dh_send_priv": hex::encode(snap.dh_send_priv),
        "dh_recv": snap.dh_recv.map(hex::encode),
        "prev_send_count": snap.prev_send_count,
        "skipped_count": snap.skipped.len(),
        "msg": {
            "ratchet_key": hex::encode(msg.ratchet_key),
            "counter": msg.counter,
            "prev_counter": msg.prev_counter,
            "ciphertext_len": msg.ciphertext.len(),
            "ciphertext_head": hex::encode(&msg.ciphertext[..msg.ciphertext.len().min(32)]),
        },
        "err": err,
    });
    if let Ok(pretty) = serde_json::to_string_pretty(&value) {
        let _ = std::fs::write(&path, pretty);
    }
}

/// libsignal MAC associated data. Order is direction-aware:
/// `sender_identity || receiver_identity`, each as `0x05 || pub32`.
fn make_ad(sender_pub: &[u8; 32], receiver_pub: &[u8; 32]) -> [u8; 66] {
    let mut ad = [0u8; 66];
    ad[0] = 0x05;
    ad[1..33].copy_from_slice(sender_pub);
    ad[33] = 0x05;
    ad[34..].copy_from_slice(receiver_pub);
    ad
}

/// Wrap an inner SignalMessage wire blob into a libsignal
/// PreKeySignalMessage: `version(1) || protobuf(1=preKeyId?, 2=baseKey,
/// 3=identityKey, 4=innerMessage, 5=registrationId, 6=signedPreKeyId)`.
/// `baseKey` and `identityKey` are serialized with the `0x05` version byte.
fn encode_pre_key_signal_message(
    pk: &PendingPreKey,
    our_identity_pub: &[u8; 32],
    inner_wire: &[u8],
) -> Vec<u8> {
    let mut base33 = Vec::with_capacity(33);
    base33.push(0x05);
    base33.extend_from_slice(&pk.base_key_pub);

    let mut id33 = Vec::with_capacity(33);
    id33.push(0x05);
    id33.extend_from_slice(our_identity_pub);

    let mut body = Vec::new();
    if let Some(pre_key_id) = pk.pre_key_id {
        body.extend(wa_proto::proto_varint(1, pre_key_id as u64));
    }
    body.extend(wa_proto::proto_bytes(2, &base33));
    body.extend(wa_proto::proto_bytes(3, &id33));
    body.extend(wa_proto::proto_bytes(4, inner_wire));
    body.extend(wa_proto::proto_varint(5, pk.registration_id as u64));
    body.extend(wa_proto::proto_varint(6, pk.signed_pre_key_id as u64));

    let mut out = Vec::with_capacity(1 + body.len());
    out.push(SIGNAL_VERSION);
    out.extend_from_slice(&body);
    out
}

/// libsignal SignalMessage wire format:
///   `version(1) || protobuf(fields 1=rk, 2=ctr, 3=prev, 4=aes_ct) || mac8`
///
/// `RatchetMessage.ciphertext` carries the entire `version || proto || mac8`
/// blob (produced by `decode_signal_wire` or finalised by the encoder),
/// so the ratchet's `msg_decrypt` can both verify the libsignal MAC and
/// pull the AES ciphertext out of field 4.
fn encode_signal_wire(msg: &RatchetMessage) -> Result<Vec<u8>> {
    // `msg.ciphertext` was produced by `msg_encrypt`, which returns
    // `aes_ct || placeholder_mac(8)`. Strip the placeholder and rebuild the
    // wire payload, then finalise the MAC at the outermost layer where we
    // know the auth_key and associated data.
    //
    // However, re-deriving auth_key here would require the message key,
    // which we no longer have. So `encrypt` at the session layer has to
    // pass it through. We cheat: ratchet.encrypt now returns a
    // RatchetMessage whose `ciphertext` already has the full wire bytes
    // (version || proto || real_mac).
    Ok(msg.ciphertext.clone())
}

fn decode_signal_wire(data: &[u8]) -> Result<(RatchetMessage, Vec<u8>)> {
    if data.is_empty() || data[0] != SIGNAL_VERSION {
        bail!("bad signal version byte: {:?}", data.first());
    }
    if data.len() < 1 + 8 {
        bail!("signal message too short: {}", data.len());
    }
    let proto_end = data.len() - 8;
    let proto_body = &data[1..proto_end];

    let fields = wa_proto::parse_proto_fields(proto_body)
        .ok_or_else(|| anyhow::anyhow!("bad signal header"))?;

    let rk_bytes = fields.get(&1)
        .ok_or_else(|| anyhow::anyhow!("signal msg missing ratchetKey"))?;
    let rk_slice: &[u8] = if rk_bytes.len() == 33 && rk_bytes[0] == 0x05 {
        &rk_bytes[1..]
    } else {
        rk_bytes.as_slice()
    };
    let rk: [u8; 32] = rk_slice.try_into()
        .map_err(|_| anyhow::anyhow!("ratchetKey wrong length"))?;

    let counter_val = wa_proto::read_varint_from_bytes(
        fields.get(&2).ok_or_else(|| anyhow::anyhow!("signal msg missing counter"))?,
    ).ok_or_else(|| anyhow::anyhow!("bad counter varint"))?;
    let counter = counter_val as u32;

    let prev_counter = fields.get(&3)
        .and_then(|b| wa_proto::read_varint_from_bytes(b))
        .map(|v| v as u32)
        .unwrap_or(0);

    // Pass the whole wire blob through to the ratchet; `msg_decrypt`
    // verifies the MAC over `ad || version || proto` and extracts field 4.
    let wire_blob = data.to_vec();

    let header_bytes = encode_signal_header(&rk, counter, prev_counter);
    Ok((
        RatchetMessage { ratchet_key: rk, counter, prev_counter, ciphertext: wire_blob },
        header_bytes,
    ))
}

fn read_varint_at(data: &[u8], mut pos: usize) -> Result<(u64, usize)> {
    let start = pos;
    let mut result = 0u64;
    let mut shift = 0;
    loop {
        if pos >= data.len() {
            bail!("varint truncated");
        }
        let byte = data[pos];
        pos += 1;
        result |= ((byte & 0x7f) as u64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
    }
    Ok((result, pos - start))
}

// ── Key signing helpers (used by prekey upload) ───────────────────────────────

#[allow(dead_code)]
pub fn sign_pre_key(identity_key: &KeyPair, pre_key_pub: &[u8; 32]) -> [u8; 64] {
    use ed25519_dalek::{Signer, SigningKey};
    let sk = SigningKey::from_bytes(&identity_key.private);
    sk.sign(pre_key_pub).to_bytes()
}

#[allow(dead_code)]
pub fn generate_signed_pre_key(identity_key: &KeyPair, key_id: u32) -> SignedKeyPair {
    let kp = KeyPair::generate();
    let sig = sign_pre_key(identity_key, &kp.public);
    SignedKeyPair { key_pair: kp, signature: sig.to_vec(), key_id }
}
