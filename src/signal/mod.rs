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
    ad: Vec<u8>,
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
    ad: [u8; 66],
    /// Pre-key data we need to carry until the first outgoing encrypt, after
    /// which the peer knows our session and we can switch to regular Whisper
    /// messages. `None` once the session is established.
    pending_pre_key: Option<PendingPreKey>,
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
        Self {
            identity: creds.signed_identity_key.clone(),
            signed_pre_key: creds.signed_pre_key.clone(),
            registration_id: creds.registration_id,
            account_enc: creds.account_enc.clone(),
            sessions: Arc::new(Mutex::new(sessions)),
            sender_keys: Arc::new(Mutex::new(sender_keys)),
            store,
            pkmsg_count: Arc::new(AtomicU32::new(0)),
        }
    }

    pub fn account_identity_bytes(&self) -> &[u8] { &self.account_enc }

    pub fn pkmsg_count(&self) -> u32 {
        self.pkmsg_count.load(Ordering::Relaxed)
    }

    /// Build the WAProto.Message bytes (field 35 SKDM) to distribute to a group participant.
    pub fn get_skdm_proto(&self, group_jid: &str) -> Vec<u8> {
        let mut sk = self.sender_keys.lock().expect("sender_keys");
        let own = sk.get_or_create_own(group_jid);
        let axolotl = wa_proto::encode_axolotl_skdm(own.key_id, own.iteration, &own.chain_key, &own.signing_pub);
        drop(sk);
        wa_proto::encode_wa_skdm_message(group_jid, &axolotl)
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
        let mut sessions = self.sessions.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        let entry = sessions
            .get_mut(jid)
            .ok_or_else(|| anyhow::anyhow!("no Signal session for {jid}"))?;
        let msg = entry.session.encrypt(plaintext, &entry.ad)?;
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

        let ad = entry.ad;
        let snap = entry.session.snapshot();
        drop(sessions);
        self.persist_session(jid, &ad, &snap);
        Ok(EncryptedMessage { ciphertext: wire, msg_type })
    }

    pub async fn decrypt_message(
        &self,
        jid: &str,
        ciphertext: &[u8],
        msg_type: &str,
    ) -> Result<Vec<u8>> {
        match msg_type {
            "pkmsg" => self.decrypt_pre_key_message(jid, ciphertext),
            "msg" => self.decrypt_normal_message(jid, ciphertext),
            other => bail!("unknown msg type: {other}"),
        }
    }

    pub fn create_sender_session(&self, jid: &str, bundle: &PreKeyBundle) -> Result<Vec<u8>> {
        let result = x3dh::x3dh_sender(&self.identity, bundle);
        let session = RatchetSession::init_sender(result.root_key, bundle.signed_pre_key);
        let ad = make_ad(&self.identity.public, &bundle.identity_key);
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
                ad,
                pending_pre_key: Some(pending),
            });
        self.persist_session(jid, &ad, &snap);
        Ok(result.ephemeral_key.public.to_vec())
    }

    pub fn has_session(&self, jid: &str) -> bool {
        self.sessions.lock().map(|s| s.contains_key(jid)).unwrap_or(false)
    }
}

// ── Decrypt ───────────────────────────────────────────────────────────────────

impl SignalRepository {
    fn decrypt_normal_message(&self, jid: &str, data: &[u8]) -> Result<Vec<u8>> {
        let (msg, _) = decode_signal_wire(data)?;
        let mut sessions = self.sessions.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        let entry = sessions
            .get_mut(jid)
            .ok_or_else(|| anyhow::anyhow!("no session for {jid}"))?;
        let plaintext = entry.session.decrypt(&msg, &entry.ad)?;
        let ad = entry.ad;
        let snap = entry.session.snapshot();
        drop(sessions);
        self.persist_session(jid, &ad, &snap);
        Ok(plaintext)
    }

    fn decrypt_pre_key_message(&self, jid: &str, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() || data[0] != SIGNAL_VERSION {
            bail!("bad pre-key message version");
        }
        let pkm = decode_pre_key_message(&data[1..])
            .ok_or_else(|| anyhow::anyhow!("could not parse pre-key message"))?;

        // Load and consume the one-time pre-key if the sender used one
        let otk = if let Some(kid) = pkm.pre_key_id {
            match self.store.load_prekey(kid) {
                Ok(Some(bytes)) if bytes.len() == 64 => {
                    let mut priv_b = [0u8; 32];
                    let mut pub_b = [0u8; 32];
                    priv_b.copy_from_slice(&bytes[..32]);
                    pub_b.copy_from_slice(&bytes[32..64]);
                    // Consume: overwrite with zeros so it can't be reused
                    let _ = self.store.save_prekey(kid, &[0u8; 64]);
                    Some(KeyPair { private: priv_b, public: pub_b })
                }
                _ => {
                    debug!("OTK id={kid} not found, proceeding without it");
                    None
                }
            }
        } else {
            None
        };

        let pre_msg = PreKeyMessage {
            identity_key: pkm.identity_key,
            ephemeral_key: pkm.base_key,
            signed_pre_key_id: pkm.signed_pre_key_id,
            one_time_pre_key_id: pkm.pre_key_id,
        };
        let root_key = x3dh_receiver(
            &self.identity,
            &self.signed_pre_key.key_pair,
            otk.as_ref(),
            &pre_msg,
        );

        let mut session =
            RatchetSession::init_receiver(root_key, self.signed_pre_key.key_pair.clone());
        let ad = make_ad(&pkm.identity_key, &self.identity.public);
        let (msg, _) = decode_signal_wire(&pkm.message)?;
        let plaintext = session.decrypt(&msg, &ad)?;

        let snap = session.snapshot();
        self.sessions
            .lock()
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .insert(jid.to_string(), SessionEntry { session, ad, pending_pre_key: None });
        self.persist_session(jid, &ad, &snap);
        self.pkmsg_count.fetch_add(1, Ordering::Relaxed);

        Ok(plaintext)
    }
}

// ── Persistence ───────────────────────────────────────────────────────────────

impl SignalRepository {
    fn persist_session(&self, jid: &str, ad: &[u8; 66], snap: &RatchetSnapshot) {
        // Look up the still-in-memory entry so we can capture any
        // pending_pre_key before flushing to disk.
        let pending = self.sessions.lock().ok()
            .and_then(|m| m.get(jid).and_then(|e| e.pending_pre_key.as_ref().cloned()));

        let entry = PersistedEntry {
            ad: ad.to_vec(),
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
        let ad = match p.ad.as_slice().try_into() as Result<[u8; 66], _> {
            Ok(a) => a,
            Err(_) => {
                warn!("bad AD length for {jid}, skipping");
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
        out.insert(jid, SessionEntry { session, ad, pending_pre_key: pending });
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

/// libsignal MAC associated data: `0x05 || sender_pub || 0x05 || receiver_pub`.
fn make_ad(initiator_ik: &[u8; 32], responder_ik: &[u8; 32]) -> [u8; 66] {
    let mut ad = [0u8; 66];
    ad[0] = 0x05;
    ad[1..33].copy_from_slice(initiator_ik);
    ad[33] = 0x05;
    ad[34..].copy_from_slice(responder_ik);
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
