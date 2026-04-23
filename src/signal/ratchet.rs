use anyhow::{bail, Result};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;

use crate::auth::credentials::KeyPair;

type HmacSha256 = Hmac<Sha256>;

const MAX_SKIP: u32 = 100;

// ── Chain key ─────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct ChainKey {
    key: [u8; 32],
    index: u32,
}

impl ChainKey {
    fn new(key: [u8; 32]) -> Self {
        Self { key, index: 0 }
    }

    fn advance(&self) -> (Self, [u8; 32]) {
        let msg_key = hmac32(&self.key, &[0x01]);
        let next_key = hmac32(&self.key, &[0x02]);
        (ChainKey { key: next_key, index: self.index + 1 }, msg_key)
    }
}

// ── Ratchet session ───────────────────────────────────────────────────────────

pub struct RatchetSession {
    root_key: [u8; 32],
    send_chain: ChainKey,
    recv_chain: Option<ChainKey>,
    dh_send: KeyPair,
    dh_recv: Option<[u8; 32]>,
    prev_send_count: u32,
    skipped: HashMap<([u8; 32], u32), [u8; 32]>,
}

impl RatchetSession {
    /// Sender-side init after X3DH. `init_chain_key` = second half of the
    /// X3DH KDF; seeds the RECEIVER chain so the peer's first reply (still
    /// on `their_ratchet_pub` = their signed pre key, no DH step yet) is
    /// decryptable without an initial `dh_ratchet`. This matches libsignal:
    /// `AddReceiverChain(theirRatchetKey, derivedKeys.ChainKey)`.
    pub fn init_sender(
        root_key: [u8; 32],
        init_chain_key: [u8; 32],
        their_ratchet_pub: [u8; 32],
    ) -> Self {
        let send_kp = KeyPair::generate();
        let dh = x25519_dh(&send_kp.private, &their_ratchet_pub);
        let (root2, send_chain_key) = kdf_rk(root_key, dh);
        Self {
            root_key: root2,
            send_chain: ChainKey::new(send_chain_key),
            recv_chain: Some(ChainKey::new(init_chain_key)),
            dh_send: send_kp,
            dh_recv: Some(their_ratchet_pub),
            prev_send_count: 0,
            skipped: HashMap::new(),
        }
    }

    /// Receiver-side init after X3DH. `init_chain_key` seeds the SENDER
    /// chain — matches libsignal `SetSenderChain(ourRatchetKey, derivedKeys.ChainKey)`
    /// so Bob's first reply uses a chain Alice already has mirrored as her
    /// initial receiver chain, skipping the first ratchet step.
    pub fn init_receiver(
        root_key: [u8; 32],
        init_chain_key: [u8; 32],
        our_ratchet_key: KeyPair,
    ) -> Self {
        Self {
            root_key,
            send_chain: ChainKey::new(init_chain_key),
            recv_chain: None,
            dh_send: our_ratchet_key,
            dh_recv: None,
            prev_send_count: 0,
            skipped: HashMap::new(),
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8], ad: &[u8]) -> Result<RatchetMessage> {
        let counter = self.send_chain.index;
        tracing::debug!(
            "ratchet.encrypt: counter={} root={} send_ck={} dh_send_pub={}",
            counter,
            hex::encode(&self.root_key[..8]),
            hex::encode(&self.send_chain.key[..8]),
            hex::encode(&self.dh_send.public[..8]),
        );
        let (next, mk) = self.send_chain.advance();
        self.send_chain = next;
        let ciphertext = msg_encrypt(
            &mk,
            plaintext,
            &self.dh_send.public,
            counter,
            self.prev_send_count,
            ad,
        )?;
        Ok(RatchetMessage {
            ratchet_key: self.dh_send.public,
            counter,
            prev_counter: self.prev_send_count,
            ciphertext,
        })
    }

    pub fn decrypt(&mut self, msg: &RatchetMessage, ad: &[u8]) -> Result<Vec<u8>> {
        // Check skipped cache
        if let Some(mk) = self.skipped.remove(&(msg.ratchet_key, msg.counter)) {
            tracing::debug!("decrypt: skipped-cache hit for counter={}", msg.counter);
            return msg_decrypt(&mk, &msg.ciphertext, ad);
        }

        let need_ratchet = self.dh_recv.map_or(true, |r| r != msg.ratchet_key);
        tracing::debug!(
            "decrypt: pre-state root={} recv_chain_idx={:?} dh_recv={} incoming_rk={} counter={} need_ratchet={}",
            hex::encode(&self.root_key[..8]),
            self.recv_chain.as_ref().map(|c| c.index),
            self.dh_recv.map(|b| hex::encode(&b[..8])).unwrap_or_else(|| "none".into()),
            hex::encode(&msg.ratchet_key[..8]),
            msg.counter,
            need_ratchet,
        );
        if need_ratchet {
            // Skip remaining messages in current recv chain
            if let Some(recv_chain) = self.recv_chain.clone() {
                self.skip_until(&recv_chain, msg.prev_counter)?;
            }
            self.dh_ratchet(msg.ratchet_key)?;
        }

        // Advance recv chain to this message
        let recv_chain = self.recv_chain.clone().ok_or_else(|| anyhow::anyhow!("no recv chain"))?;
        if recv_chain.index > msg.counter {
            bail!("msg counter {} already passed (chain at {})", msg.counter, recv_chain.index);
        }
        self.skip_until(&recv_chain, msg.counter)?;

        let recv_chain = self.recv_chain.as_mut().unwrap();
        let chain_key_at_n = hex::encode(&recv_chain.key[..8]);
        let (next, mk) = recv_chain.advance();
        *recv_chain = next;
        tracing::debug!(
            "decrypt: using mk_{} from chain_key={} (next chain idx={})",
            msg.counter, chain_key_at_n, self.recv_chain.as_ref().unwrap().index,
        );

        msg_decrypt(&mk, &msg.ciphertext, ad)
    }

    fn skip_until(&mut self, chain: &ChainKey, until: u32) -> Result<()> {
        if chain.index + MAX_SKIP < until {
            bail!("too many skipped messages ({} → {})", chain.index, until);
        }
        let mut c = chain.clone();
        while c.index < until {
            let (next, mk) = c.advance();
            self.skipped.insert((self.dh_recv.unwrap_or([0u8; 32]), c.index), mk);
            c = next;
        }
        if let Some(ref mut rc) = self.recv_chain {
            *rc = c;
        }
        Ok(())
    }

    fn dh_ratchet(&mut self, their_ratchet_pub: [u8; 32]) -> Result<()> {
        self.prev_send_count = self.send_chain.index;

        let old_dh_recv = self.dh_recv;
        let old_root = self.root_key;

        // Recv ratchet step
        let dh1 = x25519_dh(&self.dh_send.private, &their_ratchet_pub);
        let (new_root, recv_ck) = kdf_rk(self.root_key, dh1);

        // Send ratchet step
        let new_dh = KeyPair::generate();
        let dh2 = x25519_dh(&new_dh.private, &their_ratchet_pub);
        let (new_root2, send_ck) = kdf_rk(new_root, dh2);

        tracing::debug!(
            "dh_ratchet: old_dh_recv={} their_new={} our_dh_send_pub={} old_root={} dh1={} new_root={} recv_ck={}",
            old_dh_recv.map(|b| hex::encode(&b[..8])).unwrap_or_else(|| "none".into()),
            hex::encode(&their_ratchet_pub[..8]),
            hex::encode(&self.dh_send.public[..8]),
            hex::encode(&old_root[..8]),
            hex::encode(&dh1[..8]),
            hex::encode(&new_root[..8]),
            hex::encode(&recv_ck[..8]),
        );

        self.root_key = new_root2;
        self.recv_chain = Some(ChainKey::new(recv_ck));
        self.send_chain = ChainKey::new(send_ck);
        self.dh_send = new_dh;
        self.dh_recv = Some(their_ratchet_pub);
        Ok(())
    }
}

pub struct RatchetMessage {
    pub ratchet_key: [u8; 32],
    pub counter: u32,
    pub prev_counter: u32,
    pub ciphertext: Vec<u8>, // includes 8-byte MAC suffix
}

// ── Snapshot (for persistence) ────────────────────────────────────────────────

pub struct RatchetSnapshot {
    pub root_key: [u8; 32],
    pub send_chain_key: [u8; 32],
    pub send_chain_index: u32,
    pub recv_chain_key: Option<[u8; 32]>,
    pub recv_chain_index: Option<u32>,
    pub dh_send_pub: [u8; 32],
    pub dh_send_priv: [u8; 32],
    pub dh_recv: Option<[u8; 32]>,
    pub prev_send_count: u32,
    pub skipped: Vec<([u8; 32], u32, [u8; 32])>, // (ratchet_key, counter, msg_key)
}

impl RatchetSession {
    pub fn snapshot(&self) -> RatchetSnapshot {
        RatchetSnapshot {
            root_key: self.root_key,
            send_chain_key: self.send_chain.key,
            send_chain_index: self.send_chain.index,
            recv_chain_key: self.recv_chain.as_ref().map(|c| c.key),
            recv_chain_index: self.recv_chain.as_ref().map(|c| c.index),
            dh_send_pub: self.dh_send.public,
            dh_send_priv: self.dh_send.private,
            dh_recv: self.dh_recv,
            prev_send_count: self.prev_send_count,
            skipped: self.skipped.iter().map(|((rk, idx), mk)| (*rk, *idx, *mk)).collect(),
        }
    }

    pub fn from_snapshot(s: RatchetSnapshot) -> Self {
        let mut skipped = HashMap::new();
        for (rk, idx, mk) in s.skipped {
            skipped.insert((rk, idx), mk);
        }
        Self {
            root_key: s.root_key,
            send_chain: ChainKey { key: s.send_chain_key, index: s.send_chain_index },
            recv_chain: s.recv_chain_key.map(|k| ChainKey {
                key: k,
                index: s.recv_chain_index.unwrap_or(0),
            }),
            dh_send: KeyPair { public: s.dh_send_pub, private: s.dh_send_priv },
            dh_recv: s.dh_recv,
            prev_send_count: s.prev_send_count,
            skipped,
        }
    }
}

// ── Crypto helpers ────────────────────────────────────────────────────────────

pub fn kdf_rk(root_key: [u8; 32], dh_out: [u8; 32]) -> ([u8; 32], [u8; 32]) {
    // libsignal: HKDF(ikm=dh_out, salt=current_root, info="WhisperRatchet", len=64)
    let hk = Hkdf::<Sha256>::new(Some(&root_key), &dh_out);
    let mut out = [0u8; 64];
    hk.expand(b"WhisperRatchet", &mut out).expect("hkdf expand");
    let mut rk = [0u8; 32];
    let mut ck = [0u8; 32];
    rk.copy_from_slice(&out[..32]);
    ck.copy_from_slice(&out[32..]);
    (rk, ck)
}

pub fn x25519_dh(private: &[u8; 32], public: &[u8; 32]) -> [u8; 32] {
    let secret = x25519_dalek::StaticSecret::from(*private);
    let pubkey = x25519_dalek::PublicKey::from(*public);
    secret.diffie_hellman(&pubkey).to_bytes()
}

fn expand_msg_key(mk: &[u8; 32]) -> ([u8; 32], [u8; 32], [u8; 16]) {
    // libsignal: HKDF(ikm=mk, salt=nil, info="WhisperMessageKeys", len=80).
    // "salt=nil" resolves to HashLen zeros in HKDF (32 zeros for SHA-256).
    let hk = Hkdf::<Sha256>::new(None, mk);
    let mut out = [0u8; 80];
    hk.expand(b"WhisperMessageKeys", &mut out).expect("hkdf expand");
    let mut enc = [0u8; 32];
    let mut auth = [0u8; 32];
    let mut iv = [0u8; 16];
    enc.copy_from_slice(&out[..32]);
    auth.copy_from_slice(&out[32..64]);
    iv.copy_from_slice(&out[64..80]);
    (enc, auth, iv)
}

/// Produce a full libsignal SignalMessage wire blob:
///   `version(1) || protobuf(1=rk, 2=counter, 3=prev, 4=aes_ct) || mac8`
/// with `mac8 = HMAC(auth_key, ad || version || protobuf)[:8]`.
fn msg_encrypt(
    mk: &[u8; 32],
    plaintext: &[u8],
    ratchet_key: &[u8; 32],
    counter: u32,
    prev_counter: u32,
    ad: &[u8],
) -> Result<Vec<u8>> {
    use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
    use aes::Aes256;
    use crate::signal::wa_proto;

    let (enc_key, auth_key, iv) = expand_msg_key(mk);
    let enc = cbc::Encryptor::<Aes256>::new_from_slices(&enc_key, &iv)
        .map_err(|e| anyhow::anyhow!("aes-cbc init: {e}"))?;
    let aes_ct = enc.encrypt_padded_vec_mut::<Pkcs7>(plaintext);

    // Build protobuf body: field 1 = 0x05 || ratchet_key, 2 = counter,
    // 3 = prev_counter, 4 = aes_ct.
    let mut rk33 = Vec::with_capacity(33);
    rk33.push(0x05);
    rk33.extend_from_slice(ratchet_key);
    let mut proto = Vec::new();
    proto.extend(wa_proto::proto_bytes(1, &rk33));
    proto.extend(wa_proto::proto_varint(2, counter as u64));
    proto.extend(wa_proto::proto_varint(3, prev_counter as u64));
    proto.extend(wa_proto::proto_bytes(4, &aes_ct));

    const SIGNAL_VERSION_BYTE: u8 = 0x33;
    let mut wire = Vec::with_capacity(1 + proto.len() + 8);
    wire.push(SIGNAL_VERSION_BYTE);
    wire.extend_from_slice(&proto);

    let mut mac = HmacSha256::new_from_slice(&auth_key).expect("hmac");
    mac.update(ad);
    mac.update(&wire); // wire is version || proto at this point
    let full = mac.finalize().into_bytes();
    wire.extend_from_slice(&full[..8]);

    Ok(wire)
}

/// Decrypt using libsignal wire-shaped input. `wire_with_mac` is the full
/// serialized SignalMessage: `version || protobuf || mac8`. The MAC covers
/// `ad || version || protobuf`.
fn msg_decrypt(mk: &[u8; 32], wire_with_mac: &[u8], ad: &[u8]) -> Result<Vec<u8>> {
    use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
    use aes::Aes256;

    if wire_with_mac.len() < 1 + 8 {
        bail!("message too short: {}", wire_with_mac.len());
    }
    let (mac_input, mac_bytes) = wire_with_mac.split_at(wire_with_mac.len() - 8);
    let (enc_key, auth_key, iv) = expand_msg_key(mk);

    // libsignal MAC: HMAC(auth_key, ad || version || protobuf)
    let mut mac = HmacSha256::new_from_slice(&auth_key).expect("hmac");
    mac.update(ad);
    mac.update(mac_input);
    let full = mac.finalize().into_bytes();
    let expected = &full[..8];
    if mac_bytes != expected {
        bail!("MAC mismatch");
    }

    // Extract field 4 (ciphertext) from the protobuf body. The proto body
    // is everything after the version byte.
    let proto_body = &mac_input[1..];
    let fields = crate::signal::wa_proto::parse_proto_fields(proto_body)
        .ok_or_else(|| anyhow::anyhow!("couldn't parse signal message proto"))?;
    let aes_ct = fields.get(&4)
        .ok_or_else(|| anyhow::anyhow!("signal message missing field 4 (ciphertext)"))?;

    let dec = cbc::Decryptor::<Aes256>::new_from_slices(&enc_key, &iv)
        .map_err(|e| anyhow::anyhow!("aes-cbc init: {e}"))?;
    dec.decrypt_padded_vec_mut::<Pkcs7>(aes_ct)
        .map_err(|e| anyhow::anyhow!("decrypt: {e}"))
}

fn msg_mac(auth_key: &[u8; 32], ad: &[u8], ciphertext: &[u8]) -> [u8; 8] {
    let mut mac = HmacSha256::new_from_slice(auth_key).expect("hmac");
    mac.update(ad);
    mac.update(ciphertext);
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; 8];
    out.copy_from_slice(&full[..8]);
    out
}

pub fn hmac32(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac");
    mac.update(data);
    mac.finalize().into_bytes().into()
}
