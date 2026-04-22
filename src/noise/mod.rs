/// Noise_XX_25519_AESGCM_SHA256
/// Implementación del handshake Noise para WhatsApp Web.
///
/// Flujo:
///   1. Client → Server: ClientHello  (ephemeral pubkey)
///   2. Server → Client: ServerHello  (server ephemeral, encrypted static, encrypted cert)
///   3. Client → Server: ClientFinish (encrypted noise key, encrypted payload)
///   4. Transición a TransportState   (cifrado simétrico con counter IVs)

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use anyhow::Result;
use rand::rngs::OsRng;

/// Header que va al inicio de cada conexión: "WA" + 0x06 + DICT_VERSION(3)
pub const NOISE_WA_HEADER: [u8; 4] = [87, 65, 6, 3];

/// Nombre del protocolo para derivar el hash inicial
const NOISE_MODE: &str = "Noise_XX_25519_AESGCM_SHA256\0\0\0\0";

#[derive(Debug)]
pub struct KeyPair {
    pub public: [u8; 32],
    pub private: [u8; 32],
}

impl KeyPair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self {
            private: secret.to_bytes(),
            public: public.to_bytes(),
        }
    }
}

/// Estado del handshake Noise
pub struct NoiseHandshake {
    hash: [u8; 32],
    chaining_key: [u8; 32],
    cipher_key: Option<[u8; 32]>,
    counter: u32,
    pub ephemeral: KeyPair,
}

impl NoiseHandshake {
    pub fn new() -> Self {
        // Baileys: if data.byteLength === 32 use raw, else sha256.
        // NOISE_MODE is exactly 32 bytes so use it directly.
        let noise_bytes = NOISE_MODE.as_bytes();
        let hash: [u8; 32] = if noise_bytes.len() == 32 {
            noise_bytes.try_into().unwrap()
        } else {
            sha256(noise_bytes)
        };
        let chaining_key = hash;
        let ephemeral = KeyPair::generate();
        Self { hash, chaining_key, cipher_key: None, counter: 0, ephemeral }
    }

    #[allow(dead_code)]
    pub fn debug_hash(&self) -> [u8; 32] { self.hash }

    /// Mezcla datos en el hash acumulado
    pub fn mix_into_hash(&mut self, data: &[u8]) {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&self.hash);
        buf.extend_from_slice(data);
        self.hash = sha256(&buf);
    }

    /// HKDF — genera dos salidas de 32 bytes
    fn hkdf2(&self, input: &[u8]) -> ([u8; 32], [u8; 32]) {
        let hk = Hkdf::<Sha256>::new(Some(&self.chaining_key), input);
        let mut out = [0u8; 64];
        hk.expand(&[], &mut out).expect("hkdf expand");
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a.copy_from_slice(&out[..32]);
        b.copy_from_slice(&out[32..]);
        (a, b)
    }

    fn make_iv(counter: u32) -> [u8; 12] {
        let mut iv = [0u8; 12];
        iv[8..].copy_from_slice(&counter.to_be_bytes());
        iv
    }

    /// Mezcla un DH result en el chaining key, deriva nueva cipher key y resetea counter
    pub fn mix_shared_secret(&mut self, shared: &[u8]) {
        let (new_ck, new_key) = self.hkdf2(shared);
        self.chaining_key = new_ck;
        self.cipher_key = Some(new_key);
        self.counter = 0;
    }

    /// Encripta con AEAD, usando hash como additional data
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let key_bytes = self.cipher_key.ok_or_else(|| anyhow::anyhow!("no cipher key"))?;
        let iv = Self::make_iv(self.counter);
        self.counter += 1;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
        let nonce = Nonce::from_slice(&iv);
        let payload = Payload { msg: plaintext, aad: &self.hash };
        let ciphertext = cipher.encrypt(nonce, payload)
            .map_err(|e| anyhow::anyhow!("encrypt error: {e}"))?;
        self.mix_into_hash(&ciphertext);
        Ok(ciphertext)
    }

    /// Desencripta con AEAD, usando hash como additional data
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let key_bytes = self.cipher_key.ok_or_else(|| anyhow::anyhow!("no cipher key"))?;
        let iv = Self::make_iv(self.counter);
        self.counter += 1;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
        let nonce = Nonce::from_slice(&iv);
        let payload = Payload { msg: ciphertext, aad: &self.hash };
        let plaintext = cipher.decrypt(nonce, payload)
            .map_err(|e| anyhow::anyhow!("decrypt error: {e}"))?;
        self.mix_into_hash(ciphertext);
        Ok(plaintext)
    }

    /// Realiza DH entre nuestra clave privada ephemeral y una pública del servidor
    pub fn dh(&self, their_public: &[u8; 32]) -> [u8; 32] {
        let our_secret = StaticSecret::from(self.ephemeral.private);
        let their_pub = PublicKey::from(*their_public);
        our_secret.diffie_hellman(&their_pub).to_bytes()
    }

    /// DH con clave estática larga duración
    pub fn dh_static(&self, our_private: &[u8; 32], their_public: &[u8; 32]) -> [u8; 32] {
        let our_secret = StaticSecret::from(*our_private);
        let their_pub = PublicKey::from(*their_public);
        our_secret.diffie_hellman(&their_pub).to_bytes()
    }

    /// Finaliza el handshake y devuelve el TransportState
    pub fn into_transport(self) -> Result<TransportState> {
        let (send_key, recv_key) = self.hkdf2(&[]);
        Ok(TransportState {
            send_key,
            recv_key,
            send_counter: 0,
            recv_counter: 0,
        })
    }
}

/// Estado de transporte post-handshake: cifrado simétrico con counters
pub struct TransportState {
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send_counter: u32,
    recv_counter: u32,
}

#[allow(dead_code)]
impl TransportState {
    pub fn split(self) -> (SendState, RecvState) {
        (
            SendState { key: self.send_key, counter: self.send_counter },
            RecvState { key: self.recv_key, counter: self.recv_counter },
        )
    }

    fn make_iv(counter: u32) -> [u8; 12] {
        let mut iv = [0u8; 12];
        iv[8..].copy_from_slice(&counter.to_be_bytes());
        iv
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.send_key));
        let iv = Self::make_iv(self.send_counter);
        let nonce = Nonce::from_slice(&iv);
        let ct = cipher.encrypt(nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("transport encrypt: {e}"))?;
        self.send_counter += 1;
        Ok(ct)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.recv_key));
        let iv = Self::make_iv(self.recv_counter);
        let nonce = Nonce::from_slice(&iv);
        let pt = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("transport decrypt: {e}"))?;
        self.recv_counter += 1;
        Ok(pt)
    }
}

pub struct SendState {
    key: [u8; 32],
    counter: u32,
}

impl SendState {
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
        let mut iv = [0u8; 12];
        iv[8..].copy_from_slice(&self.counter.to_be_bytes());
        let nonce = Nonce::from_slice(&iv);
        let ct = cipher.encrypt(nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("send encrypt: {e}"))?;
        self.counter += 1;
        Ok(ct)
    }
}

pub struct RecvState {
    key: [u8; 32],
    pub counter: u32,
}

impl RecvState {
    #[allow(dead_code)]
    pub fn counter(&self) -> u32 { self.counter }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
        let mut iv = [0u8; 12];
        iv[8..].copy_from_slice(&self.counter.to_be_bytes());
        let nonce = Nonce::from_slice(&iv);
        let pt = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("recv decrypt: {e}"))?;
        self.counter += 1;
        Ok(pt)
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}
