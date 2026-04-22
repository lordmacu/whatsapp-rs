/// Pairing code crypto primitives (companion_hello / companion_finish).
/// Extracted to a separate module so they can be unit-tested.

pub const CROCKFORD: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTVWXYZ";

/// 5 random bytes → 8-char Crockford base32 string.
pub fn generate_pairing_code() -> String {
    let mut buf = [0u8; 5];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut buf);
    bytes_to_crockford(&buf)
}

pub fn bytes_to_crockford(buf: &[u8]) -> String {
    let mut value: u64 = 0;
    let mut bit_count = 0u32;
    let mut out = String::new();
    for &b in buf {
        value = (value << 8) | (b as u64);
        bit_count += 8;
        while bit_count >= 5 {
            let idx = ((value >> (bit_count - 5)) & 31) as usize;
            out.push(CROCKFORD[idx] as char);
            bit_count -= 5;
        }
    }
    if bit_count > 0 {
        let idx = ((value << (5 - bit_count)) & 31) as usize;
        out.push(CROCKFORD[idx] as char);
    }
    out
}

/// PBKDF2-SHA256 with `iterations` rounds.
pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password, salt, iterations, out);
}

/// AES-256-CTR encrypt/decrypt (symmetric — same function for both).
pub fn aes256_ctr(data: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> Vec<u8> {
    use aes::cipher::{KeyIvInit, StreamCipher};
    use ctr::Ctr128BE;
    type Aes256Ctr = Ctr128BE<aes::Aes256>;
    let mut cipher = Aes256Ctr::new(key.into(), iv.into());
    let mut buf = data.to_vec();
    cipher.apply_keystream(&mut buf);
    buf
}

/// AES-256-GCM encrypt; returns ciphertext || 16-byte auth tag.
pub fn aes256_gcm_encrypt(plaintext: &[u8], key: &[u8; 32], iv: &[u8; 12]) -> Vec<u8> {
    use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Key, Nonce};
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher.encrypt(Nonce::from_slice(iv), plaintext).expect("aes-gcm encrypt")
}

/// HKDF-SHA256 with optional salt.
pub fn hkdf_sha256(ikm: &[u8], salt: Option<&[u8]>, info: &[u8], len: usize) -> Vec<u8> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut out = vec![0u8; len];
    hk.expand(info, &mut out).expect("hkdf expand");
    out
}

/// Build the wrapped companion ephemeral public key for companion_hello.
/// Returns `salt(32) || iv(16) || AES-256-CTR(ephemeral_pub, PBKDF2(code, salt), iv)`.
pub fn make_wrapped_companion_ephemeral(code: &str, ephemeral_pub: &[u8; 32]) -> Vec<u8> {
    use rand::RngCore;
    let mut salt = [0u8; 32];
    let mut iv   = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut iv);
    make_wrapped_with(code, ephemeral_pub, &salt, &iv)
}

/// Deterministic version for testing (caller provides salt+iv).
pub fn make_wrapped_with(code: &str, ephemeral_pub: &[u8; 32], salt: &[u8; 32], iv: &[u8; 16]) -> Vec<u8> {
    let mut key = [0u8; 32];
    pbkdf2_sha256(code.as_bytes(), salt, 2 << 16, &mut key);
    let ciphered = aes256_ctr(ephemeral_pub, &key, iv);
    let mut out = Vec::with_capacity(80);
    out.extend_from_slice(salt);
    out.extend_from_slice(iv);
    out.extend_from_slice(&ciphered);
    out
}

/// Decrypt the phone's wrapped ephemeral public key.
/// `data` = `salt(32) || iv(16) || ciphertext(32)`.
pub fn decipher_link_public_key(code: &str, data: &[u8]) -> anyhow::Result<[u8; 32]> {
    if data.len() < 80 {
        anyhow::bail!("link public key data too short: {}", data.len());
    }
    let salt = &data[0..32];
    let iv: [u8; 16] = data[32..48].try_into()?;
    let payload = &data[48..80];
    let mut key = [0u8; 32];
    pbkdf2_sha256(code.as_bytes(), salt, 2 << 16, &mut key);
    let decrypted = aes256_ctr(payload, &key, &iv);
    Ok(decrypted.try_into().map_err(|_| anyhow::anyhow!("bad decrypted length"))?)
}

/// X25519 DH shared secret.
pub fn x25519_dh(private: &[u8; 32], public: &[u8; 32]) -> [u8; 32] {
    use x25519_dalek::{PublicKey, StaticSecret};
    let secret = StaticSecret::from(*private);
    let pub_key = PublicKey::from(*public);
    secret.diffie_hellman(&pub_key).to_bytes()
}
