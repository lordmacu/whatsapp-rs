/// WhatsApp media encryption/decryption.
///
/// Wire format of an encrypted media blob (CDN):
///   ciphertext (AES-256-CBC, PKCS7) || HMAC-SHA256(mac_key, iv || ciphertext)[0..10]
///
/// Key derivation:
///   expanded = HKDF(salt=[0x00;32], ikm=media_key, info=<type-string>, length=112)
///   iv        = expanded[0..16]
///   cipher_key= expanded[16..48]
///   mac_key   = expanded[48..80]

use anyhow::{bail, Result};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

// ── Media type ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub enum MediaType {
    Image,
    Video,
    Audio,
    Document,
    Sticker,
    HistorySync,
}

impl MediaType {
    fn hkdf_info(self) -> &'static [u8] {
        match self {
            MediaType::Image | MediaType::Sticker => b"WhatsApp Image Keys",
            MediaType::Video => b"WhatsApp Video Keys",
            MediaType::Audio => b"WhatsApp Audio Keys",
            MediaType::Document => b"WhatsApp Document Keys",
            MediaType::HistorySync => b"WhatsApp History Keys",
        }
    }
}

// ── Key expansion ─────────────────────────────────────────────────────────────

struct ExpandedKey {
    iv: [u8; 16],
    cipher_key: [u8; 32],
    mac_key: [u8; 32],
}

fn expand_media_key(media_key: &[u8], media_type: MediaType) -> Result<ExpandedKey> {
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), media_key);
    let mut out = [0u8; 112];
    hk.expand(media_type.hkdf_info(), &mut out)
        .map_err(|e| anyhow::anyhow!("hkdf expand: {e}"))?;
    let mut iv = [0u8; 16];
    let mut cipher_key = [0u8; 32];
    let mut mac_key = [0u8; 32];
    iv.copy_from_slice(&out[0..16]);
    cipher_key.copy_from_slice(&out[16..48]);
    mac_key.copy_from_slice(&out[48..80]);
    Ok(ExpandedKey { iv, cipher_key, mac_key })
}

// ── Decrypt ───────────────────────────────────────────────────────────────────

/// Decrypt an encrypted media blob downloaded from the CDN.
pub fn decrypt_media_blob(media_key: &[u8], blob: &[u8], media_type: MediaType) -> Result<Vec<u8>> {
    use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
    use aes::Aes256;

    if blob.len() < 10 {
        bail!("media blob too short: {} bytes", blob.len());
    }

    let ek = expand_media_key(media_key, media_type)?;
    let (ciphertext, mac_bytes) = blob.split_at(blob.len() - 10);

    // Verify MAC
    let mut hmac = Hmac::<Sha256>::new_from_slice(&ek.mac_key).expect("hmac");
    hmac.update(&ek.iv);
    hmac.update(ciphertext);
    let full_mac = hmac.finalize().into_bytes();
    if mac_bytes != &full_mac[..10] {
        bail!("media MAC mismatch");
    }

    // Decrypt
    let dec = cbc::Decryptor::<Aes256>::new_from_slices(&ek.cipher_key, &ek.iv)
        .map_err(|e| anyhow::anyhow!("aes-cbc init: {e}"))?;
    dec.decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|e| anyhow::anyhow!("media decrypt: {e}"))
}

/// Encrypt plaintext media for upload to the CDN.
/// Returns `(encrypted_blob, media_key, file_enc_sha256, file_sha256)`.
pub fn encrypt_media_blob(plaintext: &[u8], media_type: MediaType) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
    use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
    use aes::Aes256;
    use sha2::Digest;

    let mut media_key = [0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut media_key);

    let ek = expand_media_key(&media_key, media_type)?;

    let enc = cbc::Encryptor::<Aes256>::new_from_slices(&ek.cipher_key, &ek.iv)
        .map_err(|e| anyhow::anyhow!("aes-cbc init: {e}"))?;
    let ciphertext = enc.encrypt_padded_vec_mut::<Pkcs7>(plaintext);

    let mut hmac = Hmac::<Sha256>::new_from_slice(&ek.mac_key).expect("hmac");
    hmac.update(&ek.iv);
    hmac.update(&ciphertext);
    let mac = hmac.finalize().into_bytes();

    let mut blob = ciphertext.clone();
    blob.extend_from_slice(&mac[..10]);

    let file_enc_sha256 = sha2::Sha256::digest(&blob).to_vec();
    let file_sha256 = sha2::Sha256::digest(plaintext).to_vec();

    Ok((blob, media_key.to_vec(), file_enc_sha256, file_sha256))
}

// ── Download ──────────────────────────────────────────────────────────────────

/// Download an encrypted media blob from the CDN and decrypt it.
pub async fn download_media(url: &str, media_key: &[u8], media_type: MediaType) -> Result<Vec<u8>> {
    let blob = reqwest::get(url)
        .await
        .map_err(|e| anyhow::anyhow!("media download: {e}"))?
        .bytes()
        .await
        .map_err(|e| anyhow::anyhow!("media read: {e}"))?;
    decrypt_media_blob(media_key, &blob, media_type)
}
