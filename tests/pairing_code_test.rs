use whatsapp_rs::auth::pairing_crypto::{
    aes256_ctr, aes256_gcm_encrypt, bytes_to_crockford, decipher_link_public_key,
    hkdf_sha256, make_wrapped_with, pbkdf2_sha256, x25519_dh, CROCKFORD,
};

// ── Crockford encoding ────────────────────────────────────────────────────────

#[test]
fn crockford_alphabet_has_32_chars() {
    assert_eq!(CROCKFORD.len(), 32);
}

#[test]
fn crockford_no_ambiguous_chars() {
    let s = std::str::from_utf8(CROCKFORD).unwrap();
    assert!(!s.contains('0'), "0 must not appear (looks like O)");
    assert!(!s.contains('I'), "I must not appear (looks like 1)");
    assert!(!s.contains('O'), "O must not appear (looks like 0)");
    assert!(!s.contains('U'), "U must not appear (looks like V)");
}

#[test]
fn crockford_five_bytes_gives_eight_chars() {
    let result = bytes_to_crockford(&[0x00, 0x00, 0x00, 0x00, 0x00]);
    assert_eq!(result.len(), 8);
}

#[test]
fn crockford_all_zeros_is_all_ones() {
    // 0x00 * 5 → all 5-bit groups are 0 → index 0 in CROCKFORD = '1'
    let result = bytes_to_crockford(&[0x00; 5]);
    assert_eq!(result, "11111111");
}

#[test]
fn crockford_all_ff_is_all_z() {
    // 0xFF * 5 → all 5-bit groups are 31 → index 31 in CROCKFORD = 'Z'
    let result = bytes_to_crockford(&[0xFF; 5]);
    assert_eq!(result, "ZZZZZZZZ");
}

#[test]
fn crockford_only_valid_chars() {
    let valid: std::collections::HashSet<char> =
        CROCKFORD.iter().map(|&b| b as char).collect();
    for _ in 0..20 {
        let buf: Vec<u8> = (0..5).map(|i| (i * 37 + 13) as u8).collect();
        let s = bytes_to_crockford(&buf);
        assert_eq!(s.len(), 8);
        for ch in s.chars() {
            assert!(valid.contains(&ch), "unexpected char: {ch}");
        }
    }
}

// ── AES-256-CTR ───────────────────────────────────────────────────────────────

#[test]
fn aes_ctr_encrypt_decrypt_roundtrip() {
    let key = [0x42u8; 32];
    let iv  = [0x01u8; 16];
    let plaintext = b"hello world 1234567890abcdef!!!!";
    let ciphertext = aes256_ctr(plaintext, &key, &iv);
    assert_ne!(&ciphertext, plaintext, "ciphertext must differ from plaintext");
    let recovered = aes256_ctr(&ciphertext, &key, &iv);
    assert_eq!(recovered, plaintext);
}

#[test]
fn aes_ctr_different_keys_give_different_output() {
    let iv  = [0x00u8; 16];
    let pt  = [0xAAu8; 32];
    let c1 = aes256_ctr(&pt, &[0x11u8; 32], &iv);
    let c2 = aes256_ctr(&pt, &[0x22u8; 32], &iv);
    assert_ne!(c1, c2);
}

// ── AES-256-GCM ───────────────────────────────────────────────────────────────

#[test]
fn aes_gcm_output_is_plaintext_plus_16_tag_bytes() {
    let key = [0x55u8; 32];
    let iv  = [0x77u8; 12];
    let pt  = b"test payload 32 bytes here!!!!!";
    let ct  = aes256_gcm_encrypt(pt, &key, &iv);
    assert_eq!(ct.len(), pt.len() + 16);
}

#[test]
fn aes_gcm_same_key_iv_deterministic() {
    let key = [0xAAu8; 32];
    let iv  = [0xBBu8; 12];
    let pt  = b"deterministic";
    assert_eq!(aes256_gcm_encrypt(pt, &key, &iv), aes256_gcm_encrypt(pt, &key, &iv));
}

// ── PBKDF2-SHA256 ─────────────────────────────────────────────────────────────

#[test]
fn pbkdf2_output_length_correct() {
    let mut out = [0u8; 32];
    pbkdf2_sha256(b"password", b"salt", 1, &mut out);
    assert_eq!(out.len(), 32);
}

#[test]
fn pbkdf2_deterministic() {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    pbkdf2_sha256(b"pw", b"salt", 100, &mut a);
    pbkdf2_sha256(b"pw", b"salt", 100, &mut b);
    assert_eq!(a, b);
}

#[test]
fn pbkdf2_different_passwords_differ() {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    pbkdf2_sha256(b"pass1", b"salt", 1, &mut a);
    pbkdf2_sha256(b"pass2", b"salt", 1, &mut b);
    assert_ne!(a, b);
}

// ── HKDF-SHA256 ───────────────────────────────────────────────────────────────

#[test]
fn hkdf_output_length() {
    let out = hkdf_sha256(b"ikm", None, b"info", 32);
    assert_eq!(out.len(), 32);
}

#[test]
fn hkdf_deterministic() {
    let a = hkdf_sha256(b"ikm", Some(b"salt"), b"info", 32);
    let b = hkdf_sha256(b"ikm", Some(b"salt"), b"info", 32);
    assert_eq!(a, b);
}

#[test]
fn hkdf_different_info_differs() {
    let a = hkdf_sha256(b"ikm", None, b"info-A", 32);
    let b = hkdf_sha256(b"ikm", None, b"info-B", 32);
    assert_ne!(a, b);
}

// ── Wrap / decipher roundtrip ─────────────────────────────────────────────────

#[test]
fn wrap_decipher_roundtrip() {
    let code = "ABCD1234";
    let ephemeral_pub = [0xEEu8; 32];
    let salt = [0x11u8; 32];
    let iv   = [0x22u8; 16];

    let wrapped = make_wrapped_with(code, &ephemeral_pub, &salt, &iv);
    assert_eq!(wrapped.len(), 80, "wrapped must be salt(32)+iv(16)+ciphertext(32)");

    let recovered = decipher_link_public_key(code, &wrapped).unwrap();
    assert_eq!(recovered, ephemeral_pub);
}

#[test]
fn wrong_code_gives_wrong_plaintext() {
    let code = "CORRECT1";
    let ephemeral_pub = [0xDDu8; 32];
    let salt = [0x33u8; 32];
    let iv   = [0x44u8; 16];

    let wrapped = make_wrapped_with(code, &ephemeral_pub, &salt, &iv);
    let wrong = decipher_link_public_key("WRONGWRG", &wrapped).unwrap();
    assert_ne!(wrong, ephemeral_pub, "wrong code must not recover original key");
}

#[test]
fn decipher_rejects_short_input() {
    let err = decipher_link_public_key("CODE1234", &[0u8; 50]);
    assert!(err.is_err());
}

// ── X25519 DH ─────────────────────────────────────────────────────────────────

#[test]
fn x25519_dh_commutative() {
    use whatsapp_rs::auth::credentials::KeyPair;
    let a = KeyPair::generate();
    let b = KeyPair::generate();
    let ab = x25519_dh(&a.private, &b.public);
    let ba = x25519_dh(&b.private, &a.public);
    assert_eq!(ab, ba);
}

#[test]
fn x25519_dh_different_pairs_differ() {
    use whatsapp_rs::auth::credentials::KeyPair;
    let a = KeyPair::generate();
    let b = KeyPair::generate();
    let c = KeyPair::generate();
    assert_ne!(x25519_dh(&a.private, &b.public), x25519_dh(&a.private, &c.public));
}
