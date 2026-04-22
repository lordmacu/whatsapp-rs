use whatsapp_rs::auth::credentials::KeyPair;
use whatsapp_rs::signal::ratchet::{kdf_rk, x25519_dh, RatchetSession};
use whatsapp_rs::signal::x3dh::{x3dh_receiver, x3dh_sender, PreKeyBundle, PreKeyMessage};

#[test]
fn test_x25519_dh_commutative() {
    let a = KeyPair::generate();
    let b = KeyPair::generate();
    let ab = x25519_dh(&a.private, &b.public);
    let ba = x25519_dh(&b.private, &a.public);
    assert_eq!(ab, ba, "DH must be commutative");
}

#[test]
fn test_kdf_rk_deterministic() {
    let root = [0x42u8; 32];
    let dh = [0x77u8; 32];
    let (rk1, ck1) = kdf_rk(root, dh);
    let (rk2, ck2) = kdf_rk(root, dh);
    assert_eq!(rk1, rk2);
    assert_eq!(ck1, ck2);
    assert_ne!(rk1, ck1, "root and chain keys must differ");
}

#[test]
fn test_ratchet_encrypt_decrypt_roundtrip() {
    // Simulate X3DH → both sides share a root key
    let shared_root = [0xABu8; 32];
    let bob_ratchet = KeyPair::generate();

    let mut alice = RatchetSession::init_sender(shared_root, bob_ratchet.public);
    let mut bob = RatchetSession::init_receiver(shared_root, bob_ratchet);

    let ad = b"associated-data-alice-bob";

    // Alice → Bob
    let plaintext = b"hello from alice";
    let enc = alice.encrypt(plaintext, ad).unwrap();
    let dec = bob.decrypt(&enc, ad).unwrap();
    assert_eq!(dec, plaintext);
}

#[test]
fn test_ratchet_multiple_messages() {
    let shared_root = [0x11u8; 32];
    let bob_ratchet = KeyPair::generate();

    let mut alice = RatchetSession::init_sender(shared_root, bob_ratchet.public);
    let mut bob = RatchetSession::init_receiver(shared_root, bob_ratchet);

    let ad = b"ad";

    for i in 0u8..10 {
        let plaintext = format!("message {i}");
        let enc = alice.encrypt(plaintext.as_bytes(), ad).unwrap();
        let dec = bob.decrypt(&enc, ad).unwrap();
        assert_eq!(dec, plaintext.as_bytes());
    }
}

#[test]
fn test_ratchet_bidirectional() {
    let shared_root = [0x22u8; 32];
    let bob_ratchet = KeyPair::generate();

    let mut alice = RatchetSession::init_sender(shared_root, bob_ratchet.public);
    let mut bob = RatchetSession::init_receiver(shared_root, bob_ratchet);

    let ad = b"ad";

    // Alice → Bob
    let enc1 = alice.encrypt(b"hello bob", ad).unwrap();
    bob.decrypt(&enc1, ad).unwrap();

    // Bob → Alice (triggers DH ratchet on Bob's side)
    let enc2 = bob.encrypt(b"hi alice", ad).unwrap();
    alice.decrypt(&enc2, ad).unwrap();

    // Alice → Bob again (new ratchet)
    let enc3 = alice.encrypt(b"second message", ad).unwrap();
    let dec3 = bob.decrypt(&enc3, ad).unwrap();
    assert_eq!(dec3, b"second message");
}

#[test]
fn test_x3dh_shared_secret() {
    // Alice sends to Bob using X3DH
    let alice_identity = KeyPair::generate();
    let bob_identity = KeyPair::generate();
    let bob_signed_pre_key = KeyPair::generate();

    let bundle = PreKeyBundle {
        registration_id: 1,
        device_id: 1,
        identity_key: bob_identity.public,
        signed_pre_key_id: 1,
        signed_pre_key: bob_signed_pre_key.public,
        signed_pre_key_sig: [0u8; 64],
        one_time_pre_key_id: None,
        one_time_pre_key: None,
    };

    let result = x3dh_sender(&alice_identity, &bundle);

    let pre_key_msg = PreKeyMessage {
        identity_key: alice_identity.public,
        ephemeral_key: result.ephemeral_key.public,
        signed_pre_key_id: 1,
        one_time_pre_key_id: None,
    };

    let bob_root = x3dh_receiver(&bob_identity, &bob_signed_pre_key, None, &pre_key_msg);
    assert_eq!(result.root_key, bob_root, "X3DH shared secret must match");
}
