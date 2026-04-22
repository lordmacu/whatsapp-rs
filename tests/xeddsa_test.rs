use whatsapp_rs::auth::credentials::KeyPair;
use xeddsa::{xed25519, Verify};

#[test]
fn xeddsa_sign_then_verify_roundtrip() {
    let kp = KeyPair::generate();
    let msg = b"hello whatsapp";
    let sig = kp.sign_xeddsa(msg);

    let pk = xed25519::PublicKey(kp.public);
    pk.verify(msg, &sig).expect("verify own signature");
}

#[test]
fn xeddsa_verify_rejects_wrong_message() {
    let kp = KeyPair::generate();
    let sig = kp.sign_xeddsa(b"original");
    let pk = xed25519::PublicKey(kp.public);
    assert!(pk.verify(b"tampered", &sig).is_err());
}
