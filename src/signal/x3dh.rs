/// X3DH key agreement for WhatsApp Signal protocol.
///
/// Alice (sender) computes:
///   DH1 = DH(IK_A, SPK_B)
///   DH2 = DH(EK_A, IK_B)
///   DH3 = DH(EK_A, SPK_B)
///   DH4 = DH(EK_A, OPK_B)  [if one-time pre-key present]
///   master_secret = KDF(DH1 || DH2 || DH3 [|| DH4])

use crate::auth::credentials::KeyPair;
use crate::signal::ratchet::x25519_dh;
use hkdf::Hkdf;
use sha2::Sha256;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct PreKeyBundle {
    pub registration_id: u32,
    pub device_id: u32,
    pub identity_key: [u8; 32],       // IK_B
    pub signed_pre_key_id: u32,
    pub signed_pre_key: [u8; 32],     // SPK_B
    pub signed_pre_key_sig: [u8; 64], // signature over SPK_B
    pub one_time_pre_key_id: Option<u32>,
    pub one_time_pre_key: Option<[u8; 32]>, // OPK_B
}

pub struct X3DHResult {
    pub root_key: [u8; 32],
    pub chain_key: [u8; 32],     // initial chain key (second half of KDF)
    pub ephemeral_key: KeyPair,  // EK_A to send to Bob
}

/// Sender (Alice) performs X3DH with Bob's pre-key bundle.
pub fn x3dh_sender(our_identity: &KeyPair, bundle: &PreKeyBundle) -> X3DHResult {
    let ek_a = KeyPair::generate();

    let dh1 = x25519_dh(&our_identity.private, &bundle.signed_pre_key);
    let dh2 = x25519_dh(&ek_a.private, &bundle.identity_key);
    let dh3 = x25519_dh(&ek_a.private, &bundle.signed_pre_key);

    let mut ikm = Vec::with_capacity(128);
    ikm.extend_from_slice(&[0xff_u8; 32]); // Signal KDF prefix
    ikm.extend_from_slice(&dh1);
    ikm.extend_from_slice(&dh2);
    ikm.extend_from_slice(&dh3);

    if let Some(opk) = &bundle.one_time_pre_key {
        let dh4 = x25519_dh(&ek_a.private, opk);
        ikm.extend_from_slice(&dh4);
    }

    let (root_key, chain_key) = kdf_x3dh(&ikm);
    X3DHResult { root_key, chain_key, ephemeral_key: ek_a }
}

/// Receiver (Bob) reconstructs the shared secret from an incoming PreKeyMessage.
#[allow(dead_code)]
pub struct PreKeyMessage {
    pub identity_key: [u8; 32],   // IK_A
    pub ephemeral_key: [u8; 32],  // EK_A
    pub signed_pre_key_id: u32,
    pub one_time_pre_key_id: Option<u32>,
}

pub fn x3dh_receiver(
    our_identity: &KeyPair,
    our_signed_pre_key: &KeyPair,
    our_one_time_pre_key: Option<&KeyPair>,
    msg: &PreKeyMessage,
) -> ([u8; 32], [u8; 32]) {
    let dh1 = x25519_dh(&our_signed_pre_key.private, &msg.identity_key);
    let dh2 = x25519_dh(&our_identity.private, &msg.ephemeral_key);
    let dh3 = x25519_dh(&our_signed_pre_key.private, &msg.ephemeral_key);

    let mut ikm = Vec::with_capacity(128);
    ikm.extend_from_slice(&[0xff_u8; 32]);
    ikm.extend_from_slice(&dh1);
    ikm.extend_from_slice(&dh2);
    ikm.extend_from_slice(&dh3);

    if let Some(opk) = our_one_time_pre_key {
        let dh4 = x25519_dh(&opk.private, &msg.ephemeral_key);
        ikm.extend_from_slice(&dh4);
    }

    kdf_x3dh(&ikm)
}

fn kdf_x3dh(ikm: &[u8]) -> ([u8; 32], [u8; 32]) {
    // libsignal: HKDF(ikm=master, salt=nil, info="WhisperText", len=64).
    // Output splits into rootKey(0..32) + chainKey(32..64). Both halves
    // matter: the chain key seeds the initial receiver chain for the
    // sender side, and the initial sender chain for the receiver side.
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut out = [0u8; 64];
    hk.expand(b"WhisperText", &mut out).expect("hkdf expand");
    let mut rk = [0u8; 32];
    let mut ck = [0u8; 32];
    rk.copy_from_slice(&out[..32]);
    ck.copy_from_slice(&out[32..]);
    (rk, ck)
}
