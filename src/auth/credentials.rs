use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub public: [u8; 32],
    pub private: [u8; 32],
}

impl KeyPair {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        use x25519_dalek::{PublicKey, StaticSecret};
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Self {
            private: secret.to_bytes(),
            public: public.to_bytes(),
        }
    }

    /// Sign `data` with this key's private bytes interpreted as an Ed25519 seed.
    pub fn sign_ed25519(&self, data: &[u8]) -> [u8; 64] {
        let sk = SigningKey::from_bytes(&self.private);
        sk.sign(data).to_bytes()
    }

    /// XEdDSA signature: sign `data` treating the X25519 private key as an XEdDSA key
    /// (Signal protocol compatible, what WhatsApp expects for signed pre-key signatures).
    pub fn sign_xeddsa(&self, data: &[u8]) -> [u8; 64] {
        use xeddsa::{xed25519, Sign};
        let sk = xed25519::PrivateKey::from(&self.private);
        sk.sign(data, rand::rngs::OsRng)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedKeyPair {
    pub key_pair: KeyPair,
    pub signature: Vec<u8>,
    pub key_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub id: String,
    pub name: Option<String>,
    pub lid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthCredentials {
    pub noise_key: KeyPair,
    pub pairing_ephemeral_key: KeyPair,
    pub signed_identity_key: KeyPair,
    pub signed_pre_key: SignedKeyPair,
    pub registration_id: u16,
    pub adv_secret_key: Vec<u8>,
    pub me: Option<Contact>,
    pub pairing_code: Option<String>,
    pub first_unuploaded_pre_key_id: u32,
    /// Serialized `ADVSignedDeviceIdentity` returned by the server during
    /// pair-success (re-encoded without accountSignatureKey). Required as
    /// the `<device-identity>` child in every outgoing pkmsg stanza.
    #[serde(default)]
    pub account_enc: Vec<u8>,
    /// Unix timestamp of the last signed pre-key rotation (0 = never rotated / initial key).
    #[serde(default)]
    pub spk_last_rotated: u64,
}

impl AuthCredentials {
    pub fn new() -> Self {
        let identity_key = KeyPair::generate();
        let signed_pre_key = SignedKeyPair {
            key_pair: KeyPair::generate(),
            signature: vec![],
            key_id: 1,
        };
        let registration_id: u16 = {
            let mut bytes = [0u8; 2];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            u16::from_le_bytes(bytes) & 16383
        };
        let adv_secret = {
            let mut bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            bytes.to_vec()
        };
        // Sign the pre-key with the identity key — WhatsApp uses XEdDSA over the
        // Signal-prefixed public key (0x05 || pub), which is 33 bytes total.
        let mut signed_pub = [0u8; 33];
        signed_pub[0] = 0x05;
        signed_pub[1..].copy_from_slice(&signed_pre_key.key_pair.public);
        let sig = identity_key.sign_xeddsa(&signed_pub);
        let signed_pre_key = SignedKeyPair {
            signature: sig.to_vec(),
            ..signed_pre_key
        };

        Self {
            noise_key: KeyPair::generate(),
            pairing_ephemeral_key: KeyPair::generate(),
            signed_identity_key: identity_key,
            signed_pre_key,
            registration_id,
            adv_secret_key: adv_secret,
            me: None,
            pairing_code: None,
            first_unuploaded_pre_key_id: 1,
            account_enc: Vec::new(),
            spk_last_rotated: 0,
        }
    }
}

impl Default for AuthCredentials {
    fn default() -> Self {
        Self::new()
    }
}
