pub mod credentials;
pub mod manager;
pub mod pair_success;
pub mod pairing_crypto;
pub mod session_store;

pub use credentials::*;
pub use manager::{AuthManager, AuthState};
pub use session_store::FileStore;
#[allow(unused_imports)]
pub use session_store::SessionStore;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum AuthEvent {
    NewQR { refs: Vec<Vec<u8>> },
    QRTimedOut { ref_index: usize },
    PairingCode { code: String },
    PairingSuccess,
    AuthFailure { reason: String },
}

#[cfg(test)]
mod tests {
    use crate::auth::{AuthCredentials, KeyPair};

    #[test]
    fn test_keypair_generate() {
        let kp = KeyPair::generate();
        assert_eq!(kp.public.len(), 32);
        assert_eq!(kp.private.len(), 32);
        assert_ne!(kp.public, kp.private);
    }

    #[test]
    fn test_auth_credentials_new() {
        let creds = AuthCredentials::new();
        assert!(creds.me.is_none());
        assert!(creds.pairing_code.is_none());
    }
}
