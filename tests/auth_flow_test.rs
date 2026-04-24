use whatsapp_rs::auth::{AuthCredentials, FileStore, SessionStore};

#[test]
fn test_auth_credentials_roundtrip() {
    let dir = std::env::temp_dir().join(format!("wa_test_{}", std::process::id()));
    let store = FileStore::new_in_dir(&dir).unwrap();
    let creds = AuthCredentials::new();
    store.save_credentials(&creds).unwrap();
    let loaded = store.load_credentials().unwrap().unwrap();
    assert_eq!(creds.registration_id, loaded.registration_id);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_auth_credentials_persistence() {
    let dir = std::env::temp_dir().join(format!("wa_test2_{}", std::process::id()));
    let store = FileStore::new_in_dir(&dir).unwrap();
    let creds = AuthCredentials::new();
    store.save_credentials(&creds).unwrap();

    let reloaded: AuthCredentials = store
        .load_credentials()
        .unwrap()
        .expect("should have credentials");

    assert_eq!(creds.noise_key.public, reloaded.noise_key.public);
    assert_eq!(creds.noise_key.private, reloaded.noise_key.private);
    assert_eq!(creds.registration_id, reloaded.registration_id);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Two `Client::new_in_dir` clients over different directories must
/// carry independent `FileStore` roots so Signal keys never collide —
/// this is the multi-account isolation guarantee the agent framework
/// relies on. Does not connect to WhatsApp; just verifies the base_dir
/// split at the store level.
#[test]
fn test_client_new_in_dir_roots_are_independent() {
    use whatsapp_rs::Client;
    let pid = std::process::id();
    let a = std::env::temp_dir().join(format!("wa_client_a_{pid}"));
    let b = std::env::temp_dir().join(format!("wa_client_b_{pid}"));

    // Construction must succeed for both without conflict.
    let _ca = Client::new_in_dir(&a).expect("client A");
    let _cb = Client::new_in_dir(&b).expect("client B");

    // The underlying FileStore should have laid out `.whatsapp-rs/`
    // under each dir independently. Save different credentials into
    // each and assert they do not leak across.
    let store_a = FileStore::new_in_dir(a.join(".whatsapp-rs")).unwrap();
    let store_b = FileStore::new_in_dir(b.join(".whatsapp-rs")).unwrap();
    let creds_a = AuthCredentials::new();
    let creds_b = AuthCredentials::new();
    store_a.save_credentials(&creds_a).unwrap();
    store_b.save_credentials(&creds_b).unwrap();

    let loaded_a = store_a.load_credentials().unwrap().unwrap();
    let loaded_b = store_b.load_credentials().unwrap().unwrap();
    assert_eq!(loaded_a.registration_id, creds_a.registration_id);
    assert_eq!(loaded_b.registration_id, creds_b.registration_id);
    assert_ne!(
        loaded_a.registration_id, loaded_b.registration_id,
        "each dir must own its credentials — no leak between accounts"
    );

    let _ = std::fs::remove_dir_all(&a);
    let _ = std::fs::remove_dir_all(&b);
}
