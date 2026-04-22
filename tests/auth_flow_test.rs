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
