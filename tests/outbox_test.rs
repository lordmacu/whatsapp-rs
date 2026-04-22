use whatsapp_rs::outbox::OutboxStore;
use whatsapp_rs::{MessageContent, MessageKey, MessageStatus, WAMessage};

fn make_msg(jid: &str, id: &str) -> WAMessage {
    WAMessage {
        key: MessageKey { remote_jid: jid.to_string(), from_me: true, id: id.to_string(), participant: None },
        message: Some(MessageContent::Text { text: "hi".to_string(), mentioned_jids: Vec::new() }),
        message_timestamp: 1000,
        status: MessageStatus::Pending,
        push_name: None,
    }
}

fn tmp_store() -> (OutboxStore, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "wa_outbox_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let store = OutboxStore::new(&dir).unwrap();
    (store, dir)
}

// ── push / pending ────────────────────────────────────────────────────────────

#[test]
fn push_shows_in_pending() {
    let (store, dir) = tmp_store();
    let msg = make_msg("alice@s.whatsapp.net", "MSG1");
    store.push("alice@s.whatsapp.net", &msg);
    let pending = store.pending();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].1.key.id, "MSG1");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn multiple_pushes_all_pending() {
    let (store, dir) = tmp_store();
    store.push("a@s.whatsapp.net", &make_msg("a@s.whatsapp.net", "A"));
    store.push("b@s.whatsapp.net", &make_msg("b@s.whatsapp.net", "B"));
    assert_eq!(store.pending().len(), 2);
    let _ = std::fs::remove_dir_all(dir);
}

// ── remove ────────────────────────────────────────────────────────────────────

#[test]
fn remove_clears_entry() {
    let (store, dir) = tmp_store();
    store.push("a@s.whatsapp.net", &make_msg("a@s.whatsapp.net", "A"));
    store.remove("A");
    assert!(store.pending().is_empty());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn remove_unknown_id_is_noop() {
    let (store, dir) = tmp_store();
    store.push("a@s.whatsapp.net", &make_msg("a@s.whatsapp.net", "A"));
    store.remove("DOES_NOT_EXIST");
    assert_eq!(store.pending().len(), 1);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn remove_only_removes_matching_id() {
    let (store, dir) = tmp_store();
    store.push("a@s.whatsapp.net", &make_msg("a@s.whatsapp.net", "A"));
    store.push("b@s.whatsapp.net", &make_msg("b@s.whatsapp.net", "B"));
    store.remove("A");
    let pending = store.pending();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].1.key.id, "B");
    let _ = std::fs::remove_dir_all(dir);
}

// ── persistence ───────────────────────────────────────────────────────────────

#[test]
fn entries_survive_reload() {
    let dir = std::env::temp_dir().join(format!(
        "wa_outbox_persist_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    {
        let store = OutboxStore::new(&dir).unwrap();
        store.push("alice@s.whatsapp.net", &make_msg("alice@s.whatsapp.net", "P1"));
    }
    {
        let store2 = OutboxStore::new(&dir).unwrap();
        let pending = store2.pending();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].1.key.id, "P1");
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn remove_persists_across_reload() {
    let dir = std::env::temp_dir().join(format!(
        "wa_outbox_rm_persist_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    {
        let store = OutboxStore::new(&dir).unwrap();
        store.push("alice@s.whatsapp.net", &make_msg("alice@s.whatsapp.net", "R1"));
        store.remove("R1");
    }
    {
        let store2 = OutboxStore::new(&dir).unwrap();
        assert!(store2.pending().is_empty());
    }
    let _ = std::fs::remove_dir_all(dir);
}

// ── ordering ──────────────────────────────────────────────────────────────────

#[test]
fn pending_ordered_by_created_at() {
    let (store, dir) = tmp_store();
    // Push in order; they should come back in insertion order (created_at ascending)
    for i in 0u32..5 {
        store.push("jid@s.whatsapp.net", &make_msg("jid@s.whatsapp.net", &format!("ID{i}")));
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    let pending = store.pending();
    assert_eq!(pending.len(), 5);
    assert_eq!(pending[0].1.key.id, "ID0");
    assert_eq!(pending[4].1.key.id, "ID4");
    let _ = std::fs::remove_dir_all(dir);
}
