use whatsapp_rs::message_store::MessageStore;
use whatsapp_rs::messages::{MessageContent, MessageKey, MessageStatus, WAMessage};

fn make_msg(jid: &str, id: &str, from_me: bool, text: &str, ts: u64) -> WAMessage {
    WAMessage {
        key: MessageKey {
            remote_jid: jid.to_string(),
            from_me,
            id: id.to_string(),
            participant: None,
        },
        message: Some(MessageContent::Text { text: text.to_string(), mentioned_jids: Vec::new() }),
        message_timestamp: ts,
        status: MessageStatus::Delivered,
        push_name: None,
    }
}

fn tmp_store() -> (MessageStore, std::path::PathBuf) {
    let dir = std::env::temp_dir()
        .join(format!("wa_msgstore_{}_{}", std::process::id(), rand_suffix()));
    let store = MessageStore::new(&dir).unwrap();
    (store, dir)
}

fn rand_suffix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos() as u64
}

// ── push / deduplication ──────────────────────────────────────────────────────

#[test]
fn push_returns_true_for_new_message() {
    let (store, dir) = tmp_store();
    let msg = make_msg("alice@s.whatsapp.net", "ID1", false, "hello", 1000);
    assert!(store.push(&msg));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn push_returns_false_for_duplicate() {
    let (store, dir) = tmp_store();
    let msg = make_msg("alice@s.whatsapp.net", "ID1", false, "hello", 1000);
    assert!(store.push(&msg));
    assert!(!store.push(&msg), "second push of same ID must return false");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn push_different_ids_both_stored() {
    let (store, dir) = tmp_store();
    let jid = "bob@s.whatsapp.net";
    store.push(&make_msg(jid, "A", false, "one", 1));
    store.push(&make_msg(jid, "B", false, "two", 2));
    let msgs = store.recent(jid, 10);
    assert_eq!(msgs.len(), 2);
    let _ = std::fs::remove_dir_all(dir);
}

// ── recent ────────────────────────────────────────────────────────────────────

#[test]
fn recent_returns_at_most_n() {
    let (store, dir) = tmp_store();
    let jid = "chat@s.whatsapp.net";
    for i in 0..10u32 {
        store.push(&make_msg(jid, &format!("ID{i}"), false, "x", i as u64));
    }
    let msgs = store.recent(jid, 3);
    assert_eq!(msgs.len(), 3);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn recent_returns_most_recent_last() {
    let (store, dir) = tmp_store();
    let jid = "chat@s.whatsapp.net";
    for i in 0..5u32 {
        store.push(&make_msg(jid, &format!("ID{i}"), false, "x", i as u64));
    }
    let msgs = store.recent(jid, 5);
    // oldest first, most recent last
    assert_eq!(msgs.first().unwrap().id, "ID0");
    assert_eq!(msgs.last().unwrap().id, "ID4");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn recent_empty_jid_returns_empty() {
    let (store, dir) = tmp_store();
    assert!(store.recent("unknown@s.whatsapp.net", 10).is_empty());
    let _ = std::fs::remove_dir_all(dir);
}

// ── lookup ────────────────────────────────────────────────────────────────────

#[test]
fn lookup_finds_existing_message() {
    let (store, dir) = tmp_store();
    let jid = "carol@s.whatsapp.net";
    store.push(&make_msg(jid, "TARGET", false, "find me", 42));
    let found = store.lookup(jid, "TARGET");
    assert!(found.is_some());
    assert_eq!(found.unwrap().text.as_deref(), Some("find me"));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn lookup_returns_none_for_unknown_id() {
    let (store, dir) = tmp_store();
    let jid = "carol@s.whatsapp.net";
    store.push(&make_msg(jid, "REAL", false, "msg", 1));
    assert!(store.lookup(jid, "NONEXISTENT").is_none());
    let _ = std::fs::remove_dir_all(dir);
}

// ── update_status / flush_dirty ───────────────────────────────────────────────

#[test]
fn update_status_changes_in_memory() {
    let (store, dir) = tmp_store();
    let jid = "dave@s.whatsapp.net";
    store.push(&make_msg(jid, "M1", true, "sent", 1));

    store.update_status(jid, "M1", MessageStatus::Read);

    let found = store.lookup(jid, "M1").unwrap();
    assert_eq!(found.status, MessageStatus::Read);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn flush_dirty_persists_status_change() {
    let dir = std::env::temp_dir()
        .join(format!("wa_flush_{}_{}", std::process::id(), rand_suffix()));
    {
        let store = MessageStore::new(&dir).unwrap();
        let jid = "dave@s.whatsapp.net";
        store.push(&make_msg(jid, "M1", true, "sent", 1));
        store.update_status(jid, "M1", MessageStatus::Read);
        store.flush_dirty();
    }
    // Reload from disk
    {
        let store2 = MessageStore::new(&dir).unwrap();
        let found = store2.lookup("dave@s.whatsapp.net", "M1").unwrap();
        assert_eq!(found.status, MessageStatus::Read, "status must survive reload");
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn no_status_change_does_not_dirty() {
    let (store, dir) = tmp_store();
    let jid = "eve@s.whatsapp.net";
    store.push(&make_msg(jid, "M1", true, "sent", 1));
    // update with the same status (Delivered) — should be a no-op
    store.update_status(jid, "M1", MessageStatus::Delivered);
    // flush should not panic, just be a no-op
    store.flush_dirty();
    let _ = std::fs::remove_dir_all(dir);
}

// ── persistence roundtrip ─────────────────────────────────────────────────────

#[test]
fn messages_persist_across_store_instances() {
    let dir = std::env::temp_dir()
        .join(format!("wa_persist_{}_{}", std::process::id(), rand_suffix()));
    let jid = "frank@s.whatsapp.net";
    {
        let store = MessageStore::new(&dir).unwrap();
        store.push(&make_msg(jid, "P1", false, "persisted", 999));
    }
    {
        let store2 = MessageStore::new(&dir).unwrap();
        let msgs = store2.recent(jid, 10);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].id, "P1");
        assert_eq!(msgs[0].text.as_deref(), Some("persisted"));
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn from_me_field_preserved() {
    let (store, dir) = tmp_store();
    let jid = "grace@s.whatsapp.net";
    store.push(&make_msg(jid, "OUT", true, "outgoing", 1));
    store.push(&make_msg(jid, "IN", false, "incoming", 2));
    let msgs = store.recent(jid, 10);
    let out = msgs.iter().find(|m| m.id == "OUT").unwrap();
    let inc = msgs.iter().find(|m| m.id == "IN").unwrap();
    assert!(out.from_me);
    assert!(!inc.from_me);
    let _ = std::fs::remove_dir_all(dir);
}
