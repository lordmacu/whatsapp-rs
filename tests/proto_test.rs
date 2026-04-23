use whatsapp_rs::signal::wa_proto;

// ── Text messages ─────────────────────────────────────────────────────────────

#[test]
fn test_encode_decode_text() {
    let encoded = wa_proto::encode_wa_text_message("hello world");
    let decoded = wa_proto::decode_wa_text(&encoded);
    assert_eq!(decoded, Some("hello world".to_string()));
}

#[test]
fn test_encode_decode_reply() {
    let encoded = wa_proto::encode_wa_reply_message("my reply", "ABCDEF1234", None, b"");
    let decoded = wa_proto::decode_wa_text(&encoded);
    assert_eq!(decoded, Some("my reply".to_string()));
}

#[test]
fn test_text_empty_returns_none() {
    let encoded = wa_proto::encode_wa_text_message("");
    assert_eq!(wa_proto::decode_wa_text(&encoded), None);
}

// ── Reaction messages ─────────────────────────────────────────────────────────

#[test]
fn test_encode_decode_reaction() {
    let encoded = wa_proto::encode_wa_reaction_message("123@s.whatsapp.net", "MSGID99", "👍", false);
    let decoded = wa_proto::decode_wa_reaction(&encoded);
    assert_eq!(decoded, Some(("MSGID99".to_string(), "👍".to_string())));
}

#[test]
fn test_reaction_removal_empty_emoji() {
    let encoded = wa_proto::encode_wa_reaction_message("123@s.whatsapp.net", "MSGID99", "", false);
    let (_, emoji) = wa_proto::decode_wa_reaction(&encoded).expect("should decode");
    assert_eq!(emoji, "");
}

// ── Link preview ──────────────────────────────────────────────────────────────

#[test]
fn test_encode_decode_link_preview() {
    let encoded = wa_proto::encode_wa_link_preview_message(
        "Check this out: https://example.com",
        "https://example.com",
        "Example Domain",
        "This domain is for use in illustrative examples.",
        None,
    );
    let decoded = wa_proto::decode_wa_link_preview(&encoded);
    let (text, url, title, desc) = decoded.expect("should decode link preview");
    assert_eq!(url, "https://example.com");
    assert_eq!(title, "Example Domain");
    assert!(desc.contains("illustrative"));
    assert!(text.contains("Check this out"));
}

#[test]
fn test_link_preview_without_url_not_detected() {
    // Plain text with no matchedText field should NOT decode as link preview
    let encoded = wa_proto::encode_wa_text_message("just text");
    assert!(wa_proto::decode_wa_link_preview(&encoded).is_none());
}

// ── Poll ──────────────────────────────────────────────────────────────────────

#[test]
fn test_encode_decode_poll() {
    let opts = ["Option A", "Option B", "Option C"];
    let (encoded, _enc_key) = wa_proto::encode_wa_poll_message("Best option?", &opts, 1);
    let (question, options, selectable, _key) = wa_proto::decode_wa_poll(&encoded).expect("should decode poll");
    assert_eq!(question, "Best option?");
    assert_eq!(options.len(), 3);
    assert!(options.contains(&"Option A".to_string()));
    assert!(options.contains(&"Option B".to_string()));
    assert!(options.contains(&"Option C".to_string()));
    assert_eq!(selectable, 1);
}

#[test]
fn test_poll_unlimited_selectable() {
    let opts = ["Yes", "No"];
    let (encoded, _) = wa_proto::encode_wa_poll_message("Agree?", &opts, 0);
    let (_, _, selectable, _) = wa_proto::decode_wa_poll(&encoded).expect("should decode");
    assert_eq!(selectable, 0);
}

#[test]
fn test_text_not_detected_as_poll() {
    let encoded = wa_proto::encode_wa_text_message("not a poll");
    assert!(wa_proto::decode_wa_poll(&encoded).is_none());
}
