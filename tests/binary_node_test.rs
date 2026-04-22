use whatsapp_rs::binary::{decode_frame, encode_node, BinaryNode, NodeContent};

fn roundtrip(node: &BinaryNode) -> BinaryNode {
    let encoded = encode_node(node);
    decode_frame(&encoded).expect("decode_frame must succeed")
}

/// Extract string content from a node, accepting both Text and Bytes variants.
fn content_as_str(content: &NodeContent) -> Option<String> {
    match content {
        NodeContent::Text(s) => Some(s.clone()),
        NodeContent::Bytes(b) => String::from_utf8(b.clone()).ok(),
        _ => None,
    }
}

// ── Basic encode / decode ─────────────────────────────────────────────────────

#[test]
fn text_node_roundtrip() {
    let node = BinaryNode {
        tag: "message".to_string(),
        attrs: vec![("id".to_string(), "ABC123".to_string())],
        content: NodeContent::Text("hello world".to_string()),
    };
    let decoded = roundtrip(&node);
    assert_eq!(decoded.tag, "message");
    assert_eq!(decoded.attr("id"), Some("ABC123"));
    let s = content_as_str(&decoded.content).expect("expected string content");
    assert_eq!(s, "hello world");
}

#[test]
fn bytes_node_roundtrip() {
    let payload = vec![0x01, 0x02, 0xAA, 0xFF];
    let node = BinaryNode {
        tag: "data".to_string(),
        attrs: vec![],
        content: NodeContent::Bytes(payload.clone()),
    };
    let decoded = roundtrip(&node);
    match decoded.content {
        NodeContent::Bytes(b) => assert_eq!(b, payload),
        _ => panic!("expected Bytes content"),
    }
}

#[test]
fn empty_content_node_roundtrip() {
    let node = BinaryNode {
        tag: "ping".to_string(),
        attrs: vec![
            ("xmlns".to_string(), "w:p".to_string()),
            ("type".to_string(), "get".to_string()),
        ],
        content: NodeContent::None,
    };
    let decoded = roundtrip(&node);
    assert_eq!(decoded.tag, "ping");
    assert_eq!(decoded.attr("xmlns"), Some("w:p"));
    assert_eq!(decoded.attr("type"), Some("get"));
    assert!(matches!(decoded.content, NodeContent::None));
}

#[test]
fn nested_list_roundtrip() {
    let inner = BinaryNode {
        tag: "item".to_string(),
        attrs: vec![("jid".to_string(), "5491155@s.whatsapp.net".to_string())],
        content: NodeContent::None,
    };
    let outer = BinaryNode {
        tag: "list".to_string(),
        attrs: vec![],
        content: NodeContent::List(vec![inner]),
    };
    let decoded = roundtrip(&outer);
    assert_eq!(decoded.tag, "list");
    match decoded.content {
        NodeContent::List(children) => {
            assert_eq!(children.len(), 1);
            assert_eq!(children[0].tag, "item");
            assert_eq!(
                children[0].attr("jid"),
                Some("5491155@s.whatsapp.net")
            );
        }
        _ => panic!("expected List content"),
    }
}

#[test]
fn multiple_attrs_roundtrip() {
    let node = BinaryNode {
        tag: "iq".to_string(),
        attrs: vec![
            ("id".to_string(), "12345".to_string()),
            ("type".to_string(), "get".to_string()),
            ("xmlns".to_string(), "encrypt".to_string()),
            ("to".to_string(), "s.whatsapp.net".to_string()),
        ],
        content: NodeContent::None,
    };
    let decoded = roundtrip(&node);
    assert_eq!(decoded.attr("id"),    Some("12345"));
    assert_eq!(decoded.attr("type"),  Some("get"));
    assert_eq!(decoded.attr("xmlns"), Some("encrypt"));
    assert_eq!(decoded.attr("to"),    Some("s.whatsapp.net"));
}

// ── attr() helper ────────────────────────────────────────────────────────────

#[test]
fn attr_returns_none_for_missing_key() {
    let node = BinaryNode {
        tag: "test".to_string(),
        attrs: vec![("a".to_string(), "1".to_string())],
        content: NodeContent::None,
    };
    assert_eq!(node.attr("a"), Some("1"));
    assert_eq!(node.attr("b"), None);
}

// ── deep nesting ──────────────────────────────────────────────────────────────

#[test]
fn deeply_nested_list_roundtrip() {
    let leaf = BinaryNode {
        tag: "value".to_string(),
        attrs: vec![],
        content: NodeContent::Bytes(vec![0x05, 0xDE, 0xAD]),
    };
    let mid = BinaryNode {
        tag: "skey".to_string(),
        attrs: vec![],
        content: NodeContent::List(vec![leaf]),
    };
    let root = BinaryNode {
        tag: "iq".to_string(),
        attrs: vec![("type".to_string(), "set".to_string())],
        content: NodeContent::List(vec![mid]),
    };
    let decoded = roundtrip(&root);
    let skey = match &decoded.content {
        NodeContent::List(ch) => ch.iter().find(|n| n.tag == "skey").unwrap().clone(),
        _ => panic!("expected List"),
    };
    let value_bytes = match &skey.content {
        NodeContent::List(ch) => match &ch[0].content {
            NodeContent::Bytes(b) => b.clone(),
            _ => panic!("expected Bytes"),
        },
        _ => panic!("expected List"),
    };
    assert_eq!(value_bytes, vec![0x05, 0xDE, 0xAD]);
}

// ── multiple siblings ─────────────────────────────────────────────────────────

#[test]
fn list_with_multiple_children() {
    let children: Vec<BinaryNode> = (0u8..5)
        .map(|i| BinaryNode {
            tag: "participant".to_string(),
            attrs: vec![("jid".to_string(), format!("{i}@s.whatsapp.net"))],
            content: NodeContent::None,
        })
        .collect();
    let node = BinaryNode {
        tag: "group".to_string(),
        attrs: vec![("subject".to_string(), "Test Group".to_string())],
        content: NodeContent::List(children),
    };
    let decoded = roundtrip(&node);
    match decoded.content {
        NodeContent::List(ch) => {
            assert_eq!(ch.len(), 5);
            for (i, child) in ch.iter().enumerate() {
                assert_eq!(child.attr("jid"), Some(format!("{i}@s.whatsapp.net").as_str()));
            }
        }
        _ => panic!("expected List"),
    }
}
