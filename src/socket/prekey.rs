use crate::auth::credentials::{AuthCredentials, KeyPair};
use crate::auth::session_store::SessionStore;
use crate::binary::{BinaryNode, NodeContent};
use crate::signal::x3dh::PreKeyBundle;
use crate::socket::SocketSender;
use anyhow::{bail, Result};
use tracing::info;

/// Fetch a recipient's pre-key bundle from WhatsApp servers.
/// Sends an encrypt IQ and parses the key-bundle binary nodes.
pub async fn fetch_pre_key_bundle(sender: &SocketSender, jid: &str) -> Result<PreKeyBundle> {
    let id = sender.next_id();
    let node = BinaryNode {
        tag: "iq".to_string(),
        attrs: vec![
            ("id".to_string(), id),
            ("xmlns".to_string(), "encrypt".to_string()),
            ("type".to_string(), "get".to_string()),
            ("to".to_string(), "s.whatsapp.net".to_string()),
        ],
        content: NodeContent::List(vec![BinaryNode {
            tag: "key".to_string(),
            attrs: vec![],
            content: NodeContent::List(vec![BinaryNode {
                tag: "user".to_string(),
                attrs: vec![("jid".to_string(), jid.to_string())],
                content: NodeContent::None,
            }]),
        }]),
    };

    let response = sender.send_iq_await(node).await?;
    parse_key_bundle_iq(&response, jid)
}

// ── Pre-key upload ────────────────────────────────────────────────────────────

/// Rotate the signed pre-key: generate a new keypair, upload it, and persist.
/// The new key replaces the old one in `creds`; `spk_last_rotated` is updated.
pub async fn rotate_signed_pre_key(
    sender: &SocketSender,
    creds: &mut AuthCredentials,
    store: &dyn SessionStore,
) -> Result<()> {
    let new_id = creds.signed_pre_key.key_id + 1;
    let kp = KeyPair::generate();
    let sig = creds.signed_identity_key.sign_ed25519(&kp.public);
    let new_spk = crate::auth::credentials::SignedKeyPair {
        key_pair: kp,
        signature: sig.to_vec(),
        key_id: new_id,
    };

    let id = sender.next_id();
    let node = BinaryNode {
        tag: "iq".to_string(),
        attrs: vec![
            ("id".to_string(), id),
            ("xmlns".to_string(), "encrypt".to_string()),
            ("type".to_string(), "set".to_string()),
            ("to".to_string(), "s.whatsapp.net".to_string()),
        ],
        content: NodeContent::List(vec![BinaryNode {
            tag: "rotate".to_string(),
            attrs: vec![],
            content: NodeContent::List(vec![BinaryNode {
                tag: "skey".to_string(),
                attrs: vec![],
                content: NodeContent::List(vec![
                    bytes_node("id", &u24_be(new_spk.key_id)),
                    bytes_node("value", &prefixed_key(&new_spk.key_pair.public)),
                    bytes_node("signature", &new_spk.signature),
                ]),
            }]),
        }]),
    };

    sender.send_iq_await(node).await?;

    creds.signed_pre_key = new_spk;
    creds.spk_last_rotated = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    store.save_credentials(creds)?;

    info!("rotated signed pre-key → id={new_id}");
    Ok(())
}

/// Query how many one-time pre-keys we currently have on the server.
pub async fn query_pre_key_count(sender: &SocketSender) -> Result<u32> {
    let id = sender.next_id();
    let node = BinaryNode {
        tag: "iq".to_string(),
        attrs: vec![
            ("id".to_string(), id),
            ("xmlns".to_string(), "encrypt".to_string()),
            ("type".to_string(), "get".to_string()),
            ("to".to_string(), "s.whatsapp.net".to_string()),
        ],
        content: NodeContent::List(vec![BinaryNode {
            tag: "count".to_string(),
            attrs: vec![],
            content: NodeContent::None,
        }]),
    };
    let response = sender.send_iq_await(node).await?;
    if let NodeContent::List(ch) = &response.content {
        if let Some(count_node) = ch.iter().find(|n| n.tag == "count") {
            if let Some(val) = count_node.attr("value") {
                return val.parse().map_err(|_| anyhow::anyhow!("bad count value: {val}"));
            }
        }
    }
    Err(anyhow::anyhow!("no <count> in pre-key count response"))
}

/// Upload our identity, signed pre-key, and one-time pre-keys to WhatsApp.
/// Saves each OTK private key via `store` so `x3dh_receiver` can use it later.
/// Updates `creds.first_unuploaded_pre_key_id` after a successful upload.
pub async fn upload_pre_keys(
    sender: &SocketSender,
    creds: &mut AuthCredentials,
    store: &dyn SessionStore,
) -> Result<()> {
    const BATCH_SIZE: u32 = 30;

    let reg_id = creds.registration_id as u32;
    let start_id = creds.first_unuploaded_pre_key_id;

    // Generate keys, save private parts immediately
    let mut one_time_keys: Vec<BinaryNode> = Vec::new();
    for i in 0..BATCH_SIZE {
        let kid = start_id + i;
        let kp = KeyPair::generate();

        // Persist priv || pub (64 bytes) — needed by x3dh_receiver when a pkmsg arrives
        let mut key_bytes = Vec::with_capacity(64);
        key_bytes.extend_from_slice(&kp.private);
        key_bytes.extend_from_slice(&kp.public);
        store.save_prekey(kid, &key_bytes)?;

        one_time_keys.push(BinaryNode {
            tag: "key".to_string(),
            attrs: vec![],
            content: NodeContent::List(vec![
                bytes_node("id", &u24_be(kid)),
                bytes_node("value", &prefixed_key(&kp.public)),
            ]),
        });
    }

    let spk = &creds.signed_pre_key;
    let iq_id = sender.next_id();
    let node = BinaryNode {
        tag: "iq".to_string(),
        attrs: vec![
            ("id".to_string(), iq_id),
            ("xmlns".to_string(), "encrypt".to_string()),
            ("type".to_string(), "set".to_string()),
            ("to".to_string(), "s.whatsapp.net".to_string()),
        ],
        content: NodeContent::List(vec![
            bytes_node("registration", &reg_id.to_be_bytes()),
            bytes_node("type", &[0x05]),
            bytes_node("identity", &prefixed_key(&creds.signed_identity_key.public)),
            BinaryNode {
                tag: "list".to_string(),
                attrs: vec![],
                content: NodeContent::List(one_time_keys),
            },
            BinaryNode {
                tag: "skey".to_string(),
                attrs: vec![],
                content: NodeContent::List(vec![
                    bytes_node("id", &u24_be(spk.key_id)),
                    bytes_node("value", &prefixed_key(&spk.key_pair.public)),
                    bytes_node("signature", &spk.signature),
                ]),
            },
        ]),
    };

    sender.send_node(&node).await?;

    // Mark these pre-keys as uploaded and persist updated credentials
    creds.first_unuploaded_pre_key_id = start_id + BATCH_SIZE;
    store.save_credentials(creds)?;

    info!("uploaded {BATCH_SIZE} OTKs (ids {start_id}..{})", start_id + BATCH_SIZE - 1);
    Ok(())
}

fn bytes_node(tag: &str, data: &[u8]) -> BinaryNode {
    BinaryNode {
        tag: tag.to_string(),
        attrs: vec![],
        content: NodeContent::Bytes(data.to_vec()),
    }
}

fn prefixed_key(pub_key: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(33);
    v.push(0x05);
    v.extend_from_slice(pub_key);
    v
}

fn u24_be(v: u32) -> [u8; 3] {
    [(v >> 16) as u8, (v >> 8) as u8, v as u8]
}

// ── Response parser ───────────────────────────────────────────────────────────

fn parse_key_bundle_iq(iq: &BinaryNode, _jid: &str) -> Result<PreKeyBundle> {
    // Baileys layout (src/Utils/signal.ts `parseAndInjectE2ESessions`):
    // <iq type="result"><list><user jid="...">
    //   <registration>…</registration>
    //   <identity>…</identity>
    //   <skey><id/><value/><signature/></skey>
    //   <key><id/><value/></key>
    // </user></list></iq>
    let list = find_child(iq, "list")?;
    let user = find_child(list, "user")?;
    parse_bundle_node(user)
}

fn parse_bundle_node(node: &BinaryNode) -> Result<PreKeyBundle> {
    let children = match &node.content {
        NodeContent::List(v) => v,
        _ => bail!("key-bundle has no children"),
    };

    // registration: 4 big-endian bytes → u32
    let reg_bytes = get_child_bytes(children, "registration")?;
    if reg_bytes.len() < 4 {
        bail!("registration too short: {} bytes", reg_bytes.len());
    }
    let registration_id = u32::from_be_bytes([reg_bytes[0], reg_bytes[1], reg_bytes[2], reg_bytes[3]]);

    // identity key: 33 bytes (0x05 prefix + 32 X25519 bytes)
    let identity_raw = get_child_bytes(children, "identity")?;
    let identity_key = extract_key_32(&identity_raw, "identity")?;

    // signed pre-key
    let skey = find_child_in(children, "skey")?;
    let (signed_pre_key_id, signed_pre_key, signed_pre_key_sig) = parse_skey(skey)?;

    // optional one-time pre-key
    let (one_time_pre_key_id, one_time_pre_key) = if let Some(key) = find_child_opt(children, "key") {
        let (kid, kpub) = parse_one_time_key(key)?;
        (Some(kid), Some(kpub))
    } else {
        (None, None)
    };

    Ok(PreKeyBundle {
        registration_id,
        device_id: 0,
        identity_key,
        signed_pre_key_id,
        signed_pre_key,
        signed_pre_key_sig,
        one_time_pre_key_id,
        one_time_pre_key,
    })
}

fn parse_skey(node: &BinaryNode) -> Result<(u32, [u8; 32], [u8; 64])> {
    let children = match &node.content {
        NodeContent::List(v) => v,
        _ => bail!("skey has no children"),
    };

    let id_bytes = get_child_bytes(children, "id")?;
    let key_id = bytes_to_u32_be(&id_bytes);

    let value_bytes = get_child_bytes(children, "value")?;
    let public_key = extract_key_32(&value_bytes, "skey.value")?;

    let sig_bytes = get_child_bytes(children, "signature")?;
    if sig_bytes.len() != 64 {
        bail!("skey signature wrong length: {}", sig_bytes.len());
    }
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&sig_bytes);

    Ok((key_id, public_key, sig))
}

fn parse_one_time_key(node: &BinaryNode) -> Result<(u32, [u8; 32])> {
    let children = match &node.content {
        NodeContent::List(v) => v,
        _ => bail!("key has no children"),
    };

    let id_bytes = get_child_bytes(children, "id")?;
    let key_id = bytes_to_u32_be(&id_bytes);

    let value_bytes = get_child_bytes(children, "value")?;
    let public_key = extract_key_32(&value_bytes, "key.value")?;

    Ok((key_id, public_key))
}

// ── Node helpers ──────────────────────────────────────────────────────────────

fn find_child<'a>(node: &'a BinaryNode, tag: &str) -> Result<&'a BinaryNode> {
    find_child_opt_node(node, tag)
        .ok_or_else(|| anyhow::anyhow!("missing <{tag}> in <{}>", node.tag))
}

fn find_child_opt<'a>(children: &'a [BinaryNode], tag: &str) -> Option<&'a BinaryNode> {
    children.iter().find(|n| n.tag == tag)
}

fn find_child_opt_node<'a>(node: &'a BinaryNode, tag: &str) -> Option<&'a BinaryNode> {
    if let NodeContent::List(v) = &node.content {
        v.iter().find(|n| n.tag == tag)
    } else {
        None
    }
}

fn find_child_in<'a>(children: &'a [BinaryNode], tag: &str) -> Result<&'a BinaryNode> {
    children
        .iter()
        .find(|n| n.tag == tag)
        .ok_or_else(|| anyhow::anyhow!("missing <{tag}>"))
}

fn get_child_bytes(children: &[BinaryNode], tag: &str) -> Result<Vec<u8>> {
    let node = children
        .iter()
        .find(|n| n.tag == tag)
        .ok_or_else(|| anyhow::anyhow!("missing <{tag}>"))?;
    match &node.content {
        NodeContent::Bytes(b) => Ok(b.clone()),
        NodeContent::Text(s) => Ok(s.as_bytes().to_vec()),
        _ => bail!("<{tag}> has no byte content"),
    }
}

fn extract_key_32(data: &[u8], name: &str) -> Result<[u8; 32]> {
    // Keys are 33 bytes with 0x05 prefix, or raw 32 bytes
    let raw = match data.len() {
        33 => &data[1..],
        32 => data,
        n => bail!("{name} key wrong length: {n}"),
    };
    let mut key = [0u8; 32];
    key.copy_from_slice(raw);
    Ok(key)
}

fn bytes_to_u32_be(data: &[u8]) -> u32 {
    let mut result = 0u32;
    for &b in data.iter().take(4) {
        result = (result << 8) | b as u32;
    }
    result
}
