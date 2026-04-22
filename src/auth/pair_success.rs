//! Pair-success stanza processing: decode the server-signed device identity,
//! verify HMAC + account signature, sign the device message, and build the reply.
//!
//! This mirrors Baileys `configureSuccessfulPairing` in
//! `src/Utils/validate-connection.ts`. Protobuf messages are decoded/encoded
//! by hand (no prost dependency for these small types).

use anyhow::{bail, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::auth::credentials::AuthCredentials;
use crate::binary::{BinaryNode, NodeContent};

// Prefixes used in signature computation — see Baileys Defaults/index.ts.
pub const ADV_ACCOUNT_SIG_PREFIX:        [u8; 2] = [0x06, 0x00];
pub const ADV_HOSTED_ACCOUNT_SIG_PREFIX: [u8; 2] = [0x06, 0x05];
pub const ADV_DEVICE_SIG_PREFIX:         [u8; 2] = [0x06, 0x01];

/// Encryption type from `ADVEncryptionType` enum in WAProto.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AdvEncryptionType {
    E2ee = 0,
    Hosted = 1,
}

#[derive(Debug, Clone)]
pub struct AdvSignedDeviceIdentityHmac {
    pub details: Vec<u8>,
    pub hmac: Vec<u8>,
    pub account_type: Option<AdvEncryptionType>,
}

#[derive(Debug, Clone)]
pub struct AdvSignedDeviceIdentity {
    pub details: Vec<u8>,
    pub account_signature_key: Option<Vec<u8>>,
    pub account_signature: Option<Vec<u8>>,
    pub device_signature: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AdvDeviceIdentity {
    pub raw_id: u32,
    pub timestamp: u64,
    pub key_index: u32,
    pub account_type: Option<AdvEncryptionType>,
    pub device_type: Option<AdvEncryptionType>,
}

/// Parsed outcome of a pair-success handshake.
#[allow(dead_code)]
pub struct PairSuccessOutcome {
    pub jid: String,
    pub lid: Option<String>,
    pub platform: Option<String>,
    pub business_name: Option<String>,
    pub key_index: u32,
    /// Encoded `ADVSignedDeviceIdentity` with our device signature added
    /// and the `accountSignatureKey` field stripped (as Baileys does).
    pub account_enc: Vec<u8>,
    /// `account_signature_key` (32 bytes, the server's identity pub).
    /// Saved as a signal identity for the returned `lid`.
    pub account_signature_key: Vec<u8>,
}

/// Parse a pair-success node, verify signatures, produce the reply stanza plus
/// an update to write back to credentials.
pub fn process_pair_success(
    stanza: &BinaryNode,
    creds: &AuthCredentials,
) -> Result<(PairSuccessOutcome, BinaryNode)> {
    let msg_id = stanza.attr("id").unwrap_or("").to_string();
    if msg_id.is_empty() {
        bail!("pair-success iq missing id attribute");
    }

    let pair_success = find_child(stanza, "pair-success")
        .ok_or_else(|| anyhow::anyhow!("no <pair-success> child in iq"))?;

    let device_identity = find_child(pair_success, "device-identity")
        .ok_or_else(|| anyhow::anyhow!("no <device-identity> in pair-success"))?;
    let device_node = find_child(pair_success, "device")
        .ok_or_else(|| anyhow::anyhow!("no <device> in pair-success"))?;
    let platform = find_child(pair_success, "platform")
        .and_then(|n| n.attr("name").map(str::to_string));
    let biz = find_child(pair_success, "biz")
        .and_then(|n| n.attr("name").map(str::to_string));

    let jid = device_node.attr("jid")
        .ok_or_else(|| anyhow::anyhow!("device node has no jid"))?
        .to_string();
    let lid = device_node.attr("lid").map(str::to_string);

    // device-identity content is a protobuf-encoded ADVSignedDeviceIdentityHMAC
    let identity_bytes = match &device_identity.content {
        NodeContent::Bytes(b) => b.clone(),
        NodeContent::Text(t)  => t.as_bytes().to_vec(),
        _ => bail!("device-identity has no binary content"),
    };

    let hmac_msg = decode_hmac_wrapper(&identity_bytes)?;

    // Verify HMAC: HMAC-SHA256(adv_secret, [prefix ||] details) == hmac
    let hmac_prefix: &[u8] = if matches!(hmac_msg.account_type, Some(AdvEncryptionType::Hosted)) {
        &ADV_HOSTED_ACCOUNT_SIG_PREFIX
    } else {
        &[]
    };
    let mut mac = Hmac::<Sha256>::new_from_slice(&creds.adv_secret_key)
        .map_err(|e| anyhow::anyhow!("hmac init: {e}"))?;
    mac.update(hmac_prefix);
    mac.update(&hmac_msg.details);
    mac.verify_slice(&hmac_msg.hmac)
        .map_err(|_| anyhow::anyhow!("pair-success HMAC mismatch"))?;

    // Decode the inner SignedDeviceIdentity and its DeviceIdentity details
    let mut account = decode_signed_device_identity(&hmac_msg.details)?;
    let device = decode_device_identity(
        account.details.as_slice(),
    )?;

    // Verify the account signature (XEdDSA / Curve25519) over
    // prefix || deviceDetails || ourIdentityPublic
    let account_sig_key = account.account_signature_key
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("account missing accountSignatureKey"))?;
    let account_sig = account.account_signature
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("account missing accountSignature"))?;
    let account_sig_prefix: &[u8] =
        if matches!(device.device_type, Some(AdvEncryptionType::Hosted)) {
            &ADV_HOSTED_ACCOUNT_SIG_PREFIX
        } else {
            &ADV_ACCOUNT_SIG_PREFIX
        };

    let mut account_msg = Vec::with_capacity(2 + account.details.len() + 32);
    account_msg.extend_from_slice(account_sig_prefix);
    account_msg.extend_from_slice(&account.details);
    account_msg.extend_from_slice(&creds.signed_identity_key.public);

    verify_xeddsa(account_sig_key, &account_msg, account_sig)
        .map_err(|e| anyhow::anyhow!("account signature invalid: {e}"))?;

    // Compute our device signature: XEdDSA_sign(
    //   identity_priv,
    //   prefix || details || identity_pub || account_sig_key
    // )
    let mut device_msg = Vec::with_capacity(2 + account.details.len() + 32 + 32);
    device_msg.extend_from_slice(&ADV_DEVICE_SIG_PREFIX);
    device_msg.extend_from_slice(&account.details);
    device_msg.extend_from_slice(&creds.signed_identity_key.public);
    device_msg.extend_from_slice(account_sig_key);

    let device_sig = creds.signed_identity_key.sign_xeddsa(&device_msg);
    account.device_signature = Some(device_sig.to_vec());

    // Re-encode the ADVSignedDeviceIdentity WITHOUT accountSignatureKey
    // (Baileys strips it before sending back).
    let account_enc = encode_signed_device_identity(&account, /*include_sig_key*/ false);

    let reply = BinaryNode {
        tag: "iq".into(),
        attrs: vec![
            ("to".into(),   "s.whatsapp.net".into()),
            ("type".into(), "result".into()),
            ("id".into(),   msg_id),
        ],
        content: NodeContent::List(vec![BinaryNode {
            tag: "pair-device-sign".into(),
            attrs: vec![],
            content: NodeContent::List(vec![BinaryNode {
                tag: "device-identity".into(),
                attrs: vec![("key-index".into(), device.key_index.to_string())],
                content: NodeContent::Bytes(account_enc.clone()),
            }]),
        }]),
    };

    Ok((
        PairSuccessOutcome {
            jid,
            lid,
            platform,
            business_name: biz,
            key_index: device.key_index,
            account_enc,
            account_signature_key: account_sig_key.to_vec(),
        },
        reply,
    ))
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn find_child<'a>(node: &'a BinaryNode, tag: &str) -> Option<&'a BinaryNode> {
    if let NodeContent::List(children) = &node.content {
        children.iter().find(|c| c.tag == tag)
    } else {
        None
    }
}

fn verify_xeddsa(pub_key: &[u8], msg: &[u8], sig: &[u8]) -> Result<()> {
    use xeddsa::{xed25519, Verify};
    let pk_arr: [u8; 32] = pub_key.try_into()
        .map_err(|_| anyhow::anyhow!("public key must be 32 bytes"))?;
    let sig_arr: [u8; 64] = sig.try_into()
        .map_err(|_| anyhow::anyhow!("signature must be 64 bytes"))?;
    let pk = xed25519::PublicKey(pk_arr);
    pk.verify(msg, &sig_arr).map_err(|e| anyhow::anyhow!("{e:?}"))
}

// ── Protobuf encoders/decoders ───────────────────────────────────────────────
// WA ADV messages are small and simple — hand-rolled codec.

fn decode_hmac_wrapper(buf: &[u8]) -> Result<AdvSignedDeviceIdentityHmac> {
    let mut details: Option<Vec<u8>> = None;
    let mut hmac: Option<Vec<u8>> = None;
    let mut account_type: Option<AdvEncryptionType> = None;

    for_each_field(buf, |field, wire, data, varint| {
        match (field, wire) {
            (1, 2) => { details = Some(data.to_vec()); }
            (2, 2) => { hmac    = Some(data.to_vec()); }
            (3, 0) => {
                if let Some(v) = varint { account_type = adv_enc_from_u64(v); }
            }
            _ => {}
        }
        Ok(())
    })?;

    Ok(AdvSignedDeviceIdentityHmac {
        details: details.ok_or_else(|| anyhow::anyhow!("hmac wrapper missing details"))?,
        hmac:    hmac.ok_or_else(|| anyhow::anyhow!("hmac wrapper missing hmac"))?,
        account_type,
    })
}

fn decode_signed_device_identity(buf: &[u8]) -> Result<AdvSignedDeviceIdentity> {
    let mut out = AdvSignedDeviceIdentity {
        details: Vec::new(),
        account_signature_key: None,
        account_signature:     None,
        device_signature:      None,
    };
    for_each_field(buf, |field, wire, data, _varint| {
        if wire == 2 {
            match field {
                1 => out.details = data.to_vec(),
                2 => out.account_signature_key = Some(data.to_vec()),
                3 => out.account_signature     = Some(data.to_vec()),
                4 => out.device_signature      = Some(data.to_vec()),
                _ => {}
            }
        }
        Ok(())
    })?;
    Ok(out)
}

fn decode_device_identity(buf: &[u8]) -> Result<AdvDeviceIdentity> {
    let mut raw_id = 0u32;
    let mut timestamp = 0u64;
    let mut key_index = 0u32;
    let mut account_type: Option<AdvEncryptionType> = None;
    let mut device_type:  Option<AdvEncryptionType> = None;

    for_each_field(buf, |field, wire, _data, varint| {
        if wire == 0 {
            if let Some(v) = varint {
                match field {
                    1 => raw_id       = v as u32,
                    2 => timestamp    = v,
                    3 => key_index    = v as u32,
                    4 => account_type = adv_enc_from_u64(v),
                    5 => device_type  = adv_enc_from_u64(v),
                    _ => {}
                }
            }
        }
        Ok(())
    })?;

    Ok(AdvDeviceIdentity { raw_id, timestamp, key_index, account_type, device_type })
}

pub fn encode_signed_device_identity(
    account: &AdvSignedDeviceIdentity,
    include_signature_key: bool,
) -> Vec<u8> {
    let mut out = Vec::new();
    write_bytes_field(&mut out, 1, &account.details);
    if include_signature_key {
        if let Some(k) = &account.account_signature_key {
            if !k.is_empty() {
                write_bytes_field(&mut out, 2, k);
            }
        }
    }
    if let Some(s) = &account.account_signature { write_bytes_field(&mut out, 3, s); }
    if let Some(s) = &account.device_signature  { write_bytes_field(&mut out, 4, s); }
    out
}

fn adv_enc_from_u64(v: u64) -> Option<AdvEncryptionType> {
    match v {
        0 => Some(AdvEncryptionType::E2ee),
        1 => Some(AdvEncryptionType::Hosted),
        _ => None,
    }
}

// ── Protobuf raw field iteration ─────────────────────────────────────────────

/// Visit each protobuf field. Callback receives (field, wire_type, payload).
/// For wire 0 the payload is the 8-byte little-endian varint value encoded in a slice;
/// the simpler way is a separate u64 channel, so the callback gets a small Option<u64>.
fn for_each_field<F>(mut buf: &[u8], mut f: F) -> Result<()>
where
    F: FnMut(u64, u64, &[u8], Option<u64>) -> Result<()>,
{
    while !buf.is_empty() {
        let (tag, n) = read_varint(buf)?;
        buf = &buf[n..];
        let field = tag >> 3;
        let wire  = tag & 7;
        match wire {
            0 => {
                let (v, n2) = read_varint(buf)?;
                buf = &buf[n2..];
                f(field, wire, &[], Some(v))?;
            }
            2 => {
                let (len, n2) = read_varint(buf)?;
                buf = &buf[n2..];
                let end = len as usize;
                if end > buf.len() { bail!("length-delimited overflow"); }
                f(field, wire, &buf[..end], None)?;
                buf = &buf[end..];
            }
            1 => { f(field, wire, &buf[..8], None)?; buf = &buf[8..]; }
            5 => { f(field, wire, &buf[..4], None)?; buf = &buf[4..]; }
            _ => bail!("unsupported wire type {}", wire),
        }
    }
    Ok(())
}

fn read_varint(buf: &[u8]) -> Result<(u64, usize)> {
    let mut v = 0u64;
    let mut shift = 0u32;
    for (i, &b) in buf.iter().enumerate() {
        v |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Ok((v, i + 1));
        }
        shift += 7;
        if shift >= 64 {
            bail!("varint too long");
        }
    }
    bail!("varint truncated");
}

fn write_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            break;
        } else {
            out.push(b | 0x80);
        }
    }
}

fn write_bytes_field(out: &mut Vec<u8>, field: u64, data: &[u8]) {
    write_varint(out, (field << 3) | 2);
    write_varint(out, data.len() as u64);
    out.extend_from_slice(data);
}
