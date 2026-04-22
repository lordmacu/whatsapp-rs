//! Mutation-key derivation and MAC helpers for app-state sync.
//!
//! From a 32-byte `keyData` (delivered via `AppStateSyncKeyShare`) HKDF
//! expands into five 32-byte subkeys: index, valueEncryption, valueMac,
//! snapshotMac, patchMac. Info string = `"WhatsApp Mutation Keys"`.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};

pub struct MutationKeys {
    pub index: [u8; 32],
    pub value_encryption: [u8; 32],
    pub value_mac: [u8; 32],
    pub snapshot_mac: [u8; 32],
    pub patch_mac: [u8; 32],
}

pub fn expand_mutation_keys(key_data: &[u8]) -> MutationKeys {
    let hk = Hkdf::<Sha256>::new(None, key_data);
    let mut out = [0u8; 160];
    hk.expand(b"WhatsApp Mutation Keys", &mut out)
        .expect("hkdf expand 160");
    let mut k = MutationKeys {
        index: [0; 32], value_encryption: [0; 32], value_mac: [0; 32],
        snapshot_mac: [0; 32], patch_mac: [0; 32],
    };
    k.index          .copy_from_slice(&out[0..32]);
    k.value_encryption.copy_from_slice(&out[32..64]);
    k.value_mac      .copy_from_slice(&out[64..96]);
    k.snapshot_mac   .copy_from_slice(&out[96..128]);
    k.patch_mac      .copy_from_slice(&out[128..160]);
    k
}

/// Operation byte used by mutation-value MAC.
pub fn op_byte(op: SyncdOperation) -> u8 {
    match op { SyncdOperation::Set => 0x01, SyncdOperation::Remove => 0x02 }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SyncdOperation { Set, Remove }

/// HMAC-SHA512 over `opByte || keyId || data || [0; 7] || len(keyId+1) as u8`,
/// truncated to 32 bytes. See Baileys' `generateMac`.
pub fn value_mac(
    op: SyncdOperation,
    data: &[u8],
    key_id: &[u8],
    value_mac_key: &[u8; 32],
) -> [u8; 32] {
    let mut prefix = Vec::with_capacity(1 + key_id.len());
    prefix.push(op_byte(op));
    prefix.extend_from_slice(key_id);

    let mut suffix = [0u8; 8];
    suffix[7] = prefix.len() as u8;

    let mut mac = Hmac::<Sha512>::new_from_slice(value_mac_key).expect("hmac sha512");
    mac.update(&prefix);
    mac.update(data);
    mac.update(&suffix);
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&full[..32]);
    out
}

/// HMAC-SHA256(snapshotMacKey, lthash || u64_be(version) || collectionName).
pub fn snapshot_mac(
    lthash: &[u8],
    version: u64,
    name: &str,
    snapshot_mac_key: &[u8; 32],
) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(snapshot_mac_key).expect("hmac sha256");
    mac.update(lthash);
    mac.update(&u64_be(version));
    mac.update(name.as_bytes());
    mac.finalize().into_bytes().into()
}

/// HMAC-SHA256(patchMacKey, snapshotMac || concat(valueMacs) || u64_be(version) || name).
pub fn patch_mac(
    snapshot_mac_bytes: &[u8],
    value_macs: &[&[u8]],
    version: u64,
    name: &str,
    patch_mac_key: &[u8; 32],
) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(patch_mac_key).expect("hmac sha256");
    mac.update(snapshot_mac_bytes);
    for v in value_macs { mac.update(v); }
    mac.update(&u64_be(version));
    mac.update(name.as_bytes());
    mac.finalize().into_bytes().into()
}

/// HMAC-SHA256(indexKey, indexBytes). Used to match record.index.blob.
pub fn index_mac(index_key: &[u8; 32], index_bytes: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(index_key).expect("hmac sha256");
    mac.update(index_bytes);
    mac.finalize().into_bytes().into()
}

fn u64_be(v: u64) -> [u8; 8] { v.to_be_bytes() }
