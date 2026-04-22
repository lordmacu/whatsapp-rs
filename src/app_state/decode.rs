//! Decode a sequence of SyncdPatches (or a SyncdSnapshot) applying MAC
//! verification and advancing the collection's LT-Hash state.

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::debug;

use super::crypto::{
    expand_mutation_keys, index_mac, patch_mac, snapshot_mac, value_mac,
    MutationKeys, SyncdOperation,
};
use super::keys::AppStateKeyStore;
use super::lt_hash::{add, sub, HASH_LEN};
use super::proto::{
    decode_external_blob, decode_sync_action_data, decode_syncd_mutations_blob,
    decode_syncd_patch, decode_syncd_snapshot, ExternalBlobRef, SyncdMutation,
    SyncdPatch, SyncdRecord, SyncdSnapshot,
};
use super::state::CollectionState;

/// One decoded mutation with the raw value blob (= `SyncActionValue` bytes).
#[derive(Debug, Clone)]
pub struct DecodedMutation {
    pub collection: String,
    pub operation: SyncdOperation,
    /// UTF-8 decoded JSON-ish index. Array of strings. Example:
    /// `["contact", "15551234@s.whatsapp.net"]`.
    pub index: Vec<String>,
    /// Encoded `SyncActionValue` protobuf — fed to per-action decoder.
    pub action_value: Vec<u8>,
}

/// Whether to verify the outer (patch/snapshot) MAC.
#[derive(Copy, Clone, Debug)]
pub struct Validation {
    pub patch_mac: bool,
    pub snapshot_mac: bool,
    pub mutation_mac: bool,
}

impl Default for Validation {
    fn default() -> Self { Self { patch_mac: true, snapshot_mac: true, mutation_mac: true } }
}

// ── Mutation → plaintext SyncActionValue ────────────────────────────

fn cached_keys<'a>(
    cache: &'a mut HashMap<Vec<u8>, MutationKeys>,
    store: &AppStateKeyStore,
    key_id: &[u8],
) -> Result<&'a MutationKeys> {
    if !cache.contains_key(key_id) {
        let k = store.get(key_id)
            .ok_or_else(|| anyhow!("missing app-state sync key id={}", hex::encode(key_id)))?;
        cache.insert(key_id.to_vec(), expand_mutation_keys(&k.key_data));
    }
    Ok(cache.get(key_id).unwrap())
}

fn decode_one_mutation(
    collection: &str,
    op: SyncdOperation,
    record: &SyncdRecord,
    keys: &MutationKeys,
    validate: bool,
) -> Result<(DecodedMutation, [u8; 32])> {
    // value.blob = encrypted_value_bytes (AES-CBC/PKCS7) || valueMac[32]
    if record.value_blob.len() < 32 {
        bail!("value_blob too short ({} bytes)", record.value_blob.len());
    }
    let (enc, vmac) = record.value_blob.split_at(record.value_blob.len() - 32);

    if validate {
        let computed = value_mac(op, enc, &record.key_id, &keys.value_mac);
        if computed != vmac {
            bail!("value MAC mismatch for collection={collection}");
        }
    }

    // AES-256-CBC decrypt with iv = enc[0..16], ciphertext = enc[16..]
    if enc.len() < 32 { bail!("encrypted value too short"); }
    let plaintext = aes_cbc_decrypt(&keys.value_encryption, &enc[..16], &enc[16..])?;
    let sad = decode_sync_action_data(&plaintext)
        .ok_or_else(|| anyhow!("bad SyncActionData proto"))?;

    if validate {
        let computed_index = index_mac(&keys.index, &sad.index);
        if computed_index != record.index_blob.as_slice() {
            bail!("index MAC mismatch");
        }
    }

    // index is JSON-encoded array of strings.
    let index_str = String::from_utf8_lossy(&sad.index).into_owned();
    let index: Vec<String> = serde_json::from_str(&index_str)
        .unwrap_or_else(|_| vec![index_str.clone()]);

    let mut vmac_arr = [0u8; 32];
    vmac_arr.copy_from_slice(vmac);

    Ok((
        DecodedMutation {
            collection: collection.to_string(),
            operation: op,
            index,
            action_value: sad.value_blob,
        },
        vmac_arr,
    ))
}

// ── Public: decode a single patch ───────────────────────────────────

pub async fn apply_patch(
    collection: &str,
    patch: &SyncdPatch,
    state: &mut CollectionState,
    keys_store: &AppStateKeyStore,
    validate: Validation,
) -> Result<Vec<DecodedMutation>> {
    let mut mutations = patch.mutations.clone();
    if let Some(ext) = &patch.external_mutations {
        let blob = download_external(ext).await.context("download external patch")?;
        mutations.extend(decode_syncd_mutations_blob(&blob));
    }

    let mut key_cache: HashMap<Vec<u8>, MutationKeys> = HashMap::new();
    let mut decoded = Vec::new();
    let mut value_macs_concat: Vec<[u8; 32]> = Vec::new();

    for m in &mutations {
        let keys = cached_keys(&mut key_cache, keys_store, &m.record.key_id)?;
        let (dec, vmac) = decode_one_mutation(
            collection, m.operation, &m.record, keys, validate.mutation_mac,
        )?;

        // LT-Hash mix
        let index_b64 = B64.encode(&m.record.index_blob);
        let prev = state.index_value_map.get(&index_b64).cloned();
        match m.operation {
            SyncdOperation::Remove => {
                if prev.is_none() {
                    debug!("REMOVE without prior entry ({collection}/{index_b64})");
                } else {
                    state.index_value_map.remove(&index_b64);
                }
            }
            SyncdOperation::Set => {
                add(&mut state.hash, &vmac);
                state.index_value_map.insert(index_b64, B64.encode(vmac));
            }
        }
        if let Some(prev_val) = prev {
            if let Ok(prev_bytes) = B64.decode(prev_val.as_bytes()) {
                sub(&mut state.hash, &prev_bytes);
            }
        }

        decoded.push(dec);
        value_macs_concat.push(vmac);
    }

    state.version = patch.version;

    if validate.patch_mac {
        let main_key = keys_store.get(&patch.key_id)
            .ok_or_else(|| anyhow!("missing main key for patch"))?;
        let mk = expand_mutation_keys(&main_key.key_data);

        let refs: Vec<&[u8]> = value_macs_concat.iter().map(|v| &v[..]).collect();
        let computed = patch_mac(&patch.snapshot_mac, &refs, patch.version, collection, &mk.patch_mac);
        if computed != patch.patch_mac.as_slice() {
            bail!("patchMac mismatch for {collection} v{}", patch.version);
        }
    }

    if validate.snapshot_mac && !patch.snapshot_mac.is_empty() {
        let main_key = keys_store.get(&patch.key_id)
            .ok_or_else(|| anyhow!("missing main key"))?;
        let mk = expand_mutation_keys(&main_key.key_data);
        let computed = snapshot_mac(&state.hash, patch.version, collection, &mk.snapshot_mac);
        if computed != patch.snapshot_mac.as_slice() {
            bail!("snapshotMac mismatch for {collection} v{}", patch.version);
        }
    }

    Ok(decoded)
}

// ── Public: decode a snapshot (full state replace) ──────────────────

pub async fn apply_snapshot(
    collection: &str,
    snap: &SyncdSnapshot,
    keys_store: &AppStateKeyStore,
    validate: Validation,
) -> Result<(CollectionState, Vec<DecodedMutation>)> {
    let mut state = CollectionState::default();
    state.version = snap.version;

    let mut key_cache: HashMap<Vec<u8>, MutationKeys> = HashMap::new();
    let mut decoded = Vec::new();

    for r in &snap.records {
        let keys = cached_keys(&mut key_cache, keys_store, &r.key_id)?;
        let (dec, vmac) = decode_one_mutation(
            collection, SyncdOperation::Set, r, keys, validate.mutation_mac,
        )?;

        let index_b64 = B64.encode(&r.index_blob);
        add(&mut state.hash, &vmac);
        state.index_value_map.insert(index_b64, B64.encode(vmac));

        decoded.push(dec);
    }

    if validate.snapshot_mac {
        let main_key = keys_store.get(&snap.key_id)
            .ok_or_else(|| anyhow!("missing main key for snapshot"))?;
        let mk = expand_mutation_keys(&main_key.key_data);
        let computed = snapshot_mac(&state.hash, state.version, collection, &mk.snapshot_mac);
        if computed != snap.mac.as_slice() {
            bail!("snapshotMac mismatch for {collection} v{}", state.version);
        }
    }

    Ok((state, decoded))
}

// ── External-blob downloader ────────────────────────────────────────

/// Download `ExternalBlobReference` from the CDN, verify the HMAC trailer,
/// AES-CBC decrypt using HKDF-derived keys (info = `"WhatsApp App State"`).
pub async fn download_external(r: &ExternalBlobRef) -> Result<Vec<u8>> {
    crate::media::download_media(
        &format!("https://mmg.whatsapp.net{}", r.direct_path),
        &r.media_key,
        crate::media::MediaType::AppState,
    )
    .await
}

// ── AES-CBC helper ──────────────────────────────────────────────────

fn aes_cbc_decrypt(key: &[u8; 32], iv: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
    use aes::Aes256;
    if iv.len() != 16 { bail!("bad IV length"); }
    let dec = cbc::Decryptor::<Aes256>::new_from_slices(key, iv)
        .map_err(|e| anyhow!("aes-cbc init: {e}"))?;
    dec.decrypt_padded_vec_mut::<Pkcs7>(ct)
        .map_err(|e| anyhow!("aes-cbc decrypt: {e}"))
}

// ── Re-export decoders for callers (extract <sync><collection> IQ response) ──

pub use super::proto::{decode_syncd_patch as decode_patch, decode_syncd_snapshot as decode_snapshot};
pub use super::proto::decode_external_blob as decode_ext_blob;
