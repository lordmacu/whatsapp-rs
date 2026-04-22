//! Manual proto decoders for the app-state wire messages. Uses
//! `parse_proto_fields_repeated` from `signal::wa_proto` so repeated fields
//! (mutations, records, keys) don't get collapsed.

use super::crypto::SyncdOperation;
use crate::signal::wa_proto::{parse_proto_fields, parse_proto_fields_repeated, read_varint_from_bytes};

#[derive(Debug, Clone)]
pub struct ExternalBlobRef {
    pub media_key: Vec<u8>,
    pub direct_path: String,
    pub handle: String,
    pub file_size: u64,
    pub file_sha256: Vec<u8>,
    pub file_enc_sha256: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SyncdRecord {
    pub index_blob: Vec<u8>,
    pub value_blob: Vec<u8>,
    pub key_id: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SyncdMutation {
    pub operation: SyncdOperation,
    pub record: SyncdRecord,
}

#[derive(Debug, Clone)]
pub struct SyncdPatch {
    pub version: u64,
    pub mutations: Vec<SyncdMutation>,
    pub external_mutations: Option<ExternalBlobRef>,
    pub snapshot_mac: Vec<u8>,
    pub patch_mac: Vec<u8>,
    pub key_id: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SyncdSnapshot {
    pub version: u64,
    pub records: Vec<SyncdRecord>,
    pub mac: Vec<u8>,
    pub key_id: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SyncActionData {
    pub index: Vec<u8>,
    pub value_blob: Vec<u8>,
    pub version: i32,
}

// ── ExternalBlobReference (1=mediaKey, 2=directPath, 3=handle, 4=fileSizeBytes, 5=fileSha256, 6=fileEncSha256) ──

pub fn decode_external_blob(data: &[u8]) -> Option<ExternalBlobRef> {
    let f = parse_proto_fields(data)?;
    Some(ExternalBlobRef {
        media_key:       f.get(&1).cloned().unwrap_or_default(),
        direct_path:     f.get(&2).and_then(|b| String::from_utf8(b.clone()).ok()).unwrap_or_default(),
        handle:          f.get(&3).and_then(|b| String::from_utf8(b.clone()).ok()).unwrap_or_default(),
        file_size:       f.get(&4).and_then(|b| read_varint_from_bytes(b)).unwrap_or(0),
        file_sha256:     f.get(&5).cloned().unwrap_or_default(),
        file_enc_sha256: f.get(&6).cloned().unwrap_or_default(),
    })
}

// ── SyncdRecord (1=index{blob=1}, 2=value{blob=1}, 3=keyId{id=1}) ───

pub fn decode_syncd_record(data: &[u8]) -> Option<SyncdRecord> {
    let f = parse_proto_fields(data)?;
    let index_blob = f.get(&1)
        .and_then(|b| parse_proto_fields(b))
        .and_then(|m| m.get(&1).cloned())
        .unwrap_or_default();
    let value_blob = f.get(&2)
        .and_then(|b| parse_proto_fields(b))
        .and_then(|m| m.get(&1).cloned())
        .unwrap_or_default();
    let key_id = f.get(&3)
        .and_then(|b| parse_proto_fields(b))
        .and_then(|m| m.get(&1).cloned())
        .unwrap_or_default();
    Some(SyncdRecord { index_blob, value_blob, key_id })
}

// ── SyncdMutation (1=operation, 2=record) ────────────────────────────

pub fn decode_syncd_mutation(data: &[u8]) -> Option<SyncdMutation> {
    let f = parse_proto_fields(data)?;
    let op = f.get(&1).and_then(|b| read_varint_from_bytes(b)).unwrap_or(0);
    let record = f.get(&2).and_then(|b| decode_syncd_record(b))?;
    Some(SyncdMutation {
        operation: if op == 1 { SyncdOperation::Remove } else { SyncdOperation::Set },
        record,
    })
}

// ── SyncdPatch ───────────────────────────────────────────────────────
//  1=version (SyncdVersion{version=1:uint64})
//  2=mutations (repeated SyncdMutation)
//  3=externalMutations (ExternalBlobReference)
//  4=snapshotMac, 5=patchMac, 6=keyId{id=1}

pub fn decode_syncd_patch(data: &[u8]) -> Option<SyncdPatch> {
    let rep = parse_proto_fields_repeated(data)?;
    let mut version: u64 = 0;
    let mut mutations = Vec::new();
    let mut external_mutations: Option<ExternalBlobRef> = None;
    let mut snapshot_mac = Vec::new();
    let mut patch_mac = Vec::new();
    let mut key_id = Vec::new();

    for (f, b) in rep {
        match f {
            1 => {
                if let Some(v) = parse_proto_fields(&b).and_then(|m| m.get(&1).and_then(|bb| read_varint_from_bytes(bb))) {
                    version = v;
                }
            }
            2 => if let Some(m) = decode_syncd_mutation(&b) { mutations.push(m); },
            3 => external_mutations = decode_external_blob(&b),
            4 => snapshot_mac = b,
            5 => patch_mac = b,
            6 => if let Some(m) = parse_proto_fields(&b) {
                key_id = m.get(&1).cloned().unwrap_or_default();
            },
            _ => {}
        }
    }

    Some(SyncdPatch { version, mutations, external_mutations, snapshot_mac, patch_mac, key_id })
}

// ── SyncdSnapshot (1=version, 2=records repeated, 3=mac, 4=keyId{id=1}) ──

pub fn decode_syncd_snapshot(data: &[u8]) -> Option<SyncdSnapshot> {
    let rep = parse_proto_fields_repeated(data)?;
    let mut version: u64 = 0;
    let mut records = Vec::new();
    let mut mac = Vec::new();
    let mut key_id = Vec::new();

    for (f, b) in rep {
        match f {
            1 => {
                if let Some(v) = parse_proto_fields(&b).and_then(|m| m.get(&1).and_then(|bb| read_varint_from_bytes(bb))) {
                    version = v;
                }
            }
            2 => if let Some(r) = decode_syncd_record(&b) { records.push(r); },
            3 => mac = b,
            4 => if let Some(m) = parse_proto_fields(&b) {
                key_id = m.get(&1).cloned().unwrap_or_default();
            },
            _ => {}
        }
    }
    Some(SyncdSnapshot { version, records, mac, key_id })
}

// ── SyncdMutations (1=mutations repeated) — downloaded external-blob payload ──

pub fn decode_syncd_mutations_blob(data: &[u8]) -> Vec<SyncdMutation> {
    let rep = match parse_proto_fields_repeated(data) { Some(r) => r, None => return Vec::new() };
    let mut out = Vec::new();
    for (f, b) in rep {
        if f == 1 {
            if let Some(m) = decode_syncd_mutation(&b) { out.push(m); }
        }
    }
    out
}

// ── SyncActionData (1=index bytes, 2=value, 3=padding, 4=version) ────

pub fn decode_sync_action_data(data: &[u8]) -> Option<SyncActionData> {
    let f = parse_proto_fields(data)?;
    Some(SyncActionData {
        index:      f.get(&1).cloned().unwrap_or_default(),
        value_blob: f.get(&2).cloned().unwrap_or_default(),
        version:    f.get(&4).and_then(|b| read_varint_from_bytes(b)).unwrap_or(0) as i32,
    })
}

// ── AppStateSyncKeyShare → list of (keyId, keyData, timestamp) ───────
// keys (repeated) = AppStateSyncKey { keyId{id=1}, keyData{keyData=1, timestamp=3} }

pub fn decode_app_state_sync_key_share(pm: &std::collections::HashMap<u64, Vec<u8>>) -> Vec<(Vec<u8>, Vec<u8>, i64)> {
    // ProtocolMessage field 7 = appStateSyncKeyShare; inside, field 1 = keys (repeated).
    let share_bytes = match pm.get(&7) { Some(b) => b, None => return Vec::new() };
    let rep = match parse_proto_fields_repeated(share_bytes) { Some(r) => r, None => return Vec::new() };
    let mut out = Vec::new();
    for (f, b) in rep {
        if f != 1 { continue; }
        // AppStateSyncKey: 1=keyId (AppStateSyncKeyId{keyId=1}), 2=keyData (AppStateSyncKeyData{keyData=1, timestamp=3})
        let Some(k) = parse_proto_fields(&b) else { continue };
        let key_id = k.get(&1)
            .and_then(|bb| parse_proto_fields(bb))
            .and_then(|m| m.get(&1).cloned())
            .unwrap_or_default();
        let key_data_msg = match k.get(&2) { Some(bb) => bb, None => continue };
        let Some(kd) = parse_proto_fields(key_data_msg) else { continue };
        let key_data = kd.get(&1).cloned().unwrap_or_default();
        let timestamp = kd.get(&3).and_then(|bb| read_varint_from_bytes(bb)).unwrap_or(0) as i64;
        if !key_id.is_empty() && !key_data.is_empty() {
            out.push((key_id, key_data, timestamp));
        }
    }
    out
}
