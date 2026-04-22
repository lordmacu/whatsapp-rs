//! Resync driver: send the `w:sync:app:state` IQ, extract patches/snapshots
//! from the response, apply them with MAC verification, persist state,
//! emit events.

use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

use crate::binary::{BinaryNode, NodeContent};
use crate::messages::MessageEvent;
use crate::socket::SocketSender;

use super::actions::decode as decode_action;
use super::decode::{apply_patch, apply_snapshot, Validation};
use super::keys::AppStateKeyStore;
use super::proto::{decode_syncd_patch, decode_syncd_snapshot};
use super::state::{CollectionState, CollectionStore};

pub const ALL_COLLECTIONS: &[&str] = &[
    "critical_block",
    "critical_unblock_low",
    "regular_high",
    "regular",
    "regular_low",
];

const MAX_ATTEMPTS: u32 = 5;

pub struct AppStateSync {
    pub sender: Arc<SocketSender>,
    pub keys: Arc<AppStateKeyStore>,
    pub collections: Arc<CollectionStore>,
    pub event_tx: broadcast::Sender<MessageEvent>,
}

impl AppStateSync {
    pub async fn resync(&self, collections: &[&str], initial_sync: bool) -> Result<()> {
        let validation = if initial_sync {
            Validation { patch_mac: true, snapshot_mac: false, mutation_mac: true }
        } else {
            Validation::default()
        };

        for name in collections {
            if let Err(e) = self.resync_one(name, initial_sync, validation).await {
                warn!("app-state {name} sync failed: {e:#}");
            }
        }
        Ok(())
    }

    async fn resync_one(&self, name: &str, initial_sync: bool, validation: Validation) -> Result<()> {
        let mut state = self.collections.load(name);
        let mut attempts = 0u32;
        let mut had_more = true;

        // initial-sync: if we've never seen this collection, ask for a snapshot
        let want_snapshot_initial = state.version == 0 && initial_sync;

        while had_more {
            attempts += 1;
            if attempts > MAX_ATTEMPTS {
                warn!("app-state {name}: too many attempts, giving up");
                break;
            }

            let want_snapshot = want_snapshot_initial && attempts == 1;
            let id = self.sender.next_id();
            let iq = BinaryNode {
                tag: "iq".into(),
                attrs: vec![
                    ("id".into(), id),
                    ("to".into(), "s.whatsapp.net".into()),
                    ("xmlns".into(), "w:sync:app:state".into()),
                    ("type".into(), "set".into()),
                ],
                content: NodeContent::List(vec![BinaryNode {
                    tag: "sync".into(),
                    attrs: vec![],
                    content: NodeContent::List(vec![BinaryNode {
                        tag: "collection".into(),
                        attrs: vec![
                            ("name".into(), name.to_string()),
                            ("version".into(), state.version.to_string()),
                            ("return_snapshot".into(), want_snapshot.to_string()),
                        ],
                        content: NodeContent::None,
                    }]),
                }]),
            };

            info!("app-state resync {name} v{} (snapshot={want_snapshot})", state.version);
            let resp = self.sender.send_iq_await(iq).await
                .with_context(|| format!("sync iq for {name}"))?;

            had_more = false;

            // Extract <sync><collection name="X"><snapshot>... <patches><patch>...</patch>*</patches>
            let sync = match get_child(&resp, "sync") { Some(c) => c, None => break };
            for coll in children(sync, "collection") {
                if coll.attr("name") != Some(name) { continue; }

                // Snapshot?
                if let Some(snap_node) = get_child(coll, "snapshot") {
                    if let NodeContent::Bytes(blob) = &snap_node.content {
                        match decode_external_blob_then_download(blob).await {
                            Ok(snap_bytes) => {
                                if let Some(snap) = decode_syncd_snapshot(&snap_bytes) {
                                    let validate = Validation { snapshot_mac: true, ..validation };
                                    match apply_snapshot(name, &snap, &self.keys, validate).await {
                                        Ok((new_state, decoded)) => {
                                            info!("app-state {name}: snapshot applied v{} ({} mutations)", new_state.version, decoded.len());
                                            state = new_state;
                                            self.emit(name, &decoded);
                                        }
                                        Err(e) => warn!("app-state {name} snapshot decode: {e:#}"),
                                    }
                                }
                            }
                            Err(e) => warn!("app-state {name} snapshot download: {e:#}"),
                        }
                    }
                }

                // Patches
                if let Some(patches_node) = get_child(coll, "patches") {
                    for p in children(patches_node, "patch") {
                        if let NodeContent::Bytes(pbytes) = &p.content {
                            let Some(patch) = decode_syncd_patch(pbytes) else {
                                warn!("app-state {name}: patch decode failed");
                                continue;
                            };
                            match apply_patch(name, &patch, &mut state, &self.keys, validation).await {
                                Ok(decoded) => {
                                    info!("app-state {name}: patch v{} ({} mutations)", patch.version, decoded.len());
                                    self.emit(name, &decoded);
                                }
                                Err(e) => {
                                    warn!("app-state {name} v{} failed: {e:#} — resetting", patch.version);
                                    self.collections.reset(name);
                                    state = CollectionState::default();
                                    had_more = true;
                                    break;
                                }
                            }
                        }
                    }
                }

                if coll.attr("has_more_patches") == Some("true") {
                    had_more = true;
                }
            }

            if let Err(e) = self.collections.save(name, &state) {
                warn!("app-state {name} save: {e}");
            }
        }

        debug!("app-state {name} sync done at v{}", state.version);
        Ok(())
    }

    fn emit(&self, collection: &str, decoded: &[super::decode::DecodedMutation]) {
        for m in decoded {
            if let Some(act) = decode_action(&m.index, &m.action_value) {
                let _ = self.event_tx.send(MessageEvent::AppStateUpdate {
                    collection: collection.to_string(),
                    action: act.action,
                });
            }
        }
    }
}

// ── Node helpers ────────────────────────────────────────────────────

fn get_child<'a>(node: &'a BinaryNode, tag: &str) -> Option<&'a BinaryNode> {
    if let NodeContent::List(v) = &node.content {
        v.iter().find(|c| c.tag == tag)
    } else { None }
}

fn children<'a>(node: &'a BinaryNode, tag: &str) -> Vec<&'a BinaryNode> {
    if let NodeContent::List(v) = &node.content {
        v.iter().filter(|c| c.tag == tag).collect()
    } else { Vec::new() }
}

// The <snapshot> bytes are an `ExternalBlobReference` proto — decode and
// download the encrypted SyncdSnapshot blob, then return its plaintext bytes.
async fn decode_external_blob_then_download(blob: &[u8]) -> Result<Vec<u8>> {
    use super::proto::decode_external_blob;
    let ext = decode_external_blob(blob).context("decode ExternalBlobReference")?;
    super::decode::download_external(&ext).await
}
