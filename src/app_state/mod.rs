//! WhatsApp multi-device app-state sync.
//!
//! After pairing, the primary phone ships a 32-byte `AppStateSyncKey` to us
//! inside an encrypted 1:1 `ProtocolMessage`. With that key we can fetch
//! and decrypt the server's collection patches (contacts, chat pin/mute/
//! archive, etc.) via the `w:sync:app:state` IQ — the same mechanism used
//! by the official WhatsApp Web client.
//!
//! Flow:
//!   1. `AppStateKeyStore` captures `AppStateSyncKey`s from incoming
//!      `appStateSyncKeyShare` ProtocolMessages.
//!   2. On `<notification type="server_sync">` (or at initial login)
//!      `AppStateSync::resync` is invoked for the listed collections.
//!   3. The server responds with `<patches>` (incremental) or a
//!      `<snapshot>` whose payload is an `ExternalBlobReference` pointing
//!      at a CDN blob (encrypted `SyncdSnapshot` bytes).
//!   4. Patches/snapshots are MAC-verified (valueMac + patchMac + snapshotMac
//!      via LT-Hash), AES-CBC decrypted, and the resulting
//!      `SyncActionValue`s are emitted as `MessageEvent::AppStateUpdate`.

pub mod actions;
pub mod crypto;
pub mod decode;
pub mod keys;
pub mod lt_hash;
pub mod proto;
pub mod state;
pub mod sync;

pub use actions::{DecodedAction, SyncAction};
pub use keys::{AppStateKeyStore, AppStateSyncKey};
pub use state::{CollectionState, CollectionStore};
pub use sync::{AppStateSync, ALL_COLLECTIONS};
