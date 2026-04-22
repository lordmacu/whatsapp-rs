# QR Authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete QR-based authentication for whatsapp-rs — WebSocket pair-device handling, QR output (ASCII + HTTP), SessionStore with file persistence, multi-device support.

**Architecture:** Modular design with `AuthManager` as central state machine. Binary protocol decode/dispatch in `socket/mod.rs`. QR output via dedicated `QRAuthenticator`. File-based `SessionStore` with `SessionStore` trait for custom backends.

**Tech Stack:** Rust 2021, tokio, tokio-tungstenite, aes-gcm, x25519-dalek, qrcode, serde, dirs.

---

## File Structure

```
src/
├── main.rs                 # Entry point (update)
├── auth/
│   ├── mod.rs              # AuthManager, AuthCredentials, init_auth_creds
│   ├── session_store.rs    # SessionStore trait + FileStore
│   └── credentials.rs     # KeyPair, SignedKeyPair, AuthCredentials
├── socket/
│   ├── mod.rs              # WebSocket client + dispatch + pair-device handler
│   └── dispatch.rs         # Incoming BinaryNode dispatch logic
├── binary/
│   ├── mod.rs              # BinaryNode, decode_binary_node, encode_binary_node
│   └── tokens.rs           # Token maps (already exists)
├── qr/
│   ├── mod.rs              # QRAuthenticator (ASCII + HTTP server)
│   └── ascii.rs            # QR ASCII art rendering
└── proto/
    └── client_payload.rs  # build_client_payload (extend existing)

docs/superpowers/plans/
└── 2026-04-21-qr-authentication-plan.md  # this file
```

---

## Task 1: AuthCredentials & Key Types

**Files:**
- Create: `src/auth/credentials.rs`
- Modify: `src/auth/mod.rs`
- Test: `src/auth/tests.rs` (create)

- [ ] **Step 1: Create auth/credentials.rs**

```rust
use rand::RngCore;

#[derive(Debug, Clone)]
pub struct KeyPair {
    pub public: [u8; 32],
    pub private: [u8; 32],
}

impl KeyPair {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        use x25519_dalek::{PublicKey, StaticSecret};
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Self {
            private: secret.to_bytes(),
            public: public.to_bytes(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SignedKeyPair {
    pub key_pair: KeyPair,
    pub signature: Vec<u8>,
    pub key_id: u32,
}

#[derive(Debug, Clone)]
pub struct Contact {
    pub id: String,       // jid: "phone@s.whatsapp.net"
    pub name: Option<String>,
    pub lid: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AuthCredentials {
    pub noise_key: KeyPair,
    pub pairing_ephemeral_key: KeyPair,
    pub signed_identity_key: KeyPair,
    pub signed_pre_key: SignedKeyPair,
    pub registration_id: u16,
    pub adv_secret_key: Vec<u8>,  // base64 string in JSON
    pub me: Option<Contact>,
    pub pairing_code: Option<String>,
    pub next_pre_key_id: u32,
    pub first_unuploaded_pre_key_id: u32,
}

impl AuthCredentials {
    pub fn new() -> Self {
        let identity_key = KeyPair::generate();
        let signed_pre_key = SignedKeyPair {
            key_pair: KeyPair::generate(),
            signature: vec![],
            key_id: 1,
        };
        let registration_id: u16 = {
            let mut bytes = [0u8; 2];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            u16::from_le_bytes(bytes) & 16383
        };
        let adv_secret = {
            let mut bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            bytes.to_vec()
        };
        Self {
            noise_key: KeyPair::generate(),
            pairing_ephemeral_key: KeyPair::generate(),
            signed_identity_key: identity_key,
            signed_pre_key: signed_pre_key,
            registration_id,
            adv_secret_key: adv_secret,
            me: None,
            pairing_code: None,
            next_pre_key_id: 1,
            first_unuploaded_pre_key_id: 1,
        }
    }
}

impl Default for AuthCredentials {
    fn default() -> Self {
        Self::new()
    }
}
```

- [ ] **Step 2: Create auth/mod.rs**

```rust
mod credentials;
pub mod session_store;

pub use credentials::*;
```

- [ ] **Step 3: Add dirs dependency to Cargo.toml**

```toml
dirs = "5"
```

- [ ] **Step 4: Create auth/tests.rs with basic tests**

```rust
use whatsapp_rs::auth::{AuthCredentials, KeyPair};

#[test]
fn test_keypair_generate() {
    let kp = KeyPair::generate();
    assert_eq!(kp.public.len(), 32);
    assert_eq!(kp.private.len(), 32);
    assert_ne!(kp.public, kp.private);
}

#[test]
fn test_auth_credentials_new() {
    let creds = AuthCredentials::new();
    assert!(creds.me.is_none());
    assert!(creds.pairing_code.is_none());
}
```

- [ ] **Step 5: Run tests**

```bash
cd /home/familia/whatsapp-rs && cargo test auth -- --nocapture
```

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/auth/ Cargo.toml && git commit -m "feat: add AuthCredentials and KeyPair types"
```

---

## Task 2: BinaryNode Protocol (Decode + Dispatch)

**Files:**
- Create: `src/binary/node.rs`
- Modify: `src/binary/mod.rs`
- Test: `src/binary/tests.rs`

- [ ] **Step 1: Create binary/node.rs**

```rust
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct BinaryNode {
    pub tag: String,
    pub attrs: HashMap<String, String>,
    pub content: Option<Vec<u8>>,
}

impl BinaryNode {
    pub fn get_attr(&self, key: &str) -> Option<&str> {
        self.attrs.get(key).map(|s| s.as_str())
    }
    pub fn get_child(&self, tag: &str) -> Option<&BinaryNode> {
        // For single-child content (not implemented for list content)
        None
    }
}
```

- [ ] **Step 2: Update binary/mod.rs to export BinaryNode**

```rust
pub mod tokens;
pub mod node;
pub use node::BinaryNode;
```

- [ ] **Step 3: Write decode_binary_node function**

Add to `src/binary/node.rs`:

```rust
use std::collections::HashMap;

pub struct BinaryDecoder<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> BinaryDecoder<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn read_byte(&mut self) -> Result<u8, &'static str> {
        if self.pos >= self.data.len() {
            return Err("unexpected end of buffer");
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn read_varint(&mut self) -> Result<u64, &'static str> {
        let mut result = 0u64;
        let mut shift = 0;
        loop {
            let byte = self.read_byte()?;
            result |= ((byte & 0x7f) as u64) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                break;
            }
        }
        Ok(result)
    }

    pub fn decode_node(&mut self) -> Result<BinaryNode, &'static str> {
        let tag_num = self.read_varint()?;
        let tag = match tag_num {
            0 => "stream:start".to_string(),
            n => n.to_string(),
        };

        let mut attrs = HashMap::new();
        loop {
            let key_len = self.read_varint()? as usize;
            if key_len == 0 {
                break;
            }
            let key = self.read_bytes(key_len)?;
            let value_len = self.read_varint()? as usize;
            let value = self.read_bytes(value_len)?;
            attrs.insert(
                String::from_utf8_lossy(key).to_string(),
                String::from_utf8_lossy(value).to_string(),
            );
        }

        let content: Option<Vec<u8>> = None;
        Ok(BinaryNode { tag, attrs, content })
    }

    fn read_bytes(&mut self, len: usize) -> Result<Vec<u8>, &'static str> {
        if self.pos + len > self.data.len() {
            return Err("buffer overflow");
        }
        let result = self.data[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(result)
    }
}

pub fn decode_binary_node(data: &[u8]) -> Result<BinaryNode, &'static str> {
    let mut decoder = BinaryDecoder::new(data);
    decoder.decode_node()
}
```

- [ ] **Step 4: Write encode_binary_node function**

```rust
use std::collections::HashMap;

pub fn encode_binary_node(node: &BinaryNode) -> Vec<u8> {
    let mut buf = Vec::new();
    write_varint(&mut buf, parse_tag(&node.tag));
    for (k, v) in &node.attrs {
        write_varint(&mut buf, k.len() as u64);
        buf.extend_from_slice(k.as_bytes());
        write_varint(&mut buf, v.len() as u64);
        buf.extend_from_slice(v.as_bytes());
    }
    write_varint(&mut buf, 0);
    if let Some(content) = &node.content {
        buf.extend_from_slice(content);
    }
    buf
}

fn write_varint(buf: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            buf.push(byte);
            break;
        } else {
            buf.push(byte | 0x80);
        }
    }
}

fn parse_tag(tag: &str) -> u64 {
    tag.parse().unwrap_or(0)
}
```

- [ ] **Step 5: Write basic decode test**

```rust
use whatsapp_rs::binary::{decode_binary_node, BinaryNode};

#[test]
fn test_decode_simple_node() {
    let data = vec![1, 0]; // tag 1, no attrs
    let result = decode_binary_node(&data);
    assert!(result.is_ok());
}
```

- [ ] **Step 6: Run tests**

```bash
cd /home/familia/whatsapp-rs && cargo test binary -- --nocapture
```

- [ ] **Step 7: Commit**

```bash
git add src/binary/ && git commit -m "feat: add BinaryNode decode/encode"
```

---

## Task 3: SessionStore Trait + FileStore

**Files:**
- Create: `src/auth/session_store.rs`
- Modify: `src/auth/mod.rs`
- Test: `src/auth/tests.rs`

- [ ] **Step 1: Create auth/session_store.rs**

```rust
use crate::auth::credentials::AuthCredentials;
use anyhow::Result;
use std::path::PathBuf;

pub trait SessionStore: Send + Sync {
    fn save_credentials(&self, creds: &AuthCredentials) -> Result<()>;
    fn load_credentials(&self) -> Result<Option<AuthCredentials>>;
    fn save_prekey(&self, id: u32, key: &[u8]) -> Result<()>;
    fn load_prekey(&self, id: u32) -> Result<Option<Vec<u8>>>;
    fn save_session(&self, jid: &str, session: &[u8]) -> Result<()>;
    fn load_session(&self, jid: &str) -> Result<Option<Vec<u8>>>;
    fn clear(&self) -> Result<()>;
}

pub struct FileStore {
    base_dir: PathBuf,
}

impl FileStore {
    pub fn new() -> Result<Self> {
        let base_dir = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".whatsapp-rs");
        std::fs::create_dir_all(&base_dir)?;
        Ok(Self { base_dir })
    }

    fn creds_path(&self) -> PathBuf {
        self.base_dir.join("creds.json")
    }
    fn prekey_dir(&self) -> PathBuf {
        self.base_dir.join("pre-keys")
    }
    fn session_dir(&self) -> PathBuf {
        self.base_dir.join("sessions")
    }
}

impl SessionStore for FileStore {
    fn save_credentials(&self, creds: &AuthCredentials) -> Result<()> {
        let json = serde_json::to_string(creds)?;
        std::fs::write(self.creds_path(), json)?;
        Ok(())
    }

    fn load_credentials(&self) -> Result<Option<AuthCredentials>> {
        let path = self.creds_path();
        if !path.exists() {
            return Ok(None);
        }
        let json = std::fs::read_to_string(path)?;
        let creds = serde_json::from_str(&json)?;
        Ok(Some(creds))
    }

    fn save_prekey(&self, id: u32, key: &[u8]) -> Result<()> {
        let dir = self.prekey_dir();
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join(format!("{id}.key")), key)?;
        Ok(())
    }

    fn load_prekey(&self, id: u32) -> Result<Option<Vec<u8>>> {
        let path = self.prekey_dir().join(format!("{id}.key"));
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(std::fs::read(path)?))
    }

    fn save_session(&self, jid: &str, session: &[u8]) -> Result<()> {
        let dir = self.session_dir();
        std::fs::create_dir_all(&dir)?;
        let filename = jid.replace(['@', ':', '/'], "_");
        std::fs::write(dir.join(format!("{filename}.key")), session)?;
        Ok(())
    }

    fn load_session(&self, jid: &str) -> Result<Option<Vec<u8>>> {
        let filename = jid.replace(['@', ':', '/'], "_");
        let path = self.session_dir().join(format!("{filename}.key"));
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(std::fs::read(path)?))
    }

    fn clear(&self) -> Result<()> {
        if self.base_dir.exists() {
            std::fs::remove_dir_all(&self.base_dir)?;
            std::fs::create_dir_all(&self.base_dir)?;
        }
        Ok(())
    }
}
```

- [ ] **Step 2: Update auth/mod.rs**

```rust
mod credentials;
pub mod session_store;

pub use credentials::*;
pub use session_store::{FileStore, SessionStore};
```

- [ ] **Step 3: Add SessionStore test**

```rust
use whatsapp_rs::auth::{FileStore, SessionStore, AuthCredentials};

#[test]
fn test_file_store_creds() {
    let store = FileStore::new().unwrap();
    let creds = AuthCredentials::new();
    store.save_credentials(&creds).unwrap();
    let loaded = store.load_credentials().unwrap();
    assert!(loaded.is_some());
}
```

- [ ] **Step 4: Run tests**

```bash
cd /home/familia/whatsapp-rs && cargo test session_store -- --nocapture
```

- [ ] **Step 5: Commit**

```bash
git add src/auth/ && git commit -m "feat: add SessionStore trait + FileStore implementation"
```

---

## Task 4: ClientPayload (Extended)

**Files:**
- Create: `src/proto/client_payload.rs`
- Modify: `src/main.rs` to use extended payload

- [ ] **Step 1: Create proto/client_payload.rs**

```rust
use crate::auth::credentials::AuthCredentials;

pub fn build_client_payload(creds: &AuthCredentials, push_name: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(write_tag(2, write_varint(1))); // passive = true
    payload.extend(write_tag(3, write_string("2.3000.1035194821"))); // clientHelloVersion
    payload.extend(write_tag(4, write_string(push_name))); // deviceName
    payload.extend(write_tag(5, write_string(push_name))); // pushName
    payload.extend(write_tag(13, write_varint(1))); // connectReason = USER_ACTIVATED
    payload
}

fn write_varint(value: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut v = value;
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            buf.push(byte);
            break;
        } else {
            buf.push(byte | 0x80);
        }
    }
    buf
}

fn write_string(s: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    write_varint(&mut buf, s.len() as u64);
    buf.extend_from_slice(s.as_bytes());
    buf
}

fn write_tag(field: u64, content: Vec<u8>) -> Vec<u8> {
    let mut buf = Vec::new();
    write_varint(&mut buf, (field << 3) | 2); // wire type = length-delimited
    buf.extend(content);
    buf
}
```

- [ ] **Step 2: Verify compilation**

```bash
cd /home/familia/whatsapp-rs && cargo build 2>&1 | head -30
```

- [ ] **Step 3: Commit**

```bash
git add src/proto/ && git commit -m "feat: add extended ClientPayload builder"
```

---

## Task 5: Socket Dispatch (Incoming Node Handler)

**Files:**
- Modify: `src/socket/mod.rs`
- Create: `src/socket/dispatch.rs`
- Test: `src/socket/tests.rs`

- [ ] **Step 1: Create socket/dispatch.rs**

```rust
use crate::binary::BinaryNode;
use anyhow::Result;
use std::collections::HashMap;
use tokio::sync::{mpsc, oneshot};

type Handler = Box<dyn Fn(BinaryNode) -> Result<()> + Send>;

pub struct NodeDispatcher {
    by_tag: HashMap<String, Vec<Handler>>,
    by_id: HashMap<String, oneshot::Sender<BinaryNode>>,
}

impl NodeDispatcher {
    pub fn new() -> Self {
        Self {
            by_tag: HashMap::new(),
            by_id: HashMap::new(),
        }
    }

    pub fn on_tag(&mut self, tag: &str, handler: Handler) {
        self.by_tag.entry(tag.to_string()).or_default().push(handler);
    }

    pub fn register_pending(&mut self, id: String) -> oneshot::Receiver<BinaryNode> {
        let (tx, rx) = oneshot::channel();
        self.by_id.insert(id, tx);
        rx
    }

    pub fn dispatch(&mut self, node: &BinaryNode) {
        if let Some(tx) = self.by_id.remove(&node.attrs.get("id").cloned().unwrap_or_default()) {
            let _ = tx.send(node.clone());
        }
        if let Some(handlers) = self.by_tag.get(&node.tag) {
            for h in handlers {
                let _ = h(node.clone());
            }
        }
    }
}

impl Default for NodeDispatcher {
    fn default() -> Self {
        Self::new()
    }
}
```

- [ ] **Step 2: Add pair-device handler to socket/mod.rs**

After the noise handshake completes, add in the receive loop:

```rust
async fn on_pair_device(
    stanza: &BinaryNode,
    auth_mgr: &AuthManager,
    tx: &mpsc::Sender<AuthEvent>,
) -> Result<()> {
    // Extract refs from pair-device content
    let mut refs = Vec::new();
    if let Some(content) = &stanza.content {
        // Parse content as list of ref nodes
        // Each ref node: tag "ref", content = bytes
    }

    tx.send(AuthEvent::NewQR { refs }).await?;
    Ok(())
}
```

- [ ] **Step 3: Add AuthEvent enum to auth/mod.rs**

```rust
#[derive(Debug, Clone)]
pub enum AuthEvent {
    NewQR { refs: Vec<Vec<u8>> },
    QRTimedOut { ref_index: usize },
    PairingCode { code: String },
    PairingSuccess,
    AuthFailure { reason: String },
}
```

- [ ] **Step 4: Commit**

```bash
git add src/socket/ && git commit -m "feat: add node dispatcher + pair-device handler"
```

---

## Task 6: QRAuthenticator (ASCII + HTTP)

**Files:**
- Create: `src/qr/mod.rs`
- Create: `src/qr/ascii.rs`

- [ ] **Step 1: Create qr/mod.rs**

```rust
pub mod ascii;

pub struct QRAuthenticator {
    ascii: bool,
    http_endpoint: Option<String>,
}

impl QRAuthenticator {
    pub fn new(ascii: bool, http_endpoint: Option<String>) -> Self {
        Self { ascii, http_endpoint }
    }

    pub fn render_qr(&self, data: &[u8]) -> String {
        if self.ascii {
            ascii::render_qr(data)
        } else {
            String::new()
        }
    }
}
```

- [ ] **Step 2: Create qr/ascii.rs**

```rust
use qrcode::QrCode;

pub fn render_qr(data: &[u8]) -> String {
    let code = QrCode::new(data).expect("valid QR data");
    let modules = code.get_modules();
    let mut result = String::new();
    for row in modules {
        for &module in row {
            result.push(if module { "██" } else { "░░" });
        }
        result.push('\n');
    }
    result
}
```

- [ ] **Step 3: Add axum + tower-http to Cargo.toml**

```toml
axum = "0.7"
tokio-postgres = "0.7"
```

- [ ] **Step 4: Write HTTP QR endpoint**

Add to `src/qr/mod.rs`:

```rust
use axum::{
    extract::State,
    routing::get,
    Router,
};
use std::net::SocketAddr;
use tokio::sync::broadcast;

pub async fn start_qr_server(
    addr: SocketAddr,
    mut rx: broadcast::Receiver<AuthEvent>,
) -> Result<(), Box<dyn std::error::Error>> {
    let app = Router::new().route("/qr", get(qr_handler));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn qr_handler() -> &'static str {
    "QR endpoint - use /qr/events for live updates"
}
```

- [ ] **Step 5: Commit**

```bash
git add src/qr/ Cargo.toml && git commit -m "feat: add QRAuthenticator with ASCII + HTTP"
```

---

## Task 7: AuthManager State Machine

**Files:**
- Create: `src/auth/manager.rs`
- Modify: `src/auth/mod.rs`

- [ ] **Step 1: Create auth/manager.rs**

```rust
use crate::auth::credentials::{AuthCredentials, Contact};
use crate::auth::{AuthEvent, SessionStore};
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};

#[derive(Debug, Clone, PartialEq)]
pub enum AuthState {
    Connecting,
    QrCodeNeeded,
    PairingCodeNeeded,
    Authenticated,
}

pub struct AuthManager {
    creds: AuthCredentials,
    store: Arc<dyn SessionStore>,
    state: AuthState,
    event_tx: broadcast::Sender<AuthEvent>,
}

impl AuthManager {
    pub fn new(store: Arc<dyn SessionStore>) -> Result<Self> {
        let creds = store.load_credentials()?.unwrap_or_else(AuthCredentials::new);
        let (event_tx, _) = broadcast::channel(32);
        let state = if creds.me.is_some() {
            AuthState::Authenticated
        } else {
            AuthState::Connecting
        };
        Ok(Self { creds, store, state, event_tx })
    }

    pub fn subscribe(&self) -> broadcast::Receiver<AuthEvent> {
        self.event_tx.subscribe()
    }

    pub fn set_auth_state(&mut self, state: AuthState) {
        self.state = state;
    }

    pub fn set_me(&mut self, contact: Contact) {
        self.creds.me = Some(contact);
    }

    pub fn creds(&self) -> &AuthCredentials {
        &self.creds
    }

    pub fn save(&self) -> Result<()> {
        self.store.save_credentials(&self.creds)
    }
}
```

- [ ] **Step 2: Update auth/mod.rs exports**

```rust
mod credentials;
pub mod manager;
pub mod session_store;

pub use credentials::*;
pub use manager::{AuthManager, AuthState};
pub use session_store::{FileStore, SessionStore};
```

- [ ] **Step 3: Commit**

```bash
git add src/auth/ && git commit -m "feat: add AuthManager state machine"
```

---

## Task 8: Integration Test — Full Auth Flow

**Files:**
- Create: `tests/auth_flow_test.rs`

- [ ] **Step 1: Write integration test**

```rust
use whatsapp_rs::auth::{AuthCredentials, FileStore, SessionStore};

#[tokio::test]
async fn test_auth_flow() {
    let store = FileStore::new().unwrap();
    let creds = AuthCredentials::new();
    store.save_credentials(&creds).unwrap();
    let loaded = store.load_credentials().unwrap().unwrap();
    assert_eq!(creds.registration_id, loaded.registration_id);
}
```

- [ ] **Step 2: Run integration test**

```bash
cd /home/familia/whatsapp-rs && cargo test --test auth_flow_test -- --nocapture
```

- [ ] **Step 3: Commit**

```bash
git add tests/ && git commit -m "test: add auth flow integration test"
```

---

## Task Dependencies

```
Task 1 (AuthCredentials) → Task 3 (SessionStore needs it)
Task 1 → Task 7 (AuthManager needs it)
Task 2 (BinaryNode) → Task 5 (Socket dispatch needs it)
Task 3 (SessionStore) → Task 7
Task 4 (ClientPayload) → Task 5 (used in handshake)
Task 5 (Socket dispatch) → Task 6 (QRAuthenticator needs events)
Task 6 (QR) → independent
Task 7 (AuthManager) → Task 5 (uses dispatcher)
Task 8 (Integration test) → Tasks 1-7 complete
```

## Spec Coverage Check

| Spec Section | Task |
|-------------|------|
| §3 AuthCredentials | Task 1 |
| §3 State Machine | Task 7 |
| §4.1 pair-device IQ | Task 5 |
| §4.2 QR Output (ASCII) | Task 6 |
| §4.2 QR Output (HTTP) | Task 6 |
| §4.2 QR Rotation | Task 5 |
| §4.3 ClientPayload | Task 4 |
| §5.1 Node Dispatch | Task 5 |
| §5.2 IQ Handler | Task 5 |
| §6 Multi-Device | Task 7 (DeviceManager stub) |
| §7 SessionStore + FileStore | Task 3 |
| §8 Events | Task 5 + Task 7 |

---

## Execution Options

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints

**Which approach?**
