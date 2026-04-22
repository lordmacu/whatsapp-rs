# QR Authentication Design — whatsapp-rs

## 1. Overview

Authentication flow for whatsapp-rs based on Baileys reference implementation.
Supports QR code display, 8-digit pairing code entry, HTTP endpoint, and file-based session persistence.

## 2. Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Client Session                       │
│  ┌──────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │ AuthMgr  │  │ SessionStore │  │  QRAuthenticator  │  │
│  └────┬─────┘  └──────┬───────┘  └────────┬──────────┘  │
│       │               │                   │             │
│       │         ┌─────▼─────┐            │             │
│       │         │ FileStore │◄────────────┤             │
│       │         │  (~/.whatsapp-rs/)      │             │
│       └────────►│           │◄────────────┘             │
│                 └───────────┘                            │
└─────────────────────────────────────────────────────────┘
```

### Modules

| Module | Responsibility |
|--------|---------------|
| `auth/` | Credentials (keys, pre-keys, session tokens) |
| `socket/` | WebSocket lifecycle, incoming node dispatch |
| `binary/` | Protocol encoding/decoding (tokens, varint, nodes) |
| `noise/` | Noise handshake, transport encryption (exists) |

## 3. AuthManager

Manages authentication state throughout the connection lifecycle.

### Credentials Structure

```rust
pub struct AuthCredentials {
    noise_key: KeyPair,           // long-term identity
    signed_identity_key: KeyPair, // DH for key exchange
    signed_pre_key: SignedKeyPair,
    registration_id: u16,
    adv_secret_key: [u8; 32],
    me: Option<Contact>,          // set after pairing success
    pairing_code: Option<String>,
}
```

### State Machine

```
                    ┌──────────────────────────────┐
                    │           START              │
                    └──────────────┬───────────────┘
                                   │
                    ┌──────────────▼───────────────┐
                    │     CONNECTING              │
                    │  (Noise handshake done,     │
                    │   wait for pair-device IQ)   │
                    └──────────────┬───────────────┘
                                   │
              ┌──────────────────┼──────────────────┐
              │                  │                  │
   ┌──────────▼──────────┐ ┌──────▼──────┐ ┌───────▼────────┐
   │  QR_CODE_NEEDED    │ │CODE_NEEDED  │ │PAIRING_COMPLETE│
   │ (pair-device recv) │ │(link code   │ │(pair-success   │
   │                    │ │ received)   │ │ recv)          │
   └────────────────────┘ └─────────────┘ └────────────────┘
              │                     │                 │
              └─────────────────────┼─────────────────┘
                                    ▼
                         ┌────────────────────┐
                         │    AUTHENTICATED   │───────► ready to send/recv
                         └────────────────────┘
```

## 4. QR Authentication Flow

### 4.1 Incoming pair-device IQ

When the server sends `CB:iq,type:set,pair-device` (IQ tag with type "set"):

1. Extract all `<ref>` nodes from the IQ content
2. Build QR string: `[ref].base64(noiseKey),base64(identityKey),advSecret`
3. Emit `AuthEvent::NewQR(qr_string)` with refs array for rotation

### 4.2 QR Output Mechanisms

All three output mechanisms are configurable via `QrConfig`:

```rust
pub struct QrConfig {
    pub ascii: bool,        // print QR as ANSI/Unicode art
    pub http_endpoint: Option<String>, // e.g. "0.0.0.0:3000"
    pub pairing_code: bool, // expose 8-digit code as alternative
}
```

**ASCII QR**: Convert QR data to UTF-8 block characters (░▒▓█) printed to stdout. Use `qrenco` crate or manual bit-to-block mapping.

**HTTP endpoint**: Spawn axum server serving:
- `GET /qr` → HTML page with JS QR library rendering the code
- `GET /qr/raw` → raw QR string as text
- Server-sent events `GET /qr/events` → `EventSource` stream for live updates

**Pairing code**: Expose 8-digit code via:
- `GET /pairing-code` → plain text
- Part of the HTML endpoint above

### 4.3 QR Rotation

The server sends multiple refs (typically 4-8). Each QR times out after 20s (subsequent) or 60s (first).
Rotate through refs sequentially:
- First QR: 60s timeout
- Subsequent QRs: 20s timeout
- After last ref consumed: emit `AuthEvent::QrExpired`

## 5. Socket Module Changes

### 5.1 WebSocket Message Dispatch

Add incoming node dispatch after decryption in `socket/mod.rs`:

```rust
// In receive loop:
let node = decode_binary_node(&frame)?;
dispatch_node(&node).await;
```

Dispatch rules (Baileys pattern):
1. If `node.attrs.id` matches a pending query → resolve promise
2. Emit `CB:{tag}` event for exact tag match
3. Emit `CB:{tag},{attr}:{value}` for attribute callbacks
4. Unhandled nodes logged at `debug!` level

### 5.2 Incoming IQ Handler

```rust
async fn on_pair_device(stanza: BinaryNode) {
    // Respond with empty result IQ (ack the request)
    send_node(IQResult { id: stanza.attrs.id });

    // Extract refs and emit QR
    let refs = stanza.content.iter()
        .filter_map(|n| n.tag == "ref")
        .map(|n| n.content.as_bytes())
        .collect::<Vec<_>>();
    auth.emit_qr(refs);
}
```

### 5.3 ClientPayload

For new registrations, include additional fields in ClientPayload:

```protobuf
// Fields needed in ClientPayload
passive              = true          // field 2
clientHelloVersion   = "2.3000.1035194821" // field 3
deviceName          = "whatsapp-rs" // field 4
pushName            = "whatsapp-rs" // field 5
 connectType         = WIFI_UNKNOWN  // field 12 (omit for simplicity)
 connectReason      = USER_ACTIVATED // field 13
```

For existing sessions (returning users):
- Same payload but with `me.id` already populated
- Server sends `success` without requiring QR scan

## 6. Multi-Device Support

### 6.1 Device Listing

```rust
pub struct DeviceManager {
    auth_state: AuthState,
}

impl DeviceManager {
    /// Fetch device list from server via USync query
    pub async fn list_devices(&self) -> Result<Vec<Device>>;

    /// Remove a linked device
    pub async fn unlink_device(&self, jid: &str, device_id: u32) -> Result<()>;

    /// Get own LID (Linked ID) for message targeting
    pub fn own_lid(&self) -> Option<String>;
}
```

### 6.2 LID (Linked ID) Storage

Store LID-PN (Phone Number) mappings in Signal store:
- Key: `lid-mapping:{lid}` → pn string
- On `pair-success`, extract `lid` from success node attrs
- Store own LID → PN mapping for session encryption

## 7. Session Persistence

### 7.1 FileStore

File-based storage at `~/.whatsapp-rs/`:

```
~/.whatsapp-rs/
├── creds.json          # AuthCredentials (keys, tokens, me)
├── pre-keys/          # pre-key KeyPairs (one file per ID)
│   ├── 1.key
│   ├── 2.key
│   └── ...
├── sessions/          # Signal sessions (one file per jid)
│   └── 123456789@s.whatsapp.net.key
└── device-list.json   # linked devices
```

### 7.2 SessionStore Trait

```rust
pub trait SessionStore {
    async fn save_credentials(&self, creds: &AuthCredentials) -> Result<()>;
    async fn load_credentials(&self) -> Result<Option<AuthCredentials>>;

    async fn save_prekey(&self, id: u32, key: &KeyPair) -> Result<()>;
    async fn load_prekey(&self, id: u32) -> Result<Option<KeyPair>>;
    async fn load_all_prekeys(&self) -> Result<Vec<(u32, KeyPair)>>;

    async fn save_session(&self, jid: &str, session: &[u8]) -> Result<()>;
    async fn load_session(&self, jid: &str) -> Result<Option<Vec<u8>>>;

    async fn clear(&self) -> Result<()>;
}
```

FileStore implements this trait. Users can provide custom implementations (Redis, DB, etc.).

## 8. Event Emission

```rust
pub enum AuthEvent {
    NewQR { qr: String, refs: Vec<Vec<u8>> },
    QRScanned { ref_index: usize },
    QRTimedOut { ref_index: usize },
    PairingCode { code: String },       // 8-digit code
    PairingSuccess { me: Contact },
    AuthFailure { reason: String },
}
```

Socket module emits these events. `AuthManager` provides a channel/ Future that listeners subscribe to.

## 9. Testing

### 9.1 Integration Test Plan

1. **Handshake test**: Connect, complete noise handshake, verify transport state
2. **QR capture test**: Mock WebSocket server sends pair-device IQ, verify QR string format
3. **Pairing code test**: Generate code, verify format (8 Crockford chars)
4. **Roundtrip test**: Connect + authenticate + send a message (if test account available)

### 9.2 Test Infrastructure

Use `mockito` for WebSocket mocking or implement a local WhatsApp Web mock.

## 10. Dependencies Additions

```toml
# Cargo.toml additions
qrenco = "0.1"       # QR ASCII generation
axum = "0.7"         # HTTP server for QR endpoint
tokio-tungstenite = { version = "0.21", features = ["native-tls"] }
serde_json = "1.0"
dirs = "5.0"          # ~/.whatsapp-rs path resolution
```

## 11. Reference: Baileys Pairing Flow

Key code locations in Baileys (`/home/familia/Baileys/src/Socket/socket.ts`):

- `validateConnection()`: handles handshake + ClientPayload (lines 416-454)
- `pair-device` handler: lines 856-895
- `pair-success` handler: lines 898-918
- `success` handler: lines 920-970
- `requestPairingCode()`: lines 748-810
- `logout()`: lines 722-746

Key types (`/home/familia/Baileys/src/Types/`):
- `Socket.ts`: SocketConfig structure
- `Auth.ts`: AuthenticationCreds, SignalCreds, SignalKeyStore
- `Socket.ts` Events: connection.update, creds.update
