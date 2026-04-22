# Messaging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement 1:1 message send/receive with text, media, reactions, replies, receipts, and Signal encryption.

**Architecture:** Modular design with `MessageManager` as central orchestrator. `SignalRepository` handles session encryption. `MediaHandler` manages upload/download with AES-GCM encryption. Events emitted via channel to upper layers.

**Tech Stack:** Rust 2021, tokio, libsignal-client, aes-gcm, hkdf, reqwest.

---

## File Structure

```
src/
├── messages/
│   ├── mod.rs              # MessageManager, WAMessage types, events
│   ├── send.rs             # send_text, send_reaction, send_reply
│   └── recv.rs             # decrypt_and_dispatch, handle_message
├── media/
│   ├── mod.rs              # MediaHandler
│   └── crypto.rs           # media_encrypt, media_decrypt
├── signal/
│   └── mod.rs              # SignalRepository (interface only, libsignal impl)
└── events/
    └── mod.rs              # MessageEvent enum
```

---

## Task 1: Message Types & Events

**Files:**
- Create: `src/messages/mod.rs`
- Modify: `src/lib.rs`

- [ ] **Step 1: Create src/messages/mod.rs**

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WAMessage {
    pub key: MessageKey,
    pub message: Option<MessageContent>,
    pub messageTimestamp: u64,
    pub status: MessageStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageKey {
    pub remoteJid: String,
    pub fromMe: bool,
    pub id: String,
    pub participant: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageContent {
    Text { text: String },
    Image { url: String, mimetype: String, caption: Option<String> },
    Video { url: String, mimetype: String, caption: Option<String> },
    Audio { url: String, mimetype: String },
    Document { url: String, mimetype: String, fileName: String },
    Sticker { url: String, mimetype: String },
    Reaction { targetMessageId: String, text: String },
    Reply { messageId: String, message: Box<MessageContent> },
    ExtendedText { text: String, previewUrl: Option<String> },
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum MessageStatus {
    Pending,
    Sent,
    Delivered,
    Read,
    Played,
}

#[derive(Debug, Clone, Copy)]
pub enum MessageReceiptType {
    Delivered,
    Read,
    ReadSelf,
    Sender,
}

impl MessageReceiptType {
    pub fn as_str(&self) -> &'static str {
        match self {
            MessageReceiptType::Delivered => "delivered",
            MessageReceiptType::Read => "read",
            MessageReceiptType::ReadSelf => "read-self",
            MessageReceiptType::Sender => "sender",
        }
    }
}

#[derive(Debug, Clone)]
pub enum MessageEvent {
    NewMessage { msg: WAMessage },
    MessageUpdate { key: MessageKey, status: MessageStatus },
    Reaction { key: MessageKey, reaction: String, fromMe: bool },
    Receipt { key: MessageKey, receiptType: MessageReceiptType },
}

pub struct MessageManager {
    auth_mgr: Arc<AuthManager>,
    signal: Arc<SignalRepository>,
    socket: Arc<Socket>,
    event_tx: broadcast::Sender<MessageEvent>,
}
```

- [ ] **Step 2: Update src/lib.rs**

```rust
pub mod auth;
pub mod binary;
pub mod noise;
pub mod qr;
pub mod socket;
pub mod messages;
pub mod media;
pub mod signal;
```

- [ ] **Step 3: Add tests for message types**

```rust
#[cfg(test)]
mod tests {
    use crate::messages::{WAMessage, MessageKey, MessageContent, MessageStatus};

    #[test]
    fn test_message_key_serialization() {
        let key = MessageKey {
            remoteJid: "123456789@s.whatsapp.net".to_string(),
            fromMe: true,
            id: "test123".to_string(),
            participant: None,
        };
        let json = serde_json::to_string(&key).unwrap();
        let loaded: MessageKey = serde_json::from_str(&json).unwrap();
        assert_eq!(key.id, loaded.id);
    }

    #[test]
    fn test_message_content_text() {
        let content = MessageContent::Text { text: "Hello".to_string() };
        match content {
            MessageContent::Text { text } => assert_eq!(text, "Hello"),
            _ => panic!("Expected Text variant"),
        }
    }
}
```

- [ ] **Step 4: Run tests**

```bash
cd /home/familia/whatsapp-rs && cargo test messages -- --nocapture
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/messages/ src/lib.rs && git commit -m "feat: add message types and events"
```

---

## Task 2: SignalRepository (Encryption Interface)

**Files:**
- Create: `src/signal/mod.rs`

- [ ] **Step 1: Create SignalRepository struct**

```rust
use crate::auth::AuthManager;
use anyhow::Result;
use std::sync::Arc;

pub struct SignalRepository {
    auth_mgr: Arc<AuthManager>,
}

impl SignalRepository {
    pub fn new(auth_mgr: Arc<AuthManager>) -> Self {
        Self { auth_mgr }
    }

    pub async fn encrypt_message(&self, jid: &str, plaintext: &[u8]) -> Result<EncryptedMessage> {
        todo!("libsignal-client integration")
    }

    pub async fn decrypt_message(&self, jid: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        todo!("libsignal-client integration")
    }

    pub async fn encrypt_group_message(&self, group_jid: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        todo!("libsignal-client integration")
    }
}

pub struct EncryptedMessage {
    pub ciphertext: Vec<u8>,
    pub message_type: String,  // "pkmsg" or "skmsg"
}
```

- [ ] **Step 2: Verify compilation**

```bash
cd /home/familia/whatsapp-rs && cargo build 2>&1 | grep -E "(error|warning:.*signal)"
```

Expected: Only unused warnings, no errors

- [ ] **Step 3: Commit**

```bash
git add src/signal/ && git commit -m "feat: add SignalRepository interface"
```

---

## Task 3: MediaHandler & Crypto

**Files:**
- Create: `src/media/mod.rs`

- [ ] **Step 1: Create MediaHandler with crypto functions**

```rust
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use anyhow::Result;

pub struct MediaHandler {
    http_client: reqwest::Client,
}

impl MediaHandler {
    pub fn new() -> Self {
        Self {
            http_client: reqwest::Client::new(),
        }
    }

    pub fn derive_media_keys(&self, media_key: &[u8; 32]) -> MediaKeys {
        let hk = Hkdf::<Sha256>::new(None, media_key);
        let mut okm = [0u8; 112];
        hk.expand(b"WhatsApp Media Keys", &mut okm).unwrap();
        
        let cipher_key: [u8; 32] = okm[0..32].try_into().unwrap();
        let mac_key: [u8; 32] = okm[32..64].try_into().unwrap();
        let iv: [u8; 16] = okm[64..80].try_into().unwrap();
        
        MediaKeys { cipher_key, mac_key, iv }
    }

    pub fn encrypt_media(&self, data: &[u8], keys: &MediaKeys) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&keys.cipher_key));
        let nonce = Nonce::from_slice(&keys.iv);
        let ciphertext = cipher
            .encrypt(nonce, Payload { msg: data, aad: b"" })
            .map_err(|e| anyhow::anyhow!("encryption failed: {}", e))?;
        Ok(ciphertext)
    }

    pub fn decrypt_media(&self, ciphertext: &[u8], keys: &MediaKeys) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&keys.cipher_key));
        let nonce = Nonce::from_slice(&keys.iv);
        let plaintext = cipher
            .decrypt(nonce, Payload { msg: ciphertext, aad: b"" })
            .map_err(|e| anyhow::anyhow!("decryption failed: {}", e))?;
        Ok(plaintext)
    }

    pub async fn upload_media(&self, data: Vec<u8>, media_key: [u8; 32]) -> Result<MediaUploadResult> {
        todo!("WhatsApp media upload endpoint")
    }

    pub async fn download_media(&self, url: &str) -> Result<Vec<u8>> {
        todo!("Download from WhatsApp CDN")
    }
}

pub struct MediaKeys {
    pub cipher_key: [u8; 32],
    pub mac_key: [u8; 32],
    pub iv: [u8; 16],
}

pub struct MediaUploadResult {
    pub url: String,
    pub direct_path: String,
}
```

- [ ] **Step 2: Add reqwest and mime dependencies to Cargo.toml**

```toml
reqwest = { version = "0.12", features = ["json", "stream"] }
mime = "0.3"
```

- [ ] **Step 3: Verify compilation**

```bash
cd /home/familia/whatsapp-rs && cargo build 2>&1 | grep -E "error"
```

Expected: No errors

- [ ] **Step 4: Commit**

```bash
git add src/media/ Cargo.toml && git commit -m "feat: add MediaHandler with AES-GCM encryption"
```

---

## Task 4: Send Handlers

**Files:**
- Modify: `src/messages/mod.rs`

- [ ] **Step 1: Add send functions to MessageManager**

```rust
impl MessageManager {
    pub async fn send_text(&self, jid: &str, text: &str) -> Result<String> {
        let msg_id = generate_message_id();
        let content = MessageContent::Text { text: text.to_string() };
        self.send_message(jid, msg_id.clone(), content).await?;
        Ok(msg_id)
    }

    pub async fn send_reaction(&self, jid: &str, message_id: &str, reaction: &str) -> Result<()> {
        let msg_id = generate_message_id();
        let content = MessageContent::Reaction {
            targetMessageId: message_id.to_string(),
            text: reaction.to_string(),
        };
        self.send_message(jid, msg_id, content).await
    }

    pub async fn send_reply(&self, jid: &str, reply_to_id: &str, text: &str) -> Result<String> {
        let msg_id = generate_message_id();
        let content = MessageContent::Reply {
            messageId: reply_to_id.to_string(),
            message: Box::new(MessageContent::Text { text: text.to_string() }),
        };
        self.send_message(jid, msg_id.clone(), content).await?;
        Ok(msg_id)
    }

    async fn send_message(&self, jid: &str, msg_id: String, content: MessageContent) -> Result<()> {
        let msg = WAMessage {
            key: MessageKey {
                remoteJid: jid.to_string(),
                fromMe: true,
                id: msg_id.clone(),
                participant: None,
            },
            message: Some(content),
            messageTimestamp: unix_timestamp(),
            status: MessageStatus::Pending,
        };
        
        let node = self.build_message_node(&msg)?;
        self.socket.send_node(node).await?;
        
        Ok(())
    }

    fn build_message_node(&self, msg: &WAMessage) -> Result<BinaryNode> {
        let attrs = vec![
            ("to".to_string(), msg.key.remoteJid.clone()),
            ("id".to_string(), msg.key.id.clone()),
        ];
        
        let content = match &msg.message {
            Some(MessageContent::Text { text }) => vec![
                BinaryNode {
                    tag: "text".to_string(),
                    attrs: vec![],
                    content: NodeContent::Text(text.clone()),
                }
            ],
            _ => todo!("other message types"),
        };

        Ok(BinaryNode {
            tag: "message".to_string(),
            attrs,
            content: NodeContent::List(content),
        })
    }
}

fn generate_message_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 8] = rng.gen();
    hex::encode(bytes)
}

fn unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
```

- [ ] **Step 2: Verify compilation**

```bash
cd /home/familia/whatsapp-rs && cargo build 2>&1 | tail -20
```

Expected: No errors related to messages

- [ ] **Step 3: Commit**

```bash
git add src/messages/ && git commit -m "feat: add send_text, send_reaction, send_reply handlers"
```

---

## Task 5: Receipt Handlers

**Files:**
- Modify: `src/messages/mod.rs`

- [ ] **Step 1: Add receipt functions**

```rust
impl MessageManager {
    pub async fn send_receipt(&self, jid: &str, message_ids: &[String], receipt_type: MessageReceiptType) -> Result<()> {
        let node = BinaryNode {
            tag: "receipt".to_string(),
            attrs: vec![
                ("id".to_string(), message_ids[0].clone()),
                ("to".to_string(), jid.to_string()),
                ("type".to_string(), receipt_type.as_str().to_string()),
            ],
            content: if message_ids.len() > 1 {
                NodeContent::List(
                    message_ids[1..].iter().map(|id| BinaryNode {
                        tag: "item".to_string(),
                        attrs: vec![("id".to_string(), id.clone())],
                        content: NodeContent::None,
                    }).collect()
                )
            } else {
                NodeContent::None
            },
        };
        self.socket.send_node(node).await
    }

    pub async fn read_messages(&self, keys: &[MessageKey]) -> Result<()> {
        let mut by_jid: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
        for key in keys {
            by_jid.entry(key.remoteJid.clone()).or_default().push(key.id.clone());
        }
        for (jid, ids) in by_jid {
            self.send_receipt(&jid, &ids, MessageReceiptType::Read).await?;
        }
        Ok(())
    }
}
```

- [ ] **Step 2: Commit**

```bash
git add src/messages/ && git commit -m "feat: add receipt handlers"
```

---

## Task 6: Receive Handler

**Files:**
- Modify: `src/socket/mod.rs`

- [ ] **Step 1: Add receive loop integration**

After noise handshake completes, add message receive loop:

```rust
pub async fn connect_and_handshake(noise_key: &KeyPair) -> Result<TransportState> {
    // ... existing handshake code ...
    
    let transport = hs.into_transport()?;
    info!("noise handshake complete");
    
    // Start message receive loop
    tokio::spawn(async move {
        while let Some(node) = recv_node(&mut ws).await {
            match node.tag.as_str() {
                "message" => {
                    if let Err(e) = message_mgr.handle_message(&node).await {
                        tracing::error!("handle message error: {}", e);
                    }
                }
                "receipt" => {
                    if let Err(e) = message_mgr.handle_receipt(&node).await {
                        tracing::error!("handle receipt error: {}", e);
                    }
                }
                _ => {
                    tracing::debug!("unhandled node: {}", node.tag);
                }
            }
        }
    });
    
    Ok(transport)
}

async fn recv_node(ws: &mut WebSocketStream<MaybeTlsStream<TcpStream>>) -> Result<Option<BinaryNode>> {
    while let Some(msg) = ws.next().await {
        let msg = msg?;
        if let Message::Binary(data) = msg {
            if data.len() < 3 { continue; }
            return Ok(Some(decode_frame(&data[3..])?));
        }
    }
    Ok(None)
}
```

- [ ] **Step 2: Add handle_message to MessageManager**

```rust
impl MessageManager {
    pub async fn handle_message(&self, node: &BinaryNode) -> Result<()> {
        let key = MessageKey {
            remoteJid: node.attr("from").unwrap_or("").to_string(),
            fromMe: false,
            id: node.attr("id").unwrap_or("").to_string(),
            participant: node.attr("participant").map(|s| s.to_string()),
        };
        
        let content = self.decode_message_content(node)?;
        let timestamp = node.attr("t").and_then(|s| s.parse().ok()).unwrap_or(0);
        
        let msg = WAMessage {
            key,
            message: Some(content),
            messageTimestamp: timestamp,
            status: MessageStatus::Delivered,
        };
        
        self.event_tx.send(MessageEvent::NewMessage { msg })?;
        
        // Send delivery receipt
        if let Some(remote_jid) = node.attr("from") {
            if let Some(msg_id) = node.attr("id") {
                self.send_receipt(remote_jid, &[msg_id.to_string()], MessageReceiptType::Delivered).await?;
            }
        }
        
        Ok(())
    }
    
    fn decode_message_content(&self, node: &BinaryNode) -> Result<MessageContent> {
        let content_node = get_child_node(node, "content")
            .or_else(|| get_child_node(node, "encrypted"));
        
        match content_node {
            Some(c) => match c.tag.as_str() {
                "text" => {
                    if let NodeContent::Text(text) = &c.content {
                        return Ok(MessageContent::Text { text: text.clone() });
                    }
                }
                "image" => todo!("image decode"),
                "video" => todo!("video decode"),
                "reaction" => {
                    let target = c.attr("target").unwrap_or("").to_string();
                    let text = get_child_string(&c, "reaction").unwrap_or_default();
                    return Ok(MessageContent::Reaction { targetMessageId: target, text });
                }
                _ => {}
            },
            None => {}
        }
        
        Ok(MessageContent::ExtendedText { text: "".to_string(), previewUrl: None })
    }
}

pub fn get_child_node<'a>(node: &'a BinaryNode, tag: &str) -> Option<&'a BinaryNode> {
    if let NodeContent::List(nodes) = &node.content {
        nodes.iter().find(|n| n.tag == tag)
    } else {
        None
    }
}

pub fn get_child_string(node: &BinaryNode, tag: &str) -> Option<String> {
    get_child_node(node, tag)
        .and_then(|n| if let NodeContent::Text(s) = &n.content { Some(s.clone()) } else { None })
}
```

- [ ] **Step 3: Commit**

```bash
git add src/socket/ src/messages/ && git commit -m "feat: add receive handler and message dispatch"
```

---

## Task 7: Integration Test

**Files:**
- Create: `tests/messaging_test.rs`

- [ ] **Step 1: Write integration test**

```rust
use whatsapp_rs::messages::{WAMessage, MessageKey, MessageContent, MessageStatus};

#[test]
fn test_message_roundtrip() {
    let msg = WAMessage {
        key: MessageKey {
            remoteJid: "123@s.whatsapp.net".to_string(),
            fromMe: true,
            id: "test123".to_string(),
            participant: None,
        },
        message: Some(MessageContent::Text { text: "Hello".to_string() }),
        messageTimestamp: 1234567890,
        status: MessageStatus::Sent,
    };
    
    let json = serde_json::to_string(&msg).unwrap();
    let loaded: WAMessage = serde_json::from_str(&json).unwrap();
    
    assert_eq!(msg.key.id, loaded.key.id);
    assert_eq!(msg.key.remoteJid, loaded.key.remoteJid);
}

#[test]
fn test_message_content_variants() {
    let text = MessageContent::Text { text: "Hello".to_string() };
    assert!(matches!(text, MessageContent::Text { .. }));
    
    let reaction = MessageContent::Reaction {
        targetMessageId: "msg123".to_string(),
        text: "👍".to_string(),
    };
    assert!(matches!(reaction, MessageContent::Reaction { .. }));
}
```

- [ ] **Step 2: Run tests**

```bash
cd /home/familia/whatsapp-rs && cargo test --test messaging_test -- --nocapture
```

Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add tests/messaging_test.rs && git commit -m "test: add messaging integration tests"
```

---

## Task Dependencies

```
Task 1 (Message Types) → all other tasks
Task 2 (Signal) → Task 4, Task 6
Task 3 (Media) → independent
Task 4 (Send Handlers) → Task 1, Task 2
Task 5 (Receipt Handlers) → Task 1, Task 4
Task 6 (Receive Handler) → Task 1, Task 2, Task 4
Task 7 (Integration Test) → all complete
```

## Spec Coverage Check

| Spec Section | Task |
|-------------|------|
| §3 Message Types | Task 1 |
| §4 BinaryNode Protocol | Task 1, Task 6 |
| §5 Send Flow | Task 4 |
| §6 Receive Flow | Task 6 |
| §7 Signal Protocol | Task 2 |
| §8 Media Handling | Task 3 |
| §9 Reaction Handling | Task 4, Task 6 |
| §10 Receipt Handling | Task 5 |

---

## Execution Options

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints

**Which approach?**