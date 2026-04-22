# Message Send/Receive Design — whatsapp-rs

## 1. Overview

Complete 1:1 messaging implementation for whatsapp-rs: text, media (upload/download/encrypt/decrypt), reactions, replies, receipts, and encryption via Signal protocol.

## 2. Architecture

```
src/
├── messages/
│   ├── mod.rs              # MessageManager, WAMessage types
│   ├── send.rs             # send_text, send_media, send_reaction
│   ├── recv.rs             # decrypt_and_dispatch, handle_message
│   └── receipt.rs          # send_receipt, read_messages
├── media/
│   ├── mod.rs              # MediaHandler
│   ├── upload.rs           # upload_to_whatsapp (POST to media upload endpoint)
│   ├── download.rs         # download_media, decrypt_media
│   └── crypto.rs           # aes_encrypt, aes_decrypt (media keys)
├── signal/
│   ├── mod.rs              # SignalRepository
│   ├── session.rs          # Session encryption/decryption
│   └── keys.rs             # Pre-key management
└── events/
    └── mod.rs               # MessageEvent enum
```

## 3. Message Types

```rust
#[derive(Debug, Clone)]
pub struct WAMessage {
    pub key: MessageKey,
    pub message: Option<MessageContent>,
    pub messageTimestamp: u64,
    pub status: MessageStatus,
}

#[derive(Debug, Clone)]
pub struct MessageKey {
    pub remoteJid: String,      // "phone@s.whatsapp.net"
    pub fromMe: bool,
    pub id: String,             // 16-char message ID
    pub participant: Option<String>,
}

#[derive(Debug, Clone)]
pub enum MessageContent {
    Text(TextMessage),
    Image(ImageMessage),
    Video(VideoMessage),
    Audio(AudioMessage),
    Document(DocumentMessage),
    Sticker(StickerMessage),
    Reaction(ReactionMessage),
    Reply(ReplyMessage),
    ExtendedText(ExtendedTextMessage),
    ReactionMessage { target: String, text: String },
}

#[derive(Debug, Clone, PartialEq)]
pub enum MessageStatus {
    Pending,
    Sent,
    Delivered,
    Read,
    Played,
}

pub enum MessageReceiptType {
    Delivered,
    Read,
    ReadSelf,
    Sender,
}

#[derive(Debug, Clone)]
pub enum MessageEvent {
    NewMessage { msg: WAMessage },
    MessageUpdate { key: MessageKey, status: MessageStatus },
    Reaction { key: MessageKey, reaction: String, fromMe: bool },
    Receipt { key: MessageKey, receiptType: MessageReceiptType },
}
```

## 4. BinaryNode Message Protocol

### 4.1 Outgoing Message Node (send)

```
<message to="jid" type="text" id="MSG_ID" t="TIMESTAMP">
  <content>
    <text>Hello</text>
  </content>
</message>
```

For encrypted media:
```
<message to="jid" id="MSG_ID">
  <enc v="2" type="pkmsg">
    CIPHERTEXT_BYTES
  </enc>
</message>
```

### 4.2 Incoming Message Node (recv)

```
<message from="jid" id="MSG_ID" t="TIMESTAMP" type="text">
  <participant jid="..."/>
  <content>
    <text>Hello</text>
  </content>
</message>
```

### 4.3 Reaction Node

```
<reaction from="jid" id="MSG_ID" t="TIMESTAMP">
  <reaction>👍</reaction>
</reaction>
```

### 4.4 Receipt Node (delivery/read ack)

```
<receipt id="MSG_ID" from="jid" t="TIMESTAMP" type="delivered|read"/>
```

## 5. Send Flow

```
User: send_text(jid, text)
  │
  ├─► generate_message_id() → "3EB0A7B8C9D2E1F0"
  │
  ├─► build_message_node(text)
  │     └─► BinaryNode { tag: "message", attrs: {...}, content: [...] }
  │
  ├─► signal.encrypt(jid, message_bytes)
  │     ├─► session_exists(jid)? ──yes──► encrypt_message()
  │     └─◄──no──► fetch_session(jid) ──► encrypt_message()
  │
  └─► socket.send_node(encrypted_node)
```

## 6. Receive Flow

```
WebSocket: receive frame
  │
  ├─► decode_binary_node(frame) → BinaryNode
  │
  ├─► dispatch.node(node)
  │     └─► handle_message(node)
  │           │
  │           ├─► is_encrypted(node)?
  │           │     ├─► yes: signal.decrypt(enc_payload)
  │           │     │     └─► decode_message(decrypted_bytes)
  │           │     └─► no: decode_message(node.content)
  │           │
  │           └─► emit(MessageEvent::NewMessage { msg })
  │
  └─► send_receipt(msg.key, "received")
```

## 7. Signal Protocol Integration

Uses `libsignal` crate for session encryption:

```rust
pub struct SignalRepository {
    session_store: Arc<dyn SessionStore>,
    prekey_store: Arc<dyn PreKeyStore>,
}

impl SignalRepository {
    pub async fn encrypt_message(&self, jid: &str, plaintext: &[u8]) -> Result<EncryptedMessage>;
    pub async fn decrypt_message(&self, jid: &str, ciphertext: &[u8]) -> Result<Vec<u8>>;
    pub async fn encrypt_group_message(&self, group_jid: &str, plaintext: &[u8]) -> Result<Vec<u8>>;
}
```

Key derivation for media (from Baileys):
- `mediaKey` = HKDF-SHA256(randomBytes(32), "WhatsApp Media Encryption")
- `mediaKeyExpanded` = HKDF-SHA256(mediaKey, 112 bytes)

## 8. Media Handling

### 8.1 Upload Flow

```
Local file → read_bytes()
  │
  ├─► generate_media_key() → [u8; 32]
  │
  ├─► derive_media_keys(key)
  │     ├─► iv = first 16 bytes of expanded
  │     ├─► cipherKey = next 32 bytes
  │     └─► macKey = final 16 bytes
  │
  ├─► aes_gcm_encrypt(file_bytes, cipherKey, iv)
  │
  └─► upload_to_whatsapp(encrypted_data, auth)
        └─► Returns: { url: "...", direct_path: "..." }
```

### 8.2 Download Flow

```
Server: { url, direct_path, enc_file_hash }
  │
  ├─► download_file(url)
  │
  ├─► extract_media_keys_from_url(direct_path)
  │     └─► decode base64url encoded keys
  │
  ├─► verify_file_hash(enc_file_hash, downloaded)
  │
  └─► aes_gcm_decrypt(downloaded, cipherKey, iv)
        └─► Returns: plaintext media bytes
```

## 9. Reaction Handling

### Send Reaction
```rust
pub async fn send_reaction(&self, jid: &str, message_id: &str, reaction: &str) -> Result<()> {
    let node = BinaryNode {
        tag: "message".to_string(),
        attrs: vec![
            ("to".to_string(), jid.to_string()),
            ("id".to_string(), generate_message_id()),
            ("type".to_string(), "reaction".to_string()),
        ],
        content: NodeContent::List(vec![
            BinaryNode {
                tag: "reaction".to_string(),
                attrs: vec![("code".to_string(), reaction.to_string())],
                content: NodeContent::None,
            },
            BinaryNode {
                tag: "react".to_string(),
                attrs: vec![("to".to_string(), message_id.to_string())],
                content: NodeContent::None,
            },
        ]),
    };
    self.socket.send_node(node).await
}
```

### Receive Reaction
```rust
async fn handle_reaction(&self, node: &BinaryNode) -> Result<()> {
    let reaction = get_child_string(node, "reaction")?;
    let target_id = node.attr("id").unwrap_or("");
    self.event_tx.send(MessageEvent::Reaction {
        key: MessageKey { remoteJid: node.attr("from").unwrap(), id: target_id },
        reaction,
        fromMe: node.attr("from").map(|f| f == self.auth.me()).unwrap_or(false),
    }).await?;
    Ok(())
}
```

## 10. Receipt Handling

```rust
pub async fn send_receipt(&self, jid: &str, message_ids: &[String], receipt_type: MessageReceiptType) -> Result<()> {
    let node = BinaryNode {
        tag: "receipt".to_string(),
        attrs: vec![
            ("id".to_string(), message_ids[0].clone()),
            ("to".to_string(), jid.to_string()),
            ("type".to_string(), receipt_type.as_str().to_string()),
        ],
        content: message_ids[1..].map(|id| {
            BinaryNode { tag: "item".to_string(), attrs: vec![("id".to_string(), id)], content: NodeContent::None }
        }).collect(),
    };
    self.socket.send_node(node).await
}
```

## 11. Dependencies

```toml
# Media handling
aes-gcm = "0.10"
hkdf = "0.12"

# Signal protocol (libsignal wrapper)
libsignal-client = "0.1"

# HTTP for media upload
reqwest = { version = "0.12", features = ["json", "stream"] }

# Async
tokio = { version = "1", features = ["full"] }
futures-util = "0.3"

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# Multipart form for media upload
mime = "0.3"
```

## 12. Reference: Baileys Code Locations

- `messages-send.ts`:
  - `sendReceipt()` lines 140-191
  - `sendText()` lines 1050+
  - `relayMessage()` core logic
  - `createParticipantNodes()` lines 522-599
  - Media upload: lines 104-134

- `messages-recv.ts`:
  - `handleEncryptNotification()` lines 524-549
  - `handleMessage()` message processing
  - `handleReceipt()` retry logic lines 400-522
  - Reaction handling lines 264-273

- `Utils/`:
  - `encodeWAMessage()` - protobuf encoding
  - `decryptMessageNode()` - decryption
  - `decodeMessageNode()` - message decoding

## 13. Task Breakdown

1. **Message Types** - Define WAMessage, MessageKey, MessageContent enums
2. **MessageManager** - Core send/receive orchestration
3. **SignalRepository** - Session encryption/decryption (interface to libsignal)
4. **MediaHandler** - Upload, download, encrypt, decrypt
5. **Send Handlers** - send_text, send_reaction, send_reply, send_receipt
6. **Receive Handlers** - decrypt_and_dispatch, handle_message, handle_reaction
7. **Receipt Handlers** - send_receipt, read_messages
8. **Integration Test** - Full send/receive roundtrip test