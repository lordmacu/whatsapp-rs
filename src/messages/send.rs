use crate::binary::{BinaryNode, NodeContent};

/// Append `:0` (primary device) to a bare user JID like `573144...@s.whatsapp.net`.
/// If the JID already carries a `:device` part it's returned unchanged.
fn ensure_device(jid: &str) -> String {
    let at = match jid.find('@') { Some(i) => i, None => return jid.to_string() };
    let before = &jid[..at];
    let server = &jid[at..];
    if before.contains(':') {
        jid.to_string()
    } else {
        format!("{}:0{}", before, server)
    }
}

/// Strip any `:device` suffix from a JID, leaving the bare user form.
fn bare_user_jid(jid: &str) -> String {
    let at = match jid.find('@') { Some(i) => i, None => return jid.to_string() };
    let before = &jid[..at];
    let server = &jid[at..];
    let user = before.split(':').next().unwrap_or(before);
    format!("{}{}", user, server)
}

/// WhatsApp-specific random padding applied to the OUTERMOST Message bytes
/// before they hit AES-CBC encrypt. Matches Baileys' `writeRandomPadMax16`:
/// pad length = (rand & 0x0f) + 1, each byte = pad length. Receiver's
/// `unpadRandomMax16` reads the last byte as padLength and trims.
fn pad_wa(bytes: &[u8]) -> Vec<u8> {
    use rand::RngCore;
    let mut r = [0u8; 1];
    rand::rngs::OsRng.fill_bytes(&mut r);
    let pad_len = ((r[0] & 0x0f) as usize) + 1;
    let mut out = Vec::with_capacity(bytes.len() + pad_len);
    out.extend_from_slice(bytes);
    out.extend(std::iter::repeat(pad_len as u8).take(pad_len));
    out
}

/// Wrap a serialized `WAMessage` inside `Message.deviceSentMessage` so our
/// own other devices can display the message as "sent by me". Matches
/// Baileys `encodeWAMessage({ deviceSentMessage: { destinationJid, message } })`.
fn wrap_device_sent_message(destination_jid: &str, inner_msg_bytes: &[u8]) -> Vec<u8> {
    use crate::signal::wa_proto::{proto_bytes, proto_varint as _};
    // DeviceSentMessage body: field 1 = destinationJid, field 2 = message.
    let mut body = Vec::new();
    body.extend(proto_bytes(1, destination_jid.as_bytes()));
    body.extend(proto_bytes(2, inner_msg_bytes));
    // Outer Message: field 31 = deviceSentMessage.
    proto_bytes(31, &body)
}
use crate::messages::{
    generate_message_id, unix_now, MessageContent, MessageEvent, MessageKey, MessageManager,
    MessageStatus, ReceiptType, WAMessage,
};
use anyhow::Result;

#[allow(dead_code)]
impl MessageManager {
    pub async fn send_text(&self, jid: &str, text: &str) -> Result<String> {
        let id = generate_message_id();
        let content = MessageContent::Text { text: text.to_string(), mentioned_jids: Vec::new() };
        self.send_message(jid, id.clone(), content).await?;
        Ok(id)
    }

    pub async fn send_reaction(&self, jid: &str, target_id: &str, emoji: &str) -> Result<()> {
        let id = generate_message_id();
        self.send_message(jid, id, MessageContent::Reaction {
            target_id: target_id.to_string(),
            emoji: emoji.to_string(),
        }).await
    }

    pub async fn send_reply(&self, jid: &str, reply_to_id: &str, text: &str) -> Result<String> {
        let id = generate_message_id();
        let content = MessageContent::Reply {
            reply_to_id: reply_to_id.to_string(),
            text: text.to_string(),
        };
        self.send_message(jid, id.clone(), content).await?;
        Ok(id)
    }

    /// Send a text message with @mention JIDs so the recipient app highlights them.
    pub async fn send_mention(
        &self,
        jid: &str,
        text: &str,
        mention_jids: &[&str],
    ) -> Result<String> {
        let id = generate_message_id();
        let wa_bytes = crate::signal::wa_proto::encode_wa_text_with_mentions(text, mention_jids);
        self.send_encrypted_bytes(jid, &id, wa_bytes).await?;
        Ok(id)
    }

    /// Send composing/paused typing indicator to a JID.
    pub async fn send_typing(&self, jid: &str, composing: bool) -> Result<()> {
        let state = if composing { "composing" } else { "paused" };
        let node = BinaryNode {
            tag: "chatstate".to_string(),
            attrs: vec![("to".to_string(), jid.to_string())],
            content: NodeContent::List(vec![BinaryNode {
                tag: state.to_string(),
                attrs: vec![],
                content: NodeContent::None,
            }]),
        };
        self.socket.send_node(&node).await
    }

    /// Broadcast presence (available/unavailable).
    ///
    /// WhatsApp needs a `name=` attribute on the first `available` presence
    /// or it keeps us flagged as passive and won't fan out incoming messages.
    /// We use the push name stored in creds (set via `Client::set_push_name`,
    /// defaults to "WhatsApp-rs" if unset).
    pub async fn send_presence(&self, available: bool) -> Result<()> {
        let pres_type = if available { "available" } else { "unavailable" };
        let mut attrs = vec![("type".to_string(), pres_type.to_string())];
        if available {
            attrs.push(("name".to_string(), "WhatsApp-rs".to_string()));
        }
        let node = BinaryNode {
            tag: "presence".to_string(),
            attrs,
            content: NodeContent::None,
        };
        self.socket.send_node(&node).await
    }

    /// Subscribe to presence updates for a specific contact JID.
    /// The server will send presence notifications whenever they come online/offline.
    pub async fn subscribe_contact_presence(&self, jid: &str) -> Result<()> {
        let node = BinaryNode {
            tag: "presence".to_string(),
            attrs: vec![
                ("type".to_string(), "subscribe".to_string()),
                ("to".to_string(), jid.to_string()),
            ],
            content: NodeContent::None,
        };
        self.socket.send_node(&node).await
    }

    /// Mark a WhatsApp Status (story) as viewed.
    /// `sender_jid` is the JID of the status author; `msg_id` is the status message ID.
    pub async fn mark_status_viewed(&self, sender_jid: &str, msg_id: &str) -> Result<()> {
        let node = BinaryNode {
            tag: "receipt".to_string(),
            attrs: vec![
                ("id".to_string(), msg_id.to_string()),
                ("to".to_string(), "status@broadcast".to_string()),
                ("participant".to_string(), sender_jid.to_string()),
                ("type".to_string(), "read".to_string()),
            ],
            content: NodeContent::None,
        };
        self.socket.send_node(&node).await
    }

    /// Fetch the current blocklist (JIDs you have blocked).
    pub async fn fetch_blocklist(&self) -> Result<Vec<String>> {
        let id = self.socket.next_id();
        let node = BinaryNode {
            tag: "iq".to_string(),
            attrs: vec![
                ("id".to_string(), id),
                ("xmlns".to_string(), "blocklist".to_string()),
                ("to".to_string(), "s.whatsapp.net".to_string()),
                ("type".to_string(), "get".to_string()),
            ],
            content: NodeContent::None,
        };
        let response = self.socket.send_iq_await(node).await?;
        let jids = match &response.content {
            NodeContent::List(ch) => {
                let list = ch.iter().find(|n| n.tag == "list");
                match list {
                    Some(l) => match &l.content {
                        NodeContent::List(items) => items
                            .iter()
                            .filter(|n| n.tag == "item")
                            .filter_map(|n| n.attr("jid").map(|s| s.to_string()))
                            .collect(),
                        _ => vec![],
                    },
                    None => vec![],
                }
            }
            _ => vec![],
        };
        Ok(jids)
    }

    /// Block a contact JID.
    pub async fn block_contact(&self, jid: &str) -> Result<()> {
        self.update_block_status(jid, "block").await
    }

    /// Unblock a contact JID.
    pub async fn unblock_contact(&self, jid: &str) -> Result<()> {
        self.update_block_status(jid, "unblock").await
    }

    async fn update_block_status(&self, jid: &str, action: &str) -> Result<()> {
        let id = self.socket.next_id();
        let node = BinaryNode {
            tag: "iq".to_string(),
            attrs: vec![
                ("id".to_string(), id),
                ("xmlns".to_string(), "blocklist".to_string()),
                ("to".to_string(), "s.whatsapp.net".to_string()),
                ("type".to_string(), "set".to_string()),
            ],
            content: NodeContent::List(vec![BinaryNode {
                tag: "item".to_string(),
                attrs: vec![
                    ("action".to_string(), action.to_string()),
                    ("jid".to_string(), jid.to_string()),
                ],
                content: NodeContent::None,
            }]),
        };
        self.socket.send_iq_await(node).await?;
        Ok(())
    }

    pub async fn send_receipt(
        &self,
        jid: &str,
        ids: &[String],
        receipt: ReceiptType,
    ) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let extra = if ids.len() > 1 {
            NodeContent::List(
                ids[1..]
                    .iter()
                    .map(|id| BinaryNode {
                        tag: "item".to_string(),
                        attrs: vec![("id".to_string(), id.clone())],
                        content: NodeContent::None,
                    })
                    .collect(),
            )
        } else {
            NodeContent::None
        };
        // WA convention: delivery receipts have NO `type` attribute;
        // any other receipt flavour does.
        let mut attrs = vec![
            ("id".to_string(), ids[0].clone()),
            ("to".to_string(), jid.to_string()),
        ];
        if !matches!(receipt, ReceiptType::Delivered) {
            attrs.push(("type".to_string(), receipt.as_str().to_string()));
        }
        let node = BinaryNode {
            tag: "receipt".to_string(),
            attrs,
            content: extra,
        };
        self.socket.send_node(&node).await
    }

    pub async fn read_messages(&self, keys: &[MessageKey]) -> Result<()> {
        let mut by_jid: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        for key in keys {
            by_jid
                .entry(key.remote_jid.clone())
                .or_default()
                .push(key.id.clone());
        }
        for (jid, ids) in by_jid {
            self.send_receipt(&jid, &ids, ReceiptType::Read).await?;
        }
        Ok(())
    }

    async fn send_message(
        &self,
        jid: &str,
        id: String,
        content: MessageContent,
    ) -> Result<()> {
        let msg = WAMessage {
            key: MessageKey {
                remote_jid: jid.to_string(),
                from_me: true,
                id: id.clone(),
                participant: None,
            },
            message: Some(content),
            message_timestamp: unix_now(),
            status: MessageStatus::Pending,
            push_name: None,
        };

        // Persist as Pending before touching the network so we can retry on reconnect
        self.msg_store.push(&msg);
        self.outbox.push(jid, &msg);

        let wa_bytes = self.encode_content(&msg)?;
        match self.send_encrypted_bytes(jid, &id, wa_bytes).await {
            Ok(()) => {
                // Socket write succeeded; remove from outbox and advance status to Sent
                self.outbox.remove(&id);
                self.msg_store.update_status(jid, &id, MessageStatus::Sent);
                let _ = self.event_tx.send(MessageEvent::MessageUpdate {
                    key: msg.key,
                    status: MessageStatus::Sent,
                });
                Ok(())
            }
            Err(e) => Err(e), // stays in outbox → retried on next reconnect
        }
    }

    /// Retry a single outbox entry (re-encodes + re-encrypts with fresh ratchet step).
    /// Called from the reconnect loop for every entry still in the outbox.
    pub(crate) async fn retry_outbox_entry(&self, jid: &str, msg: WAMessage) {
        let id = msg.key.id.clone();
        let wa_bytes = match self.encode_content(&msg) {
            Ok(b) => b,
            Err(e) => { tracing::warn!("retry encode failed for {id}: {e}"); return; }
        };
        match self.send_encrypted_bytes(jid, &id, wa_bytes).await {
            Ok(()) => {
                self.outbox.remove(&id);
                self.msg_store.update_status(jid, &id, MessageStatus::Sent);
                let _ = self.event_tx.send(MessageEvent::MessageUpdate {
                    key: msg.key,
                    status: MessageStatus::Sent,
                });
                tracing::info!("retried {id} → Sent");
            }
            Err(e) => tracing::warn!("retry send failed for {id}: {e}"),
        }
    }

    /// Encode any MessageContent variant to WAProto bytes.
    /// Side-effects: registers poll enc_key in PollStore when encoding a Poll.
    fn encode_content(&self, msg: &WAMessage) -> Result<Vec<u8>> {
        use crate::signal::wa_proto::{
            encode_wa_audio_message, encode_wa_document_message, encode_wa_image_message,
            encode_wa_link_preview_message, encode_wa_reaction_message, encode_wa_reply_message,
            encode_wa_sticker_message, encode_wa_text_message, encode_wa_video_message,
        };
        let bytes = match &msg.message {
            Some(MessageContent::Text { text, mentioned_jids }) => {
                if mentioned_jids.is_empty() {
                    encode_wa_text_message(text)
                } else {
                    let refs: Vec<&str> = mentioned_jids.iter().map(String::as_str).collect();
                    crate::signal::wa_proto::encode_wa_text_with_mentions(text, &refs)
                }
            }
            Some(MessageContent::Reply { reply_to_id, text }) =>
                encode_wa_reply_message(text, reply_to_id, msg.key.participant.as_deref()),
            Some(MessageContent::Image { info, caption }) =>
                encode_wa_image_message(info, caption.as_deref()),
            Some(MessageContent::Video { info, caption }) =>
                encode_wa_video_message(info, caption.as_deref()),
            Some(MessageContent::Audio { info }) => encode_wa_audio_message(info),
            Some(MessageContent::Document { info, file_name }) =>
                encode_wa_document_message(info, file_name),
            Some(MessageContent::Sticker { info }) => encode_wa_sticker_message(info),
            Some(MessageContent::Reaction { target_id, emoji }) =>
                encode_wa_reaction_message(&msg.key.remote_jid, target_id, emoji),
            Some(MessageContent::Poll { question, options, selectable_count }) => {
                let opts: Vec<&str> = options.iter().map(|s| s.as_str()).collect();
                let (bytes, enc_key) = crate::signal::wa_proto::encode_wa_poll_message(
                    question, &opts, *selectable_count,
                );
                self.poll_store.register(&msg.key.id, enc_key.to_vec(), question, options);
                bytes
            }
            Some(MessageContent::LinkPreview { text, url, title, description, thumbnail_jpeg }) =>
                encode_wa_link_preview_message(text, url, title, description, thumbnail_jpeg.as_deref()),
            None => anyhow::bail!("send_message called with no content"),
        };
        Ok(bytes)
    }

    /// Encrypt `wa_bytes` and send to `jid` — automatically routes 1:1 vs group.
    ///
    /// Groups (`@g.us`): fetches participants, distributes SenderKey, encrypts as skmsg.
    /// 1:1: establishes Signal session if needed, encrypts as msg/pkmsg.
    async fn send_encrypted_bytes(&self, jid: &str, id: &str, wa_bytes: Vec<u8>) -> Result<()> {
        // Do NOT pad `wa_bytes` here — padding must be applied to the
        // *outermost* Message bytes handed to encrypt. For DSM (own-device
        // copy) the outer Message is `deviceSentMessage{destinationJid,message}`
        // with an UNPADDED inner. Helper `pad_wa` does per-target padding
        // right before `signal.encrypt_message`.
        let (message_content, any_pkmsg) = if jid.ends_with("@g.us") {
            let participants =
                crate::socket::group::fetch_group_participants(&self.socket, jid).await?;
            self.distribute_sender_key(jid, &participants).await?;
            let skmsg = self.signal.encrypt_group_message(jid, &pad_wa(&wa_bytes)).await?;
            let enc_child = BinaryNode {
                tag: "enc".to_string(),
                attrs: vec![
                    ("v".to_string(), "2".to_string()),
                    ("type".to_string(), "skmsg".to_string()),
                ],
                content: NodeContent::Bytes(skmsg),
            };
            (NodeContent::List(vec![enc_child]), false)
        } else {
            // 1:1 flow — send to recipient's devices AND our own other
            // devices so the message also shows up as "sent" in our phone
            // (DeviceSentMessage).
            let our_user_jid = bare_user_jid(&self.our_jid);
            let our_device_jid = self.our_jid.clone();

            let cache = crate::device_cache::DeviceCache::new(std::path::Path::new("."));

            // Recipient devices (cached)
            let recipient_devs = if let Some(d) = cache.get(jid) { d } else {
                match crate::socket::usync::get_user_devices(&self.socket, &[jid]).await {
                    Ok(d) if !d.is_empty() => { cache.put(jid, &d); d }
                    _ => vec![ensure_device(jid)],
                }
            };
            // Our own devices (cached, minus the one we're running on)
            let own_devs = if let Some(d) = cache.get(&our_user_jid) { d } else {
                match crate::socket::usync::get_user_devices(&self.socket, &[&our_user_jid]).await {
                    Ok(d) if !d.is_empty() => { cache.put(&our_user_jid, &d); d }
                    _ => vec![],
                }
            };
            let own_other_devs: Vec<String> = own_devs
                .into_iter()
                .filter(|d| d != &our_device_jid)
                .collect();

            tracing::info!(
                "→ send 1:1 to={} other_devs={:?} own_devs={:?}",
                jid, recipient_devs, own_other_devs,
            );

            // DSM-wrapped plaintext for our own other devices. Note we wrap
            // the UNPADDED `wa_bytes` and apply padding to the outer DSM
            // bytes below, mirroring Baileys' `encodeWAMessage(dsmMessage)`.
            let dsm_bytes = wrap_device_sent_message(jid, &wa_bytes);

            let mut to_nodes: Vec<BinaryNode> = Vec::new();
            let mut any_pkmsg = false;

            // Each target gets the same outermost Message padded fresh per
            // encrypt to match the peer's `unpadRandomMax16` trim.
            for (dev_jid, plaintext) in recipient_devs.iter().map(|d| (d.clone(), pad_wa(&wa_bytes)))
                .chain(own_other_devs.iter().map(|d| (d.clone(), pad_wa(&dsm_bytes))))
            {
                if !self.signal.has_session(&dev_jid) {
                    match crate::socket::prekey::fetch_pre_key_bundle(&self.socket, &dev_jid).await {
                        Ok(bundle) => {
                            if let Err(e) = self.signal.create_sender_session(&dev_jid, &bundle) {
                                tracing::warn!("create_sender_session {dev_jid}: {e}");
                                continue;
                            }
                        }
                        Err(e) => {
                            tracing::warn!("fetch_pre_key_bundle {dev_jid}: {e}");
                            continue;
                        }
                    }
                }
                let enc = match self.signal.encrypt_message(&dev_jid, &plaintext).await {
                    Ok(e) => e,
                    Err(e) => { tracing::warn!("encrypt {dev_jid}: {e}"); continue; }
                };
                if enc.msg_type == "pkmsg" { any_pkmsg = true; }
                to_nodes.push(BinaryNode {
                    tag: "to".to_string(),
                    attrs: vec![("jid".to_string(), dev_jid)],
                    content: NodeContent::List(vec![BinaryNode {
                        tag: "enc".to_string(),
                        attrs: vec![
                            ("v".to_string(), "2".to_string()),
                            ("type".to_string(), enc.msg_type.to_string()),
                        ],
                        content: NodeContent::Bytes(enc.ciphertext),
                    }]),
                });
            }

            if to_nodes.is_empty() {
                anyhow::bail!("no devices available for {jid}");
            }

            let mut children = vec![BinaryNode {
                tag: "participants".to_string(),
                attrs: vec![],
                content: NodeContent::List(to_nodes),
            }];
            if any_pkmsg {
                let account_id = self.signal.account_identity_bytes().to_vec();
                if !account_id.is_empty() {
                    children.push(BinaryNode {
                        tag: "device-identity".to_string(),
                        attrs: vec![],
                        content: NodeContent::Bytes(account_id),
                    });
                }
            }
            (NodeContent::List(children), any_pkmsg)
        };

        let is_pkmsg = any_pkmsg;

        let stanza = BinaryNode {
            tag: "message".to_string(),
            attrs: vec![
                ("to".to_string(), jid.to_string()),
                ("id".to_string(), id.to_string()),
                ("type".to_string(), "text".to_string()),
                ("t".to_string(), unix_now().to_string()),
            ],
            content: message_content,
        };
        tracing::info!(
            "→ send message id={} to={} pkmsg={} children={}",
            id, jid, is_pkmsg,
            match &stanza.content {
                NodeContent::List(c) => c.iter().map(|n| n.tag.as_str()).collect::<Vec<_>>().join(","),
                _ => String::new(),
            },
        );
        self.socket.send_node(&stanza).await
    }

    /// Encrypt and upload media, returning a filled-in `MediaInfo`.
    pub async fn upload_media(
        &self,
        plaintext: &[u8],
        media_type: crate::media::MediaType,
        mimetype: &str,
    ) -> Result<crate::messages::MediaInfo> {
        use crate::media::{encrypt_media_blob};
        use crate::socket::media_upload::{request_upload_url, upload_to_cdn};

        let (blob, media_key, enc_sha256, sha256) = encrypt_media_blob(plaintext, media_type)?;
        let size = blob.len() as u64;
        let up = request_upload_url(&self.socket, &enc_sha256, media_type, size).await?;
        upload_to_cdn(&up.url, &blob).await?;

        Ok(crate::messages::MediaInfo {
            url: up.url,
            direct_path: up.direct_path,
            media_key,
            file_enc_sha256: enc_sha256,
            file_sha256: sha256,
            file_length: size,
            mimetype: mimetype.to_string(),
        })
    }

    pub async fn send_image(&self, jid: &str, data: &[u8], caption: Option<&str>) -> Result<String> {
        let info = self.upload_media(data, crate::media::MediaType::Image, "image/jpeg").await?;
        let id = generate_message_id();
        self.send_message(jid, id.clone(), MessageContent::Image {
            info,
            caption: caption.map(|s| s.to_string()),
        }).await?;
        Ok(id)
    }

    pub async fn send_video(&self, jid: &str, data: &[u8], caption: Option<&str>) -> Result<String> {
        let info = self.upload_media(data, crate::media::MediaType::Video, "video/mp4").await?;
        let id = generate_message_id();
        self.send_message(jid, id.clone(), MessageContent::Video {
            info,
            caption: caption.map(|s| s.to_string()),
        }).await?;
        Ok(id)
    }

    pub async fn send_audio(&self, jid: &str, data: &[u8], mimetype: &str) -> Result<String> {
        let info = self.upload_media(data, crate::media::MediaType::Audio, mimetype).await?;
        let id = generate_message_id();
        self.send_message(jid, id.clone(), MessageContent::Audio { info }).await?;
        Ok(id)
    }

    pub async fn send_document(
        &self,
        jid: &str,
        data: &[u8],
        mimetype: &str,
        file_name: &str,
    ) -> Result<String> {
        let info = self.upload_media(data, crate::media::MediaType::Document, mimetype).await?;
        let id = generate_message_id();
        self.send_message(jid, id.clone(), MessageContent::Document {
            info,
            file_name: file_name.to_string(),
        }).await?;
        Ok(id)
    }

    /// Post a text status update (WhatsApp Stories equivalent).
    pub async fn send_status_text(&self, text: &str) -> Result<String> {
        let wa_bytes = crate::signal::wa_proto::encode_wa_text_message(text);
        self.send_status_bytes(wa_bytes).await
    }

    /// Post an image status update (WhatsApp Stories).
    pub async fn send_status_image(&self, data: &[u8], caption: Option<&str>) -> Result<String> {
        let info = self.upload_media(data, crate::media::MediaType::Image, "image/jpeg").await?;
        let wa_bytes = crate::signal::wa_proto::encode_wa_image_message(&info, caption);
        self.send_status_bytes(wa_bytes).await
    }

    /// Post a video status update (WhatsApp Stories).
    pub async fn send_status_video(&self, data: &[u8], caption: Option<&str>) -> Result<String> {
        let info = self.upload_media(data, crate::media::MediaType::Video, "video/mp4").await?;
        let wa_bytes = crate::signal::wa_proto::encode_wa_video_message(&info, caption);
        self.send_status_bytes(wa_bytes).await
    }

    /// Core: encrypt wa_bytes as skmsg and send to status@broadcast.
    async fn send_status_bytes(&self, wa_bytes: Vec<u8>) -> Result<String> {
        const STATUS_JID: &str = "status@broadcast";

        let contacts: Vec<String> = self.contacts.snapshot().into_keys().collect();
        self.distribute_sender_key(STATUS_JID, &contacts).await?;

        let skmsg = self.signal.encrypt_group_message(STATUS_JID, &wa_bytes).await?;
        let id = generate_message_id();

        let to_nodes: Vec<BinaryNode> = contacts
            .iter()
            .map(|jid| BinaryNode {
                tag: "to".to_string(),
                attrs: vec![("jid".to_string(), jid.to_string())],
                content: NodeContent::None,
            })
            .collect();

        let mut content_nodes = vec![BinaryNode {
            tag: "enc".to_string(),
            attrs: vec![
                ("v".to_string(), "2".to_string()),
                ("type".to_string(), "skmsg".to_string()),
            ],
            content: NodeContent::Bytes(skmsg),
        }];
        content_nodes.extend(to_nodes);

        self.socket.send_node(&BinaryNode {
            tag: "message".to_string(),
            attrs: vec![
                ("to".to_string(), STATUS_JID.to_string()),
                ("id".to_string(), id.clone()),
                ("type".to_string(), "text".to_string()),
                ("t".to_string(), unix_now().to_string()),
            ],
            content: NodeContent::List(content_nodes),
        }).await?;
        Ok(id)
    }

    /// Send a text message to a group. Uses the SenderKey path automatically.
    pub async fn send_group_text(&self, group_jid: &str, text: &str) -> Result<String> {
        self.send_text(group_jid, text).await
    }

    /// Send our SenderKey to any participant who hasn't received it yet.
    async fn distribute_sender_key(&self, group_jid: &str, participants: &[String]) -> Result<()> {
        let skdm_proto = self.signal.get_skdm_proto(group_jid);

        for jid in participants {
            // Skip ourselves and those already distributed to
            if jid == &self.our_jid || self.signal.is_skdm_distributed(group_jid, jid) {
                continue;
            }
            // Ensure 1:1 Signal session exists
            if !self.signal.has_session(jid) {
                match crate::socket::prekey::fetch_pre_key_bundle(&self.socket, jid).await {
                    Ok(bundle) => {
                        if let Err(e) = self.signal.create_sender_session(jid, &bundle) {
                            tracing::warn!("SKDM: session for {jid} failed: {e}");
                            continue;
                        }
                    }
                    Err(e) => {
                        tracing::warn!("SKDM: pre-keys for {jid} failed: {e}");
                        continue;
                    }
                }
            }
            // Signal-encrypt the SKDM proto and send as a 1:1 message
            match self.signal.encrypt_message(jid, &skdm_proto).await {
                Ok(enc) => {
                    let id = generate_message_id();
                    let node = BinaryNode {
                        tag: "message".to_string(),
                        attrs: vec![
                            ("to".to_string(), jid.to_string()),
                            ("id".to_string(), id),
                            ("type".to_string(), "text".to_string()),
                            ("t".to_string(), unix_now().to_string()),
                        ],
                        content: NodeContent::List(vec![BinaryNode {
                            tag: "enc".to_string(),
                            attrs: vec![
                                ("v".to_string(), "2".to_string()),
                                ("type".to_string(), enc.msg_type.to_string()),
                            ],
                            content: NodeContent::Bytes(enc.ciphertext),
                        }]),
                    };
                    if let Err(e) = self.socket.send_node(&node).await {
                        tracing::warn!("SKDM send to {jid} failed: {e}");
                        continue;
                    }
                    self.signal.mark_skdm_distributed(group_jid, jid);
                }
                Err(e) => tracing::warn!("SKDM encrypt for {jid} failed: {e}"),
            }
        }
        Ok(())
    }

    /// Send a text message with a link preview card.
    /// The caller is responsible for fetching OG metadata (title, description, thumbnail).
    pub async fn send_link_preview(
        &self,
        jid: &str,
        text: &str,
        url: &str,
        title: &str,
        description: &str,
        thumbnail_jpeg: Option<Vec<u8>>,
    ) -> Result<String> {
        let id = generate_message_id();
        self.send_message(jid, id.clone(), MessageContent::LinkPreview {
            text: text.to_string(),
            url: url.to_string(),
            title: title.to_string(),
            description: description.to_string(),
            thumbnail_jpeg,
        }).await?;
        Ok(id)
    }

    /// Send a poll to a 1:1 or group JID.
    /// `selectable_count` = max options a voter can pick (0 = unlimited).
    pub async fn send_poll(
        &self,
        jid: &str,
        question: &str,
        options: &[&str],
        selectable_count: u32,
    ) -> Result<String> {
        let id = generate_message_id();
        self.send_message(jid, id.clone(), MessageContent::Poll {
            question: question.to_string(),
            options: options.iter().map(|s| s.to_string()).collect(),
            selectable_count,
        }).await?;
        Ok(id)
    }

    /// Delete (revoke) a message we sent.
    pub async fn send_revoke(&self, jid: &str, msg_id: &str) -> Result<()> {
        let wa_bytes = crate::signal::wa_proto::encode_wa_revoke_message(jid, msg_id, true);
        self.send_encrypted_bytes(jid, &generate_message_id(), wa_bytes).await
    }

    /// Edit a message we sent.
    pub async fn send_edit(&self, jid: &str, msg_id: &str, new_text: &str) -> Result<()> {
        let wa_bytes = crate::signal::wa_proto::encode_wa_edit_message(jid, msg_id, new_text);
        self.send_encrypted_bytes(jid, &generate_message_id(), wa_bytes).await
    }

    /// Vote on a poll (`selected_options` empty = deselect all).
    pub async fn send_poll_vote(
        &self,
        jid: &str,
        poll_msg_id: &str,
        selected_options: &[&str],
    ) -> Result<()> {
        let enc_key = self.poll_store.enc_key(poll_msg_id)
            .ok_or_else(|| anyhow::anyhow!("poll {poll_msg_id} not found in store"))?;
        let wa_bytes = crate::signal::wa_proto::encode_wa_poll_vote(
            poll_msg_id, jid, &enc_key, &self.our_jid, selected_options,
        );
        self.send_encrypted_bytes(jid, &generate_message_id(), wa_bytes).await
    }

    pub async fn send_sticker(&self, jid: &str, data: &[u8]) -> Result<String> {
        let info = self.upload_media(data, crate::media::MediaType::Sticker, "image/webp").await?;
        let id = generate_message_id();
        self.send_message(jid, id.clone(), MessageContent::Sticker { info }).await?;
        Ok(id)
    }

    // ── Forward ───────────────────────────────────────────────────────────────

    /// Forward a stored message to a new JID.
    /// Looks up the message in the local store; fails if not found.
    pub async fn forward_message(
        &self,
        to_jid: &str,
        from_jid: &str,
        msg_id: &str,
    ) -> Result<String> {
        use crate::signal::wa_proto::{
            encode_wa_forward_audio, encode_wa_forward_document,
            encode_wa_forward_image, encode_wa_forward_text, encode_wa_forward_video,
        };

        let stored = self.msg_store.lookup(from_jid, msg_id)
            .ok_or_else(|| anyhow::anyhow!("message {msg_id} not found in {from_jid}"))?;

        // Re-download media if needed, then re-upload to get fresh CDN URLs
        let wa_bytes = match (&stored.text, &stored.media_type, &stored.media_info) {
            (Some(text), _, _) => encode_wa_forward_text(text),
            (_, Some(mt), Some(info)) if mt.starts_with("image") => {
                let data = crate::media::download_media(
                    &info.url, &info.media_key, crate::media::MediaType::Image,
                ).await?;
                let new_info = self.upload_media(&data, crate::media::MediaType::Image, &info.mimetype).await?;
                encode_wa_forward_image(&new_info, None)
            }
            (_, Some(mt), Some(info)) if mt.starts_with("video") => {
                let data = crate::media::download_media(
                    &info.url, &info.media_key, crate::media::MediaType::Video,
                ).await?;
                let new_info = self.upload_media(&data, crate::media::MediaType::Video, &info.mimetype).await?;
                encode_wa_forward_video(&new_info, None)
            }
            (_, Some(mt), Some(info)) if mt.starts_with("audio") => {
                let data = crate::media::download_media(
                    &info.url, &info.media_key, crate::media::MediaType::Audio,
                ).await?;
                let new_info = self.upload_media(&data, crate::media::MediaType::Audio, &info.mimetype).await?;
                encode_wa_forward_audio(&new_info)
            }
            (_, Some(mt), Some(info)) if mt.starts_with("document") => {
                let file_name = msg_id;
                let data = crate::media::download_media(
                    &info.url, &info.media_key, crate::media::MediaType::Document,
                ).await?;
                let new_info = self.upload_media(&data, crate::media::MediaType::Document, &info.mimetype).await?;
                encode_wa_forward_document(&new_info, file_name)
            }
            _ => anyhow::bail!("message {msg_id} has no forwardable content"),
        };

        let id = generate_message_id();
        self.send_encrypted_bytes(to_jid, &id, wa_bytes).await?;
        Ok(id)
    }

    // ── Ephemeral ─────────────────────────────────────────────────────────────

    /// Set the ephemeral (disappearing) message timer for a chat.
    ///
    /// `expiration_secs`: 0 = off, 86400 = 24h, 604800 = 7d, 7776000 = 90d.
    ///
    /// For groups, sends an IQ to the group. For 1:1 chats, sends a ProtocolMessage.
    pub async fn set_ephemeral_duration(&self, jid: &str, expiration_secs: u32) -> Result<()> {
        if jid.ends_with("@g.us") {
            // Group: use IQ
            let id = self.socket.next_id();
            self.socket.send_iq_await(crate::binary::BinaryNode {
                tag: "iq".to_string(),
                attrs: vec![
                    ("id".to_string(), id),
                    ("type".to_string(), "set".to_string()),
                    ("xmlns".to_string(), "w:g2".to_string()),
                    ("to".to_string(), jid.to_string()),
                ],
                content: crate::binary::NodeContent::List(vec![crate::binary::BinaryNode {
                    tag: "ephemeral".to_string(),
                    attrs: vec![("period".to_string(), expiration_secs.to_string())],
                    content: crate::binary::NodeContent::None,
                }]),
            }).await?;
        } else {
            // 1:1: send ProtocolMessage
            let wa_bytes = crate::signal::wa_proto::encode_wa_ephemeral_setting(expiration_secs);
            let id = generate_message_id();
            self.send_encrypted_bytes(jid, &id, wa_bytes).await?;
        }
        Ok(())
    }

    /// Download and decrypt media referenced by a received message.
    pub async fn download_media(
        &self,
        info: &crate::messages::MediaInfo,
        media_type: crate::media::MediaType,
    ) -> Result<Vec<u8>> {
        crate::media::download_media(&info.url, &info.media_key, media_type).await
    }

    /// Fetch full group info (name, description, participants).
    pub async fn group_info(
        &self,
        group_jid: &str,
    ) -> Result<crate::socket::group::GroupInfo> {
        crate::socket::group::fetch_group_info(&self.socket, group_jid).await
    }

    /// Check whether phone numbers are registered on WhatsApp.
    /// `phones` — E.164 digits without '+', e.g. `["5491112345678"]`.
    pub async fn on_whatsapp(
        &self,
        phones: &[&str],
    ) -> Result<Vec<crate::socket::usync::ContactInfo>> {
        crate::socket::usync::on_whatsapp(&self.socket, phones).await
    }

    /// Resolve JIDs to ContactInfo (on_whatsapp + status text).
    pub async fn resolve_contacts(
        &self,
        jids: &[&str],
    ) -> Result<std::collections::HashMap<String, crate::socket::usync::ContactInfo>> {
        crate::socket::usync::resolve_contacts(&self.socket, jids).await
    }

    /// Fetch the status text for a list of JIDs.
    pub async fn fetch_status(
        &self,
        jids: &[&str],
    ) -> Result<std::collections::HashMap<String, String>> {
        crate::socket::usync::fetch_status(&self.socket, jids).await
    }

    // ── Group management ──────────────────────────────────────────────────────

    pub async fn create_group(
        &self,
        subject: &str,
        participant_jids: &[&str],
    ) -> Result<crate::socket::group::GroupInfo> {
        crate::socket::group::create_group(&self.socket, subject, participant_jids).await
    }

    pub async fn add_participants(
        &self,
        group_jid: &str,
        jids: &[&str],
    ) -> Result<Vec<crate::socket::group::ParticipantResult>> {
        crate::socket::group::add_participants(&self.socket, group_jid, jids).await
    }

    pub async fn remove_participants(
        &self,
        group_jid: &str,
        jids: &[&str],
    ) -> Result<Vec<crate::socket::group::ParticipantResult>> {
        crate::socket::group::remove_participants(&self.socket, group_jid, jids).await
    }

    pub async fn promote_to_admin(
        &self,
        group_jid: &str,
        jids: &[&str],
    ) -> Result<Vec<crate::socket::group::ParticipantResult>> {
        crate::socket::group::promote_to_admin(&self.socket, group_jid, jids).await
    }

    pub async fn demote_from_admin(
        &self,
        group_jid: &str,
        jids: &[&str],
    ) -> Result<Vec<crate::socket::group::ParticipantResult>> {
        crate::socket::group::demote_from_admin(&self.socket, group_jid, jids).await
    }

    pub async fn leave_group(&self, group_jid: &str) -> Result<()> {
        crate::socket::group::leave_group(&self.socket, group_jid).await
    }

    pub async fn set_group_subject(&self, group_jid: &str, subject: &str) -> Result<()> {
        crate::socket::group::set_group_subject(&self.socket, group_jid, subject).await
    }

    pub async fn set_group_description(&self, group_jid: &str, description: &str) -> Result<()> {
        crate::socket::group::set_group_description(&self.socket, group_jid, description).await
    }

    pub async fn subscribe_group_presence(&self, group_jid: &str) -> Result<()> {
        crate::socket::group::subscribe_group_presence(&self.socket, group_jid).await
    }

    // ── Profile pictures ──────────────────────────────────────────────────────

    pub async fn get_profile_picture(
        &self,
        jid: &str,
        high_res: bool,
    ) -> Result<Option<String>> {
        crate::socket::group::get_profile_picture(&self.socket, jid, high_res).await
    }

    pub async fn set_profile_picture(&self, jpeg_data: &[u8]) -> Result<()> {
        crate::socket::group::set_profile_picture(&self.socket, &self.our_jid, jpeg_data).await
    }

}
