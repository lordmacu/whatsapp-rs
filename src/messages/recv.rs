use crate::binary::{BinaryNode, NodeContent};
use crate::messages::{
    unix_now, ChatInfo, MessageContent, MessageEvent, MessageKey, MessageManager, MessageStatus,
    PushName, ReceiptType, WAMessage,
};
use anyhow::Result;
use tracing::debug;

/// Extract the server's remaining OTK count from an encrypt-namespaced IQ node.
/// Returns `Some(count)` if the node is an encrypt IQ with a `<count>` child,
/// or `None` if the node doesn't contain this information.
pub fn extract_encrypt_count(node: &BinaryNode) -> Option<u32> {
    if node.tag != "iq" {
        return None;
    }
    if node.attr("xmlns") != Some("encrypt") {
        return None;
    }
    let NodeContent::List(children) = &node.content else {
        return None;
    };
    let count_node = children.iter().find(|n| n.tag == "count")?;
    match &count_node.content {
        NodeContent::Text(s) => s.parse().ok(),
        NodeContent::Bytes(b) => String::from_utf8(b.clone()).ok()?.parse().ok(),
        _ => None,
    }
}

impl MessageManager {
    pub async fn handle_node(&self, node: &BinaryNode) -> Result<()> {
        match node.tag.as_str() {
            "message" => self.handle_message(node).await,
            "receipt" => self.handle_receipt(node).await,
            "ack"     => self.handle_server_ack(node).await,
            "notification" => self.handle_notification(node).await,
            "iq" => self.handle_iq(node).await,
            "presence" => self.handle_presence(node).await,
            "chatstate" => self.handle_chatstate(node).await,
            "ib" => self.handle_ib(node).await,
            "failure" | "stream:failure" => { self.handle_stream_failure(node); Ok(()) }
            _ => Ok(()),
        }
    }

    /// Handle `<ib>` (info broadcast) server-push nodes. The important one is
    /// `<offline_preview>` — the server is telling us how many offline events
    /// it has queued and asking how big a batch to deliver. Without our reply
    /// it keeps the queue frozen and never switches to live fan-out.
    async fn handle_ib(&self, node: &BinaryNode) -> Result<()> {
        let children: Vec<&BinaryNode> = if let NodeContent::List(v) = &node.content {
            v.iter().collect()
        } else { Vec::new() };

        for child in &children {
            match child.tag.as_str() {
                "offline_preview" => {
                    debug!("ib offline_preview → requesting offline_batch");
                    let reply = BinaryNode {
                        tag: "ib".into(),
                        attrs: vec![],
                        content: NodeContent::List(vec![BinaryNode {
                            tag: "offline_batch".into(),
                            attrs: vec![("count".into(), "100".into())],
                            content: NodeContent::None,
                        }]),
                    };
                    let _ = self.socket.send_node(&reply).await;
                }
                "offline" => {
                    let count = child.attr("count").unwrap_or("?");
                    debug!("ib offline drain complete (count={count}) — live fan-out should start");
                }
                "edge_routing" | "downgrade_webclient" | "dirty" => {
                    // telemetry/notice — ignore
                }
                other => {
                    debug!("ib unknown child: {other}");
                }
            }
        }
        Ok(())
    }

    /// Decrypt a group SenderKey message.
    async fn decrypt_skmsg(
        &self,
        group_jid: &str,
        sender_jid: &str,
        enc_bytes: &[u8],
    ) -> Option<DecodedPayload> {
        use crate::signal::wa_proto::decode_skmsg_header;
        let hdr = decode_skmsg_header(enc_bytes)?;
        match self.signal.decrypt_sender_key_message(sender_jid, group_jid, hdr.iteration, &hdr.ciphertext).await {
            Ok(plaintext) => Some(decode_plaintext(&plaintext)),
            Err(e) => {
                debug!("skmsg decrypt failed from {sender_jid} in {group_jid}: {e}");
                Some(DecodedPayload::Message(MessageContent::Text {
                    text: "<skmsg decrypt failed>".to_string(),
                    mentioned_jids: Vec::new(),
                }))
            }
        }
    }

    /// Check decrypted WAProto bytes for an embedded SKDM and process it.
    fn maybe_process_skdm(&self, sender_jid: &str, plaintext: &[u8]) {
        use crate::signal::wa_proto::{decode_axolotl_skdm, decode_wa_skdm};
        if let Some((group_jid, axolotl_bytes)) = decode_wa_skdm(plaintext) {
            if let Some(skdm) = decode_axolotl_skdm(&axolotl_bytes) {
                if skdm.chain_key.len() == 32 {
                    let mut ck = [0u8; 32];
                    ck.copy_from_slice(&skdm.chain_key);
                    self.signal.process_sender_key_distribution(
                        sender_jid,
                        &group_jid,
                        skdm.iteration,
                        ck,
                    );
                    debug!("stored SKDM from {sender_jid} for group {group_jid}");
                }
            }
        }
    }

    async fn handle_iq(&self, node: &BinaryNode) -> Result<()> {
        if node.attr("type") != Some("get") {
            return Ok(());
        }
        let is_ping = matches!(&node.content, NodeContent::List(ch) if ch.iter().any(|n| n.tag == "ping"));
        if is_ping {
            if let (Some(id), Some(from)) = (node.attr("id"), node.attr("from")) {
                self.socket.send_iq_result(id, from).await?;
            }
        }
        Ok(())
    }

    async fn handle_presence(&self, node: &BinaryNode) -> Result<()> {
        let jid = node.attr("from").unwrap_or("").to_string();
        let available = node.attr("type").map_or(true, |t| t == "available");
        let _ = self.event_tx.send(MessageEvent::Presence { jid, available });
        Ok(())
    }

    async fn handle_chatstate(&self, node: &BinaryNode) -> Result<()> {
        let jid = node.attr("from").unwrap_or("").to_string();
        let composing = matches!(&node.content,
            NodeContent::List(ch) if ch.iter().any(|n| n.tag == "composing"));
        let _ = self.event_tx.send(MessageEvent::Typing { jid, composing });
        Ok(())
    }

    /// Handle `<failure>` / `<stream:failure>` — the server is terminating the session.
    ///
    /// Non-retriable reasons (device_removed, logged_out, account_deleted, conflict) set
    /// `reconnect = false`; transient errors (service_unavailable, etc.) set `reconnect = true`.
    fn handle_stream_failure(&self, node: &BinaryNode) {
        // Reason can be in the `reason` attribute or as the tag of the first child node
        let reason = node.attr("reason")
            .map(|s| s.to_string())
            .or_else(|| match &node.content {
                NodeContent::List(ch) => ch.first().map(|c| c.tag.clone()),
                _ => None,
            })
            .unwrap_or_else(|| "unknown".to_string());

        let permanent = matches!(
            reason.as_str(),
            "device_removed" | "logged_out" | "account_deleted"
                | "conflict" | "replaced" | "disabled"
        );

        tracing::warn!("stream failure: reason={reason} reconnect={}", !permanent);
        let _ = self.event_tx.send(MessageEvent::Disconnected {
            reason,
            reconnect: !permanent,
        });
    }

    async fn handle_message(&self, node: &BinaryNode) -> Result<()> {
        let from = node.attr("from").unwrap_or("").to_string();
        let id = node.attr("id").unwrap_or("").to_string();
        let participant = node.attr("participant").map(|s| s.to_string());
        let push_name = node.attr("notify").map(|s| s.to_string());
        let t: u64 = node.attr("t").and_then(|s| s.parse().ok()).unwrap_or_else(unix_now);

        // Ack immediately so the server doesn't redeliver on reconnect.
        // Baileys always ACKs every incoming <message>; a delivery <receipt>
        // is a separate signal to the sender and not a substitute for this.
        self.send_message_ack(node).await;

        // For group messages, Signal session is keyed on the sender (participant),
        // not the group JID.
        let decrypt_jid = if from.ends_with("@g.us") {
            participant.as_deref().unwrap_or(from.as_str()).to_string()
        } else {
            from.clone()
        };

        let key = MessageKey {
            remote_jid: from.clone(),
            from_me: false,
            id: id.clone(),
            participant: participant.clone(),
        };

        // Decrypt Signal-encrypted content if present
        let decoded = if let Some((enc_bytes, enc_type)) = extract_enc(node) {
            match enc_type.as_str() {
                "skmsg" => {
                    // Group SenderKey message
                    self.decrypt_skmsg(&from, &decrypt_jid, &enc_bytes).await
                }
                _ => {
                    // 1:1 Signal message (msg / pkmsg)
                    match self.signal.decrypt_message(&decrypt_jid, &enc_bytes, &enc_type).await {
                        Ok(plaintext) => {
                            self.maybe_process_skdm(&decrypt_jid, &plaintext);
                            Some(decode_plaintext(&plaintext))
                        }
                        Err(e) => {
                            debug!("signal decrypt failed for {from}: {e}");
                            // Wipe the stale session so the sender's re-send
                            // (prompted by our retry receipt) is treated as a
                            // fresh pkmsg and creates a new session for us.
                            self.signal.drop_session(&decrypt_jid);
                            send_retry_receipt_fn(
                                &self.socket, node, &from, &id, t,
                                self.signal.registration_id(),
                                self.signal.identity_public(),
                                self.signal.signed_prekey_fields(),
                                self.signal.pick_unused_prekey(),
                                self.signal.account_identity_bytes(),
                            ).await;
                            Some(DecodedPayload::Message(MessageContent::Text {
                                text: "<decrypt failed>".to_string(),
                                mentioned_jids: Vec::new(),
                            }))
                        }
                    }
                }
            }
        } else {
            decode_message_content(node).map(DecodedPayload::Message)
        };

        // Cache the sender's display name
        if let Some(ref name) = push_name {
            let name_jid = participant.as_deref().unwrap_or(from.as_str());
            self.contacts.upsert(name_jid, name);
        }

        match decoded {
            Some(DecodedPayload::Reaction { target_id: _, emoji }) => {
                let _ = self.event_tx.send(MessageEvent::Reaction {
                    key,
                    emoji,
                    from_me: false,
                });
            }
            Some(DecodedPayload::Protocol(proto)) => {
                use crate::signal::wa_proto::ProtocolMessagePayload;
                match proto {
                    ProtocolMessagePayload::Revoke(rk) => {
                        let revoke_key = MessageKey {
                            remote_jid: rk.remote_jid,
                            from_me: rk.from_me,
                            id: rk.id,
                            participant: rk.participant,
                        };
                        let _ = self.event_tx.send(MessageEvent::MessageRevoke { key: revoke_key });
                    }
                    ProtocolMessagePayload::MessageEdit { key: rk, new_text } => {
                        let edit_key = MessageKey {
                            remote_jid: rk.remote_jid,
                            from_me: rk.from_me,
                            id: rk.id,
                            participant: rk.participant,
                        };
                        let _ = self.event_tx.send(MessageEvent::MessageEdit {
                            key: edit_key,
                            new_text,
                        });
                    }
                    ProtocolMessagePayload::EphemeralSetting { expiration_secs } => {
                        let _ = self.event_tx.send(MessageEvent::EphemeralSetting {
                            jid: from.clone(),
                            expiration_secs,
                        });
                    }
                    ProtocolMessagePayload::HistorySync(hsn) => {
                        let event_tx = self.event_tx.clone();
                        let contacts = self.contacts.clone();
                        let msg_store = self.msg_store.clone();
                        tokio::spawn(async move {
                            process_history_sync(hsn, event_tx, contacts, msg_store).await;
                        });
                    }
                    ProtocolMessagePayload::AppStateSyncKeyShare(shares) => {
                        if let Some(ks) = self.app_state_keys.as_ref() {
                            for (key_id, key_data, ts) in &shares {
                                ks.put(key_id, key_data.clone(), *ts);
                            }
                            debug!(
                                "stored {} app-state sync key(s) from {from}",
                                shares.len()
                            );
                            // Kick off a resync now that we can decrypt patches.
                            if let Some(sync) = self.app_state_sync.clone() {
                                tokio::spawn(async move {
                                    let _ = sync.resync(crate::app_state::ALL_COLLECTIONS, true).await;
                                });
                            }
                        } else {
                            debug!("received {} app-state key(s) but no store configured", shares.len());
                        }
                    }
                    ProtocolMessagePayload::Unknown(_) => {}
                }
            }
            Some(DecodedPayload::PollCreation { content, enc_key }) => {
                // Register the encKey so we can decrypt votes later
                if let MessageContent::Poll { ref question, ref options, .. } = content {
                    self.poll_store.register(&id, enc_key, question, options);
                }
                let msg = WAMessage {
                    key,
                    message: Some(content),
                    message_timestamp: t,
                    status: MessageStatus::Delivered,
                    push_name,
                };
                self.msg_store.push(&msg);
                let _ = self.event_tx.send(MessageEvent::NewMessage { msg });
            }
            Some(DecodedPayload::PollVoteRaw(info)) => {
                if let Some(enc_key) = self.poll_store.enc_key(&info.poll_msg_id) {
                    if let Some((_, options)) = self.poll_store.meta(&info.poll_msg_id) {
                        let voter_jid = participant.as_deref().unwrap_or(from.as_str());
                        let selected = crate::signal::wa_proto::decrypt_poll_vote(
                            &enc_key, voter_jid, &info.enc_payload, &info.enc_iv, &options,
                        );
                        let _ = self.event_tx.send(MessageEvent::PollVote {
                            voter_key: key,
                            poll_msg_id: info.poll_msg_id,
                            selected_options: selected,
                        });
                    }
                }
            }
            content => {
                let msg_content = content.and_then(|d| match d {
                    DecodedPayload::Message(c) => Some(c),
                    _ => None,
                });
                let msg = WAMessage {
                    key,
                    message: msg_content,
                    message_timestamp: t,
                    status: MessageStatus::Delivered,
                    push_name,
                };
                self.msg_store.push(&msg);
                let _ = self.event_tx.send(MessageEvent::NewMessage { msg });
            }
        }

        // Auto-send delivered receipt
        self.send_receipt(&from, &[id], ReceiptType::Delivered)
            .await?;

        Ok(())
    }

    /// Handle `<ack class="message">` from the WA server — confirms the server received our message.
    /// Advances the outgoing message status from Pending/Sent to Delivered.
    async fn handle_server_ack(&self, node: &BinaryNode) -> Result<()> {
        if node.attr("class") != Some("message") {
            return Ok(());
        }
        let id   = node.attr("id").unwrap_or("").to_string();
        let from = node.attr("from").unwrap_or("").to_string();
        if id.is_empty() { return Ok(()); }

        self.outbox.remove(&id);
        self.msg_store.update_status(&from, &id, MessageStatus::Delivered);
        self.msg_store.flush_dirty();

        let _ = self.event_tx.send(MessageEvent::MessageUpdate {
            key: MessageKey { remote_jid: from, from_me: true, id, participant: None },
            status: MessageStatus::Delivered,
        });
        Ok(())
    }

    async fn handle_receipt(&self, node: &BinaryNode) -> Result<()> {
        let id = node.attr("id").unwrap_or("").to_string();
        let from = node.attr("from").unwrap_or("").to_string();
        let receipt_type_str = node.attr("type").unwrap_or("delivered");

        let receipt_type = match receipt_type_str {
            "read" => ReceiptType::Read,
            "read-self" => ReceiptType::ReadSelf,
            "sender" => ReceiptType::Sender,
            _ => ReceiptType::Delivered,
        };

        let status = match receipt_type {
            ReceiptType::Read | ReceiptType::ReadSelf => MessageStatus::Read,
            _ => MessageStatus::Delivered,
        };

        let key = MessageKey {
            remote_jid: from,
            from_me: true,
            id: id.clone(),
            participant: None,
        };

        // Persist status change for messages we sent (flushed to disk after events)
        self.msg_store.update_status(&key.remote_jid, &key.id, status);
        self.msg_store.flush_dirty();

        let _ = self.event_tx.send(MessageEvent::MessageUpdate {
            key: key.clone(),
            status,
        });

        let _ = self.event_tx.send(MessageEvent::Receipt { key, receipt_type });

        // Ack the receipt back to server
        let receipt_id = node.attr("id").unwrap_or("").to_string();
        let to = node.attr("from").unwrap_or("s.whatsapp.net").to_string();
        let ack = BinaryNode {
            tag: "ack".to_string(),
            attrs: vec![
                ("id".to_string(), receipt_id),
                ("to".to_string(), to),
                ("class".to_string(), "receipt".to_string()),
            ],
            content: NodeContent::None,
        };
        self.socket.send_node(&ack).await?;

        Ok(())
    }

    /// Send an `<ack class="message">` for an incoming message. Matches
    /// Baileys' `buildAckStanza` — the server relies on this to stop
    /// redelivering the message on reconnect.
    async fn send_message_ack(&self, node: &BinaryNode) {
        let id = match node.attr("id") { Some(v) => v.to_string(), None => return };
        let from = match node.attr("from") { Some(v) => v.to_string(), None => return };

        let mut attrs = vec![
            ("id".to_string(), id),
            ("to".to_string(), from),
            ("class".to_string(), node.tag.clone()),
        ];
        if let Some(t) = node.attr("type")        { attrs.push(("type".into(), t.to_string())); }
        if let Some(p) = node.attr("participant") { attrs.push(("participant".into(), p.to_string())); }
        if let Some(r) = node.attr("recipient")   { attrs.push(("recipient".into(), r.to_string())); }
        if node.tag == "message" && !self.our_jid.is_empty() {
            attrs.push(("from".to_string(), self.our_jid.clone()));
        }

        let ack = BinaryNode {
            tag: "ack".to_string(),
            attrs,
            content: NodeContent::None,
        };
        if let Err(e) = self.socket.send_node(&ack).await {
            debug!("message ack send failed: {e}");
        }
    }

    async fn handle_notification(&self, node: &BinaryNode) -> Result<()> {
        let notif_type = node.attr("type").unwrap_or("").to_string();
        let from = node.attr("from").unwrap_or("").to_string();
        debug!("notification: type={notif_type} from={from}");

        // Parse group notifications
        if notif_type == "w:g2" || from.ends_with("@g.us") {
            self.handle_group_notification(node, &from).await;
        }

        // App-state sync: server is telling us one or more collections changed.
        if notif_type == "server_sync" {
            if let Some(sync) = self.app_state_sync.clone() {
                let collections = extract_sync_collections(node);
                if !collections.is_empty() {
                    debug!("server_sync touched: {:?}", collections);
                    tokio::spawn(async move {
                        let names: Vec<&str> = collections.iter().map(String::as_str).collect();
                        let _ = sync.resync(&names, false).await;
                    });
                }
            }
        }

        // Ack all notifications
        if let (Some(id), Some(from)) = (node.attr("id"), node.attr("from")) {
            let ack = BinaryNode {
                tag: "ack".to_string(),
                attrs: vec![
                    ("id".to_string(), id.to_string()),
                    ("to".to_string(), from.to_string()),
                    ("class".to_string(), "notification".to_string()),
                ],
                content: NodeContent::None,
            };
            self.socket.send_node(&ack).await?;
        }
        Ok(())
    }

    async fn handle_group_notification(&self, node: &BinaryNode, group_jid: &str) {
        use crate::messages::GroupUpdateKind;

        let children = match &node.content {
            NodeContent::List(v) => v,
            _ => return,
        };

        for child in children {
            let kind = match child.tag.as_str() {
                "add" | "remove" | "promote" | "demote" | "leave" => {
                    let jids = extract_participant_jids(child);
                    if jids.is_empty() { continue; }
                    match child.tag.as_str() {
                        "add"     => GroupUpdateKind::ParticipantsAdded(jids),
                        "remove" | "leave" => GroupUpdateKind::ParticipantsRemoved(jids),
                        "promote" => GroupUpdateKind::ParticipantsPromoted(jids),
                        "demote"  => GroupUpdateKind::ParticipantsDemoted(jids),
                        _ => continue,
                    }
                }
                "subject" => {
                    let subject = child.attr("subject").unwrap_or("").to_string();
                    GroupUpdateKind::SubjectChanged(subject)
                }
                "description" => {
                    let body = if let NodeContent::List(gc) = &child.content {
                        gc.iter().find(|n| n.tag == "body").and_then(|b| {
                            if let NodeContent::Text(t) = &b.content { Some(t.clone()) } else { None }
                        })
                    } else { None };
                    GroupUpdateKind::DescriptionChanged(body)
                }
                "ephemeral" | "not_ephemeral" => {
                    let secs: u32 = child.attr("expiration")
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                    GroupUpdateKind::EphemeralChanged(secs)
                }
                "announcement" | "not_announcement" => {
                    GroupUpdateKind::AnnounceModeChanged(child.tag == "announcement")
                }
                "locked" | "unlocked" => {
                    GroupUpdateKind::RestrictModeChanged(child.tag == "locked")
                }
                _ => continue,
            };
            let _ = self.event_tx.send(MessageEvent::GroupUpdate {
                group_jid: group_jid.to_string(),
                kind,
            });
        }
    }
}

#[allow(dead_code)]
pub enum DecodedPayload {
    Message(MessageContent),
    Reaction { target_id: String, emoji: String },
    Protocol(crate::signal::wa_proto::ProtocolMessagePayload),
    PollCreation { content: MessageContent, enc_key: Vec<u8> },
    PollVoteRaw(crate::signal::wa_proto::PollVoteInfo),
}

/// Decode decrypted WAProto bytes.
fn decode_plaintext(data: &[u8]) -> DecodedPayload {
    use crate::messages::MediaInfo;
    use crate::signal::wa_proto;

    // DSM wrapper: Message.deviceSentMessage (field 31) { destinationJid=1, message=2 }.
    // Our own phone sends self-addressed payloads wrapped like this, including
    // history-sync and app-state-sync-key-share. Unwrap the inner Message and
    // recurse so downstream decoders see the real content.
    if let Some(fields) = wa_proto::parse_proto_fields(data) {
        if let Some(dsm) = fields.get(&31) {
            if let Some(dsm_fields) = wa_proto::parse_proto_fields(dsm) {
                if let Some(inner) = dsm_fields.get(&2) {
                    return decode_plaintext(inner);
                }
            }
        }
    }

    // ProtocolMessage (revoke, edit, ephemeral, history sync, …)
    if let Some(proto_payload) = wa_proto::decode_protocol_message(data) {
        return DecodedPayload::Protocol(proto_payload);
    }

    // Link preview (ExtendedTextMessage with matchedText URL)
    if let Some((text, url, title, description)) = wa_proto::decode_wa_link_preview(data) {
        return DecodedPayload::Message(MessageContent::LinkPreview {
            text,
            url,
            title,
            description,
            thumbnail_jpeg: None, // thumbnails are not decoded inline
        });
    }

    // Poll creation — carry enc_key so caller can register it in PollStore
    if let Some((question, options, selectable_count, enc_key)) = wa_proto::decode_wa_poll(data) {
        return DecodedPayload::PollCreation {
            content: MessageContent::Poll { question, options, selectable_count },
            enc_key,
        };
    }

    // Poll vote
    if let Some(vote_info) = wa_proto::decode_wa_poll_vote(data) {
        return DecodedPayload::PollVoteRaw(vote_info);
    }

    // Reaction
    if let Some((target_id, emoji)) = wa_proto::decode_wa_reaction(data) {
        return DecodedPayload::Reaction { target_id, emoji };
    }

    // Media
    if let Some((m, field)) = wa_proto::decode_wa_media(data) {
        let info = MediaInfo {
            url: m.url,
            direct_path: m.direct_path,
            media_key: m.media_key,
            file_enc_sha256: m.file_enc_sha256,
            file_sha256: m.file_sha256,
            file_length: m.file_length,
            mimetype: m.mimetype,
        };
        let content = match field {
            3 => MessageContent::Image { info, caption: m.caption },
            4 => MessageContent::Document { info, file_name: m.file_name.unwrap_or_default() },
            5 => MessageContent::Audio { info },
            6 => MessageContent::Video { info, caption: m.caption },
            20 => MessageContent::Sticker { info },
            _ => MessageContent::Image { info, caption: m.caption },
        };
        return DecodedPayload::Message(content);
    }

    // Text (+ mentionedJid from contextInfo)
    if let Some((text, mentioned_jids)) = wa_proto::decode_wa_text_full(data) {
        return DecodedPayload::Message(MessageContent::Text { text, mentioned_jids });
    }

    DecodedPayload::Message(MessageContent::Text {
        text: format!("<binary {}B>", data.len()),
        mentioned_jids: Vec::new(),
    })
}

fn decode_message_content(node: &BinaryNode) -> Option<MessageContent> {
    let children = match &node.content {
        NodeContent::List(v) => v,
        _ => return None,
    };

    // Plaintext body (debug/test)
    if let Some(body) = children.iter().find(|n| n.tag == "body") {
        if let NodeContent::Text(text) = &body.content {
            return Some(MessageContent::Text { text: text.clone(), mentioned_jids: Vec::new() });
        }
    }

    // Encrypted body — caller should use signal.decrypt_message before this
    if children.iter().any(|n| n.tag == "enc") {
        return Some(MessageContent::Text {
            text: "<encrypted — decrypt first>".to_string(),
            mentioned_jids: Vec::new(),
        });
    }

    None
}

/// Send a retry receipt so the sender re-establishes the session and re-sends.
/// Matches Baileys' format: `<receipt type="retry" id to [participant] [recipient]>`
/// with `<retry …/>`, `<registration>`, and a full `<keys>` bundle so the sender
/// has everything to build a fresh pkmsg (version byte 0x05 prefix on each key,
/// u24 big-endian key ids, signed-pre-key includes signature).
async fn send_retry_receipt_fn(
    socket: &crate::socket::SocketSender,
    orig: &BinaryNode,
    to: &str,
    msg_id: &str,
    t: u64,
    registration_id: u16,
    identity_pub: &[u8; 32],
    signed_prekey: (u32, [u8; 32], Vec<u8>),
    one_time_prekey: Option<(u32, [u8; 32])>,
    device_identity: &[u8],
) {
    let mut attrs = vec![
        ("id".to_string(), msg_id.to_string()),
        ("type".to_string(), "retry".to_string()),
        ("to".to_string(), to.to_string()),
    ];
    if let Some(p) = orig.attr("participant") {
        attrs.push(("participant".to_string(), p.to_string()));
    }
    if let Some(r) = orig.attr("recipient") {
        attrs.push(("recipient".to_string(), r.to_string()));
    }

    let reg_id_be: Vec<u8> = (registration_id as u32).to_be_bytes().to_vec();

    // Helper: u24 big-endian key id + 0x05-prefixed 33-byte pub key.
    let u24_be = |v: u32| -> Vec<u8> { vec![(v >> 16) as u8, (v >> 8) as u8, v as u8] };
    let prefixed = |pk: &[u8; 32]| -> Vec<u8> {
        let mut out = Vec::with_capacity(33);
        out.push(0x05);
        out.extend_from_slice(pk);
        out
    };
    let bytes_node = |tag: &str, data: Vec<u8>| BinaryNode {
        tag: tag.to_string(),
        attrs: vec![],
        content: NodeContent::Bytes(data),
    };

    // Build <keys> block
    let (spk_id, spk_pub, spk_sig) = signed_prekey;
    let mut keys_children: Vec<BinaryNode> = vec![
        bytes_node("type", vec![0x05]),
        bytes_node("identity", prefixed(identity_pub)),
    ];
    if let Some((otk_id, otk_pub)) = one_time_prekey {
        keys_children.push(BinaryNode {
            tag: "key".to_string(),
            attrs: vec![],
            content: NodeContent::List(vec![
                bytes_node("id", u24_be(otk_id)),
                bytes_node("value", prefixed(&otk_pub)),
            ]),
        });
    }
    keys_children.push(BinaryNode {
        tag: "skey".to_string(),
        attrs: vec![],
        content: NodeContent::List(vec![
            bytes_node("id", u24_be(spk_id)),
            bytes_node("value", prefixed(&spk_pub)),
            bytes_node("signature", spk_sig),
        ]),
    });
    keys_children.push(bytes_node("device-identity", device_identity.to_vec()));

    let node = BinaryNode {
        tag: "receipt".to_string(),
        attrs,
        content: NodeContent::List(vec![
            BinaryNode {
                tag: "retry".to_string(),
                attrs: vec![
                    ("count".to_string(), "1".to_string()),
                    ("id".to_string(), msg_id.to_string()),
                    ("t".to_string(), t.to_string()),
                    ("v".to_string(), "1".to_string()),
                    ("error".to_string(), "0".to_string()),
                ],
                content: NodeContent::None,
            },
            bytes_node("registration", reg_id_be),
            BinaryNode {
                tag: "keys".to_string(),
                attrs: vec![],
                content: NodeContent::List(keys_children),
            },
        ]),
    };
    if let Err(e) = socket.send_node(&node).await {
        tracing::debug!("retry receipt failed: {e}");
    }
}

async fn process_history_sync(
    hsn: crate::signal::wa_proto::HistorySyncNotification,
    event_tx: tokio::sync::broadcast::Sender<MessageEvent>,
    contacts: std::sync::Arc<crate::contacts::ContactStore>,
    msg_store: std::sync::Arc<crate::message_store::MessageStore>,
) {
    use crate::signal::wa_proto;
    use flate2::read::ZlibDecoder;
    use std::io::Read;

    // Get the raw compressed blob — either inline or via CDN download
    let compressed = if let Some(inline) = hsn.inline_payload {
        inline
    } else if !hsn.direct_path.is_empty() && !hsn.media_key.is_empty() {
        match crate::media::download_media(
            &format!("https://mmg.whatsapp.net{}", hsn.direct_path),
            &hsn.media_key,
            crate::media::MediaType::HistorySync,
        )
        .await
        {
            Ok(data) => data,
            Err(e) => {
                debug!("history sync download failed: {e}");
                return;
            }
        }
    } else {
        return;
    };

    // Inflate
    let mut dec = ZlibDecoder::new(compressed.as_slice());
    let mut inflated = Vec::new();
    if dec.read_to_end(&mut inflated).is_err() {
        debug!("history sync inflate failed");
        return;
    }

    let sync = match wa_proto::decode_history_sync(&inflated) {
        Some(s) => s,
        None => {
            debug!("history sync decode failed");
            return;
        }
    };

    let push_names: Vec<PushName> = sync
        .push_names
        .into_iter()
        .map(|p| PushName { jid: p.jid, name: p.push_name })
        .collect();

    // Persist push names from history sync
    let entries: Vec<(String, String)> = push_names
        .iter()
        .map(|p| (p.jid.clone(), p.name.clone()))
        .collect();
    contacts.bulk_upsert(&entries);
    // Also cache group/chat names from the conversation list
    let name_entries: Vec<(String, String)> = sync.chats.iter()
        .filter_map(|c| c.name.as_ref().map(|n| (c.jid.clone(), n.clone())))
        .collect();
    contacts.bulk_upsert(&name_entries);
    contacts.save();

    let chats: Vec<ChatInfo> = sync.chats
        .into_iter()
        .map(|c| ChatInfo {
            jid: c.jid,
            name: c.name,
            unread_count: c.unread_count,
            last_msg_timestamp: c.last_msg_timestamp,
        })
        .collect();

    let messages: Vec<WAMessage> = sync
        .messages
        .into_iter()
        .map(|m| WAMessage {
            key: MessageKey {
                remote_jid: m.remote_jid,
                from_me: m.from_me,
                id: m.id,
                participant: m.participant,
            },
            message: m.content,
            message_timestamp: m.timestamp,
            status: MessageStatus::Read,
            push_name: m.push_name,
        })
        .collect();

    for msg in &messages {
        msg_store.push(msg);
    }

    let _ = event_tx.send(MessageEvent::HistorySync {
        sync_type: sync.sync_type,
        push_names,
        chats,
        messages,
    });
}

fn extract_participant_jids(node: &BinaryNode) -> Vec<String> {
    let mut out = Vec::new();
    if let NodeContent::List(children) = &node.content {
        for child in children {
            if child.tag == "participant" {
                if let Some(jid) = child.attr("jid") {
                    out.push(jid.to_string());
                }
            }
        }
    }
    out
}

/// Extract enc node bytes + type from message node.
pub fn extract_enc(node: &BinaryNode) -> Option<(Vec<u8>, String)> {
    if let NodeContent::List(children) = &node.content {
        for child in children {
            if child.tag == "enc" {
                let msg_type = child.attr("type").unwrap_or("msg").to_string();
                if let NodeContent::Bytes(data) = &child.content {
                    return Some((data.clone(), msg_type));
                }
            }
        }
    }
    None
}

/// Extract the list of collection names from a `<notification type="server_sync">`.
/// Structure: `<notification><collection name="regular" version="…"/>…</notification>`.
fn extract_sync_collections(node: &BinaryNode) -> Vec<String> {
    let mut out = Vec::new();
    if let NodeContent::List(children) = &node.content {
        for child in children {
            if child.tag == "collection" {
                if let Some(name) = child.attr("name") {
                    out.push(name.to_string());
                }
            }
            // Also walk one level deeper in case the node wraps <sync><collection>...
            if let NodeContent::List(inner) = &child.content {
                for c2 in inner {
                    if c2.tag == "collection" {
                        if let Some(name) = c2.attr("name") {
                            out.push(name.to_string());
                        }
                    }
                }
            }
        }
    }
    out
}
