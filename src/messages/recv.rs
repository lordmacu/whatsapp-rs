use crate::binary::{BinaryNode, NodeContent};
use crate::messages::{
    unix_now, ChatInfo, MessageContent, MessageEvent, MessageKey, MessageManager, MessageStatus,
    PendingPdoRetry, PushName, ReceiptType, WAMessage,
};
use anyhow::Result;
use tracing::{debug, info};

const NACK_UNHANDLED_ERROR: u32 = 500;

/// Ensure a JID carries an explicit device slot. `user@server` → `user:0@server`.
/// Canonicalising on recv avoids having two disjoint Signal sessions for the
/// same peer (one keyed on bare, another on `:0`) — which is exactly what
/// happens when the primary phone sends to us without a device suffix in the
/// `from` attr, but we separately initiate a session using the explicit `:0`
/// form.
fn normalize_device_jid(jid: &str) -> String {
    let at = match jid.find('@') { Some(i) => i, None => return jid.to_string() };
    let (before, server) = (&jid[..at], &jid[at..]);
    if before.contains(':') { jid.to_string() } else { format!("{before}:0{server}") }
}

fn bare_user_jid(jid: &str) -> String {
    let at = match jid.find('@') { Some(i) => i, None => return jid.to_string() };
    let before = &jid[..at];
    let server = &jid[at..];
    let user = before.split(':').next().unwrap_or(before);
    format!("{user}{server}")
}

/// Sender-only retry counter key. Unlike [`retry_cache_key`] this is not
/// scoped by msg id, so repeated decrypt failures from the same sender
/// accumulate and trigger the count=2-with-keys escalation on the second
/// failure in a row. Reset on any successful decrypt.
fn sender_retry_key(sender: &str) -> String {
    format!("sender:{sender}")
}

fn retry_cache_key(id: &str, sender: &str) -> String {
    format!("{id}:{sender}")
}

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

fn summarize_message(message: Option<&MessageContent>) -> Option<String> {
    match message? {
        MessageContent::Text { text, mentioned_jids } => {
            if mentioned_jids.is_empty() {
                Some(text.clone())
            } else {
                Some(format!("{text}  (mentions: {})", mentioned_jids.join(", ")))
            }
        }
        MessageContent::Image { caption, .. } => {
            Some(format!("<image: {}>", caption.as_deref().unwrap_or("")))
        }
        MessageContent::Video { caption, .. } => {
            Some(format!("<video: {}>", caption.as_deref().unwrap_or("")))
        }
        MessageContent::Audio { .. } => Some("<audio>".to_string()),
        MessageContent::Document { file_name, .. } => Some(format!("<document: {file_name}>")),
        MessageContent::Sticker { .. } => Some("<sticker>".to_string()),
        MessageContent::Reaction { emoji, target_id } => {
            Some(format!("reacted {emoji} to {target_id}"))
        }
        MessageContent::Reply { text, reply_to_id } => {
            Some(format!("(reply to {reply_to_id}) {text}"))
        }
        MessageContent::Poll { question, options, .. } => {
            Some(format!("poll: {question} — {}", options.join(" / ")))
        }
        MessageContent::LinkPreview { text, url, .. } => Some(format!("{text}  [{url}]")),
    }
}

fn log_incoming_message(msg: &WAMessage) {
    let from = msg.key.remote_jid.as_str();
    let sender = msg.key.participant.as_deref().unwrap_or(from);
    let sender_name = msg.push_name.as_deref().unwrap_or(sender);
    let summary = summarize_message(msg.message.as_ref());

    if from.ends_with("@g.us") {
        info!(
            group_jid = %from,
            sender_jid = %sender,
            sender_name = %sender_name,
            message_id = %msg.key.id,
            summary = %summary.as_deref().unwrap_or("<empty>"),
            "recv group message",
        );
    } else {
        info!(
            jid = %from,
            sender_jid = %sender,
            sender_name = %sender_name,
            message_id = %msg.key.id,
            summary = %summary.as_deref().unwrap_or("<empty>"),
            "recv message",
        );
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
            Ok(plaintext) => Some(decode_plaintext(unpad_wa(&plaintext))),
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
        let wa = decode_wa_skdm(plaintext);
        debug!(
            "maybe_process_skdm: sender={sender_jid} plaintext_len={} decoded_wa={}",
            plaintext.len(),
            wa.is_some(),
        );
        if let Some((group_jid, axolotl_bytes)) = wa {
            let ax = decode_axolotl_skdm(&axolotl_bytes);
            debug!(
                "maybe_process_skdm: group={group_jid} axolotl_len={} decoded_ax={}",
                axolotl_bytes.len(),
                ax.is_some(),
            );
            if let Some(skdm) = ax {
                if skdm.chain_key.len() == 32 {
                    let mut ck = [0u8; 32];
                    ck.copy_from_slice(&skdm.chain_key);
                    self.signal.process_sender_key_distribution(
                        sender_jid,
                        &group_jid,
                        skdm.iteration,
                        ck,
                    );
                    info!(
                        sender_jid = %sender_jid,
                        group_jid = %group_jid,
                        iteration = skdm.iteration,
                        "stored sender key distribution",
                    );
                } else {
                    debug!("SKDM chain_key wrong size: {}", skdm.chain_key.len());
                }
            }
        } else {
            debug!("maybe_process_skdm: first 32 bytes hex={}", hex::encode(&plaintext[..plaintext.len().min(32)]));
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
        // `offline=N` means the message was queued on the server while we
        // were disconnected and is being replayed now. Retrying every one of
        // these causes a massive burst of receipt traffic on reconnect,
        // which trips WA's abuse detection and silently drops us from
        // routing. Only send retry-receipts for live traffic.
        let is_offline_replay = node.attr("offline").is_some();
        let push_name = node.attr("notify").map(|s| s.to_string());
        let t: u64 = node.attr("t").and_then(|s| s.parse().ok()).unwrap_or_else(unix_now);

        // Learn LID↔PN equivalence from stanza attrs so Session::equivalent_jids
        // can resolve peers addressed under either identity.
        let pn_counterpart = node.attr("sender_pn").or_else(|| node.attr("participant_pn"));
        if let Some(pn) = pn_counterpart {
            let lid_user = bare_user_jid(
                participant.as_deref().unwrap_or(from.as_str()),
            );
            let pn_user = bare_user_jid(pn);
            if lid_user.ends_with("@lid") && pn_user.ends_with("@s.whatsapp.net") {
                {
                    let mut map = self.lid_pn_map.lock().unwrap();
                    map.insert(lid_user.clone(), pn_user.clone());
                    map.insert(pn_user.clone(), lid_user.clone());
                }
                // Also inform the Signal layer so session lookup can fall
                // back across LID/PN before decrypt (critical for MAC match).
                self.signal.set_jid_alias(&lid_user, &pn_user);
            }
        }

        // Ack is deferred until after decrypt: success → plain ack, failure →
        // retry-receipt then ack with error code. Sending a success-ack first
        // tells the server the message was delivered and retry is ignored.

        // For group messages, Signal session is keyed on the sender (participant),
        // not the group JID.
        let decrypt_jid = if from.ends_with("@g.us") {
            participant.as_deref().unwrap_or(from.as_str()).to_string()
        } else {
            from.clone()
        };
        let sender_jid = participant.as_deref().unwrap_or(from.as_str());
        let sender_bare = bare_user_jid(sender_jid);
        let mut from_me = sender_bare == bare_user_jid(&self.our_jid);
        if let Some(our_lid) = &self.our_lid {
            from_me |= sender_bare == bare_user_jid(our_lid);
        }

        let key = MessageKey {
            remote_jid: from.clone(),
            from_me,
            id: id.clone(),
            participant: participant.clone(),
        };

        // Group messages can ship BOTH a pkmsg (SKDM bootstrap) and a skmsg
        // (actual text). Decrypt the pkmsg first so the SKDM registers the
        // sender key, then fall through to the skmsg for the content.
        let all_enc = extract_all_enc(node);
        debug!(
            "recv msg {id} from={from} participant={:?} enc_types={:?}",
            participant,
            all_enc.iter().map(|(b, t)| format!("{t}({}B)", b.len())).collect::<Vec<_>>(),
        );
        let enc_summary = all_enc.iter()
            .map(|(b, t)| format!("{t}({}B)", b.len()))
            .collect::<Vec<_>>()
            .join(",");
        if from.ends_with("@g.us") {
            info!(
                group_jid = %from,
                participant = %participant.as_deref().unwrap_or(""),
                message_id = %id,
                enc_types = %enc_summary,
                offline = %node.attr("offline").unwrap_or(""),
                "incoming group stanza",
            );
        } else {
            info!(
                jid = %from,
                participant = %participant.as_deref().unwrap_or(""),
                message_id = %id,
                enc_types = %enc_summary,
                offline = %node.attr("offline").unwrap_or(""),
                "incoming message stanza",
            );
        }
        let has_skmsg = all_enc.iter().any(|(_, t)| t == "skmsg");
        if from.ends_with("@g.us") && has_skmsg {
            for (bytes, t) in &all_enc {
                if t == "pkmsg" || t == "msg" {
                    if let Ok(pt) = self.signal.decrypt_message(&decrypt_jid, bytes, t).await {
                        let pt = unpad_wa(&pt);
                        self.maybe_process_skdm(&decrypt_jid, pt);
                    }
                }
            }
        }

        // Decrypt Signal-encrypted content if present
        let decoded = if let Some((enc_bytes, enc_type)) = all_enc.iter()
            .find(|(_, t)| t == "skmsg")
            .cloned()
            .or_else(|| all_enc.into_iter().next()) {
            match enc_type.as_str() {
                "skmsg" => {
                    let r = self.decrypt_skmsg(&from, &decrypt_jid, &enc_bytes).await;
                    // If no sender key yet, ask sender to re-ship SKDM. For
                    // group msgs the retry is addressed to the participant
                    // (actual sender), not the group JID.
                    let failed = matches!(&r, Some(DecodedPayload::Message(
                        MessageContent::Text { text, .. })) if text == "<skmsg decrypt failed>");
                    if failed && !is_offline_replay {
                        let retry_key = retry_cache_key(&id, sender_jid);
                        let retry_count = {
                            let mut retries = self.retry_ids.lock().unwrap();
                            let count = retries.entry(retry_key.clone()).or_insert(0);
                            *count += 1;
                            *count
                        };
                        let include_keys = retry_count > 1;
                        debug!(
                            "skmsg recovery: id={id} from={from} retry_count={retry_count} include_keys={include_keys} + PDO"
                        );
                        send_retry_receipt_inner(
                            &self.socket, node, &from, &id, t,
                            self.signal.registration_id(),
                            self.signal.identity_public(),
                            self.signal.signed_prekey_fields(),
                            self.signal.pick_unused_prekey(),
                            self.signal.account_identity_bytes(),
                            include_keys,
                            retry_count,
                        ).await;
                        if retry_count <= 2 {
                            let socket = self.socket.clone();
                            let signal = self.signal.clone();
                            let our_jid = self.our_jid.clone();
                            let pdo_key = key.clone();
                            let pending_pdo_retries = self.pending_pdo_retries.clone();
                            let retry_key_for_pdo = retry_key.clone();
                            let orig_node = node.clone();
                            let to = from.clone();
                            let msg_id = id.clone();
                            tokio::spawn(async move {
                                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                match crate::messages::send::placeholder_resend_send(
                                    socket, signal, our_jid, pdo_key,
                                ).await {
                                    Ok(request_id) => {
                                        pending_pdo_retries.lock().unwrap().insert(
                                            request_id,
                                            PendingPdoRetry {
                                                retry_key: retry_key_for_pdo,
                                                orig: orig_node,
                                                to,
                                                msg_id,
                                                t,
                                            },
                                        );
                                    }
                                    Err(e) => {
                                        tracing::debug!("PDO send failed: {e}");
                                    }
                                }
                            });
                        }
                    }
                    r
                }
                _ => {
                    // 1:1 Signal message (msg / pkmsg). We do NOT retry on
                    // sibling sessions — each decrypt attempt mutates the
                    // ratchet state even when it fails, so trying multiple
                    // candidates corrupts every session we touch.
                    match self.signal.decrypt_message(&decrypt_jid, &enc_bytes, &enc_type).await {
                        Ok(plaintext) => {
                            // Reset the per-sender failure counter on success
                            // so a later transient failure still gets a count=1
                            // reminder before we escalate to count=2+keys.
                            self.retry_ids.lock().unwrap()
                                .remove(&sender_retry_key(sender_jid));
                            let plaintext = unpad_wa(&plaintext);
                            self.maybe_process_skdm(&decrypt_jid, plaintext);
                            Some(decode_plaintext(plaintext))
                        }
                        Err(e) => {
                            debug!("signal decrypt failed for {from}: {e}");
                            // Count consecutive decrypt failures from this
                            // sender (keyed by the sender jid, not the msg
                            // id — each msg has a unique id so a per-msg
                            // counter always starts at 1 and we never
                            // escalate to count=2 with keys). Two straight
                            // failures means the session is truly broken
                            // and we need peer to re-X3DH.
                            if !is_offline_replay {
                                let retry_count = {
                                    let mut retries = self.retry_ids.lock().unwrap();
                                    let count = retries.entry(sender_retry_key(sender_jid)).or_insert(0);
                                    *count += 1;
                                    *count
                                };
                                let include_keys = retry_count > 1;
                                send_retry_receipt_fn(
                                    &self.socket, node, &from, &id, t,
                                    self.signal.registration_id(),
                                    self.signal.identity_public(),
                                    self.signal.signed_prekey_fields(),
                                    self.signal.pick_unused_prekey(),
                                    self.signal.account_identity_bytes(),
                                    retry_count,
                                    include_keys,
                                ).await;
                            }
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

        // Send ack: plain on success, with error code on decrypt failure so
        // server schedules a resend after our retry-receipt.
        let decrypt_failed = matches!(
            &decoded,
            Some(DecodedPayload::Message(MessageContent::Text { text, .. }))
                if text == "<decrypt failed>" || text == "<skmsg decrypt failed>"
        );
        if decrypt_failed {
            if from.ends_with("@g.us") {
                info!(
                    group_jid = %from,
                    participant = %participant.as_deref().unwrap_or(""),
                    message_id = %id,
                    "group message decrypt failed",
                );
            } else {
                info!(
                    jid = %from,
                    participant = %participant.as_deref().unwrap_or(""),
                    message_id = %id,
                    "message decrypt failed",
                );
            }
            if is_offline_replay {
                // Historical backlog can contain messages whose sender-key/session
                // material is no longer recoverable locally. Asking the server to
                // retry those again keeps the offline queue alive and WA eventually
                // tears down the stream. Drain them with a plain ack instead.
                info!(
                    jid = %from,
                    message_id = %id,
                    "offline decrypt failure: acking without retry to drain backlog",
                );
                self.send_message_ack(node).await;
            } else {
                self.send_message_ack_with(node, Some(NACK_UNHANDLED_ERROR)).await;
            }
        } else {
            self.send_message_ack(node).await;
        }

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
                    from_me,
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
                    ProtocolMessagePayload::PeerDataOperationResponse { stanza_id, messages, result_types } => {
                        debug!(
                            "peer data operation response: stanza_id={:?} messages={}",
                            stanza_id,
                            messages.len(),
                        );
                        let pending_retry = stanza_id
                            .as_ref()
                            .and_then(|request_id| self.pending_pdo_retries.lock().unwrap().remove(request_id));
                        if messages.is_empty() && result_types.iter().any(|t| *t == 2) {
                            if let Some(pending) = pending_retry {
                                let retry_count = {
                                    let mut retries = self.retry_ids.lock().unwrap();
                                    let count = retries.entry(pending.retry_key.clone()).or_insert(1);
                                    if *count < 2 {
                                        *count = 2;
                                    }
                                    *count
                                };
                                if retry_count == 2 {
                                    info!(
                                        "PDO returned NOT_FOUND for request {:?}; escalating retry with keys for message {}",
                                        stanza_id,
                                        pending.msg_id,
                                    );
                                    send_retry_receipt_inner(
                                        &self.socket,
                                        &pending.orig,
                                        &pending.to,
                                        &pending.msg_id,
                                        pending.t,
                                        self.signal.registration_id(),
                                        self.signal.identity_public(),
                                        self.signal.signed_prekey_fields(),
                                        self.signal.pick_unused_prekey(),
                                        self.signal.account_identity_bytes(),
                                        true,
                                        retry_count,
                                    ).await;
                                }
                            }
                        }
                        for resent in messages {
                            let sender_jid = resent
                                .participant
                                .as_deref()
                                .unwrap_or(resent.remote_jid.as_str())
                                .to_string();
                            if let Some(raw) = resent.raw_message.as_deref() {
                                if sender_jid.is_empty() {
                                    debug!(
                                        "peer data operation response: skipping SKDM processing for id={} because sender is unknown",
                                        resent.id
                                    );
                                } else {
                                    self.maybe_process_skdm(&sender_jid, raw);
                                }
                            }
                            if resent.remote_jid.is_empty() {
                                debug!(
                                    "peer data operation response: processed partial resent payload id={} participant={:?} without remote_jid",
                                    resent.id,
                                    resent.participant,
                                );
                                continue;
                            }
                            let resent_msg = WAMessage {
                                key: MessageKey {
                                    remote_jid: resent.remote_jid.clone(),
                                    from_me: resent.from_me,
                                    id: resent.id.clone(),
                                    participant: resent.participant.clone(),
                                },
                                message: resent.content.clone(),
                                message_timestamp: resent.timestamp,
                                status: MessageStatus::Delivered,
                                push_name: resent.push_name.clone(),
                            };
                            self.msg_store.push(&resent_msg);
                            log_incoming_message(&resent_msg);
                            let _ = self.event_tx.send(MessageEvent::NewMessage { msg: resent_msg });
                        }
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
                log_incoming_message(&msg);
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
                log_incoming_message(&msg);
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

        // Retry receipt: peer device asks us to resend the named message.
        // Delegate to send.rs handler which looks up cached plaintext and
        // ships a fresh pkmsg/msg to the requesting device, then still ack.
        if receipt_type_str == "retry" {
            if let Err(e) = self.handle_incoming_retry_receipt(node).await {
                tracing::warn!("handle_incoming_retry_receipt {from}/{id}: {e}");
            }
            let to = from.clone();
            let ack = BinaryNode {
                tag: "ack".to_string(),
                attrs: vec![
                    ("id".to_string(), id),
                    ("to".to_string(), to),
                    ("class".to_string(), "receipt".to_string()),
                    ("type".to_string(), "retry".to_string()),
                ],
                content: NodeContent::None,
            };
            self.socket.send_node(&ack).await?;
            return Ok(());
        }

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
        self.send_message_ack_with(node, None).await;
    }

    async fn send_message_ack_with(&self, node: &BinaryNode, error: Option<u32>) {
        let id = match node.attr("id") { Some(v) => v.to_string(), None => return };
        let from = match node.attr("from") { Some(v) => v.to_string(), None => return };

        let mut attrs = vec![
            ("id".to_string(), id),
            ("to".to_string(), from),
            ("class".to_string(), node.tag.clone()),
        ];
        if let Some(e) = error {
            attrs.push(("error".into(), e.to_string()));
        }
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

/// Strip WhatsApp's `writeRandomPadMax16` trailing pad: last byte is pad_len
/// (1..=16), strip that many bytes from the end. Applied to plaintext AFTER
/// Signal/PKCS7 decrypt, BEFORE WAProto parsing.
fn unpad_wa(data: &[u8]) -> &[u8] {
    if let Some(&last) = data.last() {
        let n = last as usize;
        if n >= 1 && n <= 16 && n <= data.len() {
            return &data[..data.len() - n];
        }
    }
    data
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

    // Nothing matched — dump the proto fields so we can see which variant
    // we need to decode next. Only at debug level to avoid log spam.
    if let Some(fields) = wa_proto::parse_proto_fields(data) {
        let mut keys: Vec<u64> = fields.keys().copied().collect();
        keys.sort();
        let sample: Vec<String> = keys.iter().take(10).map(|k| {
            let v = &fields[k];
            let preview = if v.len() > 40 { format!("{}B", v.len()) } else { hex::encode(v) };
            format!("{k}={preview}")
        }).collect();
        debug!("unrecognized message proto ({}B), fields=[{}]", data.len(), sample.join(", "));
    } else {
        let head = &data[..data.len().min(64)];
        debug!("unrecognized payload, not proto ({}B), head={}", data.len(), hex::encode(head));
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
    retry_count: u32,
    include_keys: bool,
) {
    send_retry_receipt_inner(
        socket, orig, to, msg_id, t, registration_id,
        identity_pub, signed_prekey, one_time_prekey, device_identity, include_keys, retry_count,
    ).await;
}

async fn send_retry_receipt_inner(
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
    include_keys: bool,
    retry_count: u32,
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
    // Baileys uses raw 32-byte pubkeys in identity, key.value, skey.value.
    // Only the <type> block carries the 0x05 key-bundle-type marker.
    let _ = prefixed;
    let mut keys_children: Vec<BinaryNode> = vec![
        bytes_node("type", vec![0x05]),
        bytes_node("identity", identity_pub.to_vec()),
    ];
    if let Some((otk_id, otk_pub)) = one_time_prekey {
        keys_children.push(BinaryNode {
            tag: "key".to_string(),
            attrs: vec![],
            content: NodeContent::List(vec![
                bytes_node("id", u24_be(otk_id)),
                bytes_node("value", otk_pub.to_vec()),
            ]),
        });
    }
    keys_children.push(BinaryNode {
        tag: "skey".to_string(),
        attrs: vec![],
        content: NodeContent::List(vec![
            bytes_node("id", u24_be(spk_id)),
            bytes_node("value", spk_pub.to_vec()),
            bytes_node("signature", spk_sig),
        ]),
    });
    keys_children.push(bytes_node("device-identity", device_identity.to_vec()));

    let mut children = vec![
        BinaryNode {
            tag: "retry".to_string(),
            attrs: vec![
                ("count".to_string(), retry_count.to_string()),
                ("id".to_string(), msg_id.to_string()),
                ("t".to_string(), t.to_string()),
                ("v".to_string(), "1".to_string()),
                ("error".to_string(), "0".to_string()),
            ],
            content: NodeContent::None,
        },
        bytes_node("registration", reg_id_be),
    ];
    if include_keys {
        children.push(BinaryNode {
            tag: "keys".to_string(),
            attrs: vec![],
            content: NodeContent::List(keys_children),
        });
    }
    let node = BinaryNode {
        tag: "receipt".to_string(),
        attrs,
        content: NodeContent::List(children),
    };
    tracing::info!(
        "→ retry-receipt to={to} id={msg_id} retry_count={retry_count} include_keys={include_keys} children={:?} attrs={:?}",
        match &node.content {
            NodeContent::List(c) => c.iter().map(|n| n.tag.as_str()).collect::<Vec<_>>(),
            _ => vec![],
        },
        node.attrs,
    );
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
    extract_all_enc(node).into_iter().next()
}

/// Return every `<enc>` child as (ciphertext, msg_type). Groups ship both
/// `pkmsg` (SKDM bootstrap, no text) and `skmsg` (actual text encrypted with
/// sender key); we need both so callers can consume SKDM first, then decrypt
/// the skmsg for the content.
pub fn extract_all_enc(node: &BinaryNode) -> Vec<(Vec<u8>, String)> {
    let mut out = Vec::new();
    if let NodeContent::List(children) = &node.content {
        for child in children {
            if child.tag == "enc" {
                let msg_type = child.attr("type").unwrap_or("msg").to_string();
                if let NodeContent::Bytes(data) = &child.content {
                    out.push((data.clone(), msg_type));
                }
            }
        }
    }
    out
}

/// Extract the list of collection names from a `<notification type="server_sync">`.
/// Structure: `<notification><collection name="regular" version="…"/>…</notification>`.
/// Build the ordered list of session JIDs to try decrypting with.
///
/// For a PN address we only ever need the exact JID. For a LID address we
/// also try:
///   1. every existing session under the same LID user (different devices);
///   2. if the stanza carried `sender_pn` / `peer_recipient_pn`, every
///      session we have for that PN user (populated earlier by outgoing
///      sends to that number).
///
/// The first candidate that successfully decrypts wins.
fn build_candidate_jids(
    primary: &str,
    node: &BinaryNode,
    signal: &crate::signal::SignalRepository,
) -> Vec<String> {
    let mut out = vec![primary.to_string()];
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    seen.insert(primary.to_string());

    let mut add = |jid: String, acc: &mut Vec<String>, seen: &mut std::collections::HashSet<String>| {
        if seen.insert(jid.clone()) {
            acc.push(jid);
        }
    };

    // Siblings of the primary JID (same user, different device).
    for j in signal.sibling_jids(primary) {
        add(j, &mut out, &mut seen);
    }

    // LID-specific fallbacks.
    if primary.ends_with("@lid") {
        for attr in &["sender_pn", "peer_recipient_pn"] {
            if let Some(pn) = node.attr(attr) {
                for j in signal.sibling_jids(pn) {
                    add(j, &mut out, &mut seen);
                }
            }
        }
    }

    out
}

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
