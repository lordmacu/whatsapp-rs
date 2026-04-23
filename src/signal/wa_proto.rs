/// Manual protobuf encoding for Signal wire format and WAProto.Message.
/// We follow the same manual-varint approach used in socket/mod.rs.

// ── WAProto.Message ───────────────────────────────────────────────────────────

/// Encode a plain text WAProto.Message.
/// field 1 = conversation (string)
pub fn encode_wa_text_message(text: &str) -> Vec<u8> {
    proto_bytes(1, text.as_bytes())
}

/// Encode a reply WAProto.Message with a quote bubble.
///
/// To render a quote, peer clients require all of:
///   - `ContextInfo.stanzaId` (field 1) — the id of the message being replied to
///   - `ContextInfo.participant` (field 2) — the sender jid of that message
///   - `ContextInfo.quotedMessage` (field 3) — a minimal copy of the quoted content
///
/// `quoted_body` is the pre-built inner WAProto.Message bytes of the
/// referenced message — e.g. `proto_bytes(1, text.as_bytes())` for text or
/// `proto_message(3, image_fields)` for an image. Caller is responsible for
/// producing it (send.rs has a helper that reads `msg_store` and assembles
/// the right sub-message based on the stored type).
///
/// Empty `quoted_body` keeps the reply well-formed but peers won't render
/// a quote bubble — use the text fallback `proto_bytes(1, "")` to at least
/// force the ContextInfo path.
pub fn encode_wa_reply_message(
    text: &str,
    reply_to_id: &str,
    participant: Option<&str>,
    quoted_body: &[u8],
) -> Vec<u8> {
    // ContextInfo: stanzaId, participant, quotedMessage.
    let mut ctx_info = Vec::new();
    ctx_info.extend(proto_bytes(1, reply_to_id.as_bytes())); // stanzaId
    if let Some(p) = participant {
        ctx_info.extend(proto_bytes(2, p.as_bytes())); // participant
    }
    ctx_info.extend(proto_message(3, quoted_body)); // quotedMessage

    // ExtendedTextMessage: text + contextInfo.
    let mut extended = Vec::new();
    extended.extend(proto_bytes(1, text.as_bytes()));
    extended.extend(proto_message(17, &ctx_info));

    // Message.extendedTextMessage = field 6.
    proto_message(6, &extended)
}

/// Encode a text message with @mention JIDs embedded in contextInfo.
#[allow(dead_code)]
pub fn encode_wa_text_with_mentions(text: &str, mention_jids: &[&str]) -> Vec<u8> {
    if mention_jids.is_empty() {
        return encode_wa_text_message(text);
    }
    let mut ctx_info = Vec::new();
    for jid in mention_jids {
        ctx_info.extend(proto_bytes(15, jid.as_bytes())); // mentionedJid (repeated)
    }
    let mut extended = Vec::new();
    extended.extend(proto_bytes(1, text.as_bytes()));
    // ExtendedTextMessage.contextInfo = field 17.
    extended.extend(proto_message(17, &ctx_info));
    // Message.extendedTextMessage = field 6.
    proto_message(6, &extended)
}

// ── WAProto.Message encode (media) ───────────────────────────────────────────

fn encode_media_fields(info: &crate::messages::MediaInfo, caption: Option<&str>, extra: &[u8]) -> Vec<u8> {
    // Canonical ImageMessage/VideoMessage/AudioMessage/DocumentMessage field
    // numbers (verified against Baileys WAProto.ImageMessage):
    //   1 = url            2 = mimetype       3 = caption
    //   4 = fileSha256     5 = fileLength
    //   8 = mediaKey       9 = fileEncSha256  11 = directPath
    //   12 = mediaKeyTimestamp
    // Older code used 3/4/7/8/15 for the non-caption slots — modern WA
    // renders those as a broken placeholder because it can't find the
    // mediaKey / direct_path / length at the expected tags.
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut sub = Vec::new();
    sub.extend(proto_bytes(1, info.url.as_bytes()));
    sub.extend(proto_bytes(2, info.mimetype.as_bytes()));
    if let Some(cap) = caption {
        if !cap.is_empty() {
            sub.extend(proto_bytes(3, cap.as_bytes()));
        }
    }
    sub.extend(proto_bytes(4, &info.file_sha256));
    sub.extend(proto_varint(5, info.file_length));
    sub.extend(proto_bytes(8, &info.media_key));
    sub.extend(proto_bytes(9, &info.file_enc_sha256));
    sub.extend(proto_bytes(11, info.direct_path.as_bytes()));
    sub.extend(proto_varint(12, now_unix));
    sub.extend_from_slice(extra);
    sub
}

// Canonical WAProto Message oneof field numbers (verified against Baileys
// and whatsmeow protos): imageMessage=3, documentMessage=7, audioMessage=8,
// videoMessage=9, stickerMessage=26.
//
// Each media sub-message has ITS OWN internal field layout — same logical
// fields (fileSha256, mediaKey, directPath, …) sit at different tags in
// ImageMessage vs VideoMessage vs AudioMessage vs DocumentMessage vs
// StickerMessage. Using one shared helper (`encode_media_fields` below)
// only works for image; the others need per-type encoders.
pub fn encode_wa_image_message(info: &crate::messages::MediaInfo, caption: Option<&str>) -> Vec<u8> {
    encode_wa_image_message_opts(info, caption, false)
}

/// Like [`encode_wa_image_message`] but also sets `ImageMessage.viewOnce = true`
/// (field 25) in the sub-message. Used together with [`wrap_view_once`] — the
/// flag *inside* the ImageMessage is what drives the "1" icon in the UI,
/// while the envelope forces the client to delete after open.
pub fn encode_wa_image_message_opts(
    info: &crate::messages::MediaInfo, caption: Option<&str>, view_once: bool,
) -> Vec<u8> {
    let mut sub = encode_media_fields(info, caption, &[]);
    if view_once {
        sub.extend(proto_varint(25, 1));
    }
    proto_message(3, &sub)
}

pub fn encode_wa_video_message(info: &crate::messages::MediaInfo, caption: Option<&str>) -> Vec<u8> {
    encode_wa_video_message_opts(info, caption, false)
}

/// Like [`encode_wa_video_message`] but sets `VideoMessage.viewOnce = true`
/// (field 20) when requested.
pub fn encode_wa_video_message_opts(
    info: &crate::messages::MediaInfo, caption: Option<&str>, view_once: bool,
) -> Vec<u8> {
    let mut sub = encode_video_fields(info, caption);
    if view_once {
        sub.extend(proto_varint(20, 1));
    }
    proto_message(9, &sub)
}

pub fn encode_wa_audio_message(info: &crate::messages::MediaInfo, ptt: bool) -> Vec<u8> {
    proto_message(8, &encode_audio_fields(info, ptt))
}

pub fn encode_wa_document_message(info: &crate::messages::MediaInfo, file_name: &str) -> Vec<u8> {
    proto_message(7, &encode_document_fields(info, file_name))
}

pub fn encode_wa_sticker_message(info: &crate::messages::MediaInfo) -> Vec<u8> {
    proto_message(26, &encode_sticker_fields(info))
}

/// WAProto Message.locationMessage = field 5.
/// LocationMessage: 1=lat, 2=lon, 3=name, 4=address, 5=url, 17=contextInfo.
pub fn encode_wa_location_message(
    lat: f64,
    lon: f64,
    name: Option<&str>,
    address: Option<&str>,
) -> Vec<u8> {
    let mut loc = Vec::new();
    loc.extend(proto_double(1, lat));
    loc.extend(proto_double(2, lon));
    if let Some(n) = name {
        if !n.is_empty() { loc.extend(proto_bytes(3, n.as_bytes())); }
    }
    if let Some(a) = address {
        if !a.is_empty() { loc.extend(proto_bytes(4, a.as_bytes())); }
    }
    proto_message(5, &loc)
}

/// WAProto Message.contactMessage = field 4.
/// ContactMessage: 1=displayName, 16=vcard.
///
/// `vcard` must be a complete vCard 3.0 string (BEGIN:VCARD … END:VCARD).
/// Peer clients render the "Add contact" button off this payload.
pub fn encode_wa_contact_message(display_name: &str, vcard: &str) -> Vec<u8> {
    let mut c = Vec::new();
    c.extend(proto_bytes(1, display_name.as_bytes()));
    c.extend(proto_bytes(16, vcard.as_bytes()));
    proto_message(4, &c)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// WAProto VideoMessage:
///   1 url  2 mimetype  3 fileSha256  4 fileLength  5 seconds  6 mediaKey
///   7 caption  11 fileEncSha256  13 directPath  14 mediaKeyTimestamp
fn encode_video_fields(info: &crate::messages::MediaInfo, caption: Option<&str>) -> Vec<u8> {
    let mut sub = Vec::new();
    sub.extend(proto_bytes(1, info.url.as_bytes()));
    sub.extend(proto_bytes(2, info.mimetype.as_bytes()));
    sub.extend(proto_bytes(3, &info.file_sha256));
    sub.extend(proto_varint(4, info.file_length));
    sub.extend(proto_bytes(6, &info.media_key));
    if let Some(cap) = caption {
        if !cap.is_empty() {
            sub.extend(proto_bytes(7, cap.as_bytes()));
        }
    }
    sub.extend(proto_bytes(11, &info.file_enc_sha256));
    sub.extend(proto_bytes(13, info.direct_path.as_bytes()));
    sub.extend(proto_varint(14, now_unix()));
    sub
}

/// WAProto AudioMessage:
///   1 url  2 mimetype  3 fileSha256  4 fileLength  5 seconds  6 ptt
///   7 mediaKey  8 fileEncSha256  9 directPath  10 mediaKeyTimestamp
fn encode_audio_fields(info: &crate::messages::MediaInfo, ptt: bool) -> Vec<u8> {
    let mut sub = Vec::new();
    sub.extend(proto_bytes(1, info.url.as_bytes()));
    sub.extend(proto_bytes(2, info.mimetype.as_bytes()));
    sub.extend(proto_bytes(3, &info.file_sha256));
    sub.extend(proto_varint(4, info.file_length));
    if ptt {
        sub.extend(proto_varint(6, 1));
    }
    sub.extend(proto_bytes(7, &info.media_key));
    sub.extend(proto_bytes(8, &info.file_enc_sha256));
    sub.extend(proto_bytes(9, info.direct_path.as_bytes()));
    sub.extend(proto_varint(10, now_unix()));
    sub
}

/// WAProto DocumentMessage:
///   1 url  2 mimetype  3 title  4 fileSha256  5 fileLength
///   7 mediaKey  8 fileName  9 fileEncSha256  10 directPath
///   11 mediaKeyTimestamp
fn encode_document_fields(info: &crate::messages::MediaInfo, file_name: &str) -> Vec<u8> {
    let mut sub = Vec::new();
    sub.extend(proto_bytes(1, info.url.as_bytes()));
    sub.extend(proto_bytes(2, info.mimetype.as_bytes()));
    sub.extend(proto_bytes(3, file_name.as_bytes())); // title same as file_name
    sub.extend(proto_bytes(4, &info.file_sha256));
    sub.extend(proto_varint(5, info.file_length));
    sub.extend(proto_bytes(7, &info.media_key));
    sub.extend(proto_bytes(8, file_name.as_bytes()));
    sub.extend(proto_bytes(9, &info.file_enc_sha256));
    sub.extend(proto_bytes(10, info.direct_path.as_bytes()));
    sub.extend(proto_varint(11, now_unix()));
    sub
}

/// WAProto StickerMessage:
///   1 url  2 fileSha256  3 fileEncSha256  4 mediaKey  5 mimetype
///   8 directPath  9 fileLength  10 mediaKeyTimestamp
/// Note: layout is different from other media types (mimetype at 5, not 2).
fn encode_sticker_fields(info: &crate::messages::MediaInfo) -> Vec<u8> {
    let mut sub = Vec::new();
    sub.extend(proto_bytes(1, info.url.as_bytes()));
    sub.extend(proto_bytes(2, &info.file_sha256));
    sub.extend(proto_bytes(3, &info.file_enc_sha256));
    sub.extend(proto_bytes(4, &info.media_key));
    sub.extend(proto_bytes(5, info.mimetype.as_bytes()));
    sub.extend(proto_bytes(8, info.direct_path.as_bytes()));
    sub.extend(proto_varint(9, info.file_length));
    sub.extend(proto_varint(10, now_unix()));
    sub
}

/// Encode WAProto.Message with link preview (field 6 = ExtendedTextMessage).
///
/// Canonical ExtendedTextMessage fields (Baileys):
///   1 = text, 2 = matchedText (URL), 4 = canonicalUrl, 5 = description,
///   6 = title, 16 = jpegThumbnail
pub fn encode_wa_link_preview_message(
    text: &str,
    url: &str,
    title: &str,
    description: &str,
    thumbnail_jpeg: Option<&[u8]>,
) -> Vec<u8> {
    let mut ext = Vec::new();
    ext.extend(proto_bytes(1, text.as_bytes()));
    ext.extend(proto_bytes(2, url.as_bytes()));
    ext.extend(proto_bytes(4, url.as_bytes()));
    if !description.is_empty() {
        ext.extend(proto_bytes(5, description.as_bytes()));
    }
    if !title.is_empty() {
        ext.extend(proto_bytes(6, title.as_bytes()));
    }
    if let Some(thumb) = thumbnail_jpeg {
        if !thumb.is_empty() {
            ext.extend(proto_bytes(16, thumb));
        }
    }
    proto_message(6, &ext)
}

/// Encode WAProto.Message poll creation (field 49 = PollCreationMessage).
///
/// PollCreationMessage:
///   field 1 = encKey (bytes, 32-byte random key for HMAC vote encryption)
///   field 2 = name (string, question)
///   field 3 = options (repeated PollOption { field 1 = name })
///   field 4 = selectableOptionsCount (varint, 0 = unlimited)
/// Returns `(encoded_bytes, enc_key)` — caller must persist enc_key to decrypt votes later.
pub fn encode_wa_poll_message(
    question: &str,
    options: &[&str],
    selectable_count: u32,
) -> (Vec<u8>, [u8; 32]) {
    use rand::RngCore;
    let mut enc_key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut enc_key);

    let mut poll = Vec::new();
    poll.extend(proto_bytes(1, &enc_key));
    poll.extend(proto_bytes(2, question.as_bytes()));
    for opt in options {
        let opt_bytes = proto_bytes(1, opt.as_bytes());
        poll.extend(proto_message(3, &opt_bytes));
    }
    if selectable_count > 0 {
        poll.extend(proto_varint(4, selectable_count as u64));
    }
    (proto_message(49, &poll), enc_key)
}

/// Wrap a normal WAProto.Message blob (image/video) in a `viewOnceMessage`
/// envelope so the receiver's WA client deletes the media after first open.
///
/// Field numbers verified against local Baileys WAProto.proto:
///   `viewOnceMessage = 37` (V1 — what Baileys actually sends),
///   `viewOnceMessageV2 = 55`, `viewOnceMessageV2Extension = 59`.
///   `messageContextInfo = 35`, `MessageContextInfo.messageSecret = 3`.
///
/// Structure:
/// ```text
/// outer Message {
///   messageContextInfo = MessageContextInfo { messageSecret = <32 random bytes> }   // field 35
///   viewOnceMessage    = FutureProofMessage   { message = inner Message }           // field 37
/// }
/// ```
///
/// Baileys uses V1 (field 37) here (`Utils/messages.ts`), not V2. The inner
/// Image/VideoMessage does NOT carry an additional `viewOnce` bool — the
/// envelope alone drives the UI. `messageSecret` is unconditionally added
/// for non-reaction/poll/event messages (the reporting-token path).
pub fn wrap_view_once(inner_message: &[u8]) -> Vec<u8> {
    use rand::RngCore;
    let mut secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);

    let mci_body = proto_bytes(3, &secret);
    let mci_outer = proto_message(35, &mci_body);

    let fp = proto_bytes(1, inner_message);
    let view_once = proto_message(37, &fp);

    let mut out = Vec::with_capacity(view_once.len() + mci_outer.len());
    out.extend_from_slice(&view_once);
    out.extend_from_slice(&mci_outer);
    out
}

// ── WAProto.Message decode ────────────────────────────────────────────────────

/// Extract the best text representation from a decrypted WAProto.Message blob.
#[allow(dead_code)]
pub fn decode_wa_text(data: &[u8]) -> Option<String> {
    decode_wa_text_full(data).map(|(t, _)| t)
}

/// Decode text + mentionedJid list. ContextInfo lives in ExtendedTextMessage.field 17,
/// mentionedJid is ContextInfo.field 15 (repeated string).
pub fn decode_wa_text_full(data: &[u8]) -> Option<(String, Vec<String>)> {
    let fields = parse_proto_fields(data)?;
    // field 1 = conversation (no contextInfo)
    if let Some(b) = fields.get(&1) {
        if let Ok(s) = String::from_utf8(b.clone()) {
            if !s.is_empty() { return Some((s, Vec::new())); }
        }
    }
    // field 6 = extendedTextMessage { field 1 = text, field 17 = contextInfo }
    // Legacy: we used to encode under field 17 ourselves — accept that too
    // so round-trip with older stored messages still decodes.
    if let Some(ext) = fields.get(&6).or_else(|| fields.get(&17)) {
        let ef = parse_proto_fields(ext)?;
        if let Some(b) = ef.get(&1) {
            if let Ok(s) = String::from_utf8(b.clone()) {
                if !s.is_empty() {
                    let mentions = ef.get(&17)
                        .and_then(|ctx| parse_proto_repeated(ctx))
                        .map(|entries| entries.into_iter()
                            .filter(|(f, _)| *f == 15)
                            .filter_map(|(_, v)| String::from_utf8(v).ok())
                            .filter(|s| !s.is_empty())
                            .collect::<Vec<_>>())
                        .unwrap_or_default();
                    return Some((s, mentions));
                }
            }
        }
    }
    None
}

/// Decode link preview from WAProto.Message field 6 = ExtendedTextMessage
/// (legacy field 17 also accepted for backwards compat).
/// Returns `(text, url, title, description)` — only present when field 2 (matchedText/URL) is set.
pub fn decode_wa_link_preview(data: &[u8]) -> Option<(String, String, String, String)> {
    let outer = parse_proto_fields(data)?;
    let ext = outer.get(&6).or_else(|| outer.get(&17))?;
    let ef = parse_proto_fields(ext)?;

    let url = ef.get(&2).and_then(|b| String::from_utf8(b.clone()).ok()).filter(|s| !s.is_empty())?;
    let text = ef.get(&1).and_then(|b| String::from_utf8(b.clone()).ok()).unwrap_or_default();
    // Canonical: description=5, title=6. Fall back to legacy 4/5 (our earlier
    // wrong mapping) so previews sent before the fix still decode.
    let description = ef.get(&5).or_else(|| ef.get(&4))
        .and_then(|b| String::from_utf8(b.clone()).ok()).unwrap_or_default();
    let title = ef.get(&6).or_else(|| ef.get(&5))
        .and_then(|b| String::from_utf8(b.clone()).ok()).unwrap_or_default();

    Some((text, url, title, description))
}

/// Parsed media info from a WAProto.Message media sub-message.
pub struct WaMediaFields {
    pub url: String,
    pub direct_path: String,
    pub media_key: Vec<u8>,
    pub file_enc_sha256: Vec<u8>,
    pub file_sha256: Vec<u8>,
    pub file_length: u64,
    pub mimetype: String,
    pub caption: Option<String>,
    pub file_name: Option<String>, // documents only
}

/// Detect and decode a media sub-message from a WAProto.Message blob.
/// Returns `(WaMediaFields, media_field_number)` where field numbers are:
///   3=image, 4=document, 5=audio, 6=video, 20=sticker
pub fn decode_wa_media(data: &[u8]) -> Option<(WaMediaFields, u64)> {
    let outer = parse_proto_fields(data)?;
    // Canonical fields first (image=3, document=7, audio=8, video=9,
    // sticker=26). Legacy 4/5/6/20 kept as fallback so messages we sent
    // ourselves before the field-number fix still decode.
    for &field in &[3u64, 7, 8, 9, 26, 4, 5, 6, 20] {
        if let Some(sub) = outer.get(&field) {
            if let Some(m) = parse_media_sub(sub) {
                return Some((m, field));
            }
        }
    }
    None
}

fn parse_media_sub(data: &[u8]) -> Option<WaMediaFields> {
    let f = parse_proto_fields(data)?;

    // Canonical (Baileys) sub-field layout. Legacy tags (3=sha,4=len,7=key,
    // 8=caption,15=directPath) tried as fallback so our own stored messages
    // from before the fix still round-trip.
    let url = f.get(&1).and_then(|b| String::from_utf8(b.clone()).ok()).unwrap_or_default();
    let mimetype = f.get(&2).and_then(|b| String::from_utf8(b.clone()).ok()).unwrap_or_default();
    let caption = f.get(&3).and_then(|b| String::from_utf8(b.clone()).ok())
        .or_else(|| f.get(&8).and_then(|b| String::from_utf8(b.clone()).ok()));
    let file_sha256 = f.get(&4).cloned().or_else(|| f.get(&3).cloned()).unwrap_or_default();
    let file_length = f.get(&5).or_else(|| f.get(&4))
        .and_then(|b| read_varint_from_bytes(b)).unwrap_or(0);
    let media_key = f.get(&8).cloned().or_else(|| f.get(&7).cloned()).unwrap_or_default();
    let file_enc_sha256 = f.get(&9).cloned().unwrap_or_default();
    let direct_path = f.get(&11).and_then(|b| String::from_utf8(b.clone()).ok())
        .or_else(|| f.get(&15).and_then(|b| String::from_utf8(b.clone()).ok()))
        .unwrap_or_default();
    let file_name = f.get(&30).and_then(|b| String::from_utf8(b.clone()).ok());

    if url.is_empty() && direct_path.is_empty() {
        return None;
    }
    Some(WaMediaFields { url, direct_path, media_key, file_enc_sha256, file_sha256, file_length, mimetype, caption, file_name })
}

/// Encode WAProto.Message reaction (field 85 = ReactionMessage).
/// `remote_jid` = conversation JID, `target_id` = message being reacted to.
pub fn encode_wa_reaction_message(
    remote_jid: &str,
    target_id: &str,
    emoji: &str,
    target_from_me: bool,
) -> Vec<u8> {
    let mut key = Vec::new();
    key.extend(proto_bytes(1, remote_jid.as_bytes()));
    key.extend(proto_varint(2, if target_from_me { 1 } else { 0 }));
    key.extend(proto_bytes(3, target_id.as_bytes()));
    let now_ms: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let mut react = Vec::new();
    react.extend(proto_message(1, &key));
    react.extend(proto_bytes(2, emoji.as_bytes()));
    // Field 4 = senderTimestampMs (int64). Without this Baileys/WA clients
    // silently drop the reaction from the UI even though the server accepted.
    react.extend(proto_varint(4, now_ms));
    // Message.reactionMessage = field 46 (WAProto). Previous code used 85
    // which is `eventCoverImage` — WA silently ignored the reaction.
    proto_message(46, &react)
}

/// Decode poll creation from WAProto.Message field 49 = PollCreationMessage.
/// Returns `(question, options, selectable_count, enc_key)`.
pub fn decode_wa_poll(data: &[u8]) -> Option<(String, Vec<String>, u32, Vec<u8>)> {
    let outer = parse_proto_fields(data)?;
    let poll = outer.get(&49)?;
    let pf = parse_proto_fields(poll)?;

    let enc_key = pf.get(&1).cloned().unwrap_or_default();

    let question = pf.get(&2)
        .and_then(|b| String::from_utf8(b.clone()).ok())
        .filter(|s| !s.is_empty())?;

    // field 3 = repeated PollOption { field 1 = name } — use repeated parser
    let repeated = parse_proto_repeated(poll)?;
    let options: Vec<String> = repeated
        .iter()
        .filter(|(field, _)| *field == 3)
        .filter_map(|(_, bytes)| {
            let of = parse_proto_fields(bytes)?;
            of.get(&1).and_then(|b| String::from_utf8(b.clone()).ok())
        })
        .collect();

    let selectable_count = pf.get(&4)
        .and_then(|b| read_varint_from_bytes(b))
        .unwrap_or(0) as u32;

    Some((question, options, selectable_count, enc_key))
}

/// Encode a ProtocolMessage that revokes (deletes) a sent message.
pub fn encode_wa_revoke_message(remote_jid: &str, msg_id: &str, from_me: bool) -> Vec<u8> {
    let mut key = Vec::new();
    key.extend(proto_bytes(1, remote_jid.as_bytes()));
    key.extend(proto_varint(2, from_me as u64));
    key.extend(proto_bytes(3, msg_id.as_bytes()));
    let mut pm = Vec::new();
    pm.extend(proto_message(1, &key));
    pm.extend(proto_varint(2, 0)); // type = REVOKE
    proto_message(12, &pm)
}

/// Encode a ProtocolMessage that edits a sent message (type 14 = MESSAGE_EDIT).
pub fn encode_wa_edit_message(remote_jid: &str, msg_id: &str, new_text: &str) -> Vec<u8> {
    let mut key = Vec::new();
    key.extend(proto_bytes(1, remote_jid.as_bytes()));
    key.extend(proto_varint(2, 1)); // fromMe = true
    key.extend(proto_bytes(3, msg_id.as_bytes()));
    let edited = proto_bytes(1, new_text.as_bytes()); // Message.conversation
    let mut pm = Vec::new();
    pm.extend(proto_message(1, &key));
    pm.extend(proto_varint(2, 14));          // type = MESSAGE_EDIT
    pm.extend(proto_message(14, &edited));   // editedMessage
    proto_message(12, &pm)
}

// ── Poll votes ────────────────────────────────────────────────────────────────

#[allow(dead_code)]
pub struct PollVoteInfo {
    pub poll_msg_id: String,
    pub poll_remote_jid: String,
    pub enc_payload: Vec<u8>,
    pub enc_iv: Vec<u8>,
}

/// Decode PollUpdateMessage (field 50) from a decrypted WAProto.Message blob.
pub fn decode_wa_poll_vote(data: &[u8]) -> Option<PollVoteInfo> {
    let outer = parse_proto_fields(data)?;
    let vote_bytes = outer.get(&50)?;
    let vf = parse_proto_fields(vote_bytes)?;

    let key_bytes = vf.get(&1)?;
    let kf = parse_proto_fields(key_bytes)?;
    let poll_msg_id = kf.get(&3)
        .and_then(|b| String::from_utf8(b.clone()).ok())
        .filter(|s| !s.is_empty())?;
    let poll_remote_jid = kf.get(&1)
        .and_then(|b| String::from_utf8(b.clone()).ok())
        .unwrap_or_default();

    let enc_val_bytes = vf.get(&2)?;
    let ef = parse_proto_fields(enc_val_bytes)?;
    let enc_payload = ef.get(&1)?.clone();
    let enc_iv = ef.get(&2)?.clone();

    Some(PollVoteInfo { poll_msg_id, poll_remote_jid, enc_payload, enc_iv })
}

/// Decrypt a received poll vote and return the selected option names.
///
/// `enc_key` = 32-byte key stored in PollStore when the poll was created.
/// `voter_jid` = normalised JID of the voter (participant or remote_jid).
pub fn decrypt_poll_vote(
    enc_key: &[u8],
    voter_jid: &str,
    enc_payload: &[u8],
    enc_iv: &[u8],
    all_options: &[String],
) -> Vec<String> {
    use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Key, Nonce};
    use hkdf::Hkdf;
    use sha2::{Digest, Sha256};

    let mut ikm = enc_key.to_vec();
    ikm.extend_from_slice(voter_jid.as_bytes());
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), &ikm);
    let mut dk = [0u8; 32];
    if hk.expand(b"WhatsApp Poll Vote Mac\x00", &mut dk).is_err() {
        return vec![];
    }

    if enc_iv.len() != 12 { return vec![]; }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&dk));
    let Ok(plaintext) = cipher.decrypt(Nonce::from_slice(enc_iv), enc_payload) else {
        return vec![];
    };

    // Plaintext = concatenated 32-byte SHA256 hashes of selected option names
    plaintext.chunks_exact(32).filter_map(|chunk| {
        all_options.iter().find(|opt| {
            let mut h = Sha256::new();
            h.update(opt.as_bytes());
            h.finalize().as_slice() == chunk
        }).cloned()
    }).collect()
}

/// Encode a PollUpdateMessage (field 46) to cast a vote.
///
/// `enc_key` = 32-byte key from PollStore.
/// `voter_jid` = our own JID (the sender of this vote message).
pub fn encode_wa_poll_vote(
    poll_msg_id: &str,
    poll_remote_jid: &str,
    enc_key: &[u8],
    voter_jid: &str,
    selected_options: &[&str],
) -> Vec<u8> {
    use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Key, Nonce};
    use hkdf::Hkdf;
    use rand::RngCore;
    use sha2::{Digest, Sha256};

    // Plaintext = SHA256 of each selected option name
    let mut plaintext = Vec::new();
    for opt in selected_options {
        let mut h = Sha256::new();
        h.update(opt.as_bytes());
        plaintext.extend_from_slice(&h.finalize());
    }

    let mut ikm = enc_key.to_vec();
    ikm.extend_from_slice(voter_jid.as_bytes());
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), &ikm);
    let mut dk = [0u8; 32];
    hk.expand(b"WhatsApp Poll Vote Mac\x00", &mut dk).expect("hkdf");

    let mut iv_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut iv_bytes);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&dk));
    let enc_payload = cipher.encrypt(Nonce::from_slice(&iv_bytes), plaintext.as_slice())
        .expect("aes-gcm");

    // MessageKey for the original poll creation message
    let mut poll_key = Vec::new();
    poll_key.extend(proto_bytes(1, poll_remote_jid.as_bytes()));
    poll_key.extend(proto_varint(2, 0)); // fromMe of the poll creator
    poll_key.extend(proto_bytes(3, poll_msg_id.as_bytes()));

    let mut enc_val = Vec::new();
    enc_val.extend(proto_bytes(1, &enc_payload));
    enc_val.extend(proto_bytes(2, &iv_bytes));

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let mut pum = Vec::new();
    pum.extend(proto_message(1, &poll_key));
    pum.extend(proto_message(2, &enc_val));
    pum.extend(proto_varint(3, now_ms));

    // Message.pollUpdateMessage = field 50 (WAProto). Previous code used 46
    // which is reactionMessage — WA silently dropped the vote.
    proto_message(50, &pum)
}

/// Decode reaction from WAProto.Message field 46 = ReactionMessage.
/// Returns `(target_message_id, emoji)` — emoji is empty string for reaction removal.
pub fn decode_wa_reaction(data: &[u8]) -> Option<(String, String)> {
    let fields = parse_proto_fields(data)?;
    let react = fields.get(&46)?;
    let rf = parse_proto_fields(react)?;
    let emoji = rf.get(&2).and_then(|b| String::from_utf8(b.clone()).ok()).unwrap_or_default();
    let kf = rf.get(&1).and_then(|b| parse_proto_fields(b))?;
    let target_id = kf.get(&3).and_then(|b| String::from_utf8(b.clone()).ok()).unwrap_or_default();
    Some((target_id, emoji))
}

// ── Sender Key wire format ────────────────────────────────────────────────────

pub struct AxolotlSkdm {
    pub iteration: u32,
    pub chain_key: Vec<u8>, // 32 bytes
}

/// Encode axolotlSenderKeyDistributionMessage bytes (Signal SKDM binary).
/// Wire: version byte || proto { id(1), iteration(2), chainKey(3), signingKey(4) }
/// libsignal serializes the version as `strconv.Itoa(3)` → ASCII '3' = 0x33
/// (high nibble = current version 3, low nibble = min version 3). We had
/// 0x35 hardcoded, which the official WA client silently rejects — SKDM
/// never registers on the peer, so subsequent skmsg always retries.
pub fn encode_axolotl_skdm(key_id: u32, iteration: u32, chain_key: &[u8; 32], signing_pub: &[u8; 32]) -> Vec<u8> {
    // libsignal SKDM `signingKey` is an EC point in DJB serialization:
    // `0x05 || pub32`. Sending bare 32 bytes makes `ecc.DecodePoint` parse
    // the first key byte as the type tag (typically 0xeb etc.), which isn't
    // 0x05 → peer drops the SKDM silently and subsequent skmsg retry forever.
    let mut signing_pub_djb = Vec::with_capacity(33);
    signing_pub_djb.push(0x05);
    signing_pub_djb.extend_from_slice(signing_pub);
    let mut body = Vec::new();
    body.extend(proto_varint(1, key_id as u64));
    body.extend(proto_varint(2, iteration as u64));
    body.extend(proto_bytes(3, chain_key));
    body.extend(proto_bytes(4, &signing_pub_djb));
    let mut out = vec![0x33];
    out.extend(body);
    out
}

/// Encode WAProto.Message with embedded SKDM. Per WAProto:
///   Message.senderKeyDistributionMessage = 2
///   Message.SenderKeyDistributionMessage.groupId = 1
///   Message.SenderKeyDistributionMessage.axolotlSenderKeyDistributionMessage = 2
/// We had the outer wrap at field 35, which the official client silently
/// ignores — peers never register our sender key, so every outgoing skmsg
/// reads as "esperando mensaje" and every incoming skmsg retries forever.
pub fn encode_wa_skdm_message(group_jid: &str, axolotl_bytes: &[u8]) -> Vec<u8> {
    let mut skdm = Vec::new();
    skdm.extend(proto_bytes(1, group_jid.as_bytes()));
    skdm.extend(proto_bytes(2, axolotl_bytes));
    proto_message(2, &skdm)
}

/// Encode + sign a SenderKeyMessage (skmsg).
/// Wire: version byte || proto { id(1), iteration(2), ciphertext(3) } || XEdDSA signature.
/// libsignal version byte is `fmt.Sprint(3)` → ASCII '3' = 0x33 (high nibble =
/// current version, low nibble = min version). We had 0x35 which the peer
/// treats as "unsupported version 5" and drops silently.
pub fn encode_skmsg_signed(key_id: u32, iteration: u32, ciphertext: &[u8], signing_priv: &[u8; 32]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend(proto_varint(1, key_id as u64));
    body.extend(proto_varint(2, iteration as u64));
    body.extend(proto_bytes(3, ciphertext));
    let mut msg = vec![0x33];
    msg.extend(&body);
    use xeddsa::{xed25519, Sign};
    let sig: [u8; 64] = xed25519::PrivateKey::from(signing_priv).sign(&msg, rand::rngs::OsRng);
    msg.extend_from_slice(&sig);
    msg
}

/// Decode the axolotlSenderKeyDistributionMessage field.
/// Wire: 1-byte version | proto { id(1), iteration(2), chainKey(3), signingKey(4) }
pub fn decode_axolotl_skdm(data: &[u8]) -> Option<AxolotlSkdm> {
    if data.len() < 2 { return None; }
    let body = &data[1..]; // skip version byte
    let fields = parse_proto_fields(body)?;
    let iteration = read_varint_from_bytes(fields.get(&2)?)? as u32;
    let chain_key = fields.get(&3)?.clone();
    if chain_key.len() != 32 { return None; }
    Some(AxolotlSkdm { iteration, chain_key })
}

/// Decode WAProto.Message sender-key distribution payload.
/// Supports:
///   - senderKeyDistributionMessage (field 2)
///   - fastRatchetKeySenderKeyDistributionMessage (field 15)
///   - deviceSentMessage wrapper (field 31) with inner Message field 2
/// Returns `(group_jid, axolotl_bytes)`.
pub fn decode_wa_skdm(data: &[u8]) -> Option<(String, Vec<u8>)> {
    let outer = parse_proto_fields(data)?;

    // Message.deviceSentMessage { destinationJid=1, message=2 }
    if let Some(dsm) = outer.get(&31) {
        if let Some(dsm_fields) = parse_proto_fields(dsm) {
            if let Some(inner) = dsm_fields.get(&2) {
                if let Some(found) = decode_wa_skdm(inner) {
                    return Some(found);
                }
            }
        }
    }

    for field_no in [2u64, 15u64] {
        if let Some(skdm) = outer.get(&field_no) {
            let sf = parse_proto_fields(skdm)?;
            let group_id = sf.get(&1).and_then(|b| String::from_utf8(b.clone()).ok())?;
            let axolotl = sf.get(&2)?.clone();
            return Some((group_id, axolotl));
        }
    }

    None
}

pub struct SkmsgHeader {
    pub iteration: u32,
    pub ciphertext: Vec<u8>,
}

/// Decode a SenderKeyMessage (enc type="skmsg").
/// Wire: 1-byte version | proto { id(1), iteration(2), ciphertext(3) } | 64-byte signature
pub fn decode_skmsg_header(data: &[u8]) -> Option<SkmsgHeader> {
    if data.len() < 2 { return None; }
    let inner = &data[1..]; // skip version byte
    // Strip trailing 64-byte XEdDSA signature so proto parser sees only the body
    let body = if inner.len() > 64 { &inner[..inner.len() - 64] } else { inner };
    let fields = parse_proto_fields(body)?;
    let iteration = read_varint_from_bytes(fields.get(&2)?)? as u32;
    let ciphertext = fields.get(&3)?.clone();
    Some(SkmsgHeader { iteration, ciphertext })
}

// ── SignalMessage header ──────────────────────────────────────────────────────

/// Encode a SignalMessage header protobuf (fields 1,2,3,4).
/// Format: 1=ratchetKey, 2=counter, 3=previousCounter.
/// ratchetKey is serialized in Signal's public-key form: `0x05 || 32-byte pub`.
pub fn encode_signal_header(ratchet_key: &[u8; 32], counter: u32, prev_counter: u32) -> Vec<u8> {
    let mut rk33 = Vec::with_capacity(33);
    rk33.push(0x05);
    rk33.extend_from_slice(ratchet_key);

    let mut hdr = Vec::new();
    hdr.extend(proto_bytes(1, &rk33));
    hdr.extend(proto_varint(2, counter as u64));
    hdr.extend(proto_varint(3, prev_counter as u64));
    hdr
}

/// Decode a SignalMessage header.
pub fn decode_signal_header(data: &[u8]) -> Option<([u8; 32], u32, u32)> {
    let fields = parse_proto_fields(data)?;
    // ratchetKey is serialized as `0x05 || 32-byte pubkey` (33 bytes).
    let rk_bytes = fields.get(&1)?;
    let slice: &[u8] = if rk_bytes.len() == 33 && rk_bytes[0] == 0x05 {
        &rk_bytes[1..]
    } else {
        rk_bytes.as_slice()
    };
    let rk: [u8; 32] = slice.try_into().ok()?;
    let counter = read_varint_from_bytes(fields.get(&2)?)? as u32;
    let prev = read_varint_from_bytes(fields.get(&3)?)? as u32;
    Some((rk, counter, prev))
}

// ── PreKeySignalMessage ───────────────────────────────────────────────────────

#[allow(dead_code)]
pub struct PreKeyMsgFields {
    pub registration_id: u32,
    pub pre_key_id: Option<u32>,
    pub signed_pre_key_id: u32,
    pub base_key: [u8; 32],
    pub identity_key: [u8; 32],
    pub message: Vec<u8>,
    pub device_id: u32,
}

pub fn decode_pre_key_message(data: &[u8]) -> Option<PreKeyMsgFields> {
    let fields = parse_proto_fields(data)?;

    // Signal serializes X25519 public keys as `0x05 || 32-byte pubkey` (33 bytes).
    // Strip that prefix before copying into our fixed-size array.
    let into32 = |b: &Vec<u8>| -> Option<[u8; 32]> {
        let slice: &[u8] = if b.len() == 33 && b[0] == 0x05 { &b[1..] } else { b.as_slice() };
        slice.try_into().ok()
    };

    Some(PreKeyMsgFields {
        pre_key_id:        fields.get(&1).and_then(|b| read_varint_from_bytes(b)).map(|v| v as u32),
        base_key:          into32(fields.get(&2)?)?,
        identity_key:      into32(fields.get(&3)?)?,
        message:           fields.get(&4)?.clone(),
        registration_id:   read_varint_from_bytes(fields.get(&5)?)? as u32,
        signed_pre_key_id: read_varint_from_bytes(fields.get(&6)?)? as u32,
        // device_id is not in the libsignal PreKeySignalMessage spec — tolerate absence.
        device_id:         fields.get(&7).and_then(|b| read_varint_from_bytes(b)).map(|v| v as u32).unwrap_or(0),
    })
}

// ── Protobuf helpers ──────────────────────────────────────────────────────────

pub fn proto_bytes(field: u64, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    write_varint(&mut out, (field << 3) | 2);
    write_varint(&mut out, data.len() as u64);
    out.extend_from_slice(data);
    out
}

pub fn proto_message(field: u64, data: &[u8]) -> Vec<u8> {
    proto_bytes(field, data)
}

pub fn proto_varint(field: u64, value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    write_varint(&mut out, (field << 3) | 0);
    write_varint(&mut out, value);
    out
}

/// Encode a protobuf `double` (wire type 1, fixed64, IEEE 754 little-endian).
pub fn proto_double(field: u64, value: f64) -> Vec<u8> {
    let mut out = Vec::new();
    write_varint(&mut out, (field << 3) | 1);
    out.extend_from_slice(&value.to_le_bytes());
    out
}

/// Write `data` as a length-prefixed blob into `buf` (no field tag).
pub fn write_proto_bytes_into(buf: &mut Vec<u8>, data: &[u8]) {
    write_varint(buf, data.len() as u64);
    buf.extend_from_slice(data);
}

fn write_varint(buf: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 { buf.push(b); break; } else { buf.push(b | 0x80); }
    }
}

/// Parse protobuf wire format preserving repeated fields (same tag appearing
/// multiple times). Returned as a flat list of (field_number, value_bytes).
///
/// For length-delimited fields (wire type 2) `value_bytes` is the payload.
/// For varints (type 0) `value_bytes` is the re-encoded varint (so callers
/// can run `read_varint_from_bytes` on it uniformly).
pub fn parse_proto_fields_repeated(data: &[u8]) -> Option<Vec<(u64, Vec<u8>)>> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let (tag, n) = read_varint_at(data, pos)?;
        pos += n;
        let field = tag >> 3;
        match tag & 7 {
            0 => {
                let (v, n) = read_varint_at(data, pos)?;
                pos += n;
                let mut buf = Vec::new();
                write_varint(&mut buf, v);
                out.push((field, buf));
            }
            1 => {
                if pos + 8 > data.len() { return None; }
                out.push((field, data[pos..pos + 8].to_vec()));
                pos += 8;
            }
            2 => {
                let (len, n) = read_varint_at(data, pos)?;
                pos += n;
                let end = pos + len as usize;
                if end > data.len() { return None; }
                out.push((field, data[pos..end].to_vec()));
                pos = end;
            }
            5 => {
                if pos + 4 > data.len() { return None; }
                out.push((field, data[pos..pos + 4].to_vec()));
                pos += 4;
            }
            _ => return None,
        }
    }
    Some(out)
}

pub fn parse_proto_fields(data: &[u8]) -> Option<std::collections::HashMap<u64, Vec<u8>>> {
    let mut map = std::collections::HashMap::new();
    let mut pos = 0;
    while pos < data.len() {
        let (tag, n) = read_varint_at(data, pos)?;
        pos += n;
        let field = tag >> 3;
        match tag & 7 {
            0 => {
                let (v, n) = read_varint_at(data, pos)?;
                pos += n;
                let mut buf = Vec::new();
                write_varint(&mut buf, v);
                map.insert(field, buf);
            }
            1 => {
                // 64-bit fixed — skip 8 bytes
                if pos + 8 > data.len() { return None; }
                map.insert(field, data[pos..pos + 8].to_vec());
                pos += 8;
            }
            2 => {
                let (len, n) = read_varint_at(data, pos)?;
                pos += n;
                let end = pos + len as usize;
                if end > data.len() { return None; }
                map.insert(field, data[pos..end].to_vec());
                pos = end;
            }
            5 => {
                // 32-bit fixed — skip 4 bytes
                if pos + 4 > data.len() { return None; }
                map.insert(field, data[pos..pos + 4].to_vec());
                pos += 4;
            }
            _ => return None, // wire types 3/4 are deprecated; bail
        }
    }
    Some(map)
}

fn read_varint_at(data: &[u8], mut pos: usize) -> Option<(u64, usize)> {
    let start = pos;
    let mut result = 0u64;
    let mut shift = 0;
    loop {
        if pos >= data.len() { return None; }
        let byte = data[pos]; pos += 1;
        result |= ((byte & 0x7f) as u64) << shift;
        shift += 7;
        if byte & 0x80 == 0 { break; }
    }
    Some((result, pos - start))
}

pub fn read_varint_from_bytes(data: &[u8]) -> Option<u64> {
    read_varint_at(data, 0).map(|(v, _)| v)
}

/// Like `parse_proto_fields` but keeps ALL entries for repeated fields.
fn parse_proto_repeated(data: &[u8]) -> Option<Vec<(u64, Vec<u8>)>> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let (tag, n) = read_varint_at(data, pos)?;
        pos += n;
        let field = tag >> 3;
        match tag & 7 {
            0 => {
                let (v, n) = read_varint_at(data, pos)?;
                pos += n;
                let mut buf = Vec::new();
                write_varint(&mut buf, v);
                out.push((field, buf));
            }
            1 => {
                if pos + 8 > data.len() { return None; }
                out.push((field, data[pos..pos + 8].to_vec()));
                pos += 8;
            }
            2 => {
                let (len, n) = read_varint_at(data, pos)?;
                pos += n;
                let end = pos + len as usize;
                if end > data.len() { return None; }
                out.push((field, data[pos..end].to_vec()));
                pos = end;
            }
            5 => {
                if pos + 4 > data.len() { return None; }
                out.push((field, data[pos..pos + 4].to_vec()));
                pos += 4;
            }
            _ => return None,
        }
    }
    Some(out)
}

// ── Protocol messages (revoke, edit, ephemeral, history sync) ────────────────

pub struct RevokeKey {
    pub remote_jid: String,
    pub from_me: bool,
    pub id: String,
    pub participant: Option<String>,
}

#[allow(dead_code)]
pub enum ProtocolMessagePayload {
    Revoke(RevokeKey),
    EphemeralSetting { expiration_secs: u32 },
    HistorySync(HistorySyncNotification),
    MessageEdit { key: RevokeKey, new_text: String },
    PeerDataOperationResponse { stanza_id: Option<String>, messages: Vec<HistoryMessage>, result_types: Vec<u32> },
    /// Primary device shared app-state sync keys with us. Each entry is
    /// `(keyId, keyData, timestamp_ms)`.
    AppStateSyncKeyShare(Vec<(Vec<u8>, Vec<u8>, i64)>),
    Unknown(u32),
}

/// Parse Message.protocolMessage (field 12) and return its payload.
pub fn decode_protocol_message(data: &[u8]) -> Option<ProtocolMessagePayload> {
    let msg = parse_proto_fields(data)?;
    let pm_bytes = msg.get(&12)?;
    let pm = parse_proto_fields(pm_bytes)?;

    let proto_type = pm.get(&2)
        .and_then(|b| read_varint_from_bytes(b))
        .unwrap_or(0) as u32;

    let parse_key = |pm: &std::collections::HashMap<u64, Vec<u8>>| -> Option<RevokeKey> {
        let key_bytes = pm.get(&1)?;
        let kf = parse_proto_fields(key_bytes)?;
        let remote_jid = kf.get(&1).and_then(|b| String::from_utf8(b.clone()).ok()).unwrap_or_default();
        if remote_jid.is_empty() { return None; }
        let from_me = kf.get(&2).and_then(|b| read_varint_from_bytes(b)).unwrap_or(0) != 0;
        let id = kf.get(&3).and_then(|b| String::from_utf8(b.clone()).ok()).unwrap_or_default();
        let participant = kf.get(&4).and_then(|b| String::from_utf8(b.clone()).ok());
        Some(RevokeKey { remote_jid, from_me, id, participant })
    };

    match proto_type {
        0 => {
            // REVOKE
            let key = parse_key(&pm)?;
            Some(ProtocolMessagePayload::Revoke(key))
        }
        3 => {
            // EPHEMERAL_SETTING — field 4 = ephemeralExpiration
            let secs = pm.get(&4).and_then(|b| read_varint_from_bytes(b)).unwrap_or(0) as u32;
            Some(ProtocolMessagePayload::EphemeralSetting { expiration_secs: secs })
        }
        5 => {
            // HISTORY_SYNC_NOTIFICATION — handled by decode_history_sync_notification
            let hsn = decode_hsn_from_pm(&pm)?;
            Some(ProtocolMessagePayload::HistorySync(hsn))
        }
        6 => {
            // APP_STATE_SYNC_KEY_SHARE — field 7 = appStateSyncKeyShare { repeated keys = 1 }
            let shares = crate::app_state::proto::decode_app_state_sync_key_share(&pm);
            Some(ProtocolMessagePayload::AppStateSyncKeyShare(shares))
        }
        14 => {
            // MESSAGE_EDIT — field 1 = key of original, field 14 = editedMessage
            let key = parse_key(&pm)?;
            let new_text = pm.get(&14)
                .and_then(|b| {
                    let mf = parse_proto_fields(b)?;
                    // field 1 = conversation text
                    mf.get(&1).and_then(|tb| String::from_utf8(tb.clone()).ok())
                })
                .unwrap_or_default();
            Some(ProtocolMessagePayload::MessageEdit { key, new_text })
        }
        17 => {
            // PEER_DATA_OPERATION_REQUEST_RESPONSE_MESSAGE — field 17
            let response_bytes = pm.get(&17)?;
            let response = parse_proto_fields(response_bytes)?;
            let response_type = response.get(&1).and_then(|b| read_varint_from_bytes(b)).unwrap_or(0);
            let stanza_id = response.get(&2).and_then(|b| String::from_utf8(b.clone()).ok());
            let mut messages = Vec::new();
            let mut result_count = 0usize;
            let mut result_types = Vec::new();
            for (field, bytes) in parse_proto_repeated(response_bytes)? {
                if field != 3 {
                    continue;
                }
                result_count += 1;
                let result = match parse_proto_fields(&bytes) {
                    Some(v) => v,
                    None => {
                        tracing::debug!("pdo decode: could not parse peerDataOperationResult");
                        continue;
                    }
                };
                let result_fields = parse_proto_repeated(&bytes)
                    .map(|entries| {
                        entries.into_iter()
                            .map(|(f, v)| format!("{f}({}B)", v.len()))
                            .collect::<Vec<_>>()
                            .join(",")
                    })
                    .unwrap_or_default();
                let result_type = result.get(&1).and_then(|b| read_varint_from_bytes(b)).unwrap_or(0);
                result_types.push(result_type as u32);
                let placeholder = match result.get(&4).and_then(|b| parse_proto_fields(b)) {
                    Some(v) => v,
                    None => {
                        tracing::debug!(
                            "pdo decode: result without placeholderMessageResendResponse result_type={} fields={result_fields}",
                            result_type,
                        );
                        continue;
                    }
                };
                let web_message_info = match placeholder.get(&1) {
                    Some(v) => v,
                    None => {
                        tracing::debug!("pdo decode: placeholderMessageResendResponse without webMessageInfoBytes");
                        continue;
                    }
                };
                if let Some(msg) = parse_web_message_info_partial(web_message_info) {
                    if msg.remote_jid.is_empty() {
                        tracing::debug!(
                            "pdo decode: accepted partial webMessageInfo id={} participant={:?} raw_message_len={}",
                            msg.id,
                            msg.participant,
                            msg.raw_message.as_ref().map(|b| b.len()).unwrap_or(0),
                        );
                    }
                    messages.push(msg);
                } else {
                    tracing::debug!(
                        "pdo decode: could not decode webMessageInfo len={}",
                        web_message_info.len(),
                    );
                }
            }
            tracing::debug!(
                "pdo decode: type={} stanza_id={stanza_id:?} results={result_count} decoded_messages={}",
                response_type,
                messages.len(),
            );
            Some(ProtocolMessagePayload::PeerDataOperationResponse { stanza_id, messages, result_types })
        }
        other => Some(ProtocolMessagePayload::Unknown(other)),
    }
}

// ── History sync ──────────────────────────────────────────────────────────────

#[allow(dead_code)]
pub struct HistorySyncNotification {
    pub direct_path: String,
    pub media_key: Vec<u8>,
    pub file_enc_sha256: Vec<u8>,
    pub file_sha256: Vec<u8>,
    pub file_length: u64,
    pub sync_type: u32,
    pub inline_payload: Option<Vec<u8>>,
}

/// Extract HistorySyncNotification from an already-parsed ProtocolMessage field map.
fn decode_hsn_from_pm(pm: &std::collections::HashMap<u64, Vec<u8>>) -> Option<HistorySyncNotification> {
    let hsn_bytes = pm.get(&6)?;
    let hsn = parse_proto_fields(hsn_bytes)?;

    let direct_path = hsn.get(&5).and_then(|b| String::from_utf8(b.clone()).ok()).unwrap_or_default();
    let media_key = hsn.get(&3).cloned().unwrap_or_default();
    let file_enc_sha256 = hsn.get(&4).cloned().unwrap_or_default();
    let file_sha256 = hsn.get(&1).cloned().unwrap_or_default();
    let file_length = hsn.get(&2).and_then(|b| read_varint_from_bytes(b)).unwrap_or(0);
    let sync_type = hsn.get(&6).and_then(|b| read_varint_from_bytes(b)).unwrap_or(0) as u32;
    let inline_payload = hsn.get(&11).cloned();

    Some(HistorySyncNotification { direct_path, media_key, file_enc_sha256, file_sha256, file_length, sync_type, inline_payload })
}

#[derive(Debug, Clone)]
pub struct HistoryPushName {
    pub jid: String,
    pub push_name: String,
}

#[derive(Debug, Clone)]
pub struct HistoryMessage {
    pub remote_jid: String,
    pub from_me: bool,
    pub id: String,
    pub participant: Option<String>,
    pub timestamp: u64,
    pub push_name: Option<String>,
    pub content: Option<crate::messages::MessageContent>,
    pub raw_message: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct HistoryChat {
    pub jid: String,
    pub name: Option<String>,
    pub unread_count: u32,
    pub last_msg_timestamp: u64,
}

pub struct HistorySyncData {
    pub sync_type: u32,
    pub push_names: Vec<HistoryPushName>,
    pub chats: Vec<HistoryChat>,
    pub messages: Vec<HistoryMessage>,
}

/// Parse an inflated HistorySync protobuf blob.
pub fn decode_history_sync(data: &[u8]) -> Option<HistorySyncData> {
    let entries = parse_proto_repeated(data)?;

    let sync_type = entries.iter()
        .find(|(f, _)| *f == 1)
        .and_then(|(_, b)| read_varint_from_bytes(b))
        .unwrap_or(0) as u32;

    let mut push_names = Vec::new();
    let mut chats = Vec::new();
    let mut messages = Vec::new();

    for (field, bytes) in &entries {
        match field {
            7 => {
                // Pushname: field 1 = id, field 2 = pushname
                if let Some(pn) = parse_proto_fields(bytes) {
                    let jid = pn.get(&1).and_then(|b| String::from_utf8(b.clone()).ok()).unwrap_or_default();
                    let push_name = pn.get(&2).and_then(|b| String::from_utf8(b.clone()).ok()).unwrap_or_default();
                    if !jid.is_empty() && !push_name.is_empty() {
                        push_names.push(HistoryPushName { jid, push_name });
                    }
                }
            }
            2 => {
                // Conversation: field 1 = id, field 2 = messages, field 5 = lastMsgTimestamp,
                //               field 6 = unreadCount, field 13 = name
                if let Some(conv) = parse_proto_fields(bytes) {
                    let jid = conv.get(&1).and_then(|b| String::from_utf8(b.clone()).ok()).unwrap_or_default();
                    if jid.is_empty() { continue; }

                    let name = conv.get(&13).and_then(|b| String::from_utf8(b.clone()).ok());
                    let unread_count = conv.get(&6).and_then(|b| read_varint_from_bytes(b)).unwrap_or(0) as u32;
                    let last_msg_timestamp = conv.get(&5).and_then(|b| read_varint_from_bytes(b)).unwrap_or(0);

                    chats.push(HistoryChat { jid: jid.clone(), name, unread_count, last_msg_timestamp });

                    // Parse embedded messages in conversation (field 2 repeated = HistorySyncMsg)
                    if let Some(conv_entries) = parse_proto_repeated(bytes) {
                        for (cf, cb) in conv_entries {
                            if cf != 2 { continue; }
                            // HistorySyncMsg: field 1 = WebMessageInfo
                            if let Some(hsm) = parse_proto_fields(&cb) {
                                if let Some(wmi_bytes) = hsm.get(&1) {
                                    if let Some(msg) = parse_web_message_info(wmi_bytes) {
                                        messages.push(msg);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    Some(HistorySyncData { sync_type, push_names, chats, messages })
}

/// Extract MediaInfo from an image/video/audio/document/sticker sub-message.
fn parse_media_info(data: &[u8]) -> Option<crate::messages::MediaInfo> {
    let f = parse_proto_fields(data)?;
    let url         = f.get(&1).and_then(|b| String::from_utf8(b.clone()).ok()).unwrap_or_default();
    let mimetype    = f.get(&2).and_then(|b| String::from_utf8(b.clone()).ok()).unwrap_or_default();
    let file_sha256 = f.get(&3).cloned().unwrap_or_default();
    let file_length = f.get(&4).and_then(|b| read_varint_from_bytes(b)).unwrap_or(0);
    let media_key   = f.get(&7).cloned().unwrap_or_default();
    let file_enc_sha256 = f.get(&9).cloned().unwrap_or_default();
    let direct_path = f.get(&15).and_then(|b| String::from_utf8(b.clone()).ok()).unwrap_or_default();
    if url.is_empty() && direct_path.is_empty() { return None; }
    Some(crate::messages::MediaInfo { url, direct_path, media_key, file_enc_sha256, file_sha256, file_length, mimetype })
}

fn parse_web_message_info(data: &[u8]) -> Option<HistoryMessage> {
    parse_web_message_info_inner(data, false)
}

fn parse_web_message_info_partial(data: &[u8]) -> Option<HistoryMessage> {
    parse_web_message_info_inner(data, true)
}

fn parse_web_message_info_inner(data: &[u8], allow_missing_remote_jid: bool) -> Option<HistoryMessage> {
    let fields = parse_proto_fields(data)?;

    // field 1 = MessageKey
    let key_bytes = fields.get(&1)?;
    let key = parse_proto_fields(key_bytes)?;
    let remote_jid = key.get(&1).and_then(|b| String::from_utf8(b.clone()).ok()).unwrap_or_default();
    let from_me = key.get(&2).and_then(|b| read_varint_from_bytes(b)).unwrap_or(0) != 0;
    let id = key.get(&3).and_then(|b| String::from_utf8(b.clone()).ok()).unwrap_or_default();
    let participant = key.get(&4).and_then(|b| String::from_utf8(b.clone()).ok());
    if remote_jid.is_empty() && !allow_missing_remote_jid {
        return None;
    }

    let timestamp = fields.get(&3).and_then(|b| read_varint_from_bytes(b)).unwrap_or(0);
    let push_name = fields.get(&19).and_then(|b| String::from_utf8(b.clone()).ok());

    // field 2 = Message
    let raw_message = fields.get(&2).cloned();
    let content = fields.get(&2).and_then(|msg_bytes| {
        let mf = parse_proto_fields(msg_bytes)?;

        // field 1 = conversation (plain text)
        if let Some(t) = mf.get(&1).and_then(|b| String::from_utf8(b.clone()).ok()) {
            return Some(crate::messages::MessageContent::Text { text: t, mentioned_jids: Vec::new() });
        }

        // ExtendedTextMessage = field 6 (canonical). Legacy: we used to
        // encode under 17, accept both for backward compat with our own
        // stored msgs.
        if let Some(ext_bytes) = mf.get(&6).or_else(|| mf.get(&17)) {
            if let Some(ef) = parse_proto_fields(ext_bytes) {
                let text = ef.get(&1).and_then(|b| String::from_utf8(b.clone()).ok()).unwrap_or_default();
                let url  = ef.get(&2).and_then(|b| String::from_utf8(b.clone()).ok()).unwrap_or_default();
                let title = ef.get(&5).and_then(|b| String::from_utf8(b.clone()).ok()).unwrap_or_default();
                let description = ef.get(&4).and_then(|b| String::from_utf8(b.clone()).ok()).unwrap_or_default();
                if !text.is_empty() {
                    if !url.is_empty() {
                        return Some(crate::messages::MessageContent::LinkPreview {
                            text, url, title, description, thumbnail_jpeg: ef.get(&8).cloned(),
                        });
                    }
                    let mentions = ef.get(&17)
                        .and_then(|ctx| parse_proto_repeated(ctx))
                        .map(|e| e.into_iter()
                            .filter(|(f, _)| *f == 15)
                            .filter_map(|(_, v)| String::from_utf8(v).ok())
                            .filter(|s| !s.is_empty())
                            .collect::<Vec<_>>())
                        .unwrap_or_default();
                    return Some(crate::messages::MessageContent::Text { text, mentioned_jids: mentions });
                }
            }
        }

        // ImageMessage = field 3.
        if let Some(info) = mf.get(&3).and_then(|b| parse_media_info(b)) {
            let caption = parse_proto_fields(mf.get(&3)?).ok_or(()).ok()
                .and_then(|f| f.get(&8).and_then(|b| String::from_utf8(b.clone()).ok()));
            return Some(crate::messages::MessageContent::Image { info, caption, view_once: false });
        }

        // VideoMessage = field 9 (canonical) / legacy 6.
        if let Some(info) = mf.get(&9).or_else(|| mf.get(&6)).and_then(|b| parse_media_info(b)) {
            let src = mf.get(&9).or_else(|| mf.get(&6))?;
            let caption = parse_proto_fields(src).ok_or(()).ok()
                .and_then(|f| f.get(&8).and_then(|b| String::from_utf8(b.clone()).ok()));
            return Some(crate::messages::MessageContent::Video { info, caption, view_once: false });
        }

        // AudioMessage = field 8 (canonical) / legacy 5.
        if let Some(info) = mf.get(&8).or_else(|| mf.get(&5)).and_then(|b| parse_media_info(b)) {
            // ptt flag lives inside the AudioMessage sub-proto at field 6 —
            // we don't decode it yet; default false so render picks the
            // normal audio-file UI.
            return Some(crate::messages::MessageContent::Audio { info, ptt: false });
        }

        // DocumentMessage = field 7 (canonical) / legacy 4.
        if let Some(info) = mf.get(&7).or_else(|| mf.get(&4)).and_then(|b| parse_media_info(b)) {
            let src = mf.get(&7).or_else(|| mf.get(&4))?;
            let file_name = parse_proto_fields(src).ok_or(()).ok()
                .and_then(|f| f.get(&30).and_then(|b| String::from_utf8(b.clone()).ok()))
                .unwrap_or_default();
            return Some(crate::messages::MessageContent::Document { info, file_name });
        }

        // StickerMessage = field 26 (canonical) / legacy 20.
        if let Some(info) = mf.get(&26).or_else(|| mf.get(&20)).and_then(|b| parse_media_info(b)) {
            return Some(crate::messages::MessageContent::Sticker { info });
        }

        // LocationMessage = field 5. Canonical layout:
        //   1 = latitude (double)  2 = longitude (double)  3 = name  4 = address.
        if let Some(loc) = mf.get(&5).and_then(|b| parse_proto_fields(b)) {
            let read_f64 = |k: u64| -> Option<f64> {
                let b = loc.get(&k)?;
                if b.len() == 8 { Some(f64::from_le_bytes([b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7]])) } else { None }
            };
            if let (Some(lat), Some(lon)) = (read_f64(1), read_f64(2)) {
                let name = loc.get(&3).and_then(|b| String::from_utf8(b.clone()).ok());
                let address = loc.get(&4).and_then(|b| String::from_utf8(b.clone()).ok());
                return Some(crate::messages::MessageContent::Location {
                    latitude: lat, longitude: lon, name, address,
                });
            }
        }

        // ContactMessage = field 4: 1 = displayName, 16 = vcard.
        if let Some(c) = mf.get(&4).and_then(|b| parse_proto_fields(b)) {
            let display_name = c.get(&1).and_then(|b| String::from_utf8(b.clone()).ok()).unwrap_or_default();
            let vcard = c.get(&16).and_then(|b| String::from_utf8(b.clone()).ok()).unwrap_or_default();
            if !display_name.is_empty() || !vcard.is_empty() {
                return Some(crate::messages::MessageContent::Contact { display_name, vcard });
            }
        }

        None
    });

    if remote_jid.is_empty() && participant.is_none() && id.is_empty() && raw_message.is_none() {
        return None;
    }

    Some(HistoryMessage { remote_jid, from_me, id, participant, timestamp, push_name, content, raw_message })
}

// ── Forward helpers ───────────────────────────────────────────────────────────

/// Encode a ContextInfo with isForwarded=true and forwardingScore=1.
fn forward_context_info() -> Vec<u8> {
    let mut ctx = Vec::new();
    ctx.extend(proto_varint(22, 1)); // isForwarded = true
    ctx.extend(proto_varint(6, 1));  // forwardingScore = 1
    ctx
}

/// Encode media fields with an injected forward contextInfo (field 17).
fn encode_media_fields_forwarded(info: &crate::messages::MediaInfo, caption: Option<&str>, extra: &[u8]) -> Vec<u8> {
    let ctx = forward_context_info();
    let mut all_extra = extra.to_vec();
    all_extra.extend(proto_message(17, &ctx)); // contextInfo
    encode_media_fields(info, caption, &all_extra)
}

/// Forward an image message. Canonical Message.imageMessage = 3.
pub fn encode_wa_forward_image(info: &crate::messages::MediaInfo, caption: Option<&str>) -> Vec<u8> {
    proto_message(3, &encode_media_fields_forwarded(info, caption, &[]))
}

/// Forward a video message. Canonical Message.videoMessage = 9.
pub fn encode_wa_forward_video(info: &crate::messages::MediaInfo, caption: Option<&str>) -> Vec<u8> {
    proto_message(9, &encode_media_fields_forwarded(info, caption, &[]))
}

/// Forward an audio message. Canonical Message.audioMessage = 8.
pub fn encode_wa_forward_audio(info: &crate::messages::MediaInfo) -> Vec<u8> {
    proto_message(8, &encode_media_fields_forwarded(info, None, &[]))
}

/// Forward a document message. Canonical Message.documentMessage = 7.
pub fn encode_wa_forward_document(info: &crate::messages::MediaInfo, file_name: &str) -> Vec<u8> {
    let extra = proto_bytes(30, file_name.as_bytes());
    proto_message(7, &encode_media_fields_forwarded(info, None, &extra))
}

/// Forward a text message (wrapped in ExtendedTextMessage with contextInfo).
pub fn encode_wa_forward_text(text: &str) -> Vec<u8> {
    let ctx = forward_context_info();
    let mut ext = Vec::new();
    ext.extend(proto_bytes(1, text.as_bytes())); // text
    ext.extend(proto_message(2, &ctx));          // contextInfo
    proto_message(17, &ext)
}

// ── Ephemeral setting ─────────────────────────────────────────────────────────

/// Encode a ProtocolMessage that sets ephemeral timer for a 1:1 chat.
/// `expiration_secs`: 0 = off, 86400 = 1d, 604800 = 7d, 7776000 = 90d.
pub fn encode_wa_ephemeral_setting(expiration_secs: u32) -> Vec<u8> {
    let mut pm = Vec::new();
    pm.extend(proto_varint(2, 4));                        // type = EPHEMERAL_SETTING (4)
    pm.extend(proto_varint(4, expiration_secs as u64));   // expirationDuration
    proto_message(12, &pm)
}
