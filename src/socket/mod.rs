pub mod dispatch;
pub mod group;
pub mod media_upload;
pub mod prekey;
pub mod privacy;
pub mod usync;

use crate::auth::credentials::AuthCredentials;
use crate::binary::{decode_frame, encode_node, BinaryNode, NodeContent};
use crate::noise::{KeyPair as NoiseKeyPair, NoiseHandshake, RecvState, SendState, NOISE_WA_HEADER};
use anyhow::{bail, Result};
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::{oneshot, Mutex as AsyncMutex};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, protocol::Message},
};
use tracing::{debug, info};

const WS_URL: &str = "wss://web.whatsapp.com/ws/chat";
const WS_ORIGIN: &str = "https://web.whatsapp.com";

type WsStream = tokio_tungstenite::WebSocketStream<
    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
>;
type WsTx = futures_util::stream::SplitSink<WsStream, Message>;
type WsRx = futures_util::stream::SplitStream<WsStream>;

type PendingMap = Arc<Mutex<HashMap<String, oneshot::Sender<BinaryNode>>>>;

// ── SocketSender ─────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct SocketSender {
    tx: Arc<AsyncMutex<WsTx>>,
    state: Arc<AsyncMutex<SendState>>,
    pending: PendingMap,
    id_seq: Arc<AtomicU32>,
}

impl SocketSender {
    pub async fn send_node(&self, node: &BinaryNode) -> Result<()> {
        let encoded = encode_node(node);
        let encrypted = self.state.lock().await.encrypt(&encoded)?;
        let frame = build_frame(&encrypted);
        self.tx.lock().await.send(Message::Binary(frame)).await?;
        Ok(())
    }

    /// Send a node and wait for the IQ response matching its `id` attr.
    /// Times out after 60 seconds and returns an error. On a fresh connect
    /// the server often queues our iqs behind offline-message delivery, so
    /// 30 s was too short.
    pub async fn send_iq_await(&self, node: BinaryNode) -> Result<BinaryNode> {
        use tokio::time::{timeout, Duration};

        let id = node
            .attr("id")
            .ok_or_else(|| anyhow::anyhow!("node has no id attr"))?
            .to_string();
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(id.clone(), tx);
        self.send_node(&node).await?;
        match timeout(Duration::from_secs(60), rx).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => {
                self.pending.lock().unwrap().remove(&id);
                anyhow::bail!("IQ response channel closed (id={id})")
            }
            Err(_) => {
                self.pending.lock().unwrap().remove(&id);
                anyhow::bail!("IQ timeout after 60s (id={id})")
            }
        }
    }

    pub async fn send_iq_result(&self, id: &str, to: &str) -> Result<()> {
        self.send_node(&BinaryNode {
            tag: "iq".to_string(),
            attrs: vec![
                ("to".to_string(), to.to_string()),
                ("type".to_string(), "result".to_string()),
                ("id".to_string(), id.to_string()),
            ],
            content: NodeContent::None,
        })
        .await
    }

    pub fn next_id(&self) -> String {
        // Lowercase — server echoes ids in lowercase hex; our pending map is
        // keyed verbatim on the id we sent, so we need to send it in the same
        // form the server will reply with.
        format!("{:08x}", self.id_seq.fetch_add(1, Ordering::Relaxed))
    }

    /// Close the underlying WebSocket. The receive loop sees EOF on its next
    /// `recv_node` and breaks, which is what the caller wants when a
    /// liveness watchdog decides the socket has gone silent.
    pub async fn close(&self) {
        use futures_util::SinkExt;
        let _ = self.tx.lock().await.close().await;
    }

    /// Send `<iq xmlns="passive"><active/></iq>`. Baileys does this after <success>.
    pub async fn send_passive_active(&self) -> Result<()> {
        let id = self.next_id();
        let node = BinaryNode {
            tag: "iq".into(),
            attrs: vec![
                ("id".into(), id),
                ("to".into(), "s.whatsapp.net".into()),
                ("xmlns".into(), "passive".into()),
                ("type".into(), "set".into()),
            ],
            content: NodeContent::List(vec![BinaryNode {
                tag: "active".into(),
                attrs: vec![],
                content: NodeContent::None,
            }]),
        };
        self.send_iq_await(node).await.map(|_| ())
    }
}

// ── SocketReceiver ────────────────────────────────────────────────────────────

pub struct SocketReceiver {
    rx: WsRx,
    state: RecvState,
    pending: PendingMap,
    buf: Vec<u8>,
}

impl SocketReceiver {
    /// Read next application-level node.
    /// IQ responses for pending requests are silently resolved and not returned.
    pub async fn recv_node(&mut self) -> Result<Option<BinaryNode>> {
        loop {
            // Drain any pending frames from the buffer first
            if let Some(node) = self.try_next_from_buf()? {
                return Ok(Some(node));
            }

            // Need more data — read next WebSocket message
            match self.rx.next().await {
                Some(Ok(Message::Binary(data))) => {
                    self.buf.extend_from_slice(&data);
                }
                Some(Ok(_)) => continue,
                Some(Err(e)) => return Err(e.into()),
                None => return Ok(None),
            }
        }
    }

    fn try_next_from_buf(&mut self) -> Result<Option<BinaryNode>> {
        loop {
            if self.buf.len() < 3 {
                return Ok(None);
            }
            let frame_len = ((self.buf[0] as usize) << 16)
                | ((self.buf[1] as usize) << 8)
                | self.buf[2] as usize;

            if self.buf.len() < 3 + frame_len {
                return Ok(None); // wait for more data
            }

            let payload = self.buf[3..3 + frame_len].to_vec();
            self.buf.drain(..3 + frame_len);

            if frame_len == 0 {
                continue;
            }

            tracing::trace!("recv frame: frame_len={} buf_remaining={}", frame_len, self.buf.len());

            let decrypted = match self.state.decrypt(&payload) {
                Ok(d) => d,
                Err(e) => {
                    debug!("recv decrypt error (counter={}): {e}", self.state.counter);
                    continue;
                }
            };

            let node = match decode_frame(&decrypted) {
                Ok(n) => n,
                Err(e) => {
                    debug!("decode_frame skipped: {e}");
                    continue;
                }
            };

            // Intercept IQ responses for pending requests
            if node.tag == "iq" {
                if let Some(id) = node.attr("id") {
                    if let Some(tx) = self.pending.lock().unwrap().remove(id) {
                        let _ = tx.send(node);
                        continue;
                    }
                }
            }

            return Ok(Some(node));
        }
    }
}

// ── Connect ───────────────────────────────────────────────────────────────────

pub async fn connect(creds: &AuthCredentials) -> Result<(SocketSender, SocketReceiver)> {
    info!("connecting to {}", WS_URL);

    let mut req = WS_URL.into_client_request()?;
    req.headers_mut().insert("Origin", WS_ORIGIN.parse()?);
    req.headers_mut().insert(
        "User-Agent",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
         AppleWebKit/537.36 (KHTML, like Gecko) \
         Chrome/124.0.0.0 Safari/537.36"
            .parse()?,
    );

    let (mut ws, _) = connect_async(req).await?;
    info!("websocket connected");

    // ── Noise handshake ───────────────────────────────────────────────────────
    let noise_key = NoiseKeyPair {
        public: creds.noise_key.public,
        private: creds.noise_key.private,
    };

    let mut hs = NoiseHandshake::new();
    hs.mix_into_hash(&NOISE_WA_HEADER);
    hs.mix_into_hash(&hs.ephemeral.public.clone());

    let client_hello = build_client_hello(&hs.ephemeral.public);
    ws.send(Message::Binary(build_intro_frame(&client_hello))).await?;
    debug!("sent ClientHello");

    let server_frame = recv_raw_frame(&mut ws).await?;
    let sh = parse_server_hello(&server_frame)?;
    debug!("received ServerHello");

    let server_eph: [u8; 32] = sh
        .ephemeral
        .try_into()
        .map_err(|_| anyhow::anyhow!("bad server ephemeral"))?;
    hs.mix_into_hash(&server_eph);
    let dh1 = hs.dh(&server_eph);
    hs.mix_shared_secret(&dh1);

    let server_static_bytes = hs.decrypt(&sh.static_enc)
        .map_err(|e| anyhow::anyhow!("decrypt static: {e}"))?;
    let server_static: [u8; 32] = server_static_bytes[..32]
        .try_into()
        .map_err(|_| anyhow::anyhow!("bad server static"))?;
    let dh2 = hs.dh(&server_static);
    hs.mix_shared_secret(&dh2);

    let _cert = hs.decrypt(&sh.payload)
        .map_err(|e| anyhow::anyhow!("decrypt cert: {e}"))?;

    let noise_static_enc = hs.encrypt(&noise_key.public)?;
    let dh3 = hs.dh_static(&noise_key.private, &server_eph);
    hs.mix_shared_secret(&dh3);

    let payload_enc = hs.encrypt(&build_client_payload(creds))?;
    let finish = build_client_finish(noise_static_enc, payload_enc);
    ws.send(Message::Binary(build_frame(&finish))).await?;
    debug!("sent ClientFinish");

    let transport = hs.into_transport()?;
    info!("noise handshake complete");

    let (send_state, recv_state) = transport.split();
    let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));

    let (ws_tx, ws_rx) = ws.split();
    let sender = SocketSender {
        tx: Arc::new(AsyncMutex::new(ws_tx)),
        state: Arc::new(AsyncMutex::new(send_state)),
        pending: pending.clone(),
        id_seq: Arc::new(AtomicU32::new(1)),
    };
    let receiver = SocketReceiver {
        rx: ws_rx,
        state: recv_state,
        pending,
        buf: Vec::new(),
    };
    Ok((sender, receiver))
}

// ── Frame helpers ─────────────────────────────────────────────────────────────

fn build_frame(payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut f = Vec::with_capacity(3 + len);
    f.push((len >> 16) as u8);
    f.push((len >> 8) as u8);
    f.push(len as u8);
    f.extend_from_slice(payload);
    f
}

fn build_intro_frame(payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(4 + 3 + payload.len());
    f.extend_from_slice(&NOISE_WA_HEADER);
    let len = payload.len();
    f.push((len >> 16) as u8);
    f.push((len >> 8) as u8);
    f.push(len as u8);
    f.extend_from_slice(payload);
    f
}

async fn recv_raw_frame(ws: &mut WsStream) -> Result<Vec<u8>> {
    while let Some(msg) = ws.next().await {
        if let Message::Binary(data) = msg? {
            if data.len() >= 3 {
                return Ok(data[3..].to_vec());
            }
        }
    }
    bail!("websocket closed before frame received")
}

// ── ClientPayload ─────────────────────────────────────────────────────────────

const WA_VERSION: [u32; 3] = [2, 3000, 1035194821];

fn build_client_payload(creds: &AuthCredentials) -> Vec<u8> {
    // If we already have a `me` JID, this is a reconnect → LOGIN node. Otherwise REGISTRATION.
    match creds.me.as_ref() {
        Some(me) => build_login_payload(&me.id),
        None => build_registration_payload(creds),
    }
}

fn build_registration_payload(creds: &AuthCredentials) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend(proto_varint(3, 0));                   // passive = false
    p.extend(proto_msg(5, &build_user_agent()));    // userAgent
    p.extend(proto_msg(6, &build_web_info()));      // webInfo
    p.extend(proto_varint(12, 1));                  // connectType = WIFI_UNKNOWN
    p.extend(proto_varint(13, 1));                  // connectReason = USER_ACTIVATED
    p.extend(proto_msg(19, &build_device_pairing(creds)));
    p.extend(proto_varint(33, 0));                  // pull = false
    p
}

fn build_login_payload(jid: &str) -> Vec<u8> {
    let (user_num, device) = parse_user_device(jid);
    let mut p = Vec::new();
    if let Some(u) = user_num {
        p.extend(proto_varint(1, u));               // username (uint64)
    }
    p.extend(proto_varint(3, 1));                   // passive = true
    p.extend(proto_msg(5, &build_user_agent()));
    p.extend(proto_msg(6, &build_web_info()));
    p.extend(proto_varint(12, 1));                  // connectType
    p.extend(proto_varint(13, 1));                  // connectReason
    if device > 0 {
        p.extend(proto_varint(18, device as u64));  // device
    }
    p.extend(proto_varint(33, 1));                  // pull = true
    p.extend(proto_varint(41, 0));                  // lidDbMigrated = false
    p
}

/// Parse a JID of the form `user[:device]@server` into (user_num, device).
fn parse_user_device(jid: &str) -> (Option<u64>, u32) {
    let before_at = jid.split('@').next().unwrap_or("");
    let mut parts = before_at.splitn(2, ':');
    let user_part = parts.next().unwrap_or("");
    let device_part = parts.next().unwrap_or("0");
    let user = user_part.parse::<u64>().ok();
    let device = device_part.parse::<u32>().unwrap_or(0);
    (user, device)
}

fn build_user_agent() -> Vec<u8> {
    let mut ua = Vec::new();
    ua.extend(proto_varint(1, 14)); // platform = WEB
    let mut av = Vec::new();
    av.extend(proto_varint(1, WA_VERSION[0] as u64));
    av.extend(proto_varint(2, WA_VERSION[1] as u64));
    av.extend(proto_varint(3, WA_VERSION[2] as u64));
    ua.extend(proto_msg(2, &av));   // appVersion
    ua.extend(proto_varint(10, 0)); // releaseChannel = RELEASE
    ua.extend(proto_bytes(11, b"en"));
    ua.extend(proto_bytes(12, b"US"));
    ua
}

fn build_web_info() -> Vec<u8> {
    let mut wi = Vec::new();
    wi.extend(proto_varint(4, 0)); // webSubPlatform = WEB_BROWSER
    wi
}

fn build_device_pairing(creds: &AuthCredentials) -> Vec<u8> {
    let build_hash = md5_of_version();
    let device_props = build_device_props();

    let mut rd = Vec::new();
    rd.extend(proto_bytes(1, &(creds.registration_id as u32).to_be_bytes()));
    rd.extend(proto_bytes(2, &[0x05u8]));           // eKeytype = KEY_BUNDLE_TYPE
    rd.extend(proto_bytes(3, &creds.signed_identity_key.public));
    rd.extend(proto_bytes(4, &encode_big_endian_3(creds.signed_pre_key.key_id)));
    rd.extend(proto_bytes(5, &creds.signed_pre_key.key_pair.public));
    let sig = if creds.signed_pre_key.signature.is_empty() {
        vec![0u8; 64]
    } else {
        creds.signed_pre_key.signature.clone()
    };
    rd.extend(proto_bytes(6, &sig));
    rd.extend(proto_bytes(7, &build_hash));
    rd.extend(proto_bytes(8, &device_props));
    rd
}

fn encode_big_endian_3(v: u32) -> [u8; 3] {
    [(v >> 16) as u8, (v >> 8) as u8, v as u8]
}

fn md5_of_version() -> [u8; 16] {
    let version_str = format!("{}.{}.{}", WA_VERSION[0], WA_VERSION[1], WA_VERSION[2]);
    *md5::compute(version_str.as_bytes())
}

fn build_device_props() -> Vec<u8> {
    let mut dp = Vec::new();
    dp.extend(proto_bytes(1, b"Mac OS"));  // os
    // version (field 2): primary=10, secondary=15, tertiary=7
    let mut dv = Vec::new();
    dv.extend(proto_varint(1, 10));
    dv.extend(proto_varint(2, 15));
    dv.extend(proto_varint(3, 7));
    dp.extend(proto_msg(2, &dv));
    dp.extend(proto_varint(3, 1)); // platformType = CHROME
    dp.extend(proto_varint(4, 0)); // requireFullSync = false
    // historySyncConfig (field 5)
    let mut hs = Vec::new();
    hs.extend(proto_varint(3, 10240)); // storageQuotaMb
    hs.extend(proto_varint(4, 1));     // inlineInitialPayloadInE2EeMsg
    hs.extend(proto_varint(7, 1));     // supportBotUserAgentChatHistory
    hs.extend(proto_varint(8, 1));     // supportCagReactionsAndPolls
    hs.extend(proto_varint(9, 1));     // supportBizHostedMsg
    hs.extend(proto_varint(10, 1));    // supportRecentSyncChunkMessageCountTuning
    hs.extend(proto_varint(11, 1));    // supportHostedGroupMsg
    hs.extend(proto_varint(12, 1));    // supportFbidBotChatHistory
    hs.extend(proto_varint(14, 1));    // supportMessageAssociation
    dp.extend(proto_msg(5, &hs));
    dp
}

// ── Handshake protos ──────────────────────────────────────────────────────────

fn build_client_hello(eph: &[u8; 32]) -> Vec<u8> {
    proto_msg(2, &proto_bytes(1, eph))
}

fn build_client_finish(static_enc: Vec<u8>, payload_enc: Vec<u8>) -> Vec<u8> {
    let mut inner = Vec::new();
    inner.extend(proto_bytes(1, &static_enc));
    inner.extend(proto_bytes(2, &payload_enc));
    proto_msg(4, &inner)
}

struct ServerHello {
    ephemeral: Vec<u8>,
    static_enc: Vec<u8>,
    payload: Vec<u8>,
}

fn parse_server_hello(data: &[u8]) -> Result<ServerHello> {
    let outer = parse_proto(data)?;
    let inner = parse_proto(
        outer
            .get(&3)
            .ok_or_else(|| anyhow::anyhow!("no serverHello"))?,
    )?;
    Ok(ServerHello {
        ephemeral: inner
            .get(&1)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no ephemeral"))?,
        static_enc: inner
            .get(&2)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no static"))?,
        payload: inner
            .get(&3)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no payload"))?,
    })
}

// ── Protobuf manual ───────────────────────────────────────────────────────────

pub fn proto_bytes(field: u64, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    write_varint(&mut out, (field << 3) | 2);
    write_varint(&mut out, data.len() as u64);
    out.extend_from_slice(data);
    out
}

pub fn proto_msg(field: u64, data: &[u8]) -> Vec<u8> {
    proto_bytes(field, data)
}

pub fn proto_varint(field: u64, value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    write_varint(&mut out, (field << 3) | 0);
    write_varint(&mut out, value);
    out
}

fn write_varint(buf: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            buf.push(b);
            break;
        } else {
            buf.push(b | 0x80);
        }
    }
}

pub fn parse_proto(data: &[u8]) -> Result<HashMap<u64, Vec<u8>>> {
    let mut map = HashMap::new();
    let mut pos = 0;
    while pos < data.len() {
        let (tag, n) = read_varint_at(data, pos)?;
        pos += n;
        match tag & 7 {
            0 => {
                let (_, n) = read_varint_at(data, pos)?;
                pos += n;
            }
            2 => {
                let (len, n) = read_varint_at(data, pos)?;
                pos += n;
                let end = pos + len as usize;
                if end > data.len() {
                    bail!("proto overflow");
                }
                map.insert(tag >> 3, data[pos..end].to_vec());
                pos = end;
            }
            _ => bail!("unsupported wire type {}", tag & 7),
        }
    }
    Ok(map)
}

pub fn read_varint_at(data: &[u8], mut pos: usize) -> Result<(u64, usize)> {
    let start = pos;
    let mut result = 0u64;
    let mut shift = 0;
    loop {
        if pos >= data.len() {
            bail!("varint truncated");
        }
        let b = data[pos];
        pos += 1;
        result |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            break;
        }
    }
    Ok((result, pos - start))
}
