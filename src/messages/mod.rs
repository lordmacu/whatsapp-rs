pub mod link_preview;
pub mod rate_limit;
pub mod recent_sends;
pub mod recv;
pub mod send;

use crate::binary::BinaryNode;
use crate::signal::SignalRepository;
use crate::socket::SocketSender;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::broadcast;


// ── Media info ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaInfo {
    pub url: String,
    pub direct_path: String,
    pub media_key: Vec<u8>,
    pub file_enc_sha256: Vec<u8>,
    pub file_sha256: Vec<u8>,
    pub file_length: u64,
    pub mimetype: String,
}

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WAMessage {
    pub key: MessageKey,
    pub message: Option<MessageContent>,
    pub message_timestamp: u64,
    pub status: MessageStatus,
    /// Push name provided by the sender (the `notify` attribute on the message node).
    pub push_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageKey {
    pub remote_jid: String,
    pub from_me: bool,
    pub id: String,
    pub participant: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct PendingPdoRetry {
    pub retry_key: String,
    pub orig: BinaryNode,
    pub to: String,
    pub msg_id: String,
    pub t: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageContent {
    Text {
        text: String,
        #[serde(default)]
        mentioned_jids: Vec<String>,
    },
    Image {
        info: MediaInfo,
        caption: Option<String>,
        /// "Ver una vez": receiver's WA client deletes the media from
        /// disk + UI after it's opened once. Default `false`.
        #[serde(default)]
        view_once: bool,
    },
    Video {
        info: MediaInfo,
        caption: Option<String>,
        #[serde(default)]
        view_once: bool,
    },
    Audio { info: MediaInfo, #[serde(default)] ptt: bool },
    Document { info: MediaInfo, file_name: String },
    Sticker { info: MediaInfo },
    Reaction { target_id: String, emoji: String },
    Reply { reply_to_id: String, text: String },
    Poll { question: String, options: Vec<String>, selectable_count: u32 },
    LinkPreview {
        text: String,
        url: String,
        title: String,
        description: String,
        thumbnail_jpeg: Option<Vec<u8>>,
    },
    Location {
        latitude: f64,
        longitude: f64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        address: Option<String>,
    },
    Contact {
        display_name: String,
        /// Full vCard 3.0 payload. Use [`MessageContent::contact_vcard`]
        /// to build a minimal one from name + phone.
        vcard: String,
    },
    /// Interactive message with up to 3 inline buttons. Modern consumer WA
    /// may render as plain text (buttons are reliable only for Business
    /// accounts); the `text` field duplicates into `contentText` so the
    /// fallback still looks right.
    Buttons {
        text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        footer: Option<String>,
        /// `(id, label)` pairs. `id` is what comes back in the response.
        buttons: Vec<(String, String)>,
    },
    /// Interactive "tap to open" list with titled sections of rows.
    List {
        title: String,
        description: String,
        /// Label of the button that opens the selection sheet.
        button_text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        footer: Option<String>,
        sections: Vec<ListSection>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListSection {
    pub title: String,
    pub rows: Vec<ListRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListRow {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub description: String,
}

impl MessageContent {
    /// Build a minimal vCard 3.0 from a display name + E.164 phone number.
    /// Convenience for `MessageContent::Contact`.
    pub fn contact_vcard(name: &str, phone_e164: &str) -> String {
        // WA expects the TEL line tagged `waid=<digits>` so it hyperlinks
        // the entry in the receiver's Contacts UI.
        let digits: String = phone_e164.chars().filter(|c| c.is_ascii_digit()).collect();
        format!(
            "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:{name}\r\nTEL;type=CELL;type=VOICE;waid={digits}:{phone_e164}\r\nEND:VCARD"
        )
    }
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
pub enum ReceiptType {
    Delivered,
    Read,
    ReadSelf,
    Sender,
}

impl ReceiptType {
    pub fn as_str(self) -> &'static str {
        match self {
            ReceiptType::Delivered => "delivered",
            ReceiptType::Read => "read",
            ReceiptType::ReadSelf => "read-self",
            ReceiptType::Sender => "sender",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PushName {
    pub jid: String,
    pub name: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ChatInfo {
    pub jid: String,
    pub name: Option<String>,
    pub unread_count: u32,
    pub last_msg_timestamp: u64,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum GroupUpdateKind {
    ParticipantsAdded(Vec<String>),
    ParticipantsRemoved(Vec<String>),
    ParticipantsPromoted(Vec<String>),
    ParticipantsDemoted(Vec<String>),
    SubjectChanged(String),
    DescriptionChanged(Option<String>),
    EphemeralChanged(u32),
    AnnounceModeChanged(bool),
    RestrictModeChanged(bool),
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum MessageEvent {
    /// Server sent `<success>` and we finished the post-login setup
    /// (pre-key upload + passive-active iq). The session is now usable for sending.
    Connected,
    NewMessage { msg: WAMessage },
    MessageUpdate { key: MessageKey, status: MessageStatus },
    Reaction { key: MessageKey, emoji: String, from_me: bool },
    Receipt { key: MessageKey, receipt_type: ReceiptType },
    Presence { jid: String, available: bool },
    Typing { jid: String, composing: bool },
    /// A message was revoked/deleted by the sender.
    MessageRevoke { key: MessageKey },
    /// A message was edited; `key` identifies the original message.
    MessageEdit { key: MessageKey, new_text: String },
    /// Disappearing-message timer changed in a 1:1 chat.
    EphemeralSetting { jid: String, expiration_secs: u32 },
    /// Group membership/metadata change.
    GroupUpdate { group_jid: String, kind: GroupUpdateKind },
    /// Someone voted on a poll we created.
    PollVote {
        /// Key of the incoming PollUpdateMessage (sender + chat).
        voter_key: MessageKey,
        /// ID of the original PollCreationMessage.
        poll_msg_id: String,
        /// Option names the voter selected (empty = deselect-all).
        selected_options: Vec<String>,
    },
    /// Batch of historical messages + push names + chat list delivered on connect.
    HistorySync {
        sync_type: u32,
        push_names: Vec<PushName>,
        chats: Vec<ChatInfo>,
        messages: Vec<WAMessage>,
    },
    /// The server terminated this session (conflict, device removed, logged out, etc.).
    /// When `reconnect` is false the reconnect loop will stop; credentials may be invalid.
    Disconnected { reason: String, reconnect: bool },
    /// The background loop is about to retry a connection. `attempt` is 1-based
    /// (first retry = 1); `delay` is how long we'll sleep before dialing.
    /// Surfaced so UIs / metrics can show "reconnecting in 4s (attempt 3)".
    Reconnecting { attempt: u32, delay: std::time::Duration },
    /// An app-state collection patch was applied. `collection` is the WhatsApp
    /// name ("critical_block", "regular", ...). `action` carries the decoded
    /// mutation (contact rename, pin, mute, archive, …).
    AppStateUpdate { collection: String, action: crate::app_state::SyncAction },
}

// ── MessageManager ────────────────────────────────────────────────────────────

pub struct MessageManager {
    pub(crate) socket: Arc<SocketSender>,
    pub(crate) signal: Arc<SignalRepository>,
    pub(crate) event_tx: broadcast::Sender<MessageEvent>,
    pub(crate) our_jid: String,
    pub(crate) our_lid: Option<String>,
    pub(crate) contacts: Arc<crate::contacts::ContactStore>,
    pub(crate) msg_store: Arc<crate::message_store::MessageStore>,
    pub(crate) poll_store: Arc<crate::poll_store::PollStore>,
    pub(crate) outbox: Arc<crate::outbox::OutboxStore>,
    /// Store for app-state sync keys delivered via `appStateSyncKeyShare`.
    /// None means "no app-state support configured" — messages carrying keys
    /// are logged and ignored.
    pub(crate) app_state_keys: Option<Arc<crate::app_state::AppStateKeyStore>>,
    pub(crate) app_state_sync: Option<Arc<crate::app_state::AppStateSync>>,
    /// Retry counts keyed by `message_id:participant_or_sender`. We follow
    /// WA Web/Baileys semantics: first retry is count=1 without `<keys>`,
    /// second occurrence escalates to count=2 with a full `<keys>` bundle.
    pub(crate) retry_ids: std::sync::Mutex<std::collections::HashMap<String, u32>>,
    /// Maps outgoing PDO request ids to the original message context so we can
    /// escalate to a second retry-with-keys immediately when the phone returns
    /// `NOT_FOUND`.
    pub(crate) pending_pdo_retries: Arc<std::sync::Mutex<std::collections::HashMap<String, PendingPdoRetry>>>,
    /// Ring cache of last ~256 outgoing messages. Answers incoming
    /// `<receipt type="retry">` from peer devices that missed the original.
    pub(crate) recent_sends: Arc<recent_sends::RecentSends>,
}

#[allow(dead_code)]
impl MessageManager {
    pub fn new(socket: Arc<SocketSender>, signal: Arc<SignalRepository>, our_jid: String) -> Self {
        let (event_tx, _) = broadcast::channel(256);
        let p = std::path::Path::new(".");
        let contacts  = Arc::new(crate::contacts::ContactStore::new(p).expect("contacts store"));
        let msg_store = Arc::new(crate::message_store::MessageStore::new(p).expect("msg store"));
        let poll_store = Arc::new(crate::poll_store::PollStore::new(p).expect("poll store"));
        let outbox = Arc::new(crate::outbox::OutboxStore::new(p).expect("outbox store"));
        Self {
            socket,
            signal,
            event_tx,
            our_jid,
            our_lid: None,
            contacts,
            msg_store,
            poll_store,
            outbox,
            app_state_keys: None,
            app_state_sync: None,
            retry_ids: std::sync::Mutex::new(std::collections::HashMap::new()),
            pending_pdo_retries: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            recent_sends: Arc::new(recent_sends::RecentSends::new()),
        }
    }

    pub fn with_tx(
        socket: Arc<SocketSender>,
        signal: Arc<SignalRepository>,
        our_jid: String,
        event_tx: broadcast::Sender<MessageEvent>,
    ) -> Self {
        let p = std::path::Path::new(".");
        let contacts  = Arc::new(crate::contacts::ContactStore::new(p).expect("contacts store"));
        let msg_store = Arc::new(crate::message_store::MessageStore::new(p).expect("msg store"));
        let poll_store = Arc::new(crate::poll_store::PollStore::new(p).expect("poll store"));
        let outbox = Arc::new(crate::outbox::OutboxStore::new(p).expect("outbox store"));
        Self {
            socket,
            signal,
            event_tx,
            our_jid,
            our_lid: None,
            contacts,
            msg_store,
            poll_store,
            outbox,
            app_state_keys: None,
            app_state_sync: None,
            retry_ids: std::sync::Mutex::new(std::collections::HashMap::new()),
            pending_pdo_retries: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            recent_sends: Arc::new(recent_sends::RecentSends::new()),
        }
    }

    pub fn with_tx_and_contacts(
        socket: Arc<SocketSender>,
        signal: Arc<SignalRepository>,
        our_jid: String,
        event_tx: broadcast::Sender<MessageEvent>,
        contacts: Arc<crate::contacts::ContactStore>,
    ) -> Self {
        let p = std::path::Path::new(".");
        let msg_store = Arc::new(crate::message_store::MessageStore::new(p).expect("msg store"));
        let poll_store = Arc::new(crate::poll_store::PollStore::new(p).expect("poll store"));
        let outbox = Arc::new(crate::outbox::OutboxStore::new(p).expect("outbox store"));
        Self {
            socket,
            signal,
            event_tx,
            our_jid,
            our_lid: None,
            contacts,
            msg_store,
            poll_store,
            outbox,
            app_state_keys: None,
            app_state_sync: None,
            retry_ids: std::sync::Mutex::new(std::collections::HashMap::new()),
            pending_pdo_retries: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            recent_sends: Arc::new(recent_sends::RecentSends::new()),
        }
    }

    pub fn with_stores(
        socket: Arc<SocketSender>,
        signal: Arc<SignalRepository>,
        our_jid: String,
        event_tx: broadcast::Sender<MessageEvent>,
        contacts: Arc<crate::contacts::ContactStore>,
        msg_store: Arc<crate::message_store::MessageStore>,
        poll_store: Arc<crate::poll_store::PollStore>,
        outbox: Arc<crate::outbox::OutboxStore>,
    ) -> Self {
        Self {
            socket,
            signal,
            event_tx,
            our_jid,
            our_lid: None,
            contacts,
            msg_store,
            poll_store,
            outbox,
            app_state_keys: None,
            app_state_sync: None,
            retry_ids: std::sync::Mutex::new(std::collections::HashMap::new()),
            pending_pdo_retries: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            recent_sends: Arc::new(recent_sends::RecentSends::new()),
        }
    }

    pub fn with_our_lid(mut self, our_lid: Option<String>) -> Self {
        self.our_lid = our_lid;
        self
    }

    pub fn subscribe(&self) -> broadcast::Receiver<MessageEvent> {
        self.event_tx.subscribe()
    }

    pub fn with_app_state(
        mut self,
        keys: Arc<crate::app_state::AppStateKeyStore>,
        sync: Arc<crate::app_state::AppStateSync>,
    ) -> Self {
        self.app_state_keys = Some(keys);
        self.app_state_sync = Some(sync);
        self
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

pub fn generate_message_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!("3EB0{}", hex::encode(bytes).to_uppercase())
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
