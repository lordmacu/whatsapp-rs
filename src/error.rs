//! Public error type for the high-level client API.
//!
//! The internal modules still use `anyhow::Result` for convenience — this
//! enum exists so callers of [`crate::Client`] / [`crate::Session`] /
//! [`crate::Chat`] get a typed error they can match on for the common
//! cases (not paired, bad JID, timeout, message not found) without
//! stringly-typed matching on `anyhow::Error`.
//!
//! `WaError: From<anyhow::Error>` is intentional: internal `?` in public
//! methods coerces seamlessly, so the migration is incremental. Chokepoints
//! that want typed variants construct them directly.

use std::time::Duration;

/// All errors returned by the public client API.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WaError {
    /// Device credentials don't exist yet. Run `whatsapp-rs listen` and
    /// scan the QR (or `pair-phone`) before starting the daemon.
    #[error("not paired yet — scan QR via `whatsapp-rs listen` first")]
    NotPaired,

    /// The socket isn't connected (disconnected, never connected, or
    /// shutting down).
    #[error("not connected to WhatsApp")]
    NotConnected,

    /// A JID passed in by the caller didn't parse / route correctly.
    #[error("invalid JID: {0}")]
    InvalidJid(String),

    /// Generic caller-input validation failure (empty string, out-of-range,
    /// etc.). Prefer more specific variants when they fit.
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// The caller referenced a message id we don't have cached.
    #[error("message not found: {0}")]
    MessageNotFound(String),

    /// Timed out waiting for a reply / status / IQ response.
    #[error("timed out after {0:?}")]
    Timeout(Duration),

    /// XMPP / binary-protocol framing or IQ error from the server.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Signal / Noise / AES / HKDF failure — the other end's message
    /// couldn't be decrypted, or our encryption failed.
    #[error("crypto error: {0}")]
    Crypto(String),

    /// Media upload/download path: bad URL, wrong MIME, decrypt mismatch.
    #[error("media error: {0}")]
    Media(String),

    /// WhatsApp server returned `<error code="…" text="…"/>`.
    #[error("server error {code}{}", .reason.as_deref().map(|r| format!(" — {r}")).unwrap_or_default())]
    Server { code: u16, reason: Option<String> },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// Fallback wrapper so internal `?` from `anyhow::Result` call sites
    /// still compiles. Callers can `.downcast_ref::<WaError>()` on the
    /// inner if needed.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Convenience alias for the public API.
pub type Result<T, E = WaError> = std::result::Result<T, E>;

impl WaError {
    /// Shorthand for `WaError::InvalidJid`. Takes anything `Display`.
    pub fn invalid_jid(jid: impl std::fmt::Display) -> Self {
        WaError::InvalidJid(jid.to_string())
    }

    /// Shorthand for `WaError::InvalidInput`.
    pub fn invalid_input(msg: impl std::fmt::Display) -> Self {
        WaError::InvalidInput(msg.to_string())
    }

    /// Shorthand for `WaError::MessageNotFound`.
    pub fn message_not_found(id: impl std::fmt::Display) -> Self {
        WaError::MessageNotFound(id.to_string())
    }

    /// Shorthand for `WaError::Protocol`.
    pub fn protocol(msg: impl std::fmt::Display) -> Self {
        WaError::Protocol(msg.to_string())
    }
}
