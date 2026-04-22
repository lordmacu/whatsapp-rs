use crate::binary::{BinaryNode, NodeContent};
use crate::socket::SocketSender;
use anyhow::Result;
use serde::{Deserialize, Serialize};

// ── Types ─────────────────────────────────────────────────────────────────────

/// Visibility for last-seen, profile picture, status text, and group-add settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyValue {
    /// Visible to everyone.
    All,
    /// Visible to your saved contacts only.
    Contacts,
    /// Visible to contacts except those you've excluded.
    ContactBlacklist,
    /// Visible to nobody.
    None,
    /// For `online` setting: mirror your `last_seen` setting.
    MatchLastSeen,
}

impl PrivacyValue {
    fn as_str(&self) -> &'static str {
        match self {
            Self::All              => "all",
            Self::Contacts         => "contacts",
            Self::ContactBlacklist => "contact_blacklist",
            Self::None             => "none",
            Self::MatchLastSeen    => "match_last_seen",
        }
    }

    fn from_str(s: &str) -> Self {
        match s {
            "contacts"         => Self::Contacts,
            "contact_blacklist" => Self::ContactBlacklist,
            "none"             => Self::None,
            "match_last_seen"  => Self::MatchLastSeen,
            _                  => Self::All,
        }
    }
}

/// Complete snapshot of account privacy settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacySettings {
    /// Who can see when you were last online.
    pub last_seen: PrivacyValue,
    /// Who can see your online status while you are active.
    pub online: PrivacyValue,
    /// Who can see your profile picture.
    pub profile_picture: PrivacyValue,
    /// Who can see your about/status text.
    pub status: PrivacyValue,
    /// Whether read receipts are sent (blue ticks).
    /// `All` = send receipts; `None` = disable.
    pub read_receipts: PrivacyValue,
    /// Who can add you to groups.
    pub group_add: PrivacyValue,
    /// Who can add you to calls.
    pub call_add: PrivacyValue,
}

impl Default for PrivacySettings {
    fn default() -> Self {
        Self {
            last_seen:     PrivacyValue::All,
            online:        PrivacyValue::All,
            profile_picture: PrivacyValue::All,
            status:        PrivacyValue::All,
            read_receipts: PrivacyValue::All,
            group_add:     PrivacyValue::All,
            call_add:      PrivacyValue::All,
        }
    }
}

// ── IQ helpers ────────────────────────────────────────────────────────────────

/// Fetch current privacy settings from the server.
pub async fn fetch_privacy(sender: &SocketSender) -> Result<PrivacySettings> {
    let id = sender.next_id();
    let node = BinaryNode {
        tag: "iq".to_string(),
        attrs: vec![
            ("id".to_string(), id.clone()),
            ("type".to_string(), "get".to_string()),
            ("xmlns".to_string(), "privacy".to_string()),
            ("to".to_string(), "s.whatsapp.net".to_string()),
        ],
        content: NodeContent::List(vec![BinaryNode {
            tag: "privacy".to_string(),
            attrs: vec![],
            content: NodeContent::None,
        }]),
    };

    let response = sender.send_iq_await(node).await?;
    parse_privacy_response(&response)
}

/// Update one or more privacy categories on the server.
///
/// Only the fields that are `Some` are sent; `None` fields are left unchanged.
pub async fn set_privacy(sender: &SocketSender, settings: &PrivacyPatch) -> Result<()> {
    let mut categories = Vec::new();

    macro_rules! add {
        ($field:expr, $name:literal) => {
            if let Some(ref v) = $field {
                categories.push(BinaryNode {
                    tag: "category".to_string(),
                    attrs: vec![
                        ("name".to_string(), $name.to_string()),
                        ("value".to_string(), v.as_str().to_string()),
                    ],
                    content: NodeContent::None,
                });
            }
        };
    }

    add!(settings.last_seen,       "last");
    add!(settings.online,          "online");
    add!(settings.profile_picture, "profile");
    add!(settings.status,          "status");
    add!(settings.read_receipts,   "readreceipts");
    add!(settings.group_add,       "groupadd");
    add!(settings.call_add,        "calladd");

    if categories.is_empty() {
        return Ok(());
    }

    let id = sender.next_id();
    let node = BinaryNode {
        tag: "iq".to_string(),
        attrs: vec![
            ("id".to_string(), id),
            ("type".to_string(), "set".to_string()),
            ("xmlns".to_string(), "privacy".to_string()),
            ("to".to_string(), "s.whatsapp.net".to_string()),
        ],
        content: NodeContent::List(vec![BinaryNode {
            tag: "privacy".to_string(),
            attrs: vec![],
            content: NodeContent::List(categories),
        }]),
    };

    let _response = sender.send_iq_await(node).await?;
    Ok(())
}

/// Sparse update — only set the fields you want to change.
#[derive(Debug, Default)]
pub struct PrivacyPatch {
    pub last_seen:       Option<PrivacyValue>,
    pub online:          Option<PrivacyValue>,
    pub profile_picture: Option<PrivacyValue>,
    pub status:          Option<PrivacyValue>,
    pub read_receipts:   Option<PrivacyValue>,
    pub group_add:       Option<PrivacyValue>,
    pub call_add:        Option<PrivacyValue>,
}

// ── Parsing ───────────────────────────────────────────────────────────────────

fn parse_privacy_response(node: &BinaryNode) -> Result<PrivacySettings> {
    let mut s = PrivacySettings::default();

    let privacy_node = match &node.content {
        NodeContent::List(ch) => ch.iter().find(|n| n.tag == "privacy").cloned(),
        _ => None,
    }
    .ok_or_else(|| anyhow::anyhow!("no <privacy> in response"))?;

    if let NodeContent::List(categories) = &privacy_node.content {
        for cat in categories {
            let name  = cat.attr("name").unwrap_or("");
            let value = cat.attr("value").unwrap_or("all");
            let v = PrivacyValue::from_str(value);
            match name {
                "last"         => s.last_seen        = v,
                "online"       => s.online           = v,
                "profile"      => s.profile_picture  = v,
                "status"       => s.status           = v,
                "readreceipts" => s.read_receipts     = v,
                "groupadd"     => s.group_add         = v,
                "calladd"      => s.call_add          = v,
                _              => {}
            }
        }
    }

    Ok(s)
}
