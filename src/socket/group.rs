use crate::binary::{BinaryNode, NodeContent};
use crate::socket::SocketSender;
use anyhow::{bail, Result};

#[derive(Debug, Clone)]
pub struct ParticipantInfo {
    pub jid: String,
    pub is_admin: bool,
    pub is_super_admin: bool,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct GroupInfo {
    pub jid: String,
    pub name: String,
    pub description: Option<String>,
    pub creation_timestamp: u64,
    pub participants: Vec<ParticipantInfo>,
    pub ephemeral_duration: Option<u32>,
}

/// Fetch full group info (name, description, participants, metadata).
pub async fn fetch_group_info(sender: &SocketSender, group_jid: &str) -> Result<GroupInfo> {
    let id = sender.next_id();
    let node = BinaryNode {
        tag: "iq".to_string(),
        attrs: vec![
            ("id".to_string(), id),
            ("type".to_string(), "get".to_string()),
            ("xmlns".to_string(), "w:g2".to_string()),
            ("to".to_string(), group_jid.to_string()),
        ],
        content: NodeContent::List(vec![BinaryNode {
            tag: "query".to_string(),
            attrs: vec![("request".to_string(), "interactive".to_string())],
            content: NodeContent::None,
        }]),
    };
    let response = sender.send_iq_await(node).await?;
    parse_group_info(&response, group_jid)
}

/// Fetch only the participant JIDs for a group (used internally for SKDM distribution).
pub async fn fetch_group_participants(sender: &SocketSender, group_jid: &str) -> Result<Vec<String>> {
    let info = fetch_group_info(sender, group_jid).await?;
    Ok(info.participants.into_iter().map(|p| p.jid).collect())
}

fn parse_group_info(node: &BinaryNode, group_jid: &str) -> Result<GroupInfo> {
    let group_node = match &node.content {
        NodeContent::List(ch) => ch.iter().find(|n| n.tag == "group"),
        _ => None,
    };

    let g = match group_node {
        Some(n) => n,
        None => anyhow::bail!("no <group> node in response"),
    };

    let name = g.attr("subject").unwrap_or("").to_string();
    let creation_timestamp: u64 = g.attr("creation")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let mut description: Option<String> = None;
    let mut participants = Vec::new();
    let mut ephemeral_duration: Option<u32> = None;

    if let NodeContent::List(children) = &g.content {
        for child in children {
            match child.tag.as_str() {
                "participant" => {
                    if let Some(jid) = child.attr("jid") {
                        let role = child.attr("type").unwrap_or("member");
                        participants.push(ParticipantInfo {
                            jid: jid.to_string(),
                            is_admin: role == "admin" || role == "superadmin",
                            is_super_admin: role == "superadmin",
                        });
                    }
                }
                "description" => {
                    description = if let NodeContent::List(gc) = &child.content {
                        gc.iter().find(|n| n.tag == "body").and_then(|b| {
                            match &b.content {
                                NodeContent::Text(t) => Some(t.clone()),
                                NodeContent::Bytes(b) => String::from_utf8(b.clone()).ok(),
                                _ => None,
                            }
                        })
                    } else {
                        None
                    };
                }
                "ephemeral" => {
                    ephemeral_duration = child.attr("period")
                        .and_then(|s| s.parse().ok());
                }
                _ => {}
            }
        }
    }

    Ok(GroupInfo {
        jid: group_jid.to_string(),
        name,
        description,
        creation_timestamp,
        participants,
        ephemeral_duration,
    })
}

// ── Participant results ───────────────────────────────────────────────────────

/// Per-participant result from add/remove/promote/demote operations.
/// `error` is `None` on success, or the server error code string on failure.
#[derive(Debug, Clone)]
pub struct ParticipantResult {
    pub jid: String,
    pub error: Option<String>,
}

fn parse_participant_results(response: &BinaryNode, action: &str) -> Result<Vec<ParticipantResult>> {
    let action_node = match &response.content {
        NodeContent::List(ch) => ch.iter().find(|n| n.tag == action).cloned(),
        _ => None,
    };
    let node = action_node.as_ref().unwrap_or(response);
    let results = match &node.content {
        NodeContent::List(ch) => ch
            .iter()
            .filter(|n| n.tag == "participant")
            .map(|n| ParticipantResult {
                jid: n.attr("jid").unwrap_or("").to_string(),
                error: n.attr("error").map(|s| s.to_string()),
            })
            .collect(),
        _ => vec![],
    };
    Ok(results)
}

// ── Mutating group operations ─────────────────────────────────────────────────

/// Create a new group. Returns the full `GroupInfo` for the new group.
pub async fn create_group(
    sender: &SocketSender,
    subject: &str,
    participant_jids: &[&str],
) -> Result<GroupInfo> {
    let id = sender.next_id();
    let participants: Vec<BinaryNode> = participant_jids
        .iter()
        .map(|jid| BinaryNode {
            tag: "participant".to_string(),
            attrs: vec![("jid".to_string(), jid.to_string())],
            content: NodeContent::None,
        })
        .collect();

    let node = BinaryNode {
        tag: "iq".to_string(),
        attrs: vec![
            ("id".to_string(), id),
            ("type".to_string(), "set".to_string()),
            ("xmlns".to_string(), "w:g2".to_string()),
            ("to".to_string(), "g.us".to_string()),
        ],
        content: NodeContent::List(vec![BinaryNode {
            tag: "create".to_string(),
            attrs: vec![("subject".to_string(), subject.to_string())],
            content: NodeContent::List(participants),
        }]),
    };

    let response = sender.send_iq_await(node).await?;

    // Response contains a <group> node with the new JID
    let group_node = match &response.content {
        NodeContent::List(ch) => ch.iter().find(|n| n.tag == "group").cloned(),
        _ => None,
    };
    let new_jid = group_node
        .as_ref()
        .and_then(|n| n.attr("jid"))
        .ok_or_else(|| anyhow::anyhow!("create_group: no JID in response"))?
        .to_string();

    // Fetch full info for the freshly created group
    fetch_group_info(sender, &new_jid).await
}

async fn group_participant_action(
    sender: &SocketSender,
    group_jid: &str,
    action: &str,
    jids: &[&str],
) -> Result<Vec<ParticipantResult>> {
    let id = sender.next_id();
    let participants: Vec<BinaryNode> = jids
        .iter()
        .map(|jid| BinaryNode {
            tag: "participant".to_string(),
            attrs: vec![("jid".to_string(), jid.to_string())],
            content: NodeContent::None,
        })
        .collect();

    let node = BinaryNode {
        tag: "iq".to_string(),
        attrs: vec![
            ("id".to_string(), id),
            ("type".to_string(), "set".to_string()),
            ("xmlns".to_string(), "w:g2".to_string()),
            ("to".to_string(), group_jid.to_string()),
        ],
        content: NodeContent::List(vec![BinaryNode {
            tag: action.to_string(),
            attrs: vec![],
            content: NodeContent::List(participants),
        }]),
    };

    let response = sender.send_iq_await(node).await?;
    parse_participant_results(&response, action)
}

pub async fn add_participants(
    sender: &SocketSender,
    group_jid: &str,
    jids: &[&str],
) -> Result<Vec<ParticipantResult>> {
    group_participant_action(sender, group_jid, "add", jids).await
}

pub async fn remove_participants(
    sender: &SocketSender,
    group_jid: &str,
    jids: &[&str],
) -> Result<Vec<ParticipantResult>> {
    group_participant_action(sender, group_jid, "remove", jids).await
}

pub async fn promote_to_admin(
    sender: &SocketSender,
    group_jid: &str,
    jids: &[&str],
) -> Result<Vec<ParticipantResult>> {
    group_participant_action(sender, group_jid, "promote", jids).await
}

pub async fn demote_from_admin(
    sender: &SocketSender,
    group_jid: &str,
    jids: &[&str],
) -> Result<Vec<ParticipantResult>> {
    group_participant_action(sender, group_jid, "demote", jids).await
}

/// Leave a group.
pub async fn leave_group(sender: &SocketSender, group_jid: &str) -> Result<()> {
    let id = sender.next_id();
    let node = BinaryNode {
        tag: "iq".to_string(),
        attrs: vec![
            ("id".to_string(), id),
            ("type".to_string(), "set".to_string()),
            ("xmlns".to_string(), "w:g2".to_string()),
            ("to".to_string(), "g.us".to_string()),
        ],
        content: NodeContent::List(vec![BinaryNode {
            tag: "leave".to_string(),
            attrs: vec![],
            content: NodeContent::List(vec![BinaryNode {
                tag: "group".to_string(),
                attrs: vec![("id".to_string(), group_jid.to_string())],
                content: NodeContent::None,
            }]),
        }]),
    };
    sender.send_iq_await(node).await?;
    Ok(())
}

/// Update the group subject (name).
pub async fn set_group_subject(
    sender: &SocketSender,
    group_jid: &str,
    subject: &str,
) -> Result<()> {
    let id = sender.next_id();
    let node = BinaryNode {
        tag: "iq".to_string(),
        attrs: vec![
            ("id".to_string(), id),
            ("type".to_string(), "set".to_string()),
            ("xmlns".to_string(), "w:g2".to_string()),
            ("to".to_string(), group_jid.to_string()),
        ],
        content: NodeContent::List(vec![BinaryNode {
            tag: "subject".to_string(),
            attrs: vec![],
            content: NodeContent::Text(subject.to_string()),
        }]),
    };
    sender.send_iq_await(node).await?;
    Ok(())
}

/// Update the group description.
pub async fn set_group_description(
    sender: &SocketSender,
    group_jid: &str,
    description: &str,
) -> Result<()> {
    let id = sender.next_id();
    let node = BinaryNode {
        tag: "iq".to_string(),
        attrs: vec![
            ("id".to_string(), id),
            ("type".to_string(), "set".to_string()),
            ("xmlns".to_string(), "w:g2".to_string()),
            ("to".to_string(), group_jid.to_string()),
        ],
        content: NodeContent::List(vec![BinaryNode {
            tag: "description".to_string(),
            attrs: vec![],
            content: NodeContent::List(vec![BinaryNode {
                tag: "body".to_string(),
                attrs: vec![],
                content: NodeContent::Text(description.to_string()),
            }]),
        }]),
    };
    sender.send_iq_await(node).await?;
    Ok(())
}

// ── Presence subscription ─────────────────────────────────────────────────────

#[allow(dead_code)]
pub async fn subscribe_group_presence(sender: &SocketSender, group_jid: &str) -> Result<()> {
    let node = BinaryNode {
        tag: "presence".to_string(),
        attrs: vec![
            ("type".to_string(), "subscribe".to_string()),
            ("to".to_string(), group_jid.to_string()),
        ],
        content: NodeContent::None,
    };
    sender.send_node(&node).await
}

// ── Profile pictures ──────────────────────────────────────────────────────────

/// Get the profile picture URL for any JID (contact or group).
/// Returns `None` if not set or not permitted.
pub async fn get_profile_picture(
    sender: &SocketSender,
    jid: &str,
    high_res: bool,
) -> Result<Option<String>> {
    let id = sender.next_id();
    let pic_type = if high_res { "image" } else { "preview" };
    let node = BinaryNode {
        tag: "iq".to_string(),
        attrs: vec![
            ("id".to_string(), id),
            ("type".to_string(), "get".to_string()),
            ("xmlns".to_string(), "w:profile:picture".to_string()),
            ("to".to_string(), jid.to_string()),
        ],
        content: NodeContent::List(vec![BinaryNode {
            tag: "picture".to_string(),
            attrs: vec![
                ("type".to_string(), pic_type.to_string()),
                ("query".to_string(), "url".to_string()),
            ],
            content: NodeContent::None,
        }]),
    };

    let response = sender.send_iq_await(node).await?;
    // Error type="item-not-found" means no photo set — not an error for us
    if response.attr("type") == Some("error") {
        return Ok(None);
    }

    let url = match &response.content {
        NodeContent::List(ch) => ch
            .iter()
            .find(|n| n.tag == "picture")
            .and_then(|n| n.attr("url"))
            .map(|s| s.to_string()),
        _ => None,
    };
    Ok(url)
}

/// Set our own profile picture. `jpeg_data` must be a valid JPEG.
pub async fn set_profile_picture(
    sender: &SocketSender,
    our_jid: &str,
    jpeg_data: &[u8],
) -> Result<()> {
    let id = sender.next_id();
    let node = BinaryNode {
        tag: "iq".to_string(),
        attrs: vec![
            ("id".to_string(), id),
            ("type".to_string(), "set".to_string()),
            ("xmlns".to_string(), "w:profile:picture".to_string()),
            ("to".to_string(), our_jid.to_string()),
        ],
        content: NodeContent::List(vec![BinaryNode {
            tag: "picture".to_string(),
            attrs: vec![("type".to_string(), "image".to_string())],
            content: NodeContent::Bytes(jpeg_data.to_vec()),
        }]),
    };
    let response = sender.send_iq_await(node).await?;
    if response.attr("type") == Some("error") {
        bail!("set_profile_picture: server returned error");
    }
    Ok(())
}
