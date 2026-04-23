#![allow(dead_code)]
use crate::binary::{BinaryNode, NodeContent};
use crate::socket::SocketSender;
use anyhow::Result;
use std::collections::{HashMap, HashSet};

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ContactInfo {
    pub jid: String,
    pub on_whatsapp: bool,
    pub status: Option<String>,
}

/// Check whether a list of phone numbers are registered on WhatsApp.
/// Phones should be in E.164 format without '+': "5491112345678"
pub async fn on_whatsapp(sender: &SocketSender, phones: &[&str]) -> Result<Vec<ContactInfo>> {
    if phones.is_empty() {
        return Ok(vec![]);
    }

    let user_nodes: Vec<BinaryNode> = phones
        .iter()
        .map(|phone| {
            let normalized = format!("+{}", phone.trim_start_matches('+'));
            BinaryNode {
                tag: "user".to_string(),
                attrs: vec![],
                content: NodeContent::List(vec![BinaryNode {
                    tag: "contact".to_string(),
                    attrs: vec![],
                    content: NodeContent::Text(normalized),
                }]),
            }
        })
        .collect();

    let result = send_usync_query(sender, "query", "interactive", &["contact"], user_nodes).await?;
    Ok(parse_contact_results(&result))
}

/// Resolve a list of JIDs to ContactInfo (on_whatsapp check + status text).
pub async fn resolve_contacts(
    sender: &SocketSender,
    jids: &[&str],
) -> Result<HashMap<String, ContactInfo>> {
    if jids.is_empty() {
        return Ok(HashMap::new());
    }

    let user_nodes: Vec<BinaryNode> = jids
        .iter()
        .map(|jid| BinaryNode {
            tag: "user".to_string(),
            attrs: vec![("jid".to_string(), jid.to_string())],
            content: NodeContent::None,
        })
        .collect();

    let result =
        send_usync_query(sender, "query", "interactive", &["contact", "status"], user_nodes)
            .await?;

    let infos = parse_contact_results(&result);
    Ok(infos.into_iter().map(|c| (c.jid.clone(), c)).collect())
}

/// Fetch status text for a list of JIDs.
pub async fn fetch_status(
    sender: &SocketSender,
    jids: &[&str],
) -> Result<HashMap<String, String>> {
    if jids.is_empty() {
        return Ok(HashMap::new());
    }

    let user_nodes: Vec<BinaryNode> = jids
        .iter()
        .map(|jid| BinaryNode {
            tag: "user".to_string(),
            attrs: vec![("jid".to_string(), jid.to_string())],
            content: NodeContent::None,
        })
        .collect();

    let result = send_usync_query(sender, "query", "interactive", &["status"], user_nodes).await?;

    let mut map = HashMap::new();
    if let NodeContent::List(children) = &result.content {
        for child in children {
            if child.tag == "usync" {
                let list_node = find_child(child, "list");
                if let Some(list) = list_node {
                    if let NodeContent::List(users) = &list.content {
                        for user in users {
                            let jid = user.attr("jid").unwrap_or("").to_string();
                            if jid.is_empty() {
                                continue;
                            }
                            if let NodeContent::List(fields) = &user.content {
                                for field in fields {
                                    if field.tag == "status" {
                                        if let NodeContent::Text(t) = &field.content {
                                            map.insert(jid.clone(), t.clone());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(map)
}

/// Query the set of devices registered under `jid`. Returns a list of device
/// JIDs like `user:0@server`, `user:10@server`. Matches the query Baileys
/// uses right before encrypting an outbound message.
pub async fn get_user_devices(sender: &SocketSender, jids: &[&str]) -> Result<Vec<String>> {
    if jids.is_empty() {
        return Ok(vec![]);
    }

    let requested_lid_users: HashSet<String> = jids
        .iter()
        .filter_map(|jid| {
            let (_, server) = split_user_server(jid)?;
            if server.ends_with("lid") {
                Some(bare_user_jid(jid))
            } else {
                None
            }
        })
        .collect();

    let user_nodes: Vec<BinaryNode> = jids
        .iter()
        .map(|jid| BinaryNode {
            tag: "user".to_string(),
            attrs: vec![("jid".to_string(), jid.to_string())],
            content: NodeContent::None,
        })
        .collect();

    let result =
        send_usync_query(sender, "query", "message", &["devices"], user_nodes).await?;
    tracing::trace!("usync devices response: {}", debug_node_shape(&result));

    let mut devices: Vec<String> = Vec::new();
    if let NodeContent::List(children) = &result.content {
        for child in children {
            if child.tag != "usync" { continue; }
            let Some(list) = find_child(child, "list") else { continue };
            let NodeContent::List(users) = &list.content else { continue };
            for user in users {
                let Some(user_jid) = user.attr("jid") else { continue };
                let base_jid = user.attr("lid")
                    .filter(|lid| requested_lid_users.contains(&bare_user_jid(lid)))
                    .unwrap_or(user_jid);
                let bare_base = bare_user_jid(base_jid);
                let (user_part, server) = match split_user_server(&bare_base) {
                    Some((u, s)) => (u.to_string(), s.to_string()),
                    None => continue,
                };
                // Look for <devices><device-list><device id="N"/>...
                let Some(devs) = find_child(user, "devices") else { continue };
                let Some(dlist) = find_child(devs, "device-list") else { continue };
                if let NodeContent::List(items) = &dlist.content {
                    for d in items {
                        if d.tag != "device" { continue; }
                        let id_str = d.attr("id").unwrap_or("0");
                        // Produce "user:id@server" — device 0 keeps the ":0".
                        devices.push(format!("{}:{}@{}", user_part, id_str, server));
                    }
                }
            }
        }
    }

    Ok(devices)
}

fn split_user_server(jid: &str) -> Option<(&str, &str)> {
    jid.split_once('@')
}

fn bare_user_jid(jid: &str) -> String {
    let Some((left, server)) = split_user_server(jid) else {
        return jid.to_string();
    };
    let user = left.split(':').next().unwrap_or(left);
    format!("{user}@{server}")
}

// ── internals ─────────────────────────────────────────────────────────────────

async fn send_usync_query(
    sender: &SocketSender,
    mode: &str,
    context: &str,
    protocols: &[&str],
    user_nodes: Vec<BinaryNode>,
) -> Result<BinaryNode> {
    let id = sender.next_id();
    let sid = sender.next_id();

    let query_children: Vec<BinaryNode> = protocols
        .iter()
        .map(|p| {
            let attrs = match *p {
                // WA rejects `<devices/>` without the `version` attr — matches
                // Baileys' `USyncDeviceProtocol.getQueryElement`.
                "devices" => vec![("version".to_string(), "2".to_string())],
                _ => vec![],
            };
            BinaryNode {
                tag: p.to_string(),
                attrs,
                content: NodeContent::None,
            }
        })
        .collect();

    let node = BinaryNode {
        tag: "iq".to_string(),
        attrs: vec![
            ("id".to_string(), id),
            ("to".to_string(), "s.whatsapp.net".to_string()),
            ("type".to_string(), "get".to_string()),
            ("xmlns".to_string(), "usync".to_string()),
        ],
        content: NodeContent::List(vec![BinaryNode {
            tag: "usync".to_string(),
            attrs: vec![
                ("context".to_string(), context.to_string()),
                ("mode".to_string(), mode.to_string()),
                ("sid".to_string(), sid),
                ("last".to_string(), "true".to_string()),
                ("index".to_string(), "0".to_string()),
            ],
            content: NodeContent::List(vec![
                BinaryNode {
                    tag: "query".to_string(),
                    attrs: vec![],
                    content: NodeContent::List(query_children),
                },
                BinaryNode {
                    tag: "list".to_string(),
                    attrs: vec![],
                    content: NodeContent::List(user_nodes),
                },
            ]),
        }]),
    };

    sender.send_iq_await(node).await
}

fn parse_contact_results(result: &BinaryNode) -> Vec<ContactInfo> {
    let mut out = Vec::new();
    if let NodeContent::List(children) = &result.content {
        for child in children {
            if child.tag == "usync" {
                if let Some(list) = find_child(child, "list") {
                    if let NodeContent::List(users) = &list.content {
                        for user in users {
                            let jid = user.attr("jid").unwrap_or("").to_string();
                            if jid.is_empty() {
                                continue;
                            }
                            let mut on_whatsapp = false;
                            let mut status = None;

                            if let NodeContent::List(fields) = &user.content {
                                for field in fields {
                                    match field.tag.as_str() {
                                        "contact" => {
                                            on_whatsapp =
                                                field.attr("type") == Some("in");
                                        }
                                        "status" => {
                                            if let NodeContent::Text(t) = &field.content {
                                                status = Some(t.clone());
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }

                            out.push(ContactInfo { jid, on_whatsapp, status });
                        }
                    }
                }
            }
        }
    }
    out
}

fn find_child<'a>(node: &'a BinaryNode, tag: &str) -> Option<&'a BinaryNode> {
    if let NodeContent::List(children) = &node.content {
        children.iter().find(|n| n.tag == tag)
    } else {
        None
    }
}

fn debug_node_shape(node: &BinaryNode) -> String {
    let mut out = format!("<{}", node.tag);
    for (k, v) in &node.attrs {
        let v = if v.len() > 30 { format!("{}...", &v[..30]) } else { v.clone() };
        out.push_str(&format!(" {k}={v:?}"));
    }
    match &node.content {
        NodeContent::List(children) => {
            out.push_str(">");
            for c in children {
                out.push_str(&debug_node_shape(c));
            }
            out.push_str(&format!("</{}>", node.tag));
        }
        NodeContent::Text(t) => {
            let t = if t.len() > 30 { format!("{}...", &t[..30]) } else { t.clone() };
            out.push_str(&format!(">{t}</{}>", node.tag));
        }
        NodeContent::Bytes(b) => out.push_str(&format!("> [{} bytes] </{}>", b.len(), node.tag)),
        NodeContent::None => out.push_str("/>"),
    }
    out
}
