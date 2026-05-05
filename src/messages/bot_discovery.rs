//! Discover the AI bots WhatsApp has assigned to the linked
//! account WITHOUT having to write to one first.
//!
//! WhatsApp exposes a single iq query in the `bot` namespace that
//! returns every persona (Meta AI today; could be more on accounts
//! enrolled in extra AI features) the user is allowed to chat with:
//!
//! ```xml
//! <iq id="…" type="get" xmlns="bot" to="s.whatsapp.net">
//!   <bot v="2"/>
//! </iq>
//! ```
//!
//! Response shape (whatsmeow-mirrored):
//!
//! ```xml
//! <iq id="…" type="result" from="s.whatsapp.net">
//!   <bot v="2">
//!     <section type="all">
//!       <bot persona_id="…" jid="…@bot"/>
//!       <bot persona_id="…" jid="…@bot"/>
//!     </section>
//!   </bot>
//! </iq>
//! ```
//!
//! No outbound message, no Signal session bootstrap, no
//! `messageSecret` capture required. Pair with the `bot_decrypt`
//! pipeline once you DO start chatting.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

use crate::binary::{BinaryNode, NodeContent};
use crate::messages::generate_message_id;
use crate::socket::SocketSender;

/// Minimal info returned from the `<iq xmlns="bot"><bot v="2"/></iq>`
/// listing — the JID + opaque persona id. Persona id is what the
/// follow-up profile usync keys on.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BotListInfo {
    pub jid: String,
    pub persona_id: String,
}

/// Send the bot-list iq and parse the response into a `Vec<BotListInfo>`.
/// Returns an empty vec when the server has no bots assigned.
///
/// Times out after the socket's default 60 s window. Fails loud on
/// transport / parse errors so the caller can distinguish "empty
/// list" (Ok(vec![])) from "couldn't ask".
pub async fn list_bots(socket: &Arc<SocketSender>) -> Result<Vec<BotListInfo>> {
    let id = generate_message_id();
    tracing::info!(target: "wa::bot_discovery", iq_id = %id, "sending bot list iq");
    let req = BinaryNode {
        tag: "iq".into(),
        attrs: vec![
            ("id".to_string(), id),
            ("type".to_string(), "get".to_string()),
            ("xmlns".to_string(), "bot".to_string()),
            ("to".to_string(), "s.whatsapp.net".to_string()),
        ],
        content: NodeContent::List(vec![BinaryNode {
            tag: "bot".into(),
            attrs: vec![("v".to_string(), "2".to_string())],
            content: NodeContent::None,
        }]),
    };
    let resp = socket.send_iq_await(req).await?;
    tracing::info!(target: "wa::bot_discovery", "bot list iq response received");

    // Walk: <iq><bot><section type="all"><bot jid persona_id/>…</section></bot></iq>
    let bot_node = match &resp.content {
        NodeContent::List(children) => children
            .iter()
            .find(|n| n.tag == "bot")
            .ok_or_else(|| anyhow!("bot list: response missing <bot>"))?,
        _ => return Err(anyhow!("bot list: response has no children")),
    };
    let mut out = Vec::new();
    let sections = match &bot_node.content {
        NodeContent::List(c) => c,
        _ => return Ok(out),
    };
    for section in sections {
        if section.tag != "section" {
            continue;
        }
        if section.attr("type") != Some("all") {
            continue;
        }
        let bots = match &section.content {
            NodeContent::List(c) => c,
            _ => continue,
        };
        for bot in bots {
            if bot.tag != "bot" {
                continue;
            }
            let jid = bot.attr("jid").unwrap_or("");
            let persona_id = bot.attr("persona_id").unwrap_or("");
            if !jid.is_empty() {
                out.push(BotListInfo {
                    jid: jid.to_string(),
                    persona_id: persona_id.to_string(),
                });
            }
        }
    }
    Ok(out)
}
