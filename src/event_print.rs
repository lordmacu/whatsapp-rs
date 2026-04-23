use tracing::info;

use crate::client::Session;
use crate::{MessageContent, MessageEvent};

pub async fn print_event(session: &Session, event: MessageEvent) {
    match event {
        MessageEvent::NewMessage { msg } => {
            let from = &msg.key.remote_jid;
            let sender = msg.key.participant.as_deref().unwrap_or(from.as_str());
            let name = msg.push_name.as_deref()
                .map(|s| s.to_string())
                .or_else(|| session.contact_name(sender))
                .unwrap_or_else(|| sender.to_string());
            let is_status = from == "status@broadcast";
            let prefix = if is_status { format!("[status {name}]") } else { format!("[{name}]") };

            match &msg.message {
                Some(MessageContent::Text { text, mentioned_jids }) => {
                    if mentioned_jids.is_empty() {
                        println!("{prefix} {text}");
                    } else {
                        println!("{prefix} {text}  (mentions: {})", mentioned_jids.join(", "));
                    }
                    let _ = session.mark_read(&[msg.key]).await;
                }
                Some(MessageContent::Image { caption, .. }) => {
                    println!("{prefix} <image: {}>", caption.as_deref().unwrap_or(""));
                    let _ = session.mark_read(&[msg.key]).await;
                }
                Some(MessageContent::Video { caption, .. }) => {
                    println!("{prefix} <video: {}>", caption.as_deref().unwrap_or(""));
                    let _ = session.mark_read(&[msg.key]).await;
                }
                Some(MessageContent::Audio { .. }) => {
                    println!("{prefix} <audio>");
                    let _ = session.mark_read(&[msg.key]).await;
                }
                Some(MessageContent::Document { file_name, .. }) => {
                    println!("{prefix} <document: {file_name}>");
                    let _ = session.mark_read(&[msg.key]).await;
                }
                Some(MessageContent::Sticker { .. }) => {
                    println!("{prefix} <sticker>");
                }
                Some(MessageContent::Reaction { emoji, target_id }) => {
                    println!("{prefix} reacted {emoji} to {target_id}");
                }
                Some(MessageContent::Reply { text, reply_to_id }) => {
                    println!("{prefix} (reply to {reply_to_id}) {text}");
                    let _ = session.mark_read(&[msg.key]).await;
                }
                Some(MessageContent::Poll { question, options, .. }) => {
                    let opts = options.join(" / ");
                    println!("{prefix} poll: {question} — {opts}");
                    let _ = session.mark_read(&[msg.key]).await;
                }
                Some(MessageContent::LinkPreview { text, url, .. }) => {
                    println!("{prefix} {text}  [{url}]");
                    let _ = session.mark_read(&[msg.key]).await;
                }
                None => {}
            }
        }
        MessageEvent::MessageRevoke { key } => {
            println!("<message {} deleted by {}>", key.id, key.remote_jid);
        }
        MessageEvent::MessageEdit { key, new_text } => {
            println!("<message {} edited: {new_text}>", key.id);
        }
        MessageEvent::Typing { jid, composing } => {
            if composing {
                let name = session.contact_name(&jid).unwrap_or(jid);
                println!("<{name} is typing…>");
            }
        }
        MessageEvent::Presence { jid, available } => {
            let name = session.contact_name(&jid).unwrap_or(jid.clone());
            println!("<{name} {}>", if available { "online" } else { "offline" });
        }
        MessageEvent::GroupUpdate { group_jid, kind } => {
            info!("group {group_jid}: {kind:?}");
        }
        MessageEvent::HistorySync { sync_type, push_names, chats, messages } => {
            info!(
                "history sync type={sync_type}: {} chats, {} push names, {} messages",
                chats.len(), push_names.len(), messages.len(),
            );
        }
        MessageEvent::PollVote { voter_key, poll_msg_id, selected_options } => {
            let voter = voter_key.participant.as_deref().unwrap_or(voter_key.remote_jid.as_str());
            let name = session.contact_name(voter).unwrap_or_else(|| voter.to_string());
            let opts = if selected_options.is_empty() {
                "<deselected all>".to_string()
            } else {
                selected_options.join(", ")
            };
            println!("<{name} voted on {poll_msg_id}: {opts}>");
        }
        MessageEvent::Disconnected { reason, reconnect } => {
            println!("[DISCONNECTED] reason={reason} reconnect={reconnect}");
        }
        MessageEvent::AppStateUpdate { collection, action } => {
            println!("[app-state {collection}] {action:?}");
        }
        MessageEvent::Receipt { .. }
        | MessageEvent::MessageUpdate { .. }
        | MessageEvent::Reaction { .. }
        | MessageEvent::EphemeralSetting { .. }
        | MessageEvent::Connected => {}
    }
}
