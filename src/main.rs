mod app_state;
mod auth;
mod binary;
mod client;
mod contacts;
mod daemon;
mod device_cache;
mod event_print;
mod install;
mod media;
mod message_store;
mod messages;
mod noise;
mod outbox;
mod poll_store;
mod qr;
mod signal;
mod socket;

use anyhow::{bail, Result};
use messages::{MessageContent, MessageEvent};
use tracing::info;

const USAGE: &str = "\
Usage: whatsapp-rs <command> [args]

Commands:
  listen                                Connect and print all incoming messages (default)
  send <jid> <text>                     Send a text message and exit
  send-group <jid> <text>               Send a text message to a group and exit
  send-file <jid> <path> [caption]      Send an image/video/audio/document from disk and exit
  sticker <jid> <path>                  Send a sticker from disk and exit
  send-voice <jid> <path.ogg>           Send a push-to-talk voice note (Opus/OGG recommended)
  send-location <jid> <lat> <lon> [name] [address]   Share a location pin
  send-contact <jid> <display-name> <phone-E164>     Share a contact card
  download <jid> <msg-id> [path]        Download received media to a file (default: ./<msg-id>)
  reply <jid> <msg-id> <text>           Reply to a specific message and exit
  react <jid> <msg-id> <emoji>          Send a reaction and exit
  revoke <jid> <msg-id>                 Delete a message you sent and exit
  edit <jid> <msg-id> <new-text>        Edit a message you sent and exit
  poll <jid> <question> <opt>...        Create a poll (options after question)
  vote <jid> <poll-msg-id> <opt>...     Vote on a poll (option names after poll-id)
  status-post <text>                    Post a text status update (story)
  status-image <path> [caption]         Post an image status update (story)
  status-video <path> [caption]         Post a video status update (story)
  forward <to-jid> <from-jid> <msg-id>  Forward a stored message to a JID
  ephemeral <jid> <secs>                Set disappearing messages timer (0=off, 86400=24h, 604800=7d)
  contacts                              List cached contacts and exit
  history <jid> [n]                     Print last N messages for a chat (default 20)
  lookup <phone>...                     Check if phone numbers are on WhatsApp
  status                                Show our JID and exit
  group <jid>                           Fetch and print group info and exit

Group management:
  group-create <name> <jid>...          Create a group with given participants
  group-add <group-jid> <jid>...        Add participants to a group
  group-remove <group-jid> <jid>...     Remove participants from a group
  group-promote <group-jid> <jid>...    Promote participants to admin
  group-demote <group-jid> <jid>...     Demote admins to regular members
  group-leave <group-jid>               Leave a group
  group-subject <group-jid> <name>      Change group name/subject
  group-desc <group-jid> <text>         Change group description

Profile pictures:
  avatar <jid>                          Print profile picture URL for a JID
  set-avatar <path>                     Set your own profile picture (JPEG)

Link by phone (first-time setup alternative to QR):
  pair-phone <phone>                    Link device using a pairing code instead of QR

Privacy & blocking:
  blocklist                             Print your blocked contacts
  block <jid>                           Block a contact
  unblock <jid>                         Unblock a contact
  subscribe-presence <jid>              Subscribe to online/offline presence for a contact
  mark-status-viewed <sender-jid> <id>  Mark a WhatsApp Status as viewed
  privacy                               Show current privacy settings
  privacy-set <setting> <value>         Change one privacy setting
    settings: last-seen | online | profile | status | read-receipts | group-add | call-add
    values:   all | contacts | contact-blacklist | none | match-last-seen

Debug:
  monitor                               Connect and print ALL incoming events as JSON-ish debug lines
";



#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("whatsapp_rs=debug,info")
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(|s| s.as_str()).unwrap_or("listen");

    match cmd {
        "daemon" => daemon::run_daemon().await,
        "daemon-stop" => cmd_daemon_stop().await,
        "install" => install::install_autostart(),
        "uninstall" => install::uninstall_autostart(),
        "setup" => cmd_setup().await,
        "listen" => cmd_listen().await,
        "send" => {
            if args.len() < 3 {
                bail!("Usage: whatsapp-rs send <jid> <text>");
            }
            cmd_send(&args[1], &args[2..].join(" ")).await
        }
        "send-group" => {
            if args.len() < 3 {
                bail!("Usage: whatsapp-rs send-group <jid> <text>");
            }
            cmd_send_group(&args[1], &args[2..].join(" ")).await
        }
        "send-file" => {
            if args.len() < 3 {
                bail!("Usage: whatsapp-rs send-file <jid> <path> [caption]");
            }
            let caption = if args.len() > 3 { Some(args[3..].join(" ")) } else { None };
            cmd_send_file(&args[1], &args[2], caption.as_deref()).await
        }
        "sticker" => {
            if args.len() < 3 {
                bail!("Usage: whatsapp-rs sticker <jid> <path>");
            }
            cmd_send_sticker(&args[1], &args[2]).await
        }
        "send-voice" => {
            if args.len() < 3 {
                bail!("Usage: whatsapp-rs send-voice <jid> <path.ogg>  (Opus-in-OGG recommended)");
            }
            cmd_send_voice(&args[1], &args[2]).await
        }
        "send-location" => {
            if args.len() < 4 {
                bail!("Usage: whatsapp-rs send-location <jid> <lat> <lon> [name] [address]");
            }
            let lat: f64 = args[2].parse()?;
            let lon: f64 = args[3].parse()?;
            let name = args.get(4).map(|s| s.as_str());
            let address = args.get(5).map(|s| s.as_str());
            cmd_send_location(&args[1], lat, lon, name, address).await
        }
        "send-contact" => {
            if args.len() < 4 {
                bail!("Usage: whatsapp-rs send-contact <jid> <display-name> <phone-E164>");
            }
            cmd_send_contact(&args[1], &args[2], &args[3]).await
        }
        "download" => {
            if args.len() < 3 {
                bail!("Usage: whatsapp-rs download <jid> <msg-id> [path]");
            }
            let out_path = args.get(3).map(|s| s.as_str());
            cmd_download(&args[1], &args[2], out_path).await
        }
        "reply" => {
            if args.len() < 4 {
                bail!("Usage: whatsapp-rs reply <jid> <msg-id> <text>");
            }
            cmd_reply(&args[1], &args[2], &args[3..].join(" ")).await
        }
        "react" => {
            if args.len() < 4 {
                bail!("Usage: whatsapp-rs react <jid> <msg-id> <emoji>");
            }
            cmd_react(&args[1], &args[2], &args[3]).await
        }
        "revoke" => {
            if args.len() < 3 {
                bail!("Usage: whatsapp-rs revoke <jid> <msg-id>");
            }
            cmd_revoke(&args[1], &args[2]).await
        }
        "edit" => {
            if args.len() < 4 {
                bail!("Usage: whatsapp-rs edit <jid> <msg-id> <new-text>");
            }
            cmd_edit(&args[1], &args[2], &args[3..].join(" ")).await
        }
        "poll" => {
            if args.len() < 4 {
                bail!("Usage: whatsapp-rs poll <jid> <question> <option1> [option2 ...]");
            }
            let opts: Vec<&str> = args[3..].iter().map(|s| s.as_str()).collect();
            cmd_poll(&args[1], &args[2], &opts).await
        }
        "vote" => {
            if args.len() < 4 {
                bail!("Usage: whatsapp-rs vote <jid> <poll-msg-id> <option> [option2 ...]");
            }
            let opts: Vec<&str> = args[3..].iter().map(|s| s.as_str()).collect();
            cmd_vote(&args[1], &args[2], &opts).await
        }
        "status-post" => {
            if args.len() < 2 {
                bail!("Usage: whatsapp-rs status-post <text>");
            }
            cmd_status_post(&args[1..].join(" ")).await
        }
        "status-image" => {
            if args.len() < 2 {
                bail!("Usage: whatsapp-rs status-image <path> [caption]");
            }
            let caption = if args.len() > 2 { Some(args[2..].join(" ")) } else { None };
            cmd_status_media_image(&args[1], caption.as_deref()).await
        }
        "status-video" => {
            if args.len() < 2 {
                bail!("Usage: whatsapp-rs status-video <path> [caption]");
            }
            let caption = if args.len() > 2 { Some(args[2..].join(" ")) } else { None };
            cmd_status_media_video(&args[1], caption.as_deref()).await
        }
        "forward" => {
            if args.len() < 4 {
                bail!("Usage: whatsapp-rs forward <to-jid> <from-jid> <msg-id>");
            }
            cmd_forward(&args[1], &args[2], &args[3]).await
        }
        "ephemeral" => {
            if args.len() < 3 {
                bail!("Usage: whatsapp-rs ephemeral <jid> <secs>");
            }
            let secs: u32 = args[2].parse().map_err(|_| anyhow::anyhow!("secs must be a number"))?;
            cmd_ephemeral(&args[1], secs).await
        }
        "contacts" => cmd_contacts(),
        "history" => {
            if args.len() < 2 {
                bail!("Usage: whatsapp-rs history <jid> [n]");
            }
            let n: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(20);
            cmd_history(&args[1], n).await
        }
        "lookup" => {
            if args.len() < 2 {
                bail!("Usage: whatsapp-rs lookup <phone> [phone2 ...]");
            }
            let phones: Vec<&str> = args[1..].iter().map(|s| s.as_str()).collect();
            cmd_lookup(&phones).await
        }
        "status" => cmd_status().await,
        "group" => {
            if args.len() < 2 {
                bail!("Usage: whatsapp-rs group <jid>");
            }
            cmd_group(&args[1]).await
        }
        "group-create" => {
            if args.len() < 3 {
                bail!("Usage: whatsapp-rs group-create <name> <jid>...");
            }
            let jids: Vec<&str> = args[2..].iter().map(|s| s.as_str()).collect();
            cmd_group_create(&args[1], &jids).await
        }
        "group-add" => {
            if args.len() < 3 {
                bail!("Usage: whatsapp-rs group-add <group-jid> <jid>...");
            }
            let jids: Vec<&str> = args[2..].iter().map(|s| s.as_str()).collect();
            cmd_group_participants("add", &args[1], &jids).await
        }
        "group-remove" => {
            if args.len() < 3 {
                bail!("Usage: whatsapp-rs group-remove <group-jid> <jid>...");
            }
            let jids: Vec<&str> = args[2..].iter().map(|s| s.as_str()).collect();
            cmd_group_participants("remove", &args[1], &jids).await
        }
        "group-promote" => {
            if args.len() < 3 {
                bail!("Usage: whatsapp-rs group-promote <group-jid> <jid>...");
            }
            let jids: Vec<&str> = args[2..].iter().map(|s| s.as_str()).collect();
            cmd_group_participants("promote", &args[1], &jids).await
        }
        "group-demote" => {
            if args.len() < 3 {
                bail!("Usage: whatsapp-rs group-demote <group-jid> <jid>...");
            }
            let jids: Vec<&str> = args[2..].iter().map(|s| s.as_str()).collect();
            cmd_group_participants("demote", &args[1], &jids).await
        }
        "group-leave" => {
            if args.len() < 2 {
                bail!("Usage: whatsapp-rs group-leave <group-jid>");
            }
            cmd_group_leave(&args[1]).await
        }
        "group-subject" => {
            if args.len() < 3 {
                bail!("Usage: whatsapp-rs group-subject <group-jid> <name>");
            }
            cmd_group_subject(&args[1], &args[2..].join(" ")).await
        }
        "group-desc" => {
            if args.len() < 3 {
                bail!("Usage: whatsapp-rs group-desc <group-jid> <text>");
            }
            cmd_group_desc(&args[1], &args[2..].join(" ")).await
        }
        "avatar" => {
            if args.len() < 2 {
                bail!("Usage: whatsapp-rs avatar <jid>");
            }
            cmd_avatar(&args[1]).await
        }
        "set-avatar" => {
            if args.len() < 2 {
                bail!("Usage: whatsapp-rs set-avatar <path>");
            }
            cmd_set_avatar(&args[1]).await
        }
        "pair-phone" => {
            if args.len() < 2 {
                bail!("Usage: whatsapp-rs pair-phone <phone-number>");
            }
            cmd_pair_phone(&args[1]).await
        }
        "blocklist" => cmd_blocklist().await,
        "block" => {
            if args.len() < 2 {
                bail!("Usage: whatsapp-rs block <jid>");
            }
            cmd_block(&args[1], true).await
        }
        "unblock" => {
            if args.len() < 2 {
                bail!("Usage: whatsapp-rs unblock <jid>");
            }
            cmd_block(&args[1], false).await
        }
        "subscribe-presence" => {
            if args.len() < 2 {
                bail!("Usage: whatsapp-rs subscribe-presence <jid>");
            }
            cmd_subscribe_presence(&args[1]).await
        }
        "mark-status-viewed" => {
            if args.len() < 3 {
                bail!("Usage: whatsapp-rs mark-status-viewed <sender-jid> <msg-id>");
            }
            cmd_mark_status_viewed(&args[1], &args[2]).await
        }
        "privacy" => cmd_privacy().await,
        "privacy-set" => {
            if args.len() < 3 {
                bail!("Usage: whatsapp-rs privacy-set <setting> <value>");
            }
            cmd_privacy_set(&args[1], &args[2]).await
        }
        "monitor" => cmd_monitor().await,
        "--help" | "-h" | "help" => {
            print!("{USAGE}");
            Ok(())
        }
        other => bail!("Unknown command: {other}\n{USAGE}"),
    }
}

// ── Commands ──────────────────────────────────────────────────────────────────

async fn cmd_listen() -> Result<()> {
    use crate::auth::{AuthManager, AuthState, FileStore};

    // Snapshot auth state before `connect()` so we can tell if pairing just
    // happened. If it did, we'll hand the session off to the daemon on exit.
    let was_paired_before = {
        let store = std::sync::Arc::new(FileStore::new()?);
        let mgr = AuthManager::new(store)?;
        *mgr.state() == AuthState::Authenticated
    };

    let client = client::Client::new()?;
    let session = client.connect().await?;
    info!("connected as {}", session.our_jid);
    session.send_presence(true).await?;

    if !was_paired_before {
        // First-time pairing just finished. Drop our WA socket, install
        // autostart, and return — the newly installed daemon will take
        // over and `whatsapp-rs send ...` will Just Work.
        println!();
        println!("✓ Paired. Installing autostart so the daemon starts every login…");
        drop(session);
        if let Err(e) = install::install_autostart() {
            eprintln!("autostart install failed: {e}");
            eprintln!("you can still run `whatsapp-rs daemon` manually.");
        } else {
            println!("✓ Daemon installed and running. You're good to send.");
        }
        return Ok(());
    }

    let mut events = session.events();
    loop {
        match events.recv().await {
            Ok(event) => event_print::print_event(&session, event).await,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                tracing::warn!("lagged, dropped {n} events");
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }
    Ok(())
}

async fn cmd_send(jid: &str, text: &str) -> Result<()> {
    // Fast path: if a daemon is running, round-trip via IPC (<100 ms).
    if let Some(v) = daemon::try_daemon_request(daemon::Request::SendText {
        jid: jid.to_string(),
        text: text.to_string(),
    }).await? {
        let id = v.get("id").and_then(|x| x.as_str()).unwrap_or("?");
        println!("sent: {id}");
        return Ok(());
    }

    // Fallback: spin up a one-shot connection.
    let client = client::Client::new()?;
    let session = client.connect().await?;
    let id = session.send_text(jid, text).await?;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    println!("sent: {id}");
    Ok(())
}

/// One-shot onboarding: pair (if needed) then install autostart.
/// After this the daemon is running and will come back on every reboot.
async fn cmd_setup() -> Result<()> {
    use crate::auth::{AuthManager, AuthState, FileStore};
    let store = std::sync::Arc::new(FileStore::new()?);
    let mgr = AuthManager::new(store)?;
    if *mgr.state() != AuthState::Authenticated {
        println!("Not paired yet — scanning QR. Leave this running until the");
        println!("pairing is confirmed on your phone (takes ~15 s), then Ctrl+C.\n");
        // Drive the normal pairing flow and exit as soon as it completes.
        let client = client::Client::new()?;
        let _session = client.connect().await?;
        println!("\n✓ Paired.");
    } else {
        println!("Already paired as {}.", mgr.creds().me.as_ref().map(|c| c.id.as_str()).unwrap_or("?"));
    }

    install::install_autostart()?;
    println!("\n✓ Autostart installed. The daemon is running and will start on every login.");
    println!("  Test it: whatsapp-rs send <jid> \"hi\"");
    Ok(())
}

async fn cmd_daemon_stop() -> Result<()> {
    match daemon::try_daemon_request(daemon::Request::Shutdown).await? {
        Some(_) => { println!("daemon: stopped"); Ok(()) }
        None => { println!("daemon: not running"); Ok(()) }
    }
}

async fn cmd_send_group(jid: &str, text: &str) -> Result<()> {
    let client = client::Client::new()?;
    let session = client.connect().await?;
    let id = session.send_group_text(jid, text).await?;
    println!("sent: {id}");
    Ok(())
}

async fn cmd_reply(jid: &str, reply_to_id: &str, text: &str) -> Result<()> {
    let client = client::Client::new()?;
    let session = client.connect().await?;
    let id = session.send_reply(jid, reply_to_id, text).await?;
    println!("sent reply: {id}");
    Ok(())
}

async fn cmd_poll(jid: &str, question: &str, options: &[&str]) -> Result<()> {
    let client = client::Client::new()?;
    let session = client.connect().await?;
    let id = session.send_poll(jid, question, options, 1).await?;
    println!("sent poll: {id}");
    Ok(())
}

async fn cmd_react(jid: &str, msg_id: &str, emoji: &str) -> Result<()> {
    let client = client::Client::new()?;
    let session = client.connect().await?;
    session.send_reaction(jid, msg_id, emoji).await?;
    println!("reacted {emoji} to {msg_id}");
    Ok(())
}

async fn cmd_revoke(jid: &str, msg_id: &str) -> Result<()> {
    let client = client::Client::new()?;
    let session = client.connect().await?;
    session.send_revoke(jid, msg_id).await?;
    println!("revoked {msg_id}");
    Ok(())
}

async fn cmd_edit(jid: &str, msg_id: &str, new_text: &str) -> Result<()> {
    let client = client::Client::new()?;
    let session = client.connect().await?;
    session.send_edit(jid, msg_id, new_text).await?;
    println!("edited {msg_id}");
    Ok(())
}

async fn cmd_vote(jid: &str, poll_msg_id: &str, options: &[&str]) -> Result<()> {
    let client = client::Client::new()?;
    let session = client.connect().await?;
    session.send_poll_vote(jid, poll_msg_id, options).await?;
    println!("voted on {poll_msg_id}: {}", options.join(", "));
    Ok(())
}

async fn cmd_send_file(jid: &str, path: &str, caption: Option<&str>) -> Result<()> {
    use std::path::Path;
    let data = std::fs::read(path)?;
    let ext = Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    // Fast path: route through the running daemon's IPC so the CLI doesn't
    // have to spin up its own WA socket (which collides with the daemon and
    // blocks on offline-drain IQ races). Falls through to a one-shot
    // standalone session if no daemon is listening.
    use base64::Engine as _;
    let data_b64 = base64::engine::general_purpose::STANDARD.encode(&data);
    let file_name = Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file")
        .to_string();
    let caption_owned = caption.map(|c| c.to_string());
    let req = match ext.as_str() {
        "jpg" | "jpeg" | "png" | "webp" | "gif" => daemon::Request::SendImage {
            jid: jid.to_string(), data_b64: data_b64.clone(), caption: caption_owned.clone(),
        },
        "mp4" | "mov" | "avi" | "mkv" => daemon::Request::SendVideo {
            jid: jid.to_string(), data_b64: data_b64.clone(), caption: caption_owned.clone(),
        },
        "mp3" | "ogg" | "opus" | "m4a" | "aac" | "wav" => {
            let mime = match ext.as_str() {
                "mp3"  => "audio/mpeg",
                "ogg" | "opus" => "audio/ogg; codecs=opus",
                "m4a"  => "audio/mp4",
                "aac"  => "audio/aac",
                _      => "audio/wav",
            };
            daemon::Request::SendAudio {
                jid: jid.to_string(), data_b64: data_b64.clone(), mimetype: mime.to_string(),
            }
        }
        _ => daemon::Request::SendDocument {
            jid: jid.to_string(), data_b64: data_b64.clone(),
            mimetype: mime_for_ext(&ext).to_string(),
            file_name: file_name.clone(),
        },
    };
    if let Some(v) = daemon::try_daemon_request(req).await? {
        let id = v.get("id").and_then(|x| x.as_str()).unwrap_or("?");
        println!("sent: {id}");
        return Ok(());
    }

    // Fallback: no daemon — spin up a one-shot session.
    let client = client::Client::new()?;
    let session = client.connect().await?;
    let id = match ext.as_str() {
        "jpg" | "jpeg" | "png" | "webp" | "gif" => {
            session.send_image(jid, &data, caption).await?
        }
        "mp4" | "mov" | "avi" | "mkv" => {
            session.send_video(jid, &data, caption).await?
        }
        "mp3" | "ogg" | "opus" | "m4a" | "aac" | "wav" => {
            let mime = match ext.as_str() {
                "mp3"  => "audio/mpeg",
                "ogg" | "opus" => "audio/ogg; codecs=opus",
                "m4a"  => "audio/mp4",
                "aac"  => "audio/aac",
                _      => "audio/wav",
            };
            session.send_audio(jid, &data, mime).await?
        }
        _ => {
            let mime = mime_for_ext(&ext);
            session.send_document(jid, &data, mime, &file_name).await?
        }
    };
    println!("sent: {id}");
    Ok(())
}

fn mime_for_ext(ext: &str) -> &'static str {
    match ext {
        "pdf"  => "application/pdf",
        "zip"  => "application/zip",
        "txt"  => "text/plain",
        "csv"  => "text/csv",
        "json" => "application/json",
        "xml"  => "application/xml",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        _      => "application/octet-stream",
    }
}

async fn cmd_send_location(
    jid: &str, lat: f64, lon: f64,
    name: Option<&str>, address: Option<&str>,
) -> Result<()> {
    let req = daemon::Request::SendLocation {
        jid: jid.to_string(), latitude: lat, longitude: lon,
        name: name.map(String::from), address: address.map(String::from),
    };
    if let Some(v) = daemon::try_daemon_request(req).await? {
        let id = v.get("id").and_then(|x| x.as_str()).unwrap_or("?");
        println!("sent: {id}");
        return Ok(());
    }
    let client = client::Client::new()?;
    let session = client.connect().await?;
    let id = session.send_location(jid, lat, lon, name, address).await?;
    println!("sent: {id}");
    Ok(())
}

async fn cmd_send_contact(jid: &str, display_name: &str, phone_e164: &str) -> Result<()> {
    let req = daemon::Request::SendContact {
        jid: jid.to_string(),
        display_name: display_name.to_string(),
        phone_e164: phone_e164.to_string(),
    };
    if let Some(v) = daemon::try_daemon_request(req).await? {
        let id = v.get("id").and_then(|x| x.as_str()).unwrap_or("?");
        println!("sent: {id}");
        return Ok(());
    }
    let client = client::Client::new()?;
    let session = client.connect().await?;
    let id = session.send_contact(jid, display_name, phone_e164).await?;
    println!("sent: {id}");
    Ok(())
}

async fn cmd_send_voice(jid: &str, path: &str) -> Result<()> {
    use base64::Engine as _;
    let data = std::fs::read(path)?;
    let ext = std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    let mime = match ext.as_str() {
        "ogg" | "opus" => "audio/ogg; codecs=opus",
        "mp3" => "audio/mpeg",
        "m4a" => "audio/mp4",
        _ => "audio/ogg; codecs=opus",
    };
    let data_b64 = base64::engine::general_purpose::STANDARD.encode(&data);

    // Route through daemon first so the CLI doesn't race its own WA socket
    // against the live daemon. Falls back to a one-shot session otherwise.
    let req = daemon::Request::SendVoiceNote {
        jid: jid.to_string(),
        data_b64,
        mimetype: mime.to_string(),
    };
    if let Some(v) = daemon::try_daemon_request(req).await? {
        let id = v.get("id").and_then(|x| x.as_str()).unwrap_or("?");
        println!("sent: {id}");
        return Ok(());
    }
    let client = client::Client::new()?;
    let session = client.connect().await?;
    let id = session.send_voice_note(jid, &data, mime).await?;
    println!("sent: {id}");
    Ok(())
}

async fn cmd_send_sticker(jid: &str, path: &str) -> Result<()> {
    let data = std::fs::read(path)?;
    let client = client::Client::new()?;
    let session = client.connect().await?;
    let id = session.send_sticker(jid, &data).await?;
    println!("sent: {id}");
    Ok(())
}

async fn cmd_download(jid: &str, msg_id: &str, out_path: Option<&str>) -> Result<()> {
    let store = message_store::MessageStore::new(std::path::Path::new("."))?;
    let stored = store
        .lookup(jid, msg_id)
        .ok_or_else(|| anyhow::anyhow!("message {msg_id} not found for {jid}"))?;
    if stored.media_info.is_none() {
        bail!("message {msg_id} is not a media message");
    }
    let media_type_str = stored.media_type.as_deref().unwrap_or("document");

    let client = client::Client::new()?;
    let session = client.connect().await?;
    let bytes = session.download_media_by_id(jid, msg_id).await?;

    let ext = match media_type_str {
        "image"    => "jpg",
        "video"    => "mp4",
        "audio"    => "ogg",
        "sticker"  => "webp",
        _          => "bin",
    };
    let dest = out_path
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("{msg_id}.{ext}"));
    std::fs::write(&dest, &bytes)?;
    println!("saved {} bytes → {dest}", bytes.len());
    Ok(())
}

async fn cmd_status_post(text: &str) -> Result<()> {
    let client = client::Client::new()?;
    let session = client.connect().await?;
    let id = session.send_status_text(text).await?;
    println!("status posted: {id}");
    Ok(())
}

async fn cmd_lookup(phones: &[&str]) -> Result<()> {
    let client = client::Client::new()?;
    let session = client.connect().await?;
    let results = session.on_whatsapp(phones).await?;
    for info in &results {
        let status = if info.on_whatsapp { "✓ on WhatsApp" } else { "✗ not registered" };
        println!("{}\t{status}", info.jid);
    }
    Ok(())
}

async fn cmd_history(jid: &str, n: usize) -> Result<()> {
    let store = auth::FileStore::new()?;
    let msg_store = message_store::MessageStore::new(store.base_dir())?;
    let msgs = msg_store.recent(jid, n);
    if msgs.is_empty() {
        println!("(no stored messages for {jid})");
        return Ok(());
    }
    for m in &msgs {
        let dir = if m.from_me { "→" } else { "←" };
        let who = m.push_name.as_deref().unwrap_or(m.participant.as_deref().unwrap_or(jid));
        let body = m.text.as_deref()
            .map(|t| t.to_string())
            .or_else(|| m.media_type.as_deref().map(|mt| format!("<{mt}>")))
            .unwrap_or_else(|| "<>".to_string());
        println!("{dir} [{who}] {body}");
    }
    Ok(())
}

fn cmd_contacts() -> Result<()> {
    let store = auth::FileStore::new()?;
    let contacts = contacts::ContactStore::new(store.base_dir())?;
    let map = contacts.snapshot();
    if map.is_empty() {
        println!("(no cached contacts — connect first to populate)");
    } else {
        let mut pairs: Vec<_> = map.into_iter().collect();
        pairs.sort_by(|a, b| a.1.cmp(&b.1));
        for (jid, name) in pairs {
            println!("{name}\t{jid}");
        }
    }
    Ok(())
}

async fn cmd_status() -> Result<()> {
    let client = client::Client::new()?;
    let session = client.connect().await?;
    println!("connected as {}", session.our_jid);
    let contacts = session.contacts_snapshot();
    println!("{} cached contacts", contacts.len());
    Ok(())
}

async fn cmd_group(jid: &str) -> Result<()> {
    let client = client::Client::new()?;
    let session = client.connect().await?;
    let info = session.group_info(jid).await?;
    println!("Group:   {}", info.name);
    println!("JID:     {}", info.jid);
    if let Some(desc) = &info.description {
        println!("Desc:    {desc}");
    }
    println!("Members: {}", info.participants.len());
    for p in &info.participants {
        let role = if p.is_super_admin { " [superadmin]" }
                   else if p.is_admin { " [admin]" }
                   else { "" };
        let name = session.contact_name(&p.jid).unwrap_or_else(|| p.jid.clone());
        println!("  {name}{role}");
    }
    Ok(())
}

// ── Status media + forward + ephemeral ───────────────────────────────────────

async fn cmd_status_media_image(path: &str, caption: Option<&str>) -> Result<()> {
    let data = std::fs::read(path)?;
    let client = client::Client::new()?;
    let session = client.connect().await?;
    let id = session.send_status_image(&data, caption).await?;
    println!("status posted: {id}");
    Ok(())
}

async fn cmd_status_media_video(path: &str, caption: Option<&str>) -> Result<()> {
    let data = std::fs::read(path)?;
    let client = client::Client::new()?;
    let session = client.connect().await?;
    let id = session.send_status_video(&data, caption).await?;
    println!("status posted: {id}");
    Ok(())
}

async fn cmd_forward(to_jid: &str, from_jid: &str, msg_id: &str) -> Result<()> {
    let client = client::Client::new()?;
    let session = client.connect().await?;
    let id = session.forward_message(to_jid, from_jid, msg_id).await?;
    println!("forwarded: {id}");
    Ok(())
}

async fn cmd_ephemeral(jid: &str, secs: u32) -> Result<()> {
    let client = client::Client::new()?;
    let session = client.connect().await?;
    session.set_ephemeral_duration(jid, secs).await?;
    let label = match secs {
        0      => "off".to_string(),
        86400  => "24h".to_string(),
        604800 => "7d".to_string(),
        _      => format!("{secs}s"),
    };
    println!("ephemeral set to {label} for {jid}");
    Ok(())
}

// ── Group management commands ─────────────────────────────────────────────────

async fn cmd_group_create(name: &str, jids: &[&str]) -> Result<()> {
    let client = client::Client::new()?;
    let session = client.connect().await?;
    let info = session.create_group(name, jids).await?;
    println!("created: {} ({})", info.name, info.jid);
    println!("{} participants", info.participants.len());
    Ok(())
}

async fn cmd_group_participants(action: &str, group_jid: &str, jids: &[&str]) -> Result<()> {
    let client = client::Client::new()?;
    let session = client.connect().await?;
    let results = match action {
        "add"     => session.add_participants(group_jid, jids).await?,
        "remove"  => session.remove_participants(group_jid, jids).await?,
        "promote" => session.promote_to_admin(group_jid, jids).await?,
        "demote"  => session.demote_from_admin(group_jid, jids).await?,
        _         => anyhow::bail!("unknown action {action}"),
    };
    for r in &results {
        match &r.error {
            None    => println!("{}: ok", r.jid),
            Some(e) => println!("{}: error {e}", r.jid),
        }
    }
    Ok(())
}

async fn cmd_group_leave(group_jid: &str) -> Result<()> {
    let client = client::Client::new()?;
    let session = client.connect().await?;
    session.leave_group(group_jid).await?;
    println!("left {group_jid}");
    Ok(())
}

async fn cmd_group_subject(group_jid: &str, subject: &str) -> Result<()> {
    let client = client::Client::new()?;
    let session = client.connect().await?;
    session.set_group_subject(group_jid, subject).await?;
    println!("subject updated");
    Ok(())
}

async fn cmd_group_desc(group_jid: &str, desc: &str) -> Result<()> {
    let client = client::Client::new()?;
    let session = client.connect().await?;
    session.set_group_description(group_jid, desc).await?;
    println!("description updated");
    Ok(())
}

// ── Pair by phone ─────────────────────────────────────────────────────────────

async fn cmd_pair_phone(phone: &str) -> Result<()> {
    let client = client::Client::new()?;
    let _session = client.connect_with_phone(phone).await?;
    println!("Paired successfully!");
    Ok(())
}

// ── Blocklist & presence commands ────────────────────────────────────────────

async fn cmd_blocklist() -> Result<()> {
    let client = client::Client::new()?;
    let session = client.connect().await?;
    let blocked = session.fetch_blocklist().await?;
    if blocked.is_empty() {
        println!("(no blocked contacts)");
    } else {
        for jid in blocked {
            println!("{jid}");
        }
    }
    Ok(())
}

async fn cmd_block(jid: &str, block: bool) -> Result<()> {
    let client = client::Client::new()?;
    let session = client.connect().await?;
    if block {
        session.block_contact(jid).await?;
        println!("blocked {jid}");
    } else {
        session.unblock_contact(jid).await?;
        println!("unblocked {jid}");
    }
    Ok(())
}

async fn cmd_subscribe_presence(jid: &str) -> Result<()> {
    let client = client::Client::new()?;
    let session = client.connect().await?;
    session.subscribe_contact_presence(jid).await?;
    println!("subscribed to presence for {jid}");
    Ok(())
}

async fn cmd_mark_status_viewed(sender_jid: &str, msg_id: &str) -> Result<()> {
    let client = client::Client::new()?;
    let session = client.connect().await?;
    session.mark_status_viewed(sender_jid, msg_id).await?;
    println!("marked status {msg_id} from {sender_jid} as viewed");
    Ok(())
}

// ── Profile picture commands ──────────────────────────────────────────────────

async fn cmd_avatar(jid: &str) -> Result<()> {
    let client = client::Client::new()?;
    let session = client.connect().await?;
    match session.get_profile_picture(jid, false).await? {
        Some(url) => println!("{url}"),
        None      => println!("(no profile picture)"),
    }
    Ok(())
}

async fn cmd_set_avatar(path: &str) -> Result<()> {
    let data = std::fs::read(path)?;
    let client = client::Client::new()?;
    let session = client.connect().await?;
    session.set_profile_picture(&data).await?;
    println!("profile picture updated");
    Ok(())
}

// ── Event printer ─────────────────────────────────────────────────────────────

async fn cmd_privacy() -> Result<()> {
    let client = client::Client::new()?;
    let session = client.connect().await?;
    let p = session.fetch_privacy().await?;
    println!("last-seen:      {:?}", p.last_seen);
    println!("online:         {:?}", p.online);
    println!("profile-pic:    {:?}", p.profile_picture);
    println!("status:         {:?}", p.status);
    println!("read-receipts:  {:?}", p.read_receipts);
    println!("group-add:      {:?}", p.group_add);
    println!("call-add:       {:?}", p.call_add);
    Ok(())
}

async fn cmd_privacy_set(setting: &str, value: &str) -> Result<()> {
    use socket::privacy::{PrivacyPatch, PrivacyValue};

    let v = match value {
        "all"                => PrivacyValue::All,
        "contacts"           => PrivacyValue::Contacts,
        "contact-blacklist"  => PrivacyValue::ContactBlacklist,
        "none"               => PrivacyValue::None,
        "match-last-seen"    => PrivacyValue::MatchLastSeen,
        _ => bail!("Unknown value '{value}'. Valid: all | contacts | contact-blacklist | none | match-last-seen"),
    };

    let mut patch = PrivacyPatch::default();
    match setting {
        "last-seen"       => patch.last_seen       = Some(v),
        "online"          => patch.online          = Some(v),
        "profile"         => patch.profile_picture = Some(v),
        "status"          => patch.status          = Some(v),
        "read-receipts"   => patch.read_receipts   = Some(v),
        "group-add"       => patch.group_add       = Some(v),
        "call-add"        => patch.call_add        = Some(v),
        _ => bail!("Unknown setting '{setting}'. Valid: last-seen | online | profile | status | read-receipts | group-add | call-add"),
    }

    let client = client::Client::new()?;
    let session = client.connect().await?;
    session.set_privacy(patch).await?;
    println!("Privacy updated: {setting} = {value}");
    Ok(())
}

/// `monitor` command: enable trace-level logging and print every event as a debug line.
async fn cmd_monitor() -> Result<()> {
    // Re-init subscriber at trace level so node-level logs show up
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "whatsapp_rs=trace,info".to_string()),
        )
        .try_init();

    let client = client::Client::new()?;
    let session = client.connect().await?;
    info!("monitor: connected as {}", session.our_jid);

    let mut events = session.events();
    loop {
        match events.recv().await {
            Ok(event) => {
                // Print a compact single-line dump for every event variant
                let label = event_label(&event);
                println!("[EVENT] {label}");
                event_print::print_event(&session, event).await;
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                println!("[WARN] dropped {n} events (channel full)");
            }
            Err(_) => break,
        }
    }
    Ok(())
}

fn event_label(event: &MessageEvent) -> &'static str {
    match event {
        MessageEvent::NewMessage { .. }   => "NewMessage",
        MessageEvent::MessageUpdate { .. } => "MessageUpdate",
        MessageEvent::Reaction { .. }     => "Reaction",
        MessageEvent::Receipt { .. }      => "Receipt",
        MessageEvent::HistorySync { .. }  => "HistorySync",
        MessageEvent::MessageRevoke { .. } => "MessageRevoke",
        MessageEvent::MessageEdit { .. }  => "MessageEdit",
        MessageEvent::PollVote { .. }     => "PollVote",
        MessageEvent::Presence { .. }       => "Presence",
        MessageEvent::Typing { .. }         => "Typing",
        MessageEvent::EphemeralSetting { .. } => "EphemeralSetting",
        MessageEvent::GroupUpdate { .. }    => "GroupUpdate",
        MessageEvent::Disconnected { .. }   => "Disconnected",
        MessageEvent::Connected             => "Connected",
        MessageEvent::AppStateUpdate { .. } => "AppStateUpdate",
    }
}

