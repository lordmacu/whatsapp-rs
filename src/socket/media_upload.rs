use crate::binary::{BinaryNode, NodeContent};
use crate::media::MediaType;
use crate::socket::SocketSender;
use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};

/// Result of a successful media upload — the CDN URL WA expects in the
/// outgoing message + the direct-path used for download on the peer side.
pub struct UploadResult {
    pub url: String,
    pub direct_path: String,
}

/// One MMS CDN host advertised by the server.
struct MediaConnHost {
    hostname: String,
}

/// Response to the `<media_conn/>` IQ: list of upload hosts + auth token
/// used in the query string of the POST URL.
struct MediaConn {
    hosts: Vec<MediaConnHost>,
    auth: String,
}

/// Request the current MMS connection info: a set of upload hostnames and
/// an auth token we present as a query param when POSTing the blob. Mirrors
/// Baileys' `refreshMediaConn`. Older code here asked the server for a
/// pre-signed URL via `action=mms-url-fetch`; modern WA ignores that path
/// and we used to time out after 60s.
/// Probe the media_conn IQ and return the first advertised upload hostname.
/// Used by `whatsapp-rs doctor` to prove the media-upload path is unlocked
/// without actually uploading anything.
pub async fn probe_media_conn(sender: &SocketSender) -> Result<String> {
    let conn = fetch_media_conn(sender).await?;
    conn.hosts.first()
        .map(|h| h.hostname.clone())
        .ok_or_else(|| anyhow::anyhow!("media_conn returned but no hosts"))
}

async fn fetch_media_conn(sender: &SocketSender) -> Result<MediaConn> {
    let id = sender.next_id();
    let node = BinaryNode {
        tag: "iq".to_string(),
        attrs: vec![
            ("id".to_string(), id),
            ("xmlns".to_string(), "w:m".to_string()),
            ("type".to_string(), "set".to_string()),
            ("to".to_string(), "s.whatsapp.net".to_string()),
        ],
        content: NodeContent::List(vec![BinaryNode {
            tag: "media_conn".to_string(),
            attrs: vec![],
            content: NodeContent::None,
        }]),
    };
    let response = sender.send_iq_await(node).await?;
    parse_media_conn(&response)
}

fn parse_media_conn(iq: &BinaryNode) -> Result<MediaConn> {
    let children = match &iq.content {
        NodeContent::List(v) => v,
        _ => bail!("media_conn IQ has no children"),
    };
    let mc = children.iter().find(|n| n.tag == "media_conn")
        .ok_or_else(|| anyhow::anyhow!("no <media_conn> in IQ response"))?;
    let auth = mc.attr("auth")
        .ok_or_else(|| anyhow::anyhow!("no auth attr on <media_conn>"))?
        .to_string();
    let hosts = if let NodeContent::List(ch) = &mc.content {
        ch.iter()
            .filter(|n| n.tag == "host")
            .filter_map(|n| n.attr("hostname").map(|h| MediaConnHost { hostname: h.to_string() }))
            .collect()
    } else {
        Vec::new()
    };
    if hosts.is_empty() {
        bail!("media_conn response carried no upload hosts");
    }
    Ok(MediaConn { hosts, auth })
}

/// Mirrors Baileys' `MEDIA_PATH_MAP`. Sticker uploads reuse the image
/// path; `md-msg-hist` and `md-app-state` share one.
fn media_path(t: MediaType) -> &'static str {
    match t {
        MediaType::Image | MediaType::Sticker => "/mms/image",
        MediaType::Video => "/mms/video",
        MediaType::Audio => "/mms/audio",
        MediaType::Document => "/mms/document",
        MediaType::HistorySync | MediaType::AppState => "/mms/md-app-state",
    }
}

/// URL-safe base64 without padding. Matches Baileys'
/// `encodeBase64EncodedStringForUpload`.
fn b64_url_safe_trimmed(raw: &[u8]) -> String {
    let s = B64.encode(raw);
    let mapped: String = s
        .chars()
        .filter(|c| *c != '=')
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            other => other,
        })
        .collect();
    url_encode(&mapped)
}

/// Minimal URL-component encoder — we only need it for the auth token and
/// the b64 hash in the query string.
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
            | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Full media upload pipeline: request media_conn, walk the hosts, POST
/// the encrypted blob until one accepts, parse the returned URL +
/// direct_path from the host's JSON response. Replaces the legacy
/// `mms-url-fetch` single-step path.
pub async fn request_upload_url(
    sender: &SocketSender,
    enc_sha256: &[u8],
    media_type: MediaType,
    _size: u64,
    blob: &[u8],
) -> Result<UploadResult> {
    let conn = fetch_media_conn(sender).await?;
    let path = media_path(media_type);
    let token = b64_url_safe_trimmed(enc_sha256);
    let auth_q = url_encode(&conn.auth);

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?;

    let mut last_err: Option<anyhow::Error> = None;
    for host in &conn.hosts {
        let url = format!(
            "https://{}{path}/{token}?auth={auth_q}&token={token}",
            host.hostname,
        );
        tracing::debug!("upload POST → {url}");
        let res = http
            .post(&url)
            .header("Content-Type", "application/octet-stream")
            .header("Origin", "https://web.whatsapp.com")
            .body(blob.to_vec())
            .send()
            .await;
        let resp = match res {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("upload to {} failed at HTTP layer: {e}", host.hostname);
                last_err = Some(e.into());
                continue;
            }
        };
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::warn!(
                "upload to {} returned {status}: {body}",
                host.hostname,
            );
            last_err = Some(anyhow::anyhow!("host {} status {status}", host.hostname));
            continue;
        }
        let body_text = match resp.text().await {
            Ok(t) => t,
            Err(e) => {
                last_err = Some(anyhow::anyhow!("read body from {}: {e}", host.hostname));
                continue;
            }
        };
        let json: serde_json::Value = match serde_json::from_str(&body_text) {
            Ok(v) => v,
            Err(e) => {
                last_err = Some(anyhow::anyhow!(
                    "decode JSON from {}: {e} (body={body_text})", host.hostname
                ));
                continue;
            }
        };
        let url = json.get("url").and_then(|v| v.as_str()).unwrap_or_default().to_string();
        let direct_path = json.get("direct_path").and_then(|v| v.as_str()).unwrap_or_default().to_string();
        if !url.is_empty() || !direct_path.is_empty() {
            return Ok(UploadResult { url, direct_path });
        }
        last_err = Some(anyhow::anyhow!(
            "host {} returned no url/direct_path: {json}",
            host.hostname,
        ));
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no media hosts advertised")))
}

/// Legacy shim — `request_upload_url` now performs the upload too, so
/// `upload_to_cdn` is a no-op kept for signature compat with older
/// callers. New code should use `request_upload_url` directly.
#[allow(dead_code)]
pub async fn upload_to_cdn(_url: &str, _blob: &[u8]) -> Result<()> {
    Ok(())
}
