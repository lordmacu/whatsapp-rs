use crate::binary::{BinaryNode, NodeContent};
use crate::media::MediaType;
use crate::socket::SocketSender;
use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};

pub struct UploadResult {
    pub url: String,
    pub direct_path: String,
}

/// Request a CDN upload URL from WhatsApp servers.
pub async fn request_upload_url(
    sender: &SocketSender,
    enc_sha256: &[u8],
    media_type: MediaType,
    size: u64,
) -> Result<UploadResult> {
    let hash_b64 = B64.encode(enc_sha256);
    let mtype_str = match media_type {
        MediaType::Image | MediaType::Sticker => "image",
        MediaType::Video => "video",
        MediaType::Audio => "audio",
        MediaType::Document => "document",
        MediaType::HistorySync => "md-msg-hist",
    };
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
            tag: "media".to_string(),
            attrs: vec![("action".to_string(), "mms-url-fetch".to_string())],
            content: NodeContent::List(vec![BinaryNode {
                tag: "file".to_string(),
                attrs: vec![
                    ("hash".to_string(), hash_b64),
                    ("type".to_string(), mtype_str.to_string()),
                    ("size".to_string(), size.to_string()),
                ],
                content: NodeContent::None,
            }]),
        }]),
    };

    let response = sender.send_iq_await(node).await?;
    parse_upload_response(&response)
}

fn parse_upload_response(node: &BinaryNode) -> Result<UploadResult> {
    let find_text = |parent: &BinaryNode, tag: &str| -> Option<String> {
        if let NodeContent::List(children) = &parent.content {
            children.iter().find(|n| n.tag == tag).and_then(|n| match &n.content {
                NodeContent::Text(s) => Some(s.clone()),
                NodeContent::Bytes(b) => String::from_utf8(b.clone()).ok(),
                _ => None,
            })
        } else {
            None
        }
    };

    let media_node = if let NodeContent::List(children) = &node.content {
        children.iter().find(|n| n.tag == "media")
            .ok_or_else(|| anyhow::anyhow!("no <media> in upload IQ response"))?
    } else {
        bail!("upload IQ response has no children");
    };

    let url = find_text(media_node, "url")
        .ok_or_else(|| anyhow::anyhow!("no <url> in upload response"))?;
    let direct_path = find_text(media_node, "direct-path").unwrap_or_default();

    Ok(UploadResult { url, direct_path })
}

/// PUT encrypted blob to the CDN URL.
pub async fn upload_to_cdn(url: &str, blob: &[u8]) -> Result<()> {
    let client = reqwest::Client::new();
    let resp = client
        .put(url)
        .header("Content-Type", "application/octet-stream")
        .body(blob.to_vec())
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("CDN PUT failed: {e}"))?;
    if !resp.status().is_success() {
        bail!("CDN upload HTTP {}", resp.status());
    }
    Ok(())
}
