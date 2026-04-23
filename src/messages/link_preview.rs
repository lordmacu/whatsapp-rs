//! Auto-fetch OG/Twitter metadata for link previews.
//!
//! No HTML parser dependency — we scan for `<meta property="og:*">`,
//! `<meta name="...">`, and `<title>` with straightforward byte search.
//! Good enough for WA's preview card (title + description + thumb).
//!
//! The single entry point is [`fetch_preview`]: give it a URL, get back a
//! `LinkPreview` ready to hand to `send_link_preview` / `Chat::text_preview`.

use std::time::Duration;

/// OG/Twitter-card data extracted from a URL, ready for WhatsApp preview.
#[derive(Debug, Clone, Default)]
pub struct LinkPreview {
    pub url: String,
    pub title: String,
    pub description: String,
    /// Raw JPEG bytes. `None` when the site exposes no usable image or the
    /// image isn't a JPEG under our size cap.
    pub thumbnail_jpeg: Option<Vec<u8>>,
}

/// Return the first `http://` or `https://` URL found in `text`, or `None`.
///
/// URL ends at whitespace or common punctuation (`)`, `>`, trailing `.`, `,`).
pub fn extract_first_url(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i + 7 < bytes.len() {
        let rest = &bytes[i..];
        let matched = rest.starts_with(b"https://") || rest.starts_with(b"http://");
        if matched {
            let end = rest.iter().position(|&b| {
                matches!(b, b' ' | b'\n' | b'\r' | b'\t' | b'"' | b'<' | b'>' | b'|' | b'`')
            }).unwrap_or(rest.len());
            let mut url_bytes = &rest[..end];
            // Trim sentence punctuation commonly stuck to a URL at the end.
            while let Some(&last) = url_bytes.last() {
                if matches!(last, b'.' | b',' | b';' | b':' | b'!' | b'?' | b')' | b']') {
                    url_bytes = &url_bytes[..url_bytes.len() - 1];
                } else {
                    break;
                }
            }
            if url_bytes.len() > 10 {
                if let Ok(s) = std::str::from_utf8(url_bytes) {
                    return Some(s.to_string());
                }
            }
        }
        i += 1;
    }
    None
}

/// Fetch and parse OG metadata for `url`. Returns `None` on network error
/// or when the response isn't HTML / has no usable metadata.
///
/// Has its own timeout (8s HTML, 5s image) so a slow site never blocks send.
pub async fn fetch_preview(url: &str) -> Option<LinkPreview> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        // WhatsApp's own preview fetcher sends a generic UA; many sites
        // serve lighter HTML to mobile-like UAs.
        .user_agent("WhatsApp/2.24 Mozilla/5.0")
        .redirect(reqwest::redirect::Policy::limited(5))
        .build().ok()?;

    let resp = client.get(url).send().await.ok()?;
    if !resp.status().is_success() { return None; }
    let ctype = resp.headers().get("content-type")
        .and_then(|v| v.to_str().ok()).unwrap_or("").to_ascii_lowercase();
    if !ctype.contains("text/html") && !ctype.contains("application/xhtml") {
        return None;
    }
    // Cap HTML read to avoid pathological pages.
    let body = resp.bytes().await.ok()?;
    let html = String::from_utf8_lossy(&body[..body.len().min(512 * 1024)]);

    let mut title = find_meta(&html, "og:title").unwrap_or_default();
    if title.is_empty() {
        title = find_meta(&html, "twitter:title").unwrap_or_default();
    }
    if title.is_empty() {
        title = find_title_tag(&html).unwrap_or_default();
    }
    let description = find_meta(&html, "og:description")
        .or_else(|| find_meta(&html, "twitter:description"))
        .or_else(|| find_meta(&html, "description"))
        .unwrap_or_default();
    let canonical = find_meta(&html, "og:url").unwrap_or_else(|| url.to_string());

    let image_url = find_meta(&html, "og:image")
        .or_else(|| find_meta(&html, "twitter:image"));
    let thumbnail_jpeg = match image_url {
        Some(img) => fetch_thumbnail(&client, &img, url).await,
        None => None,
    };

    if title.is_empty() && description.is_empty() && thumbnail_jpeg.is_none() {
        return None;
    }
    Some(LinkPreview {
        url: canonical,
        title: truncate(&title, 256),
        description: truncate(&description, 1024),
        thumbnail_jpeg,
    })
}

/// Fetch an image URL. Accept only `image/jpeg` under 120KB — no resize
/// dependency. Resolve relative URLs against `base`.
async fn fetch_thumbnail(client: &reqwest::Client, img_url: &str, base: &str) -> Option<Vec<u8>> {
    let resolved = resolve_url(img_url, base);
    let resp = client.get(&resolved)
        .timeout(Duration::from_secs(5))
        .send().await.ok()?;
    if !resp.status().is_success() { return None; }
    let ctype = resp.headers().get("content-type")
        .and_then(|v| v.to_str().ok()).unwrap_or("").to_ascii_lowercase();
    // WA accepts any image but we don't want to pull in an image crate
    // to re-encode PNG → JPEG. Keep it to already-jpeg.
    if !ctype.contains("image/jpeg") && !ctype.contains("image/jpg") {
        return None;
    }
    let bytes = resp.bytes().await.ok()?;
    if bytes.is_empty() || bytes.len() > 120 * 1024 { return None; }
    // Basic sanity: JPEGs start with 0xFF 0xD8.
    if bytes.len() < 2 || bytes[0] != 0xFF || bytes[1] != 0xD8 { return None; }
    Some(bytes.to_vec())
}

/// Look up `<meta property="NAME" content="VALUE">` OR `<meta name="NAME" content="VALUE">`.
/// Case-insensitive match on the property/name; content may come before property too.
fn find_meta(html: &str, prop: &str) -> Option<String> {
    let low = html.to_ascii_lowercase();
    let target_prop = prop.to_ascii_lowercase();
    let mut search_start = 0;
    while let Some(tag_start_rel) = low[search_start..].find("<meta ") {
        let tag_start = search_start + tag_start_rel;
        let tag_end = low[tag_start..].find('>').map(|e| tag_start + e + 1)?;
        let tag = &low[tag_start..tag_end];
        // Match either property="og:..." or name="og:..."
        let has_prop = attr_value(tag, "property").map(|v| v == target_prop).unwrap_or(false)
            || attr_value(tag, "name").map(|v| v == target_prop).unwrap_or(false);
        if has_prop {
            let raw_tag = &html[tag_start..tag_end];
            if let Some(content) = attr_value_raw(raw_tag, "content") {
                return Some(html_decode(&content));
            }
        }
        search_start = tag_end;
    }
    None
}

/// `<title>...</title>` — fallback when no og:title.
fn find_title_tag(html: &str) -> Option<String> {
    let low = html.to_ascii_lowercase();
    let start = low.find("<title")?;
    let open_end = low[start..].find('>')? + start + 1;
    let close_rel = low[open_end..].find("</title>")?;
    let raw = &html[open_end..open_end + close_rel];
    Some(html_decode(raw.trim()))
}

/// Return lowercase value of `attr` within a lowercased meta-tag snippet
/// (`<meta property="og:title" content="Hi">`).
fn attr_value(tag_lower: &str, attr: &str) -> Option<String> {
    let needle = format!("{}=", attr);
    let pos = tag_lower.find(&needle)?;
    let rest = &tag_lower[pos + needle.len()..];
    parse_quoted(rest)
}

/// Same as `attr_value` but preserves case of the value (the original-case
/// snippet is passed in). The attribute name is still matched case-
/// insensitively by searching the lowercased copy first.
fn attr_value_raw(tag_raw: &str, attr: &str) -> Option<String> {
    let low = tag_raw.to_ascii_lowercase();
    let needle = format!("{}=", attr);
    let pos = low.find(&needle)?;
    let rest = &tag_raw[pos + needle.len()..];
    parse_quoted(rest)
}

/// Parse `"value"` or `'value'` starting at the beginning of `s`.
fn parse_quoted(s: &str) -> Option<String> {
    let mut chars = s.chars();
    let quote = chars.next()?;
    if quote != '"' && quote != '\'' { return None; }
    let rest = chars.as_str();
    let end = rest.find(quote)?;
    Some(rest[..end].to_string())
}

/// Minimal HTML entity decoder — covers the common named entities we see
/// in OG metadata plus `&#NNN;` / `&#xHH;` numeric forms.
fn html_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find('&') {
        out.push_str(&rest[..pos]);
        rest = &rest[pos..];
        if let Some(semi) = rest.find(';') {
            let entity = &rest[1..semi];
            let replaced = match entity {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                "nbsp" => Some(' '),
                e if e.starts_with("#x") || e.starts_with("#X") => {
                    u32::from_str_radix(&e[2..], 16).ok().and_then(char::from_u32)
                }
                e if e.starts_with('#') => {
                    e[1..].parse::<u32>().ok().and_then(char::from_u32)
                }
                _ => None,
            };
            if let Some(c) = replaced {
                out.push(c);
                rest = &rest[semi + 1..];
                continue;
            }
        }
        // Unknown entity — emit as-is and skip past the `&`.
        out.push('&');
        rest = &rest[1..];
    }
    out.push_str(rest);
    out
}

/// Resolve relative/protocol-relative URLs against `base`. Absolute URLs
/// pass through unchanged.
fn resolve_url(href: &str, base: &str) -> String {
    if href.starts_with("http://") || href.starts_with("https://") {
        return href.to_string();
    }
    if let Some(rest) = href.strip_prefix("//") {
        // Protocol-relative. Inherit base's scheme.
        let scheme = if base.starts_with("https://") { "https:" } else { "http:" };
        return format!("{}//{}", scheme, rest);
    }
    // Derive origin from base (https://host[:port]).
    let scheme_end = base.find("://").unwrap_or(0) + 3;
    let path_start = base[scheme_end..].find('/').map(|p| p + scheme_end).unwrap_or(base.len());
    let origin = &base[..path_start];
    if href.starts_with('/') {
        return format!("{}{}", origin, href);
    }
    // Last resort: drop final path segment and append.
    let dir_end = base.rfind('/').unwrap_or(base.len());
    let dir = &base[..dir_end];
    format!("{}/{}", dir, href)
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max { return s.to_string(); }
    s.chars().take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_first_url() {
        assert_eq!(extract_first_url("hola https://example.com/foo mundo"),
                   Some("https://example.com/foo".to_string()));
        assert_eq!(extract_first_url("ver (https://example.com/foo)."),
                   Some("https://example.com/foo".to_string()));
        assert_eq!(extract_first_url("sin url"), None);
    }

    #[test]
    fn parses_og_meta() {
        let html = r#"<html><head>
            <meta property="og:title" content="Hello &amp; Goodbye">
            <meta name="og:description" content="Desc here">
        </head></html>"#;
        assert_eq!(find_meta(html, "og:title"), Some("Hello & Goodbye".to_string()));
        assert_eq!(find_meta(html, "og:description"), Some("Desc here".to_string()));
    }

    #[test]
    fn falls_back_to_title_tag() {
        let html = "<html><head><title>Just Title</title></head></html>";
        assert_eq!(find_title_tag(html), Some("Just Title".to_string()));
    }

    #[test]
    fn resolves_relative_urls() {
        assert_eq!(resolve_url("/a.jpg", "https://x.com/foo/bar"),
                   "https://x.com/a.jpg");
        assert_eq!(resolve_url("//cdn.x.com/a.jpg", "https://x.com/"),
                   "https://cdn.x.com/a.jpg");
        assert_eq!(resolve_url("https://y.com/a.jpg", "https://x.com/"),
                   "https://y.com/a.jpg");
    }
}
