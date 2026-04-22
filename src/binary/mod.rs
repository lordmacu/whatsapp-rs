/// Protocolo binario custom de WhatsApp (no es Protobuf estándar).
///
/// Formato de un nodo:
///   [list_size_tag] [list_size] [tag] [attrs...] [content]
///
/// Los strings se comprimen via tabla de tokens de un solo byte (235 entradas)
/// o de dos bytes (4 diccionarios × 256 entradas).

pub mod tokens;

use anyhow::{bail, Result};
use flate2::read::ZlibDecoder;
use std::io::Read;

// Tags especiales
#[allow(dead_code)]
const LIST_EMPTY: u8 = 0;
#[allow(dead_code)]
const STREAM_END: u8 = 2;
#[allow(dead_code)]
const DICTIONARY_0: u8 = 236;
#[allow(dead_code)]
const DICTIONARY_1: u8 = 237;
#[allow(dead_code)]
const DICTIONARY_2: u8 = 238;
#[allow(dead_code)]
const DICTIONARY_3: u8 = 239;
#[allow(dead_code)]
const INTEROP_JID: u8 = 245;
#[allow(dead_code)]
const FB_JID: u8 = 246;
const AD_JID: u8 = 247;
const LIST_8: u8 = 248;
const LIST_16: u8 = 249;
const JID_PAIR: u8 = 250;
const HEX_8: u8 = 251;
const BINARY_8: u8 = 252;
const BINARY_20: u8 = 253;
const BINARY_32: u8 = 254;
const NIBBLE_8: u8 = 255;

/// Un nodo binario de WhatsApp
#[derive(Debug, Clone)]
pub struct BinaryNode {
    pub tag: String,
    pub attrs: Vec<(String, String)>,
    pub content: NodeContent,
}

#[derive(Debug, Clone)]
pub enum NodeContent {
    None,
    Text(String),
    Bytes(Vec<u8>),
    List(Vec<BinaryNode>),
}

#[allow(dead_code)]
impl BinaryNode {
    pub fn new(tag: impl Into<String>) -> Self {
        Self {
            tag: tag.into(),
            attrs: vec![],
            content: NodeContent::None,
        }
    }

    pub fn attr(&self, key: &str) -> Option<&str> {
        self.attrs.iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// Decodifica un frame binario de WhatsApp.
/// El primer byte indica si está comprimido (bit 1) o es noise (bit 0).
pub fn decode_frame(data: &[u8]) -> Result<BinaryNode> {
    if data.is_empty() {
        bail!("empty frame");
    }

    let flags = data[0];
    let payload = &data[1..];

    // Bit 1 = zlib compressed
    let decompressed;
    let buf = if flags & 2 != 0 {
        let mut decoder = ZlibDecoder::new(payload);
        decompressed = {
            let mut v = Vec::new();
            decoder.read_to_end(&mut v)?;
            v
        };
        decompressed.as_slice()
    } else {
        payload
    };

    let mut reader = BufReader::new(buf);
    decode_node(&mut reader)
}

struct BufReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> BufReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn read_byte(&mut self) -> Result<u8> {
        if self.pos >= self.buf.len() {
            bail!("unexpected end of buffer");
        }
        let b = self.buf[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.pos + n > self.buf.len() {
            bail!("unexpected end of buffer reading {} bytes", n);
        }
        let slice = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }
}

fn decode_node(r: &mut BufReader) -> Result<BinaryNode> {
    let list_size = read_list_size(r)?;
    let tag = read_string(r)?;

    if list_size == 0 || tag == "stream:end" {
        bail!("stream end");
    }

    // Atributos: (list_size - 1) / 2 pares key-value
    let attr_count = (list_size - 1) >> 1;
    let mut attrs = Vec::with_capacity(attr_count);
    for _ in 0..attr_count {
        let key = read_string(r)?;
        let val = read_string(r)?;
        attrs.push((key, val));
    }

    let content = if list_size % 2 == 0 {
        // Hay contenido
        decode_content(r)?
    } else {
        NodeContent::None
    };

    Ok(BinaryNode { tag, attrs, content })
}

fn decode_content(r: &mut BufReader) -> Result<NodeContent> {
    let tag = r.read_byte()?;
    match tag {
        LIST_EMPTY => Ok(NodeContent::None),
        BINARY_8 => {
            let len = r.read_byte()? as usize;
            Ok(NodeContent::Bytes(r.read_bytes(len)?.to_vec()))
        }
        BINARY_20 => {
            let b0 = r.read_byte()? as usize;
            let b1 = r.read_byte()? as usize;
            let b2 = r.read_byte()? as usize;
            let len = (b0 << 16) | (b1 << 8) | b2;
            Ok(NodeContent::Bytes(r.read_bytes(len)?.to_vec()))
        }
        BINARY_32 => {
            let b0 = r.read_byte()? as usize;
            let b1 = r.read_byte()? as usize;
            let b2 = r.read_byte()? as usize;
            let b3 = r.read_byte()? as usize;
            let len = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
            Ok(NodeContent::Bytes(r.read_bytes(len)?.to_vec()))
        }
        LIST_8 | LIST_16 => {
            // Es una lista de nodos
            r.pos -= 1; // retroceder para que read_list_size lo lea
            let size = read_list_size(r)?;
            let mut nodes = Vec::with_capacity(size);
            for _ in 0..size {
                nodes.push(decode_node(r)?);
            }
            Ok(NodeContent::List(nodes))
        }
        _ => {
            // Es un string token
            r.pos -= 1;
            let s = read_string_from_tag(r, tag)?;
            Ok(NodeContent::Text(s))
        }
    }
}

fn read_list_size(r: &mut BufReader) -> Result<usize> {
    let tag = r.read_byte()?;
    match tag {
        LIST_EMPTY => Ok(0),
        LIST_8 => Ok(r.read_byte()? as usize),
        LIST_16 => {
            let hi = r.read_byte()? as usize;
            let lo = r.read_byte()? as usize;
            Ok((hi << 8) | lo)
        }
        _ => bail!("invalid list tag: {}", tag),
    }
}

fn read_string(r: &mut BufReader) -> Result<String> {
    let tag = r.read_byte()?;
    read_string_from_tag(r, tag)
}

fn read_string_from_tag(r: &mut BufReader, tag: u8) -> Result<String> {
    match tag {
        0..=235 => {
            // Token de un byte
            tokens::SINGLE_BYTE_TOKENS
                .get(tag as usize)
                .copied()
                .map(|s| s.to_string())
                .ok_or_else(|| anyhow::anyhow!("unknown token: {}", tag))
        }
        DICTIONARY_0..=DICTIONARY_3 => {
            // Token de dos bytes: [dict_idx, token_idx]
            let dict_idx = (tag - DICTIONARY_0) as usize;
            let token_idx = r.read_byte()? as usize;
            tokens::DOUBLE_BYTE_TOKENS
                .get(dict_idx)
                .and_then(|d| d.get(token_idx))
                .copied()
                .map(|s| s.to_string())
                .ok_or_else(|| anyhow::anyhow!("unknown dict token: {}/{}", dict_idx, token_idx))
        }
        JID_PAIR => {
            let user = read_string(r)?;
            let server = read_string(r)?;
            if user.is_empty() {
                Ok(server)
            } else {
                Ok(format!("{}@{}", user, server))
            }
        }
        AD_JID => {
            // [domain_type, device, user_string] — encoded server depends on domain_type.
            // Layout matches Baileys `readAdJid`.
            let domain_type = r.read_byte()?;
            let device      = r.read_byte()?;
            let user        = read_string(r)?;
            let server: &str = match domain_type {
                1 => "lid",
                2 => "hosted",
                3 => "hosted.lid",
                _ => "s.whatsapp.net",
            };
            if device == 0 {
                Ok(format!("{}@{}", user, server))
            } else {
                Ok(format!("{}:{}@{}", user, device, server))
            }
        }
        BINARY_8 => {
            let len = r.read_byte()? as usize;
            let bytes = r.read_bytes(len)?;
            Ok(String::from_utf8_lossy(bytes).into_owned())
        }
        BINARY_20 => {
            let b0 = r.read_byte()? as usize;
            let b1 = r.read_byte()? as usize;
            let b2 = r.read_byte()? as usize;
            let len = (b0 << 16) | (b1 << 8) | b2;
            let bytes = r.read_bytes(len)?;
            Ok(String::from_utf8_lossy(bytes).into_owned())
        }
        NIBBLE_8 => {
            let start = r.read_byte()?;
            let has_tail = (start & 0x80) != 0;
            let pairs = (start & 0x7f) as usize;
            let mut result = String::with_capacity(pairs * 2);
            for _ in 0..pairs {
                let b = r.read_byte()?;
                result.push(nibble_to_char((b >> 4) & 0xf));
                result.push(nibble_to_char(b & 0xf));
            }
            if has_tail { result.pop(); }
            Ok(result)
        }
        HEX_8 => {
            let start = r.read_byte()?;
            let has_tail = (start & 0x80) != 0;
            let pairs = (start & 0x7f) as usize;
            let mut result = String::with_capacity(pairs * 2);
            for _ in 0..pairs {
                let b = r.read_byte()?;
                result.push(char::from_digit(((b >> 4) & 0xf) as u32, 16).unwrap_or('0'));
                result.push(char::from_digit((b & 0xf) as u32, 16).unwrap_or('0'));
            }
            if has_tail { result.pop(); }
            Ok(result)
        }
        _ => bail!("unknown string tag: {}", tag),
    }
}

fn nibble_to_char(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10 => '-',
        11 => '.',
        15 => '\0',
        _ => '?',
    }
}

/// Encoda un nodo binario a bytes
pub fn encode_node(node: &BinaryNode) -> Vec<u8> {
    let mut buf = Vec::new();
    write_node(&mut buf, node);
    // Agregar flag byte al inicio (0 = sin compresión, no-noise)
    let mut frame = vec![0u8];
    frame.extend_from_slice(&buf);
    frame
}

fn write_node(buf: &mut Vec<u8>, node: &BinaryNode) {
    let has_content = !matches!(node.content, NodeContent::None);
    let list_size = 1 + node.attrs.len() * 2 + if has_content { 1 } else { 0 };
    write_list_size(buf, list_size);
    write_string(buf, &node.tag);
    for (k, v) in &node.attrs {
        write_string(buf, k);
        write_string(buf, v);
    }
    if has_content {
        match &node.content {
            NodeContent::None => {}
            NodeContent::Text(s) => write_string(buf, s),
            NodeContent::Bytes(b) => write_bytes(buf, b),
            NodeContent::List(nodes) => {
                write_list_size(buf, nodes.len());
                for n in nodes {
                    write_node(buf, n);
                }
            }
        }
    }
}

fn write_list_size(buf: &mut Vec<u8>, size: usize) {
    if size == 0 {
        buf.push(LIST_EMPTY);
    } else if size < 256 {
        buf.push(LIST_8);
        buf.push(size as u8);
    } else {
        buf.push(LIST_16);
        buf.push((size >> 8) as u8);
        buf.push(size as u8);
    }
}

fn write_string(buf: &mut Vec<u8>, s: &str) {
    // Buscar en tokens de un byte primero
    if let Some(idx) = tokens::SINGLE_BYTE_TOKENS.iter().position(|&t| t == s) {
        buf.push(idx as u8);
        return;
    }
    // Buscar en tokens de dos bytes
    for (dict_idx, dict) in tokens::DOUBLE_BYTE_TOKENS.iter().enumerate() {
        if let Some(token_idx) = dict.iter().position(|&t| t == s) {
            buf.push(DICTIONARY_0 + dict_idx as u8);
            buf.push(token_idx as u8);
            return;
        }
    }
    // Raw string
    write_bytes(buf, s.as_bytes());
}

fn write_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len < 256 {
        buf.push(BINARY_8);
        buf.push(len as u8);
    } else if len < (1 << 20) {
        buf.push(BINARY_20);
        buf.push((len >> 16) as u8);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    } else {
        buf.push(BINARY_32);
        buf.push((len >> 24) as u8);
        buf.push((len >> 16) as u8);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
    buf.extend_from_slice(data);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::tokens;

    fn make_node(tag: &str, attrs: Vec<(&str, &str)>, content: NodeContent) -> BinaryNode {
        BinaryNode {
            tag: tag.to_string(),
            attrs: attrs.into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            content,
        }
    }

    #[test]
    fn single_byte_token_roundtrip() {
        // "s.whatsapp.net" is token index 3
        assert_eq!(tokens::SINGLE_BYTE_TOKENS[3], "s.whatsapp.net");
        // Check the encoder picks it up as a single-byte token
        let node = make_node("s.whatsapp.net", vec![], NodeContent::None);
        let frame = encode_node(&node);
        // frame[0] = flag byte; frame[1] = list tag; frame[2] = list size;
        // frame[3] should be token 3 (not BINARY_8 = 252)
        assert_ne!(frame[3], BINARY_8, "single-byte token should not be raw-encoded");
        assert_eq!(frame[3], 3u8);
    }

    #[test]
    fn double_byte_token_roundtrip() {
        // dict 0, index 0 = "read-self"  (first entry in DOUBLE_BYTE_TOKENS[0])
        let token = tokens::DOUBLE_BYTE_TOKENS[0][0];
        assert_eq!(token, "read-self");

        let node = make_node(token, vec![], NodeContent::None);
        let frame = encode_node(&node);
        // tag byte for DICTIONARY_0 = 236
        assert!(
            frame.contains(&DICTIONARY_0),
            "double-byte token should be encoded with DICTIONARY_0 (236)"
        );
    }

    #[test]
    fn encode_decode_simple_node() {
        let node = make_node(
            "message",
            vec![("id", "abc123"), ("type", "text")],
            NodeContent::Text("hello".to_string()),
        );
        let frame = encode_node(&node);
        let decoded = decode_frame(&frame).expect("decode failed");
        assert_eq!(decoded.tag, "message");
        assert_eq!(decoded.attr("id"), Some("abc123"));
        assert_eq!(decoded.attr("type"), Some("text"));
        // Non-token strings encode as BINARY_8 and decode back as Bytes.
        let content_str = match decoded.content {
            NodeContent::Text(s) => s,
            NodeContent::Bytes(b) => String::from_utf8(b).expect("utf8"),
            other => panic!("unexpected content: {other:?}"),
        };
        assert_eq!(content_str, "hello");
    }

    #[test]
    fn encode_decode_nested_list() {
        let child = make_node("enc", vec![("v", "2"), ("type", "msg")], NodeContent::Bytes(vec![0xde, 0xad]));
        let parent = make_node("message", vec![("to", "1234@s.whatsapp.net")], NodeContent::List(vec![child]));
        let frame = encode_node(&parent);
        let decoded = decode_frame(&frame).expect("decode failed");
        assert_eq!(decoded.tag, "message");
        match &decoded.content {
            NodeContent::List(ch) => {
                assert_eq!(ch.len(), 1);
                assert_eq!(ch[0].tag, "enc");
                assert_eq!(ch[0].attr("type"), Some("msg"));
                match &ch[0].content {
                    NodeContent::Bytes(b) => assert_eq!(b, &[0xde, 0xadu8]),
                    other => panic!("expected Bytes, got {other:?}"),
                }
            }
            other => panic!("expected List, got {other:?}"),
        }
    }

    #[test]
    fn encode_decode_token_attr_value() {
        // Use a known token ("from") as key, value is a JID raw string
        let node = make_node("receipt", vec![("from", "5491112345678@s.whatsapp.net")], NodeContent::None);
        let frame = encode_node(&node);
        let decoded = decode_frame(&frame).expect("decode failed");
        assert_eq!(decoded.tag, "receipt");
        assert_eq!(decoded.attr("from"), Some("5491112345678@s.whatsapp.net"));
    }
}
