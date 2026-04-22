//! WhatsApp LT-Hash anti-tampering algorithm.
//!
//! A summation-based homomorphic hash: order-independent, so patches can be
//! applied or removed incrementally and the resulting digest is identical to
//! applying the same set of mutations from scratch.
//!
//! Algorithm (same as whatsmeow's appstate/lthash):
//!   - state: 128 bytes, viewed as 64 × u16 (little-endian)
//!   - to mix value `v`: expand it via HKDF-Expand-SHA256 with
//!     `info = "WhatsApp Patch Integrity"`, no salt, out_len = 128;
//!     reinterpret expansion as 64 × u16 LE and pointwise add/subtract mod 2¹⁶.

use hkdf::Hkdf;
use sha2::Sha256;

pub const HASH_LEN: usize = 128;
const HKDF_INFO: &[u8] = b"WhatsApp Patch Integrity";

fn expand(input: &[u8]) -> [u8; HASH_LEN] {
    // Treat input as a PRK (value MACs are 32 bytes). Fall back to
    // HKDF-Extract with empty salt if shorter — shouldn't happen for
    // WhatsApp-sized MACs but keeps the function total.
    let hk: Hkdf<Sha256> = Hkdf::<Sha256>::from_prk(input)
        .unwrap_or_else(|_| Hkdf::<Sha256>::new(None, input));
    let mut out = [0u8; HASH_LEN];
    hk.expand(HKDF_INFO, &mut out).expect("hkdf expand 128");
    out
}

/// Add `value` to `state` (mod 2¹⁶, pointwise over u16 positions).
pub fn add(state: &mut [u8; HASH_LEN], value: &[u8]) {
    let exp = expand(value);
    for i in 0..(HASH_LEN / 2) {
        let off = i * 2;
        let s = u16::from_le_bytes([state[off], state[off + 1]]);
        let e = u16::from_le_bytes([exp[off], exp[off + 1]]);
        let s2 = s.wrapping_add(e);
        state[off]     = s2 as u8;
        state[off + 1] = (s2 >> 8) as u8;
    }
}

/// Subtract `value` from `state` (mod 2¹⁶).
pub fn sub(state: &mut [u8; HASH_LEN], value: &[u8]) {
    let exp = expand(value);
    for i in 0..(HASH_LEN / 2) {
        let off = i * 2;
        let s = u16::from_le_bytes([state[off], state[off + 1]]);
        let e = u16::from_le_bytes([exp[off], exp[off + 1]]);
        let s2 = s.wrapping_sub(e);
        state[off]     = s2 as u8;
        state[off + 1] = (s2 >> 8) as u8;
    }
}
