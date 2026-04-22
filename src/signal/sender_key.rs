/// WhatsApp group message encryption via Signal Sender Key protocol.
///
/// Each (sender_jid, group_jid) pair has a SenderKeyRecord holding the
/// current chain key and iteration counter.
///
/// Key derivation per message:
///   message_seed = HMAC-SHA256(chain_key, 0x01)
///   HKDF(ikm=seed, salt=empty, info="WhatsApp Sender Keys", len=80)
///     → iv[0:16] | cipher_key[16:48] | mac_key[48:80]
///   next_chain_key = HMAC-SHA256(chain_key, 0x02)

use anyhow::{bail, Result};
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderKeyRecord {
    pub iteration: u32,
    pub chain_key: [u8; 32],
}

/// Our own outgoing SenderKey for a group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnSenderKey {
    pub key_id: u32,
    pub iteration: u32,
    pub chain_key: [u8; 32],
    pub signing_priv: [u8; 32],
    pub signing_pub: [u8; 32],
    /// JIDs that have already received our SKDM for this group.
    pub distributed_to: HashSet<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SenderKeyStore {
    // "{sender_jid}::{group_jid}" → incoming record
    records: HashMap<String, SenderKeyRecord>,
    // "own::{group_jid}" → our outgoing key
    own_keys: HashMap<String, OwnSenderKey>,
}

impl SenderKeyStore {
    pub fn process_skdm(
        &mut self,
        sender_jid: &str,
        group_jid: &str,
        iteration: u32,
        chain_key: [u8; 32],
    ) {
        let k = store_key(sender_jid, group_jid);
        let update = self.records.get(&k).map_or(true, |r| iteration >= r.iteration);
        if update {
            self.records.insert(k, SenderKeyRecord { iteration, chain_key });
        }
    }

    pub fn decrypt(
        &mut self,
        sender_jid: &str,
        group_jid: &str,
        iteration: u32,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let k = store_key(sender_jid, group_jid);
        let record = self.records.get_mut(&k)
            .ok_or_else(|| anyhow::anyhow!("no sender key for {sender_jid} in {group_jid}"))?;

        if iteration < record.iteration {
            bail!("skmsg iteration {iteration} behind stored {}", record.iteration);
        }

        let mut chain_key = record.chain_key;
        for _ in record.iteration..iteration {
            chain_key = chain_advance(&chain_key);
        }

        let (iv, cipher_key, _mac_key) = expand_message_keys(&chain_key)?;

        use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
        use aes::Aes256;
        let dec = cbc::Decryptor::<Aes256>::new_from_slices(&cipher_key, &iv)
            .map_err(|e| anyhow::anyhow!("skmsg aes: {e}"))?;
        let plaintext = dec
            .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
            .map_err(|e| anyhow::anyhow!("skmsg decrypt: {e}"))?;

        record.chain_key = chain_advance(&chain_key);
        record.iteration = iteration + 1;
        Ok(plaintext)
    }

    /// Return or create our own SenderKey for a group.
    pub fn get_or_create_own(&mut self, group_jid: &str) -> &mut OwnSenderKey {
        let k = format!("own::{group_jid}");
        self.own_keys.entry(k).or_insert_with(|| {
            use rand::RngCore;
            let mut chain_key = [0u8; 32];
            let mut signing_seed = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut chain_key);
            rand::rngs::OsRng.fill_bytes(&mut signing_seed);
            let sk = Ed25519SigningKey::from_bytes(&signing_seed);
            let signing_pub = sk.verifying_key().to_bytes();
            OwnSenderKey {
                key_id: rand::rngs::OsRng.next_u32() & 0x00FF_FFFF, // keep small
                iteration: 0,
                chain_key,
                signing_priv: signing_seed,
                signing_pub,
                distributed_to: HashSet::new(),
            }
        })
    }

    /// Encrypt `plaintext` with our outgoing SenderKey for `group_jid`.
    /// Returns `(ciphertext, key_id, iteration, signing_priv)` — call
    /// `wa_proto::encode_skmsg_signed` to produce the final wire bytes.
    pub fn encrypt_own(
        &mut self,
        group_jid: &str,
    ) -> (u32, u32, [u8; 32], [u8; 32]) {
        let k = format!("own::{group_jid}");
        self.get_or_create_own(group_jid); // ensure exists
        let own = self.own_keys.get_mut(&k).unwrap();
        let key_id = own.key_id;
        let iteration = own.iteration;
        let chain_key = own.chain_key;
        let signing_priv = own.signing_priv;
        // Advance for next message
        own.chain_key = chain_advance(&own.chain_key);
        own.iteration += 1;
        (key_id, iteration, chain_key, signing_priv)
    }

    /// Mark that `participant_jid` has received our SKDM for `group_jid`.
    pub fn mark_distributed(&mut self, group_jid: &str, participant_jid: &str) {
        let k = format!("own::{group_jid}");
        if let Some(own) = self.own_keys.get_mut(&k) {
            own.distributed_to.insert(participant_jid.to_string());
        }
    }

    /// True if `participant_jid` already has our SKDM for `group_jid`.
    pub fn is_distributed(&self, group_jid: &str, participant_jid: &str) -> bool {
        let k = format!("own::{group_jid}");
        self.own_keys.get(&k).map_or(false, |o| o.distributed_to.contains(participant_jid))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    pub fn from_bytes(data: &[u8]) -> Self {
        serde_json::from_slice(data).unwrap_or_default()
    }
}

fn store_key(sender: &str, group: &str) -> String {
    format!("{sender}::{group}")
}

fn chain_advance(key: &[u8; 32]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac");
    mac.update(&[0x02]);
    mac.finalize().into_bytes().into()
}

pub fn expand_message_keys_pub(chain_key: &[u8; 32]) -> Result<([u8; 16], [u8; 32], [u8; 32])> {
    expand_message_keys(chain_key)
}

fn expand_message_keys(chain_key: &[u8; 32]) -> Result<([u8; 16], [u8; 32], [u8; 32])> {
    let mut mac = Hmac::<Sha256>::new_from_slice(chain_key).expect("hmac");
    mac.update(&[0x01]);
    let seed: [u8; 32] = mac.finalize().into_bytes().into();

    let hk = Hkdf::<Sha256>::new(None, &seed);
    let mut out = [0u8; 80];
    hk.expand(b"WhatsApp Sender Keys", &mut out)
        .map_err(|e| anyhow::anyhow!("hkdf: {e}"))?;

    let mut iv = [0u8; 16];
    let mut cipher_key = [0u8; 32];
    let mut mac_key = [0u8; 32];
    iv.copy_from_slice(&out[0..16]);
    cipher_key.copy_from_slice(&out[16..48]);
    mac_key.copy_from_slice(&out[48..80]);
    Ok((iv, cipher_key, mac_key))
}
