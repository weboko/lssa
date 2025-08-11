use serde::{Deserialize, Serialize};

use crate::{PrivateKey, PublicKey, Signature, public_transaction::Message};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WitnessSet {
    pub(crate) signatures_and_public_keys: Vec<(Signature, PublicKey)>,
}

const MESSAGE_ENCODING_PREFIX: &[u8; 19] = b"NSSA/v0.1/TxMessage";

/// Serializes a `Message` into bytes in the following layout:
/// TAG || <program_id>  (bytes LE) * 8 || addresses_len (4 bytes LE) || addresses (32 bytes * N) || nonces_len (4 bytes LE) || nonces (16 bytes * M) || instruction_data_len || instruction_data (4 bytes * K)
/// Integers and words are encoded in little-endian byte order, and fields appear in the above order.
fn message_to_bytes(message: &Message) -> Vec<u8> {
    let mut bytes = MESSAGE_ENCODING_PREFIX.to_vec();
    // program_id: [u32; 8]
    for word in &message.program_id {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    // addresses: Vec<[u8;32]>
    // serialize length as u32 little endian, then all addresses concatenated
    let addresses_len = message.addresses.len() as u32;
    bytes.extend(&addresses_len.to_le_bytes());
    for addr in &message.addresses {
        bytes.extend_from_slice(addr.value());
    }
    // nonces: Vec<u128>
    let nonces_len = message.nonces.len() as u32;
    bytes.extend(&nonces_len.to_le_bytes());
    for nonce in &message.nonces {
        bytes.extend(&nonce.to_le_bytes());
    }
    // instruction_data: Vec<u32>
    // serialize length as u32 little endian, then all addresses concatenated
    let instr_len = message.instruction_data.len() as u32;
    bytes.extend(&instr_len.to_le_bytes());
    for word in &message.instruction_data {
        bytes.extend(&word.to_le_bytes());
    }

    bytes
}

impl WitnessSet {
    pub fn for_message(message: &Message, private_keys: &[&PrivateKey]) -> Self {
        let message_bytes = message_to_bytes(message);
        let signatures_and_public_keys = private_keys
            .iter()
            .map(|&key| (Signature::new(key, &message_bytes), PublicKey::new(key)))
            .collect();
        Self {
            signatures_and_public_keys,
        }
    }

    pub fn iter_signatures(&self) -> impl Iterator<Item = &(Signature, PublicKey)> {
        self.signatures_and_public_keys.iter()
    }
}
