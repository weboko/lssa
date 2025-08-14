use nssa_core::account::{Account, Commitment, Nonce, Nullifier};

use crate::Address;

#[derive(Debug, Clone, PartialEq, Eq)]
struct EncryptedAccountData;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    public_addresses: Vec<Address>,
    nonces: Vec<Nonce>,
    public_post_states: Vec<Account>,
    encrypted_private_post_states: Vec<EncryptedAccountData>,
    new_commitments: Vec<Commitment>,
    new_nullifiers: Vec<Nullifier>,
}
