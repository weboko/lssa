use nssa_core::{
    EncryptedAccountData,
    account::{Account, Commitment, Nonce, Nullifier},
};

use crate::Address;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub(crate) public_addresses: Vec<Address>,
    pub(crate) nonces: Vec<Nonce>,
    pub(crate) public_post_states: Vec<Account>,
    pub(crate) encrypted_private_post_states: Vec<EncryptedAccountData>,
    pub(crate) new_commitments: Vec<Commitment>,
    pub(crate) new_nullifiers: Vec<Nullifier>,
}

impl Message {
    pub fn new(
        public_addresses: Vec<Address>,
        nonces: Vec<Nonce>,
        public_post_states: Vec<Account>,
        encrypted_private_post_states: Vec<EncryptedAccountData>,
        new_commitments: Vec<Commitment>,
        new_nullifiers: Vec<Nullifier>,
    ) -> Self {
        Self {
            public_addresses,
            nonces,
            public_post_states,
            encrypted_private_post_states,
            new_commitments,
            new_nullifiers,
        }
    }
}

#[cfg(test)]
mod tests {
    use nssa_core::account::{
        Account, Commitment, Nullifier, NullifierPublicKey, NullifierSecretKey,
    };

    use crate::{Address, privacy_preserving_transaction::message::Message};

    #[test]
    fn test_constructor() {
        let account1 = Account::default();
        let account2 = Account::default();

        let nsk1 = [11; 32];
        let nsk2 = [12; 32];

        let Npk1 = NullifierPublicKey::from(&nsk1);
        let Npk2 = NullifierPublicKey::from(&nsk2);

        let public_addresses = vec![Address::new([1; 32])];

        let nonces = vec![1, 2, 3];

        let public_post_states = vec![Account::default()];

        let encrypted_private_post_states = Vec::new();

        let new_commitments = vec![Commitment::new(&Npk2, &account2)];

        let old_commitment = Commitment::new(&Npk1, &account1);
        let new_nullifiers = vec![Nullifier::new(&old_commitment, &nsk1)];

        let expected_message = Message {
            public_addresses: public_addresses.clone(),
            nonces: nonces.clone(),
            public_post_states: public_post_states.clone(),
            encrypted_private_post_states: encrypted_private_post_states.clone(),
            new_commitments: new_commitments.clone(),
            new_nullifiers: new_nullifiers.clone(),
        };

        let message = Message::new(
            public_addresses,
            nonces,
            public_post_states,
            encrypted_private_post_states,
            new_commitments,
            new_nullifiers,
        );

        assert_eq!(message, expected_message);
    }
}
