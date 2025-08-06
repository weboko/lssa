use nssa_core::{
    account::{Account, Nonce},
    program::ProgramId,
};

use crate::{
    address::Address,
    signature::{PrivateKey, PublicKey, Signature},
};

pub(crate) struct Message {
    pub(crate) program_id: ProgramId,
    pub(crate) addresses: Vec<Address>,
    pub(crate) nonces: Vec<Nonce>,
    // TODO: change to Vec<u8> for general programs
    pub(crate) instruction_data: u128,
}

impl Message {
    pub(crate) fn new(
        program_id: ProgramId,
        addresses: Vec<Address>,
        nonces: Vec<Nonce>,
        instruction_data: u128,
    ) -> Self {
        Self {
            program_id,
            addresses,
            nonces,
            instruction_data,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        //TODO: implement
        vec![0, 0]
    }
}

pub(crate) struct WitnessSet {
    pub(crate) signatures_and_public_keys: Vec<(Signature, PublicKey)>,
}

impl WitnessSet {
    pub(crate) fn for_message(message: &Message, private_keys: &[PrivateKey]) -> Self {
        let message_bytes = message.to_bytes();
        let signatures_and_public_keys = private_keys
            .iter()
            .map(|key| (Signature::new(key, &message_bytes), PublicKey::new(key)))
            .collect();
        Self {
            signatures_and_public_keys,
        }
    }
}

pub(crate) struct PublicTransaction {
    message: Message,
    witness_set: WitnessSet,
}

impl PublicTransaction {
    pub(crate) fn message(&self) -> &Message {
        &self.message
    }

    pub(crate) fn witness_set(&self) -> &WitnessSet {
        &self.witness_set
    }

    pub(crate) fn signer_addresses(&self) -> Vec<Address> {
        self.witness_set
            .signatures_and_public_keys
            .iter()
            .map(|(_, public_key)| Address::from_public_key(public_key))
            .collect()
    }

    pub(crate) fn new(message: Message, witness_set: WitnessSet) -> Self {
        Self {
            message,
            witness_set,
        }
    }
}
