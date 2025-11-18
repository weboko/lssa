use crate::{PublicTransaction, error::NssaError, public_transaction::Message};

impl Message {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(&self).unwrap()
    }
}

impl PublicTransaction {
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(&self).unwrap()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NssaError> {
        Ok(borsh::from_slice(bytes)?)
    }
}
