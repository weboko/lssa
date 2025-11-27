use crate::{
    PrivacyPreservingTransaction, error::NssaError,
    privacy_preserving_transaction::message::Message,
};

impl Message {
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(&self).expect("Autoderived borsh serialization failure")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NssaError> {
        Ok(borsh::from_slice(bytes)?)
    }
}

impl PrivacyPreservingTransaction {
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(&self).expect("Autoderived borsh serialization failure")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NssaError> {
        Ok(borsh::from_slice(bytes)?)
    }
}
