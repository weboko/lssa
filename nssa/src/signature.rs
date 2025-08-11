use serde::{Deserialize, Serialize};

use crate::{error::NssaError, public_transaction::Message};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Signature(pub(crate) u8);

// TODO: Dummy impl. Replace by actual private key.
// TODO: Remove Debug, Clone, Serialize, Deserialize, PartialEq and Eq for security reasons
// TODO: Implement Zeroize
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivateKey(pub(crate) [u8; 32]);

impl PrivateKey {
    fn is_valid_key(value: [u8; 32]) -> bool {
        secp256k1::SecretKey::from_byte_array(value).is_ok()
    }

    pub fn try_new(value: [u8; 32]) -> Result<Self, NssaError> {
        if Self::is_valid_key(value) {
            Ok(Self(value))
        } else {
            Err(NssaError::InvalidPrivateKey)
        }
    }
}

// TODO: Dummy impl. Replace by actual public key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicKey(pub(crate) [u8; 32]);

impl PublicKey {
    pub fn new(key: &PrivateKey) -> Self {
        let value = {
            let secret_key = secp256k1::SecretKey::from_byte_array(key.0).unwrap();
            let public_key =
                secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &secret_key);
            let (x_only, _) = public_key.x_only_public_key();
            x_only.serialize()
        };
        Self(value)
    }
}

impl Signature {
    pub(crate) fn new(key: &PrivateKey, _message: &[u8]) -> Self {
        Signature(0)
    }

    pub fn is_valid_for(&self, _message: &Message, _public_key: &PublicKey) -> bool {
        // TODO: implement
        true
    }
}
