use crate::{address::Address, public_transaction::Message};

pub(crate) struct Signature;

// TODO: Dummy impl. Replace by actual private key.
pub(crate) struct PrivateKey(pub(crate) u8);
// TODO: Dummy impl. Replace by actual public key.
pub(crate) struct PublicKey(pub(crate) u8);

impl PublicKey {
    pub(crate) fn new(key: &PrivateKey) -> Self {
        // TODO: implement
        Self(key.0)
    }
}

impl Signature {
    pub(crate) fn new(key: &PrivateKey, message: &[u8]) -> Self {
        Self
    }

    pub(crate) fn is_valid_for(&self, message: &Message, public_key: &PublicKey) -> bool {
        // TODO: implement
        true
    }
}
