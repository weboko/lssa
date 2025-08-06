use crate::signature::PublicKey;

#[derive(Clone, Hash, PartialEq, Eq)]
pub(crate) struct Address {
    pub(crate) value: [u8; 32],
}

impl Address {
    pub(crate) fn new(value: [u8; 32]) -> Self {
        Self { value }
    }

    pub(crate) fn from_public_key(public_key: &PublicKey) -> Self {
        // TODO: implement
        Address::new([public_key.0; 32])
    }
}
