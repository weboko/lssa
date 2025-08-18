use crate::{PrivateKey, PublicKey, Signature, privacy_preserving_transaction::message::Message};

type Proof = ();

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessSet {
    pub(super) signatures_and_public_keys: Vec<(Signature, PublicKey)>,
    pub(super) proof: Proof,
}

impl WitnessSet {
    pub fn for_message(message: &Message, private_keys: &[&PrivateKey]) -> Self {
        todo!()
    }

    pub fn signatures_are_valid_for(&self, message: &Message) -> bool {
        // let message_bytes = message.to_bytes();
        // for (signature, public_key) in self.signatures_and_public_keys() {
        //     if !signature.is_valid_for(&message_bytes, public_key) {
        //         return false;
        //     }
        // }
        // true
        todo!()
    }

    pub fn signatures_and_public_keys(&self) -> &[(Signature, PublicKey)] {
        &self.signatures_and_public_keys
    }

    pub fn proof(&self) -> &Proof {
        &self.proof
    }
}
