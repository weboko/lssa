use super::message::Message;
use super::witness_set::WitnessSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyPreservingTransaction {
    message: Message,
    witness_set: WitnessSet,
}


