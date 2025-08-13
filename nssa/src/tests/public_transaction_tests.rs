use sha2::{Digest, digest::FixedOutput};

use crate::{
    Address, PrivateKey, PublicKey, PublicTransaction,
    program::Program,
    public_transaction::{Message, WitnessSet, tests::transaction_for_tests},
};

#[test]
fn test_public_transaction_encoding_bytes_roundtrip() {
    let tx = transaction_for_tests();
    let bytes = tx.to_bytes();
    let tx_from_bytes = PublicTransaction::from_bytes(&bytes).unwrap();
    assert_eq!(tx, tx_from_bytes);
}

#[test]
fn test_hash_is_sha256_of_transaction_bytes() {
    let tx = transaction_for_tests();
    let hash = tx.hash();
    let expected_hash: [u8; 32] = {
        let bytes = tx.to_bytes();
        let mut hasher = sha2::Sha256::new();
        hasher.update(&bytes);
        hasher.finalize_fixed().into()
    };
    assert_eq!(hash, expected_hash);
}
