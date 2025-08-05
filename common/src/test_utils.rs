use k256::ecdsa::SigningKey;
use secp256k1_zkp::Tweak;

use crate::{
    block::{Block, HashableBlockData}, execution_input::PublicNativeTokenSend, transaction::{SignaturePrivateKey, Transaction, TransactionBody, TxKind}
};

//Dummy producers

///Produce dummy block with
///
/// `id` - block id, provide zero for genesis
///
/// `prev_hash` - hash of previous block, provide None for genesis
///
/// `transactions` - vector of `Transaction` objects
///
/// `additional_data` - vector with additional data
pub fn produce_dummy_block(
    id: u64,
    prev_hash: Option<[u8; 32]>,
    transactions: Vec<Transaction>,
    additional_data: Vec<u8>,
) -> Block {
    let block_data = HashableBlockData {
        block_id: id,
        prev_block_id: id.saturating_sub(1),
        prev_block_hash: prev_hash.unwrap_or_default(),
        transactions,
        data: additional_data,
    };

    block_data.into()
}

pub fn produce_dummy_empty_transaction() -> Transaction {
    let body = TransactionBody {
        tx_kind: TxKind::Public,
        execution_input: Default::default(),
        execution_output: Default::default(),
        utxo_commitments_spent_hashes: Default::default(),
        utxo_commitments_created_hashes: Default::default(),
        nullifier_created_hashes: Default::default(),
        execution_proof_private: Default::default(),
        encoded_data: Default::default(),
        ephemeral_pub_key: Default::default(),
        commitment: Default::default(),
        tweak: Default::default(),
        secret_r: Default::default(),
        sc_addr: Default::default(),
        state_changes: Default::default(),
    };

    Transaction::new(body, SignaturePrivateKey::from_slice(&[1; 32]).unwrap())
}

pub fn create_dummy_private_transaction_random_signer(
        nullifier_created_hashes: Vec<[u8; 32]>,
        utxo_commitments_spent_hashes: Vec<[u8; 32]>,
        utxo_commitments_created_hashes: Vec<[u8; 32]>,
    ) -> Transaction {
        let mut rng = rand::thread_rng();

        let body = TransactionBody {
            tx_kind: TxKind::Private,
            execution_input: vec![],
            execution_output: vec![],
            utxo_commitments_spent_hashes,
            utxo_commitments_created_hashes,
            nullifier_created_hashes,
            execution_proof_private: "dummy_proof".to_string(),
            encoded_data: vec![],
            ephemeral_pub_key: vec![10, 11, 12],
            commitment: vec![],
            tweak: Tweak::new(&mut rng),
            secret_r: [0; 32],
            sc_addr: "sc_addr".to_string(),
            state_changes: (serde_json::Value::Null, 0),
        };
        Transaction::new(body, SignaturePrivateKey::random(&mut rng))
    }

pub fn create_dummy_transaction_native_token_transfer(
        from: [u8; 32],
        nonce: u64,
        to: [u8; 32],
        balance_to_move: u64,
        signing_key: SigningKey,
    ) -> Transaction {
        let mut rng = rand::thread_rng();

        let native_token_transfer = PublicNativeTokenSend {
            from,
            nonce,
            to,
            balance_to_move,
        };

        let body = TransactionBody {
            tx_kind: TxKind::Public,
            execution_input: serde_json::to_vec(&native_token_transfer).unwrap(),
            execution_output: vec![],
            utxo_commitments_spent_hashes: vec![],
            utxo_commitments_created_hashes: vec![],
            nullifier_created_hashes: vec![],
            execution_proof_private: "".to_string(),
            encoded_data: vec![],
            ephemeral_pub_key: vec![10, 11, 12],
            commitment: vec![],
            tweak: Tweak::new(&mut rng),
            secret_r: [0; 32],
            sc_addr: "sc_addr".to_string(),
            state_changes: (serde_json::Value::Null, 0),
        };
        Transaction::new(body, signing_key)
    }
