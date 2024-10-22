use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{digest::FixedOutput, Digest};
use storage::{merkle_tree_public::TreeHashType, nullifier::UTXONullifier, AccountId};

///Raw asset data
pub type Asset = Vec<u8>;

#[derive(Debug)]
///Container for raw utxo payload
pub struct UTXO {
    pub hash: TreeHashType,
    pub owner: AccountId,
    pub nullifier: Option<UTXONullifier>,
    pub asset: Asset,
}

#[derive(Debug, Clone, Serialize)]
pub struct UTXOPayload {
    pub owner: AccountId,
    pub asset: Asset,
}

impl UTXO {
    pub fn create_utxo_from_payload(payload_with_asset: UTXOPayload) -> Self {
        let raw_payload = serde_json::to_vec(&payload_with_asset).unwrap();

        let mut hasher = sha2::Sha256::new();

        hasher.update(&raw_payload);

        let hash = <TreeHashType>::from(hasher.finalize_fixed());

        Self {
            hash,
            owner: payload_with_asset.owner,
            nullifier: None,
            asset: payload_with_asset.asset,
        }
    }

    pub fn consume_utxo(&mut self, nullifier: UTXONullifier) -> Result<()> {
        if self.nullifier.is_some() {
            anyhow::bail!("UTXO already consumed");
        } else {
            self.nullifier = Some(nullifier);
        }

        Ok(())
    }

    pub fn interpret_asset<'de, ToInterpret: Deserialize<'de>>(&'de self) -> Result<ToInterpret> {
        Ok(serde_json::from_slice(&self.asset)?)
    }
}
