//! This module contains [`WalletCore`](crate::WalletCore) facades for interacting with various
//! on-chain programs.

use nssa::{AccountId, ProgramId};
use nssa_core::program::PdaSeed;
use serde::{Serialize, ser::SerializeSeq};

pub mod amm;
pub mod native_token_transfer;
pub mod pinata;
pub mod token;

fn compute_pool_pda(
    amm_program_id: ProgramId,
    definition_token_a_id: AccountId,
    definition_token_b_id: AccountId,
) -> AccountId {
    AccountId::from((
        &amm_program_id,
        &compute_pool_pda_seed(definition_token_a_id, definition_token_b_id),
    ))
}

fn compute_pool_pda_seed(
    definition_token_a_id: AccountId,
    definition_token_b_id: AccountId,
) -> PdaSeed {
    use risc0_zkvm::sha::{Impl, Sha256};

    let mut i: usize = 0;
    let (token_1, token_2) = loop {
        if definition_token_a_id.value()[i] > definition_token_b_id.value()[i] {
            let token_1 = definition_token_a_id;
            let token_2 = definition_token_b_id;
            break (token_1, token_2);
        } else if definition_token_a_id.value()[i] < definition_token_b_id.value()[i] {
            let token_1 = definition_token_b_id;
            let token_2 = definition_token_a_id;
            break (token_1, token_2);
        }

        if i == 32 {
            panic!("Definitions match");
        } else {
            i += 1;
        }
    };

    let mut bytes = [0; 64];
    bytes[0..32].copy_from_slice(&token_1.to_bytes());
    bytes[32..].copy_from_slice(&token_2.to_bytes());

    PdaSeed::new(
        Impl::hash_bytes(&bytes)
            .as_bytes()
            .try_into()
            .expect("Hash output must be exactly 32 bytes long"),
    )
}

fn compute_vault_pda(
    amm_program_id: ProgramId,
    pool_id: AccountId,
    definition_token_id: AccountId,
) -> AccountId {
    AccountId::from((
        &amm_program_id,
        &compute_vault_pda_seed(pool_id, definition_token_id),
    ))
}

fn compute_vault_pda_seed(pool_id: AccountId, definition_token_id: AccountId) -> PdaSeed {
    use risc0_zkvm::sha::{Impl, Sha256};

    let mut bytes = [0; 64];
    bytes[0..32].copy_from_slice(&pool_id.to_bytes());
    bytes[32..].copy_from_slice(&definition_token_id.to_bytes());

    PdaSeed::new(
        Impl::hash_bytes(&bytes)
            .as_bytes()
            .try_into()
            .expect("Hash output must be exactly 32 bytes long"),
    )
}

fn compute_liquidity_token_pda(amm_program_id: ProgramId, pool_id: AccountId) -> AccountId {
    AccountId::from((&amm_program_id, &compute_liquidity_token_pda_seed(pool_id)))
}

fn compute_liquidity_token_pda_seed(pool_id: AccountId) -> PdaSeed {
    use risc0_zkvm::sha::{Impl, Sha256};

    let mut bytes = [0; 64];
    bytes[0..32].copy_from_slice(&pool_id.to_bytes());
    bytes[32..].copy_from_slice(&[0; 32]);

    PdaSeed::new(
        Impl::hash_bytes(&bytes)
            .as_bytes()
            .try_into()
            .expect("Hash output must be exactly 32 bytes long"),
    )
}

/// Why it is necessary:
///
/// Serialize implemented only for `[u8; N]` where `N<=32` and orphan rules would disallow custom
/// Serialize impls for them.
///
/// Additionally, RISC0 splits instructions into words of 4-byte size which glues bytes for custom
/// structs so we need to expand each byte into `u32` to preserve shape, because AMM awaits
/// `Vec<u8>` as instruction.
struct OrphanHackNBytesInput<const N: usize>([u32; N]);

impl<const N: usize> OrphanHackNBytesInput<N> {
    fn expand(orig: [u8; N]) -> Self {
        let mut res = [0u32; N];

        for (idx, val) in orig.into_iter().enumerate() {
            res[idx] = val as u32;
        }

        Self(res)
    }
}

impl<const N: usize> Serialize for OrphanHackNBytesInput<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(N))?;
        for word in self.0 {
            seq.serialize_element(&word)?;
        }
        seq.end()
    }
}

type OrphanHack65BytesInput = OrphanHackNBytesInput<65>;
type OrphanHack49BytesInput = OrphanHackNBytesInput<49>;
