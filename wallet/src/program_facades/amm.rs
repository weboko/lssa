use common::{error::ExecutionFailureKind, rpc_primitives::requests::SendTxResponse};
use nssa::{AccountId, ProgramId, program::Program};
use nssa_core::{SharedSecretKey, program::PdaSeed};
use serde::{Serialize, ser::SerializeSeq};

use crate::{PrivacyPreservingAccount, WalletCore, cli::account::TokenHolding};

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

struct OrphanHack65BytesInput([u32; 65]);

impl OrphanHack65BytesInput {
    fn expand(orig: [u8; 65]) -> Self {
        let mut res = [0u32; 65];

        for (idx, val) in orig.into_iter().enumerate() {
            res[idx] = val as u32;
        }

        Self(res)
    }
}

impl Serialize for OrphanHack65BytesInput {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(65))?;
        for word in self.0 {
            seq.serialize_element(&word)?;
        }
        seq.end()
    }
}

struct OrphanHack49BytesInput([u32; 49]);

impl OrphanHack49BytesInput {
    fn expand(orig: [u8; 49]) -> Self {
        let mut res = [0u32; 49];

        for (idx, val) in orig.into_iter().enumerate() {
            res[idx] = val as u32;
        }

        Self(res)
    }

    fn words(&self) -> Vec<u32> {
        self.0.to_vec()
    }
}

impl Serialize for OrphanHack49BytesInput {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(49))?;
        for word in self.0 {
            seq.serialize_element(&word)?;
        }
        seq.end()
    }
}

pub struct AMM<'w>(pub &'w WalletCore);

impl AMM<'_> {
    #[allow(clippy::too_many_arguments)]
    pub async fn send_new_amm_definition(
        &self,
        user_holding_a: PrivacyPreservingAccount,
        user_holding_b: PrivacyPreservingAccount,
        user_holding_lp: PrivacyPreservingAccount,
        balance_a: u128,
        balance_b: u128,
    ) -> Result<SendTxResponse, ExecutionFailureKind> {
        let (instruction, program) = amm_program_preparation_definition(balance_a, balance_b);

        match (user_holding_a, user_holding_b, user_holding_lp) {
            (
                PrivacyPreservingAccount::Public(user_holding_a),
                PrivacyPreservingAccount::Public(user_holding_b),
                PrivacyPreservingAccount::Public(user_holding_lp),
            ) => {
                let amm_program_id = Program::amm().id();

                let Ok(user_a_acc) = self.0.get_account_public(user_holding_a).await else {
                    return Err(ExecutionFailureKind::SequencerError);
                };
                let Ok(user_b_acc) = self.0.get_account_public(user_holding_b).await else {
                    return Err(ExecutionFailureKind::SequencerError);
                };

                let definition_token_a_id = TokenHolding::parse(&user_a_acc.data)
                    .ok_or(ExecutionFailureKind::AccountDataError(user_holding_a))?
                    .definition_id;
                let definition_token_b_id = TokenHolding::parse(&user_b_acc.data)
                    .ok_or(ExecutionFailureKind::AccountDataError(user_holding_a))?
                    .definition_id;

                let amm_pool =
                    compute_pool_pda(amm_program_id, definition_token_a_id, definition_token_b_id);
                let vault_holding_a =
                    compute_vault_pda(amm_program_id, amm_pool, definition_token_a_id);
                let vault_holding_b =
                    compute_vault_pda(amm_program_id, amm_pool, definition_token_b_id);
                let pool_lp = compute_liquidity_token_pda(amm_program_id, amm_pool);

                let account_ids = vec![
                    amm_pool,
                    vault_holding_a,
                    vault_holding_b,
                    pool_lp,
                    user_holding_a,
                    user_holding_b,
                    user_holding_lp,
                ];

                let Ok(nonces) = self
                    .0
                    .get_accounts_nonces(vec![user_holding_a, user_holding_b])
                    .await
                else {
                    return Err(ExecutionFailureKind::SequencerError);
                };

                let Some(signing_key_a) = self
                    .0
                    .storage
                    .user_data
                    .get_pub_account_signing_key(&user_holding_a)
                else {
                    return Err(ExecutionFailureKind::KeyNotFoundError);
                };

                let Some(signing_key_b) = self
                    .0
                    .storage
                    .user_data
                    .get_pub_account_signing_key(&user_holding_b)
                else {
                    return Err(ExecutionFailureKind::KeyNotFoundError);
                };

                let message = nssa::public_transaction::Message::try_new(
                    program.id(),
                    account_ids,
                    nonces,
                    instruction,
                )
                .unwrap();

                let witness_set = nssa::public_transaction::WitnessSet::for_message(
                    &message,
                    &[signing_key_a, signing_key_b],
                );

                let tx = nssa::PublicTransaction::new(message, witness_set);

                Ok(self.0.sequencer_client.send_tx_public(tx).await?)
            }
            _ => unreachable!(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn send_new_amm_definition_privacy_preserving(
        &self,
        _user_holding_a: PrivacyPreservingAccount,
        _user_holding_b: PrivacyPreservingAccount,
        _user_holding_lp: PrivacyPreservingAccount,
        _balance_a: u128,
        _balance_b: u128,
    ) -> Result<(SendTxResponse, [Option<SharedSecretKey>; 3]), ExecutionFailureKind> {
        todo!()
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn send_swap(
        &self,
        user_holding_a: PrivacyPreservingAccount,
        user_holding_b: PrivacyPreservingAccount,
        amount_in: u128,
        min_amount_out: u128,
        token_definition_id: AccountId,
    ) -> Result<SendTxResponse, ExecutionFailureKind> {
        let (instruction, program) =
            amm_program_preparation_swap(amount_in, min_amount_out, token_definition_id);

        match (user_holding_a, user_holding_b) {
            (
                PrivacyPreservingAccount::Public(user_holding_a),
                PrivacyPreservingAccount::Public(user_holding_b),
            ) => {
                let amm_program_id = Program::amm().id();

                let Ok(user_a_acc) = self.0.get_account_public(user_holding_a).await else {
                    return Err(ExecutionFailureKind::SequencerError);
                };
                let Ok(user_b_acc) = self.0.get_account_public(user_holding_b).await else {
                    return Err(ExecutionFailureKind::SequencerError);
                };

                let definition_token_a_id = TokenHolding::parse(&user_a_acc.data)
                    .ok_or(ExecutionFailureKind::AccountDataError(user_holding_a))?
                    .definition_id;
                let definition_token_b_id = TokenHolding::parse(&user_b_acc.data)
                    .ok_or(ExecutionFailureKind::AccountDataError(user_holding_a))?
                    .definition_id;

                let amm_pool =
                    compute_pool_pda(amm_program_id, definition_token_a_id, definition_token_b_id);
                let vault_holding_a =
                    compute_vault_pda(amm_program_id, amm_pool, definition_token_a_id);
                let vault_holding_b =
                    compute_vault_pda(amm_program_id, amm_pool, definition_token_b_id);

                let account_ids = vec![
                    amm_pool,
                    vault_holding_a,
                    vault_holding_b,
                    user_holding_a,
                    user_holding_b,
                ];

                let account_id_auth;

                // Checking, which account are associated with TokenDefinition
                let token_holder_acc_a = self
                    .0
                    .get_account_public(user_holding_a)
                    .await
                    .map_err(|_| ExecutionFailureKind::SequencerError)?;
                let token_holder_acc_b = self
                    .0
                    .get_account_public(user_holding_b)
                    .await
                    .map_err(|_| ExecutionFailureKind::SequencerError)?;

                let token_holder_a = TokenHolding::parse(&token_holder_acc_a.data)
                    .ok_or(ExecutionFailureKind::AccountDataError(user_holding_a))?;
                let token_holder_b = TokenHolding::parse(&token_holder_acc_b.data)
                    .ok_or(ExecutionFailureKind::AccountDataError(user_holding_b))?;

                if token_holder_a.definition_id == token_definition_id {
                    account_id_auth = user_holding_a;
                } else if token_holder_b.definition_id == token_definition_id {
                    account_id_auth = user_holding_b;
                } else {
                    return Err(ExecutionFailureKind::AccountDataError(token_definition_id));
                }

                let Ok(nonces) = self.0.get_accounts_nonces(vec![account_id_auth]).await else {
                    return Err(ExecutionFailureKind::SequencerError);
                };

                let Some(signing_key) = self
                    .0
                    .storage
                    .user_data
                    .get_pub_account_signing_key(&account_id_auth)
                else {
                    return Err(ExecutionFailureKind::KeyNotFoundError);
                };

                let message = nssa::public_transaction::Message::try_new(
                    program.id(),
                    account_ids,
                    nonces,
                    instruction,
                )
                .unwrap();

                let witness_set =
                    nssa::public_transaction::WitnessSet::for_message(&message, &[signing_key]);

                let tx = nssa::PublicTransaction::new(message, witness_set);

                Ok(self.0.sequencer_client.send_tx_public(tx).await?)
            }
            _ => unreachable!(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn send_swap_privacy_preserving(
        &self,
        _user_holding_a: PrivacyPreservingAccount,
        _user_holding_b: PrivacyPreservingAccount,
        _amount_in: u128,
        _min_amount_out: u128,
        _token_definition_id: AccountId,
    ) -> Result<(SendTxResponse, [Option<SharedSecretKey>; 5]), ExecutionFailureKind> {
        todo!()
        // let (instruction_data, program) =
        //     amm_program_preparation_swap(amount_in, min_amount_out, token_definition_id);

        // self.0
        //     .send_privacy_preserving_tx(
        //         vec![
        //             amm_pool.clone(),
        //             vault_holding_1.clone(),
        //             vault_holding_2.clone(),
        //             user_holding_a.clone(),
        //             user_holding_b.clone(),
        //         ],
        //         &instruction_data.words(),
        //         &program,
        //     )
        //     .await
        //     .map(|(resp, secrets)| {
        //         let mut secrets = secrets.into_iter();
        //         let mut secrets_res = [None; 5];

        //         for acc_id in [
        //             amm_pool,
        //             vault_holding_1,
        //             vault_holding_2,
        //             user_holding_a,
        //             user_holding_b,
        //         ]
        //         .iter()
        //         .enumerate()
        //         {
        //             if acc_id.1.is_private() {
        //                 let secret = secrets.next().expect("expected next secret");

        //                 secrets_res[acc_id.0] = Some(secret);
        //             }
        //         }

        //         (resp, secrets_res)
        //     })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn send_add_liq(
        &self,
        amm_pool: PrivacyPreservingAccount,
        vault_holding_a: PrivacyPreservingAccount,
        vault_holding_b: PrivacyPreservingAccount,
        pool_lp: PrivacyPreservingAccount,
        user_holding_a: PrivacyPreservingAccount,
        user_holding_b: PrivacyPreservingAccount,
        user_holding_lp: PrivacyPreservingAccount,
        min_amount_lp: u128,
        max_amount_a: u128,
        max_amount_b: u128,
    ) -> Result<SendTxResponse, ExecutionFailureKind> {
        let (instruction, program) =
            amm_program_preparation_add_liq(min_amount_lp, max_amount_a, max_amount_b);

        match (
            amm_pool,
            vault_holding_a,
            vault_holding_b,
            pool_lp,
            user_holding_a,
            user_holding_b,
            user_holding_lp,
        ) {
            (
                PrivacyPreservingAccount::Public(amm_pool),
                PrivacyPreservingAccount::Public(vault_holding_a),
                PrivacyPreservingAccount::Public(vault_holding_b),
                PrivacyPreservingAccount::Public(pool_lp),
                PrivacyPreservingAccount::Public(user_holding_a),
                PrivacyPreservingAccount::Public(user_holding_b),
                PrivacyPreservingAccount::Public(user_holding_lp),
            ) => {
                let account_ids = vec![
                    amm_pool,
                    vault_holding_a,
                    vault_holding_b,
                    pool_lp,
                    user_holding_a,
                    user_holding_b,
                    user_holding_lp,
                ];

                let Ok(nonces) = self
                    .0
                    .get_accounts_nonces(vec![user_holding_a, user_holding_b])
                    .await
                else {
                    return Err(ExecutionFailureKind::SequencerError);
                };

                let Some(signing_key_a) = self
                    .0
                    .storage
                    .user_data
                    .get_pub_account_signing_key(&user_holding_a)
                else {
                    return Err(ExecutionFailureKind::KeyNotFoundError);
                };

                let Some(signing_key_b) = self
                    .0
                    .storage
                    .user_data
                    .get_pub_account_signing_key(&user_holding_b)
                else {
                    return Err(ExecutionFailureKind::KeyNotFoundError);
                };

                let message = nssa::public_transaction::Message::try_new(
                    program.id(),
                    account_ids,
                    nonces,
                    instruction,
                )
                .unwrap();

                let witness_set = nssa::public_transaction::WitnessSet::for_message(
                    &message,
                    &[signing_key_a, signing_key_b],
                );

                let tx = nssa::PublicTransaction::new(message, witness_set);

                Ok(self.0.sequencer_client.send_tx_public(tx).await?)
            }
            _ => unreachable!(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn send_add_liq_privacy_preserving(
        &self,
        amm_pool: PrivacyPreservingAccount,
        vault_holding_a: PrivacyPreservingAccount,
        vault_holding_b: PrivacyPreservingAccount,
        pool_lp: PrivacyPreservingAccount,
        user_holding_a: PrivacyPreservingAccount,
        user_holding_b: PrivacyPreservingAccount,
        user_holding_lp: PrivacyPreservingAccount,
        min_amount_lp: u128,
        max_amount_a: u128,
        max_amount_b: u128,
    ) -> Result<(SendTxResponse, [Option<SharedSecretKey>; 7]), ExecutionFailureKind> {
        let (instruction_data, program) =
            amm_program_preparation_add_liq(min_amount_lp, max_amount_a, max_amount_b);

        self.0
            .send_privacy_preserving_tx(
                vec![
                    amm_pool.clone(),
                    vault_holding_a.clone(),
                    vault_holding_b.clone(),
                    pool_lp.clone(),
                    user_holding_a.clone(),
                    user_holding_b.clone(),
                    user_holding_lp.clone(),
                ],
                &instruction_data.words(),
                &program,
            )
            .await
            .map(|(resp, secrets)| {
                let mut secrets = secrets.into_iter();
                let mut secrets_res = [None; 7];

                for acc_id in [
                    amm_pool,
                    vault_holding_a,
                    vault_holding_b,
                    pool_lp,
                    user_holding_a,
                    user_holding_b,
                    user_holding_lp,
                ]
                .iter()
                .enumerate()
                {
                    if acc_id.1.is_private() {
                        let secret = secrets.next().expect("expected next secret");

                        secrets_res[acc_id.0] = Some(secret);
                    }
                }

                (resp, secrets_res)
            })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn send_remove_liq(
        &self,
        amm_pool: PrivacyPreservingAccount,
        vault_holding_a: PrivacyPreservingAccount,
        vault_holding_b: PrivacyPreservingAccount,
        pool_lp: PrivacyPreservingAccount,
        user_holding_a: PrivacyPreservingAccount,
        user_holding_b: PrivacyPreservingAccount,
        user_holding_lp: PrivacyPreservingAccount,
        balance_lp: u128,
        max_amount_a: u128,
        max_amount_b: u128,
    ) -> Result<SendTxResponse, ExecutionFailureKind> {
        let (instruction, program) =
            amm_program_preparation_remove_liq(balance_lp, max_amount_a, max_amount_b);

        match (
            amm_pool,
            vault_holding_a,
            vault_holding_b,
            pool_lp,
            user_holding_a,
            user_holding_b,
            user_holding_lp,
        ) {
            (
                PrivacyPreservingAccount::Public(amm_pool),
                PrivacyPreservingAccount::Public(vault_holding_a),
                PrivacyPreservingAccount::Public(vault_holding_b),
                PrivacyPreservingAccount::Public(pool_lp),
                PrivacyPreservingAccount::Public(user_holding_a),
                PrivacyPreservingAccount::Public(user_holding_b),
                PrivacyPreservingAccount::Public(user_holding_lp),
            ) => {
                let account_ids = vec![
                    amm_pool,
                    vault_holding_a,
                    vault_holding_b,
                    pool_lp,
                    user_holding_a,
                    user_holding_b,
                    user_holding_lp,
                ];

                let Ok(nonces) = self
                    .0
                    .get_accounts_nonces(vec![user_holding_a, user_holding_b])
                    .await
                else {
                    return Err(ExecutionFailureKind::SequencerError);
                };

                let Some(signing_key_a) = self
                    .0
                    .storage
                    .user_data
                    .get_pub_account_signing_key(&user_holding_a)
                else {
                    return Err(ExecutionFailureKind::KeyNotFoundError);
                };

                let Some(signing_key_b) = self
                    .0
                    .storage
                    .user_data
                    .get_pub_account_signing_key(&user_holding_b)
                else {
                    return Err(ExecutionFailureKind::KeyNotFoundError);
                };

                let message = nssa::public_transaction::Message::try_new(
                    program.id(),
                    account_ids,
                    nonces,
                    instruction,
                )
                .unwrap();

                let witness_set = nssa::public_transaction::WitnessSet::for_message(
                    &message,
                    &[signing_key_a, signing_key_b],
                );

                let tx = nssa::PublicTransaction::new(message, witness_set);

                Ok(self.0.sequencer_client.send_tx_public(tx).await?)
            }
            _ => unreachable!(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn send_remove_liq_privacy_preserving(
        &self,
        amm_pool: PrivacyPreservingAccount,
        vault_holding_a: PrivacyPreservingAccount,
        vault_holding_b: PrivacyPreservingAccount,
        pool_lp: PrivacyPreservingAccount,
        user_holding_a: PrivacyPreservingAccount,
        user_holding_b: PrivacyPreservingAccount,
        user_holding_lp: PrivacyPreservingAccount,
        balance_lp: u128,
        max_amount_a: u128,
        max_amount_b: u128,
    ) -> Result<(SendTxResponse, [Option<SharedSecretKey>; 7]), ExecutionFailureKind> {
        let (instruction_data, program) =
            amm_program_preparation_remove_liq(balance_lp, max_amount_a, max_amount_b);

        self.0
            .send_privacy_preserving_tx(
                vec![
                    amm_pool.clone(),
                    vault_holding_a.clone(),
                    vault_holding_b.clone(),
                    pool_lp.clone(),
                    user_holding_a.clone(),
                    user_holding_b.clone(),
                    user_holding_lp.clone(),
                ],
                &instruction_data.words(),
                &program,
            )
            .await
            .map(|(resp, secrets)| {
                let mut secrets = secrets.into_iter();
                let mut secrets_res = [None; 7];

                for acc_id in [
                    amm_pool,
                    vault_holding_a,
                    vault_holding_b,
                    pool_lp,
                    user_holding_a,
                    user_holding_b,
                    user_holding_lp,
                ]
                .iter()
                .enumerate()
                {
                    if acc_id.1.is_private() {
                        let secret = secrets.next().expect("expected next secret");

                        secrets_res[acc_id.0] = Some(secret);
                    }
                }

                (resp, secrets_res)
            })
    }
}

#[allow(unused)]
fn amm_program_preparation_definition(
    balance_a: u128,
    balance_b: u128,
) -> (OrphanHack65BytesInput, Program) {
    // An instruction data of 65-bytes, indicating the initial amm reserves' balances and
    // token_program_id with the following layout:
    // [0x00 || array of balances (little-endian 16 bytes) || AMM_PROGRAM_ID)]
    let amm_program_id = Program::amm().id();

    let mut instruction = [0; 65];
    instruction[1..17].copy_from_slice(&balance_a.to_le_bytes());
    instruction[17..33].copy_from_slice(&balance_b.to_le_bytes());

    // This can be done less verbose, but it is better to use same way, as in amm program
    instruction[33..37].copy_from_slice(&amm_program_id[0].to_le_bytes());
    instruction[37..41].copy_from_slice(&amm_program_id[1].to_le_bytes());
    instruction[41..45].copy_from_slice(&amm_program_id[2].to_le_bytes());
    instruction[45..49].copy_from_slice(&amm_program_id[3].to_le_bytes());
    instruction[49..53].copy_from_slice(&amm_program_id[4].to_le_bytes());
    instruction[53..57].copy_from_slice(&amm_program_id[5].to_le_bytes());
    instruction[57..61].copy_from_slice(&amm_program_id[6].to_le_bytes());
    instruction[61..].copy_from_slice(&amm_program_id[7].to_le_bytes());

    let instruction_data = OrphanHack65BytesInput::expand(instruction);
    let program = Program::amm();

    (instruction_data, program)
}

fn amm_program_preparation_swap(
    amount_in: u128,
    min_amount_out: u128,
    token_definition_id: AccountId,
) -> (OrphanHack65BytesInput, Program) {
    // An instruction data byte string of length 65, indicating which token type to swap, quantity
    // of tokens put into the swap (of type TOKEN_DEFINITION_ID) and min_amount_out.
    // [0x01 || amount (little-endian 16 bytes) || TOKEN_DEFINITION_ID].
    let mut instruction = [0; 65];
    instruction[0] = 0x01;
    instruction[1..17].copy_from_slice(&amount_in.to_le_bytes());
    instruction[17..33].copy_from_slice(&min_amount_out.to_le_bytes());

    // This can be done less verbose, but it is better to use same way, as in amm program
    instruction[33..].copy_from_slice(&token_definition_id.to_bytes());

    let instruction_data = OrphanHack65BytesInput::expand(instruction);
    let program = Program::amm();

    (instruction_data, program)
}

fn amm_program_preparation_add_liq(
    min_amount_lp: u128,
    max_amount_a: u128,
    max_amount_b: u128,
) -> (OrphanHack49BytesInput, Program) {
    // An instruction data byte string of length 49, amounts for minimum amount of liquidity from
    // add (min_amount_lp), max amount added for each token (max_amount_a and max_amount_b);
    // indicate [0x02 || array of of balances (little-endian 16 bytes)].
    let mut instruction = [0; 49];
    instruction[0] = 0x02;

    instruction[1..17].copy_from_slice(&min_amount_lp.to_le_bytes());
    instruction[17..33].copy_from_slice(&max_amount_a.to_le_bytes());
    instruction[33..49].copy_from_slice(&max_amount_b.to_le_bytes());

    let instruction_data = OrphanHack49BytesInput::expand(instruction);
    let program = Program::amm();

    (instruction_data, program)
}

fn amm_program_preparation_remove_liq(
    balance_lp: u128,
    max_amount_a: u128,
    max_amount_b: u128,
) -> (OrphanHack49BytesInput, Program) {
    // An instruction data byte string of length 49, amounts for minimum amount of liquidity to
    // redeem (balance_lp), minimum balance of each token to remove (min_amount_a and
    // min_amount_b); indicate [0x03 || array of balances (little-endian 16 bytes)].
    let mut instruction = [0; 49];
    instruction[0] = 0x03;

    instruction[1..17].copy_from_slice(&balance_lp.to_le_bytes());
    instruction[17..33].copy_from_slice(&max_amount_a.to_le_bytes());
    instruction[33..49].copy_from_slice(&max_amount_b.to_le_bytes());

    let instruction_data = OrphanHack49BytesInput::expand(instruction);
    let program = Program::amm();

    (instruction_data, program)
}

#[cfg(test)]
mod tests {
    use crate::program_facades::amm::OrphanHack65BytesInput;

    #[test]
    fn test_correct_ser() {
        let mut arr = [0u8; 65];

        for (i, item) in arr.iter_mut().enumerate().take(64) {
            *item = i as u8;
        }

        let hack = OrphanHack65BytesInput::expand(arr);
        let instruction_data = serde_json::to_string(&hack).unwrap();

        println!("{instruction_data:?}");

        // assert_eq!(serialization_res_1, serialization_res_2);
    }
}
