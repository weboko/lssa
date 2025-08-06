use std::{fs::File, io::BufReader, path::PathBuf, str::FromStr, sync::Arc};

use common::{
    execution_input::PublicNativeTokenSend, transaction::Transaction, ExecutionFailureKind,
};

use accounts::account_core::{address::AccountAddress, Account};
use anyhow::{anyhow, Result};
use chain_storage::NodeChainStore;
use common::transaction::TransactionBody;
use config::NodeConfig;
use log::info;
use sc_core::proofs_circuits::{generate_commitments, pedersen_commitment_vec};
use sequencer_client::{json::SendTxResponse, SequencerClient};
use serde::{Deserialize, Serialize};
use storage::sc_db_utils::DataBlobChangeVariant;
use tokio::sync::RwLock;
use utxo::utxo_core::UTXO;

use clap::{Parser, Subcommand};

pub const HOME_DIR_ENV_VAR: &str = "HOME_DIR";
pub const BLOCK_GEN_DELAY_SECS: u64 = 20;

pub mod chain_storage;
pub mod config;
pub mod sequencer_client;

pub fn vec_u8_to_vec_u64(bytes: Vec<u8>) -> Vec<u64> {
    // Pad with zeros to make sure it's a multiple of 8
    let mut padded = bytes.clone();
    while !padded.len().is_multiple_of(8) {
        padded.push(0);
    }

    padded
        .chunks(8)
        .map(|chunk| {
            let mut array = [0u8; 8];
            array.copy_from_slice(chunk);
            u64::from_le_bytes(array)
        })
        .collect()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MintMoneyPublicTx {
    pub acc: AccountAddress,
    pub amount: u128,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendMoneyShieldedTx {
    pub acc_sender: AccountAddress,
    pub amount: u128,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendMoneyDeshieldedTx {
    pub receiver_data: Vec<(u128, AccountAddress)>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UTXOPublication {
    pub utxos: Vec<UTXO>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ActionData {
    MintMoneyPublicTx(MintMoneyPublicTx),
    SendMoneyShieldedTx(SendMoneyShieldedTx),
    SendMoneyDeshieldedTx(SendMoneyDeshieldedTx),
    UTXOPublication(UTXOPublication),
}

pub struct NodeCore {
    pub storage: Arc<RwLock<NodeChainStore>>,
    pub node_config: NodeConfig,
    pub sequencer_client: Arc<SequencerClient>,
}

impl NodeCore {
    pub async fn start_from_config_update_chain(config: NodeConfig) -> Result<Self> {
        let client = Arc::new(SequencerClient::new(config.clone())?);

        let mut storage = NodeChainStore::new(config.clone())?;
        for acc in config.clone().initial_accounts {
            storage.acc_map.insert(acc.address, acc);
        }

        let wrapped_storage = Arc::new(RwLock::new(storage));

        Ok(Self {
            storage: wrapped_storage,
            node_config: config.clone(),
            sequencer_client: client.clone(),
        })
    }

    pub async fn get_roots(&self) -> [[u8; 32]; 2] {
        let storage = self.storage.read().await;
        [
            storage.utxo_commitments_store.get_root().unwrap_or([0; 32]),
            storage.pub_tx_store.get_root().unwrap_or([0; 32]),
        ]
    }

    pub async fn create_new_account(&mut self) -> AccountAddress {
        let account = Account::new();
        account.log();

        let addr = account.address;

        {
            let mut write_guard = self.storage.write().await;

            write_guard.acc_map.insert(account.address, account);
        }

        addr
    }

    pub async fn send_public_native_token_transfer(
        &self,
        from: AccountAddress,
        nonce: u64,
        to: AccountAddress,
        balance_to_move: u64,
    ) -> Result<SendTxResponse, ExecutionFailureKind> {
        let tx_roots = self.get_roots().await;

        let public_context = {
            let read_guard = self.storage.read().await;

            read_guard.produce_context(from)
        };

        let (tweak, secret_r, commitment) = pedersen_commitment_vec(
            //Will not panic, as public context is serializable
            public_context.produce_u64_list_from_context().unwrap(),
        );

        let sc_addr = hex::encode([0; 32]);

        //Native contract does not change its state
        let state_changes: Vec<DataBlobChangeVariant> = vec![];
        let new_len = 0;
        let state_changes = (serde_json::to_value(state_changes).unwrap(), new_len);

        let tx: TransactionBody =
            sc_core::transaction_payloads_tools::create_public_transaction_payload(
                serde_json::to_vec(&PublicNativeTokenSend {
                    from,
                    nonce,
                    to,
                    balance_to_move,
                })
                .unwrap(),
                commitment,
                tweak,
                secret_r,
                sc_addr,
                state_changes,
            );
        tx.log();

        {
            let read_guard = self.storage.read().await;

            let account = read_guard.acc_map.get(&from);

            if let Some(account) = account {
                let key_to_sign_transaction = account.key_holder.get_pub_account_signing_key();

                let signed_transaction = Transaction::new(tx, key_to_sign_transaction);

                Ok(self
                    .sequencer_client
                    .send_tx(signed_transaction, tx_roots)
                    .await?)
            } else {
                Err(ExecutionFailureKind::AmountMismatchError)
            }
        }
    }
}

pub fn generate_commitments_helper(input_utxos: &[UTXO]) -> Vec<[u8; 32]> {
    generate_commitments(input_utxos)
        .into_iter()
        .map(|comm_raw| comm_raw.try_into().unwrap())
        .collect()
}

///Represents CLI command for a wallet
#[derive(Subcommand, Debug, Clone)]
pub enum Command {
    SendNativeTokenTransfer {
        #[arg(long)]
        from: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u64,
    },
}

#[derive(Parser, Debug)]
#[clap(version)]
pub struct Args {
    /// Wallet command
    #[command(subcommand)]
    pub command: Command,
}

pub fn get_home() -> Result<PathBuf> {
    Ok(PathBuf::from_str(&std::env::var(HOME_DIR_ENV_VAR)?)?)
}

pub fn fetch_config() -> Result<NodeConfig> {
    let config_home = get_home()?;
    let file = File::open(config_home.join("node_config.json"))?;
    let reader = BufReader::new(file);

    Ok(serde_json::from_reader(reader)?)
}

//ToDo: Replace with structures in future
pub fn produce_account_addr_from_hex(hex_str: String) -> Result<[u8; 32]> {
    hex::decode(hex_str)?
        .try_into()
        .map_err(|_| anyhow!("Failed conversion to 32 bytes"))
}

pub async fn execute_subcommand(command: Command) -> Result<()> {
    //env_logger::init();

    match command {
        Command::SendNativeTokenTransfer { from, to, amount } => {
            let node_config = fetch_config()?;

            let from = produce_account_addr_from_hex(from)?;
            let to = produce_account_addr_from_hex(to)?;

            let wallet_core = NodeCore::start_from_config_update_chain(node_config).await?;

            //ToDo: Nonce management
            let res = wallet_core
                .send_public_native_token_transfer(from, 0, to, amount)
                .await?;

            info!("Results of tx send is {res:#?}");
        }
    }

    Ok(())
}
