use nssa_core::account::AccountWithMetadata;
use risc0_zkvm::guest::env;

fn main() {
    let input_accounts: Vec<AccountWithMetadata> = env::read();
    let _instruction_data: u128 = env::read();

    let [pre1, _] = match input_accounts.try_into() {
        Ok(array) => array,
        Err(_) => return,
    };

    let account_pre1 = pre1.account;

    env::commit(&vec![account_pre1]);
}
