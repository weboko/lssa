use nssa_core::account::AccountWithMetadata;
use risc0_zkvm::guest::env;

fn main() {
    let input_accounts: Vec<AccountWithMetadata> = env::read();
    let balance_to_burn: u128 = env::read();

    let [pre] = match input_accounts.try_into() {
        Ok(array) => array,
        Err(_) => return,
    };

    let account_pre = pre.account;
    let mut account_post = account_pre.clone();
    account_post.balance -= balance_to_burn;

    env::commit(&vec![account_post]);
}


