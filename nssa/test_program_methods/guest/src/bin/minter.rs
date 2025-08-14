use nssa_core::program::{read_nssa_inputs, write_nssa_outputs};

type Instruction = ();

fn main() {
    let (input_accounts, _) = read_nssa_inputs::<Instruction>();

    let [pre] = match input_accounts.try_into() {
        Ok(array) => array,
        Err(_) => return,
    };

    let account_pre = &pre.account;
    let mut account_post = account_pre.clone();
    account_post.balance += 1;

    write_nssa_outputs(vec![pre], vec![account_post]);
}
