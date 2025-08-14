use nssa_core::program::{read_nssa_inputs, write_nssa_outputs};

type Instruction = ();

fn main() {
    let (input_accounts, _) = read_nssa_inputs::<Instruction>();

    let [pre1, _] = match input_accounts.try_into() {
        Ok(array) => array,
        Err(_) => return,
    };

    let account_pre1 = pre1.account.clone();

    write_nssa_outputs(vec![pre1], vec![account_pre1]);
}
