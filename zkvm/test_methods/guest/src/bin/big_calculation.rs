use risc0_zkvm::{
    guest::env,
};

fn main() {
    let lhs: u128 = env::read();
    let rhs: u128 = env::read();
    let mut res = 1;
    for i in 0..lhs {
        res *= rhs;
        res += lhs;
    }
    env::commit(&(res));
}
