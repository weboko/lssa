#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub(crate) bytecode: Vec<u8>,
}
