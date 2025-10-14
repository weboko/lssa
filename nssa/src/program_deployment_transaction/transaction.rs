use std::collections::HashMap;

use nssa_core::{account::Account, address::Address};

use crate::{V01State, error::NssaError, program_deployment_transaction::message::Message};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramDeploymentTransaction {
    message: Message,
}

impl ProgramDeploymentTransaction {
    pub fn new(message: Message) -> Self {
        Self { message }
    }
    pub(crate) fn validate_and_produce_public_state_diff(
        &self,
        state: &mut V01State,
    ) -> Result<HashMap<Address, Account>, NssaError> {
        todo!()
    }
}
