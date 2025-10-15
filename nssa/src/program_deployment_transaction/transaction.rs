use crate::{
    V01State, error::NssaError, program::Program, program_deployment_transaction::message::Message,
};

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
        state: &V01State,
    ) -> Result<Program, NssaError> {
        // TODO: remove clone
        let program = Program::new(self.message.bytecode.clone())?;
        if state.programs().contains_key(&program.id()) {
            Err(NssaError::ProgramAlreadyExists)
        } else {
            Ok(program)
        }
    }
}
