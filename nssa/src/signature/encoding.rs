use std::io::{Cursor, Read};

use crate::{PublicKey, Signature, error::NssaError};

impl PublicKey {
    pub(crate) fn from_cursor(cursor: &mut Cursor<&[u8]>) -> Result<Self, NssaError> {
        let mut value = [0u8; 32];
        cursor.read_exact(&mut value)?;
        Ok(Self(value))
    }

    pub(crate) fn to_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Signature {
    pub(crate) fn from_cursor(cursor: &mut Cursor<&[u8]>) -> Result<Self, NssaError> {
        let mut value = [0u8; 64];
        cursor.read_exact(&mut value)?;
        Ok(Self { value })
    }

    pub(crate) fn to_bytes(&self) -> &[u8] {
        &self.value
    }
}
