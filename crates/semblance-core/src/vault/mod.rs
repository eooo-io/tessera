//! Vault initialization, open, lock/unlock.

use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("vault already exists at {0}")]
    AlreadyExists(PathBuf),
    #[error("vault not found at {0}")]
    NotFound(PathBuf),
    #[error("incorrect passphrase")]
    BadPassphrase,
    #[error("vault is locked")]
    Locked,
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Handle to an open, unlocked vault.
pub struct Vault {
    path: PathBuf,
}

impl Vault {
    /// Create a new vault at the given path.
    pub fn create(_path: &Path, _passphrase: &str) -> Result<Self, VaultError> {
        todo!("Iteration 1")
    }

    /// Open an existing vault.
    pub fn open(_path: &Path, _passphrase: &str) -> Result<Self, VaultError> {
        todo!("Iteration 1")
    }

    /// Lock the vault, zeroing the DEK from memory.
    pub fn lock(&mut self) -> Result<(), VaultError> {
        todo!("Iteration 1")
    }

    /// Return the vault path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    // Tests will be added in Iteration 1.
}
