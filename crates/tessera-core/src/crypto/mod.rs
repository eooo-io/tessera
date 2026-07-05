//! Key derivation (Argon2id), encryption (XChaCha20-Poly1305), macOS Keychain.

pub mod keys;

pub use keys::{Dek, KdfParams, KeyslotFile};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("key derivation failed: {0}")]
    KeyDerivation(String),
    #[error("encryption failed: {0}")]
    Encryption(String),
    #[error("decryption failed: {0}")]
    Decryption(String),
    #[error("incorrect passphrase")]
    BadPassphrase,
    #[error("invalid keyslot file: {0}")]
    InvalidFormat(String),
    #[error("keychain error: {0}")]
    Keychain(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
