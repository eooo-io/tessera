//! Key derivation (Argon2id), encryption (XChaCha20-Poly1305), macOS Keychain.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("key derivation failed: {0}")]
    KeyDerivation(String),
    #[error("encryption failed: {0}")]
    Encryption(String),
    #[error("decryption failed: {0}")]
    Decryption(String),
    #[error("keychain error: {0}")]
    Keychain(String),
}

#[cfg(test)]
mod tests {
    // Tests will be added in Iteration 1.
}
