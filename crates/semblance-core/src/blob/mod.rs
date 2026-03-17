//! Encrypted blob store — content-addressed, XChaCha20-Poly1305.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum BlobError {
    #[error("blob not found: {0}")]
    NotFound(String),
    #[error("integrity check failed for blob: {0}")]
    IntegrityError(String),
    #[error("encryption error: {0}")]
    EncryptionError(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    // Tests will be added in Iteration 1.
}
