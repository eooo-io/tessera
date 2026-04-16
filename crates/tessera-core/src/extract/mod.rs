//! Text extraction — PDF, Markdown, plaintext.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ExtractError {
    #[error("unsupported content type: {0}")]
    UnsupportedType(String),
    #[error("extraction failed: {0}")]
    ExtractionFailed(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    // Tests will be added in Iteration 2.
}
