//! semblance-core — Vault storage, ingestion, and policy-gated retrieval.

pub mod artifact;
pub mod blob;
pub mod chunk;
pub mod crypto;
pub mod db;
pub mod disclosure;
pub mod embed;
pub mod index;
pub mod lens;
pub mod receipt;
pub mod search;
pub mod space;
pub mod vault;

// Re-export primary types.
pub use artifact::{Artifact, ArtifactId, Sensitivity};
pub use lens::{ApprovalRule, DisclosureMode, LensId, LensPolicy};
pub use receipt::Receipt;
pub use search::SearchResult;
pub use space::{Space, SpaceId};
pub use vault::Vault;
