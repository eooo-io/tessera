//! tessera-core — Vault storage, ingestion, and policy-gated retrieval.

pub mod artifact;
pub mod blob;
pub mod chunk;
pub mod crypto;
pub mod db;
pub mod disclosure;
pub mod embed;
pub mod eval;
pub mod extract;
pub mod inbox;
pub mod index;
pub mod lens;
pub mod oauth;
pub mod pairing;
pub mod provenance;
pub mod receipt;
pub mod recovery;
pub mod review;
pub mod search;
pub mod session;
pub mod space;
pub mod summary;
pub mod transcript;
pub mod vault;
pub mod web;

// Cross-cutting policy-enforcement paranoia suite (#20): proves no lens can
// ever surface content it is not entitled to. Test-only; spans lens + index.
#[cfg(test)]
mod policy_enforcement;

// Re-export primary types.
pub use artifact::{Artifact, ArtifactId, Sensitivity};
pub use lens::{ApprovalRule, DisclosureMode, LensId, LensPolicy};
pub use receipt::Receipt;
pub use search::SearchResult;
pub use space::{Space, SpaceId};
pub use vault::Vault;
