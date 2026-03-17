//! Lens policy model and evaluation.
//!
//! A Lens defines what an agent can see and how — the core access control
//! primitive in Semblance.

use serde::{Deserialize, Serialize};

/// Typed wrapper for lens identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LensId(pub String);

/// How much of an artifact is revealed to an agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureMode {
    /// Artifact metadata + one-sentence summary. No verbatim text.
    Summary,
    /// Artifact metadata + verbatim excerpts up to `max_quote_chars`.
    Excerpt,
    /// Complete artifact content.
    Full,
}

/// When user approval is required for a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalRule {
    /// Never require approval (auto-approve).
    Never,
    /// Always require explicit user approval.
    Always,
    /// Require approval only for sensitive artifacts.
    OnSensitive,
}

/// A reusable access policy defining what an agent can see and how.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LensPolicy {
    pub id: LensId,
    pub name: String,
    pub space_ids: Vec<crate::space::SpaceId>,
    pub space_exclude_ids: Vec<crate::space::SpaceId>,
    pub tag_include: Vec<String>,
    pub tag_exclude: Vec<String>,
    pub content_types: Vec<String>,
    pub disclosure_mode: DisclosureMode,
    pub max_quote_chars: Option<u32>,
    pub allow_metadata: bool,
    pub operations: Vec<String>,
    pub sensitivity_ceiling: crate::artifact::Sensitivity,
    pub approval_rule: ApprovalRule,
    pub default_ttl_minutes: u32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[cfg(test)]
mod tests {
    // Tests will be added in Iteration 4.
}
