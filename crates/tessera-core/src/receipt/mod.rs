//! Receipt construction and export.
//!
//! Receipts are immutable records of what was accessed during a session.

use serde::{Deserialize, Serialize};

/// An immutable record of session activity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub receipt_id: String,
    pub session_id: String,
    pub agent_name: String,
    pub lens_name: String,
    pub purpose: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub ended_at: Option<chrono::DateTime<chrono::Utc>>,
    pub queries: Vec<QueryRecord>,
    pub summary: ReceiptSummary,
}

/// A single query within a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryRecord {
    pub query_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub query_text: String,
    pub artifacts_accessed: Vec<ArtifactAccess>,
}

/// Record of an artifact accessed during a query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactAccess {
    pub artifact_id: String,
    pub artifact_title: String,
    pub disclosure_mode: String,
    pub bytes_disclosed: u64,
}

/// Aggregate statistics for a receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptSummary {
    pub total_queries: u32,
    pub unique_artifacts_accessed: u32,
    pub total_bytes_disclosed: u64,
    pub disclosure_modes_used: Vec<String>,
}

#[cfg(test)]
mod tests {
    // Tests will be added in Iteration 5.
}
