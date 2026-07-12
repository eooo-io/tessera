//! Provenance — where every derived blob came from and what produced it.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::artifact::ArtifactId;
use crate::vault::{Vault, VaultError};

#[derive(Error, Debug)]
pub enum ProvenanceError {
    #[error("vault error: {0}")]
    Vault(#[from] VaultError),
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
}

/// One provenance record: a derived blob, its source, and its producer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceRecord {
    pub id: String,
    pub derived_blob_hash: String,
    pub source_artifact_version_id: Option<String>,
    pub tool: String,
    pub tool_version: Option<String>,
    pub locality: String,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_published_at: Option<String>,
}

/// Integrity check: derived-text blobs that lack a provenance row.
/// A healthy vault returns an empty list.
pub fn orphaned_derivations(vault: &Vault) -> Result<Vec<String>, ProvenanceError> {
    let mut stmt = vault.conn().prepare(
        "SELECT dt.blob_hash FROM derived_text dt
         LEFT JOIN provenance p ON p.derived_blob_hash = dt.blob_hash
         WHERE p.id IS NULL ORDER BY dt.created_at",
    )?;
    let orphans = stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(orphans)
}

/// The provenance chain for an artifact: every derivation of every version,
/// newest version first.
pub fn chain_for(
    vault: &Vault,
    artifact: &ArtifactId,
) -> Result<Vec<ProvenanceRecord>, ProvenanceError> {
    let mut stmt = vault.conn().prepare(
        "SELECT p.id, p.derived_blob_hash, p.source_artifact_version_id, p.tool,
                p.tool_version, p.locality, p.created_at, ws.final_url, ws.title,
                ws.published_at
         FROM provenance p
         JOIN artifact_versions av ON av.id = p.source_artifact_version_id
         LEFT JOIN web_sources ws ON ws.artifact_version_id = av.id
         WHERE av.artifact_id = ?1
         ORDER BY av.version DESC, p.created_at",
    )?;
    let records = stmt
        .query_map([artifact.0.as_str()], |r| {
            Ok(ProvenanceRecord {
                id: r.get(0)?,
                derived_blob_hash: r.get(1)?,
                source_artifact_version_id: r.get(2)?,
                tool: r.get(3)?,
                tool_version: r.get(4)?,
                locality: r.get(5)?,
                created_at: r.get(6)?,
                source_url: r.get(7)?,
                source_title: r.get(8)?,
                source_published_at: r.get(9)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KdfParams;
    use crate::space::SpaceId;
    use crate::{extract, inbox, space};

    const TEST_PARAMS: KdfParams = KdfParams {
        m_cost_kib: 1024,
        t_cost: 1,
        p_cost: 1,
    };

    fn pipeline_vault() -> (tempfile::TempDir, Vault, ArtifactId) {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::create_with_params(&dir.path().join("V.tessera"), "pass", &TEST_PARAMS)
            .expect("create vault");
        let space: SpaceId = space::create(&vault, "Docs", None).expect("space");

        let path = dir.path().join("a.md");
        std::fs::write(&path, "Provenance test body. Another sentence.").expect("write");
        inbox::add(&vault, std::slice::from_ref(&path)).expect("add");
        let report = inbox::process(&vault, &space).expect("process");
        let artifact = report.ingested[0].1.clone();
        extract::extract_text(&vault, &artifact)
            .expect("extract")
            .expect("text");
        (dir, vault, artifact)
    }

    #[test]
    fn healthy_pipeline_has_no_orphans() {
        let (_dir, vault, _artifact) = pipeline_vault();
        assert_eq!(
            orphaned_derivations(&vault).expect("check"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn deleting_a_provenance_row_is_detected() {
        let (_dir, vault, _artifact) = pipeline_vault();
        vault
            .conn()
            .execute("DELETE FROM provenance", [])
            .expect("delete");

        let orphans = orphaned_derivations(&vault).expect("check");
        assert_eq!(orphans.len(), 1, "the derivation must be reported");
    }

    #[test]
    fn chain_reports_tool_and_locality() {
        let (_dir, vault, artifact) = pipeline_vault();

        let chain = chain_for(&vault, &artifact).expect("chain");
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].tool, "passthrough");
        assert_eq!(chain[0].locality, "local");
        assert!(chain[0].source_artifact_version_id.is_some());
    }
}
