//! Artifacts — files/documents with metadata, tags, and version history.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::blob::BlobHash;
use crate::space::SpaceId;
use crate::vault::{Vault, VaultError};

#[derive(Error, Debug)]
pub enum ArtifactError {
    #[error("artifact not found: {0}")]
    NotFound(String),
    #[error("space not found: {0}")]
    SpaceNotFound(String),
    #[error("vault error: {0}")]
    Vault(#[from] VaultError),
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
}

/// Typed wrapper for artifact identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ArtifactId(pub String);

/// Sensitivity classification for artifacts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    Public,
    #[default]
    Internal,
    Confidential,
    Restricted,
}

impl Sensitivity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Sensitivity::Public => "public",
            Sensitivity::Internal => "internal",
            Sensitivity::Confidential => "confidential",
            Sensitivity::Restricted => "restricted",
        }
    }
}

/// Quarantine state. Retrieval and lenses only ever match `Live`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactState {
    #[default]
    Pending,
    Live,
    Archived,
}

impl ArtifactState {
    pub fn as_str(&self) -> &'static str {
        match self {
            ArtifactState::Pending => "pending",
            ArtifactState::Live => "live",
            ArtifactState::Archived => "archived",
        }
    }

    fn parse(s: &str) -> Self {
        match s {
            "live" => ArtifactState::Live,
            "archived" => ArtifactState::Archived,
            _ => ArtifactState::Pending,
        }
    }
}

/// An artifact in the vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub id: ArtifactId,
    pub space_id: SpaceId,
    pub filename: String,
    pub media_type: String,
    pub sensitivity: Sensitivity,
    pub state: ArtifactState,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// A version of an artifact, linked to its encrypted blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactVersion {
    pub id: String,
    pub artifact_id: ArtifactId,
    pub version: u32,
    pub blob_hash: String,
    pub size_bytes: u64,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Register a new artifact in a space. Starts quarantined (`Pending`).
pub fn register(
    vault: &Vault,
    space: &SpaceId,
    filename: &str,
    media_type: &str,
    sensitivity: Sensitivity,
) -> Result<ArtifactId, ArtifactError> {
    let id = ArtifactId(format!("art_{}", ulid::Ulid::new()));
    let now = chrono::Utc::now().to_rfc3339();
    vault
        .conn()
        .execute(
            "INSERT INTO artifacts (id, space_id, filename, media_type, sensitivity, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
            rusqlite::params![id.0, space.0, filename, media_type, sensitivity.as_str(), now],
        )
        .map_err(|e| match e {
            rusqlite::Error::SqliteFailure(err, _)
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                ArtifactError::SpaceNotFound(space.0.clone())
            }
            other => ArtifactError::Database(other),
        })?;
    Ok(id)
}

/// Record a new version pointing at an encrypted blob. Versions number from
/// 1 and increment per artifact.
pub fn record_version(
    vault: &Vault,
    artifact: &ArtifactId,
    blob_hash: &BlobHash,
    size_bytes: u64,
) -> Result<ArtifactVersion, ArtifactError> {
    let next: u32 = vault.conn().query_row(
        "SELECT COALESCE(MAX(version), 0) + 1 FROM artifact_versions WHERE artifact_id = ?1",
        [artifact.0.as_str()],
        |r| r.get(0),
    )?;
    let id = format!("artv_{}", ulid::Ulid::new());
    let now = chrono::Utc::now();
    vault
        .conn()
        .execute(
            "INSERT INTO artifact_versions (id, artifact_id, version, blob_hash, size_bytes, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                id,
                artifact.0,
                next,
                blob_hash.0,
                size_bytes as i64,
                now.to_rfc3339()
            ],
        )
        .map_err(|e| match e {
            rusqlite::Error::SqliteFailure(err, _)
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                ArtifactError::NotFound(artifact.0.clone())
            }
            other => ArtifactError::Database(other),
        })?;
    Ok(ArtifactVersion {
        id,
        artifact_id: artifact.clone(),
        version: next,
        blob_hash: blob_hash.0.clone(),
        size_bytes,
        created_at: now,
    })
}

/// Change an artifact's quarantine state. The audit row is written in the
/// same transaction as the change.
pub fn set_state(
    vault: &Vault,
    artifact: &ArtifactId,
    state: ArtifactState,
) -> Result<(), ArtifactError> {
    let conn = vault.conn();
    let now = chrono::Utc::now().to_rfc3339();

    conn.execute_batch("BEGIN")?;
    let result: Result<(), ArtifactError> = (|| {
        let from_state: String = conn
            .query_row(
                "SELECT state FROM artifacts WHERE id = ?1",
                [artifact.0.as_str()],
                |r| r.get(0),
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => ArtifactError::NotFound(artifact.0.clone()),
                other => ArtifactError::Database(other),
            })?;
        conn.execute(
            "UPDATE artifacts SET state = ?1, updated_at = ?2 WHERE id = ?3",
            rusqlite::params![state.as_str(), now, artifact.0],
        )?;
        conn.execute(
            "INSERT INTO state_transitions (id, artifact_id, from_state, to_state, actor, created_at)
             VALUES (?1, ?2, ?3, ?4, 'owner', ?5)",
            rusqlite::params![
                format!("strn_{}", ulid::Ulid::new()),
                artifact.0,
                from_state,
                state.as_str(),
                now
            ],
        )?;
        Ok(())
    })();

    match result {
        Ok(()) => {
            conn.execute_batch("COMMIT")?;
            Ok(())
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

/// Update an artifact's sensitivity classification.
pub fn set_sensitivity(
    vault: &Vault,
    artifact: &ArtifactId,
    sensitivity: Sensitivity,
) -> Result<(), ArtifactError> {
    let changed = vault.conn().execute(
        "UPDATE artifacts SET sensitivity = ?1, updated_at = ?2 WHERE id = ?3",
        rusqlite::params![
            sensitivity.as_str(),
            chrono::Utc::now().to_rfc3339(),
            artifact.0
        ],
    )?;
    if changed == 0 {
        return Err(ArtifactError::NotFound(artifact.0.clone()));
    }
    Ok(())
}

/// List artifacts in a given state across all spaces, oldest first (review
/// queue order).
pub fn list_by_state(vault: &Vault, state: ArtifactState) -> Result<Vec<Artifact>, ArtifactError> {
    let mut stmt = vault.conn().prepare(&format!(
        "SELECT {ARTIFACT_COLS} FROM artifacts WHERE state = ?1 ORDER BY created_at, id"
    ))?;
    let artifacts = stmt
        .query_map([state.as_str()], row_to_artifact)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(artifacts)
}

const ARTIFACT_COLS: &str =
    "id, space_id, filename, media_type, sensitivity, state, created_at, updated_at";

/// Fetch one artifact.
pub fn get(vault: &Vault, artifact: &ArtifactId) -> Result<Artifact, ArtifactError> {
    vault
        .conn()
        .query_row(
            &format!("SELECT {ARTIFACT_COLS} FROM artifacts WHERE id = ?1"),
            [artifact.0.as_str()],
            row_to_artifact,
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => ArtifactError::NotFound(artifact.0.clone()),
            other => ArtifactError::Database(other),
        })
}

/// List artifacts in a space, newest first.
pub fn list(vault: &Vault, space: &SpaceId) -> Result<Vec<Artifact>, ArtifactError> {
    let mut stmt = vault.conn().prepare(&format!(
        "SELECT {ARTIFACT_COLS} FROM artifacts WHERE space_id = ?1 ORDER BY created_at DESC, id DESC"
    ))?;
    let artifacts = stmt
        .query_map([space.0.as_str()], row_to_artifact)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(artifacts)
}

/// Attach a tag (created on first use) to an artifact.
pub fn tag(vault: &Vault, artifact: &ArtifactId, name: &str) -> Result<(), ArtifactError> {
    let conn = vault.conn();
    conn.execute(
        "INSERT OR IGNORE INTO tags (id, name) VALUES (?1, ?2)",
        rusqlite::params![format!("tag_{}", ulid::Ulid::new()), name],
    )?;
    let tag_id: String =
        conn.query_row("SELECT id FROM tags WHERE name = ?1", [name], |r| r.get(0))?;
    conn.execute(
        "INSERT OR IGNORE INTO artifact_tags (artifact_id, tag_id) VALUES (?1, ?2)",
        rusqlite::params![artifact.0, tag_id],
    )
    .map_err(|e| match e {
        rusqlite::Error::SqliteFailure(err, _)
            if err.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            ArtifactError::NotFound(artifact.0.clone())
        }
        other => ArtifactError::Database(other),
    })?;
    Ok(())
}

/// List an artifact's tags, sorted.
pub fn tags_of(vault: &Vault, artifact: &ArtifactId) -> Result<Vec<String>, ArtifactError> {
    let mut stmt = vault.conn().prepare(
        "SELECT t.name FROM tags t
         JOIN artifact_tags at ON at.tag_id = t.id
         WHERE at.artifact_id = ?1 ORDER BY t.name",
    )?;
    let tags = stmt
        .query_map([artifact.0.as_str()], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(tags)
}

fn row_to_artifact(row: &rusqlite::Row<'_>) -> rusqlite::Result<Artifact> {
    let parse_time = |value: String| {
        value
            .parse::<chrono::DateTime<chrono::Utc>>()
            .unwrap_or_default()
    };
    let sensitivity = match row.get::<_, String>(4)?.as_str() {
        "public" => Sensitivity::Public,
        "confidential" => Sensitivity::Confidential,
        "restricted" => Sensitivity::Restricted,
        _ => Sensitivity::Internal,
    };
    Ok(Artifact {
        id: ArtifactId(row.get(0)?),
        space_id: SpaceId(row.get(1)?),
        filename: row.get(2)?,
        media_type: row.get(3)?,
        sensitivity,
        state: ArtifactState::parse(&row.get::<_, String>(5)?),
        created_at: parse_time(row.get(6)?),
        updated_at: parse_time(row.get(7)?),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KdfParams;
    use crate::space;

    const TEST_PARAMS: KdfParams = KdfParams {
        m_cost_kib: 1024,
        t_cost: 1,
        p_cost: 1,
    };

    fn test_vault_with_space() -> (tempfile::TempDir, Vault, SpaceId) {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::create_with_params(&dir.path().join("V.tessera"), "pass", &TEST_PARAMS)
            .expect("create vault");
        let space = space::create(&vault, "Test", None).expect("create space");
        (dir, vault, space)
    }

    #[test]
    fn register_starts_pending_with_defaults() {
        let (_dir, vault, space) = test_vault_with_space();

        let id = register(
            &vault,
            &space,
            "notes.md",
            "text/markdown",
            Sensitivity::default(),
        )
        .expect("register");
        assert!(id.0.starts_with("art_"));

        let artifact = get(&vault, &id).expect("get");
        assert_eq!(artifact.state, ArtifactState::Pending);
        assert_eq!(artifact.sensitivity, Sensitivity::Internal);
        assert_eq!(artifact.filename, "notes.md");
    }

    #[test]
    fn register_in_missing_space_fails() {
        let (_dir, vault, _space) = test_vault_with_space();
        let ghost = SpaceId("space_GHOST".into());
        assert!(matches!(
            register(
                &vault,
                &ghost,
                "f.txt",
                "text/plain",
                Sensitivity::default()
            ),
            Err(ArtifactError::SpaceNotFound(_))
        ));
    }

    #[test]
    fn versions_number_from_one_and_increment() {
        let (_dir, vault, space) = test_vault_with_space();
        let id = register(
            &vault,
            &space,
            "doc.pdf",
            "application/pdf",
            Sensitivity::default(),
        )
        .expect("register");

        let v1 = record_version(&vault, &id, &BlobHash("aa11".into()), 100).expect("v1");
        let v2 = record_version(&vault, &id, &BlobHash("bb22".into()), 200).expect("v2");
        assert_eq!(v1.version, 1);
        assert_eq!(v2.version, 2);
        assert_eq!(v2.blob_hash, "bb22");
    }

    #[test]
    fn set_state_transitions_quarantine() {
        let (_dir, vault, space) = test_vault_with_space();
        let id = register(
            &vault,
            &space,
            "f.txt",
            "text/plain",
            Sensitivity::default(),
        )
        .expect("register");

        set_state(&vault, &id, ArtifactState::Live).expect("to live");
        assert_eq!(get(&vault, &id).expect("get").state, ArtifactState::Live);

        set_state(&vault, &id, ArtifactState::Archived).expect("to archived");
        assert_eq!(
            get(&vault, &id).expect("get").state,
            ArtifactState::Archived
        );
    }

    #[test]
    fn sensitivity_can_be_adjusted() {
        let (_dir, vault, space) = test_vault_with_space();
        let id = register(
            &vault,
            &space,
            "f.txt",
            "text/plain",
            Sensitivity::default(),
        )
        .expect("register");

        set_sensitivity(&vault, &id, Sensitivity::Restricted).expect("update");
        assert_eq!(
            get(&vault, &id).expect("get").sensitivity,
            Sensitivity::Restricted
        );
    }

    #[test]
    fn list_by_state_is_review_queue_order() {
        let (_dir, vault, space) = test_vault_with_space();
        let a = register(
            &vault,
            &space,
            "a.txt",
            "text/plain",
            Sensitivity::default(),
        )
        .expect("a");
        let b = register(
            &vault,
            &space,
            "b.txt",
            "text/plain",
            Sensitivity::default(),
        )
        .expect("b");
        set_state(&vault, &b, ArtifactState::Live).expect("b live");

        let pending = list_by_state(&vault, ArtifactState::Pending).expect("pending");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, a);
        let live = list_by_state(&vault, ArtifactState::Live).expect("live");
        assert_eq!(live.len(), 1);
    }

    #[test]
    fn state_changes_are_audited() {
        let (_dir, vault, space) = test_vault_with_space();
        let id = register(
            &vault,
            &space,
            "f.txt",
            "text/plain",
            Sensitivity::default(),
        )
        .expect("register");

        set_state(&vault, &id, ArtifactState::Live).expect("to live");
        set_state(&vault, &id, ArtifactState::Archived).expect("to archived");

        let mut stmt = vault
            .conn()
            .prepare(
                "SELECT from_state, to_state, actor FROM state_transitions
                 WHERE artifact_id = ?1 ORDER BY created_at, id",
            )
            .expect("prepare");
        let rows: Vec<(String, String, String)> = stmt
            .query_map([id.0.as_str()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .expect("query")
            .collect::<Result<_, _>>()
            .expect("rows");

        assert_eq!(
            rows,
            vec![
                ("pending".into(), "live".into(), "owner".into()),
                ("live".into(), "archived".into(), "owner".into()),
            ]
        );
    }

    #[test]
    fn list_scopes_to_space_newest_first() {
        let (_dir, vault, space_a) = test_vault_with_space();
        let space_b = space::create(&vault, "Other", None).expect("space B");

        let a1 = register(
            &vault,
            &space_a,
            "a1.txt",
            "text/plain",
            Sensitivity::default(),
        )
        .expect("a1");
        let _b1 = register(
            &vault,
            &space_b,
            "b1.txt",
            "text/plain",
            Sensitivity::default(),
        )
        .expect("b1");

        let in_a = list(&vault, &space_a).expect("list A");
        assert_eq!(in_a.len(), 1);
        assert_eq!(in_a[0].id, a1);
    }

    #[test]
    fn tagging_is_idempotent_and_sorted() {
        let (_dir, vault, space) = test_vault_with_space();
        let id = register(
            &vault,
            &space,
            "f.txt",
            "text/plain",
            Sensitivity::default(),
        )
        .expect("register");

        tag(&vault, &id, "spec").expect("tag 1");
        tag(&vault, &id, "code").expect("tag 2");
        tag(&vault, &id, "spec").expect("tag repeat");

        assert_eq!(tags_of(&vault, &id).expect("tags"), vec!["code", "spec"]);
    }

    #[test]
    #[ignore = "performance budget check — run explicitly (GOAL.md)"]
    fn listing_10k_artifacts_under_100ms() {
        let (_dir, vault, space) = test_vault_with_space();

        let conn = vault.conn();
        conn.execute_batch("BEGIN").expect("begin");
        for i in 0..10_000 {
            conn.execute(
                "INSERT INTO artifacts (id, space_id, filename, media_type, created_at, updated_at)
                 VALUES (?1, ?2, ?3, 'text/plain', '2026-07-05T00:00:00Z', '2026-07-05T00:00:00Z')",
                rusqlite::params![format!("art_{i:08}"), space.0, format!("file{i}.txt")],
            )
            .expect("insert");
        }
        conn.execute_batch("COMMIT").expect("commit");

        let start = std::time::Instant::now();
        let artifacts = list(&vault, &space).expect("list");
        let elapsed = start.elapsed();

        assert_eq!(artifacts.len(), 10_000);
        assert!(
            elapsed.as_millis() < 100,
            "listing took {elapsed:?} (budget: 100ms)"
        );
    }
}
