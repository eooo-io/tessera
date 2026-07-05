//! Spaces — hierarchical containers for organizing artifacts.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::vault::{Vault, VaultError};

#[derive(Error, Debug)]
pub enum SpaceError {
    #[error("space not found: {0}")]
    NotFound(String),
    #[error("vault error: {0}")]
    Vault(#[from] VaultError),
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
}

/// Typed wrapper for space identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SpaceId(pub String);

/// A space in the vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Space {
    pub id: SpaceId,
    pub name: String,
    pub parent_id: Option<SpaceId>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Create a space, optionally nested under `parent`.
pub fn create(vault: &Vault, name: &str, parent: Option<&SpaceId>) -> Result<SpaceId, SpaceError> {
    let id = SpaceId(format!("space_{}", ulid::Ulid::new()));
    let now = chrono::Utc::now().to_rfc3339();
    vault
        .conn()
        .execute(
            "INSERT INTO spaces (id, name, parent_id, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?4)",
            rusqlite::params![id.0, name, parent.map(|p| p.0.as_str()), now],
        )
        .map_err(|e| match e {
            rusqlite::Error::SqliteFailure(err, _)
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                SpaceError::NotFound(parent.map(|p| p.0.clone()).unwrap_or_else(|| name.into()))
            }
            other => SpaceError::Database(other),
        })?;
    Ok(id)
}

/// List all spaces, ordered by creation.
pub fn list(vault: &Vault) -> Result<Vec<Space>, SpaceError> {
    let mut stmt = vault.conn().prepare(
        "SELECT id, name, parent_id, created_at, updated_at FROM spaces ORDER BY created_at, id",
    )?;
    let spaces = stmt
        .query_map([], row_to_space)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(spaces)
}

/// Fetch one space by id.
pub fn get(vault: &Vault, id: &SpaceId) -> Result<Space, SpaceError> {
    vault
        .conn()
        .query_row(
            "SELECT id, name, parent_id, created_at, updated_at FROM spaces WHERE id = ?1",
            [id.0.as_str()],
            row_to_space,
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => SpaceError::NotFound(id.0.clone()),
            other => SpaceError::Database(other),
        })
}

fn row_to_space(row: &rusqlite::Row<'_>) -> rusqlite::Result<Space> {
    let parse = |value: String| {
        value
            .parse::<chrono::DateTime<chrono::Utc>>()
            .unwrap_or_default()
    };
    Ok(Space {
        id: SpaceId(row.get(0)?),
        name: row.get(1)?,
        parent_id: row.get::<_, Option<String>>(2)?.map(SpaceId),
        created_at: parse(row.get(3)?),
        updated_at: parse(row.get(4)?),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KdfParams;

    const TEST_PARAMS: KdfParams = KdfParams {
        m_cost_kib: 1024,
        t_cost: 1,
        p_cost: 1,
    };

    fn test_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::create_with_params(&dir.path().join("V.tessera"), "pass", &TEST_PARAMS)
            .expect("create vault");
        (dir, vault)
    }

    #[test]
    fn create_and_list_spaces() {
        let (_dir, vault) = test_vault();

        let id_a = create(&vault, "Clients", None).expect("create A");
        let id_b = create(&vault, "Personal", None).expect("create B");

        let spaces = list(&vault).expect("list");
        assert_eq!(spaces.len(), 2);
        assert!(spaces.iter().any(|s| s.id == id_a && s.name == "Clients"));
        assert!(spaces.iter().any(|s| s.id == id_b && s.name == "Personal"));
        assert!(id_a.0.starts_with("space_"), "typed ULID prefix");
    }

    #[test]
    fn nested_space_records_parent() {
        let (_dir, vault) = test_vault();

        let parent = create(&vault, "Clients", None).expect("parent");
        let child = create(&vault, "ClientA", Some(&parent)).expect("child");

        let fetched = get(&vault, &child).expect("get");
        assert_eq!(fetched.parent_id.as_ref(), Some(&parent));
    }

    #[test]
    fn create_under_missing_parent_fails() {
        let (_dir, vault) = test_vault();

        let ghost = SpaceId("space_DOESNOTEXIST".into());
        assert!(matches!(
            create(&vault, "Orphan", Some(&ghost)),
            Err(SpaceError::NotFound(_))
        ));
    }

    #[test]
    fn get_missing_space_is_not_found() {
        let (_dir, vault) = test_vault();
        assert!(matches!(
            get(&vault, &SpaceId("space_NOPE".into())),
            Err(SpaceError::NotFound(_))
        ));
    }
}
