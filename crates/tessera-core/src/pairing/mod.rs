//! Agent pairings — the owner's one-time authorization of a guardian
//! connection.
//!
//! An agent connects through the guardian by presenting a pairing id. The
//! pairing binds a lens and a stated purpose; the guardian refuses to serve
//! any pairing that does not exist, has been revoked, or references a lens
//! that no longer exists. This is the human-in-the-loop gate: nothing reaches
//! a vault until the owner has approved the pairing here.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::lens::{self, LensError, LensId};
use crate::vault::{Vault, VaultError};

#[derive(Error, Debug)]
pub enum PairingError {
    #[error("pairing not found: {0}")]
    NotFound(String),
    #[error("unknown lens: {0}")]
    UnknownLens(String),
    #[error("pairing {pairing_id} was approved for an older revision of lens {lens_id}")]
    StaleLens { pairing_id: String, lens_id: String },
    #[error("lens error: {0}")]
    Lens(#[from] LensError),
    #[error("vault error: {0}")]
    Vault(#[from] VaultError),
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
}

/// An owner-approved authorization for an agent to bind a lens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pairing {
    pub id: String,
    pub lens_id: String,
    pub purpose: String,
    pub agent_name: String,
    pub ttl_minutes: u32,
    pub approved_at: String,
    pub revoked_at: Option<String>,
    pub oauth_client_id: Option<String>,
    /// Exact lens revision approved by the owner. A changed lens requires a
    /// new pairing; an old credential never silently inherits new policy.
    pub lens_updated_at: Option<String>,
}

impl Pairing {
    /// A pairing is usable until revoked.
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }

    /// Whether this pairing still names the exact lens revision the owner
    /// approved. `None` fails closed for deleted/pre-versioned lens records.
    pub fn is_current_for(&self, lens: &crate::lens::LensPolicy) -> bool {
        let current_revision = lens.updated_at.to_rfc3339();
        self.lens_id == lens.id.0
            && self.lens_updated_at.as_deref() == Some(current_revision.as_str())
    }

    /// Compare the immutable authorization fields, excluding revocation state.
    pub fn same_grant_as(&self, other: &Self) -> bool {
        self.id == other.id
            && self.lens_id == other.lens_id
            && self.purpose == other.purpose
            && self.agent_name == other.agent_name
            && self.ttl_minutes == other.ttl_minutes
            && self.approved_at == other.approved_at
            && self.oauth_client_id == other.oauth_client_id
            && self.lens_updated_at == other.lens_updated_at
    }
}

/// Resolve the exact lens revision authorized by this pairing. Deleted or
/// edited lenses fail closed and require a new owner-approved pairing.
pub fn approved_lens(
    vault: &Vault,
    pairing: &Pairing,
) -> Result<crate::lens::LensPolicy, PairingError> {
    let lens = lens::get(vault, &LensId(pairing.lens_id.clone())).map_err(|error| match error {
        LensError::NotFound(id) => PairingError::UnknownLens(id),
        other => PairingError::Lens(other),
    })?;
    if !pairing.is_current_for(&lens) {
        return Err(PairingError::StaleLens {
            pairing_id: pairing.id.clone(),
            lens_id: pairing.lens_id.clone(),
        });
    }
    Ok(lens)
}

const COLS: &str =
    "id, lens_id, purpose, agent_name, ttl_minutes, approved_at, revoked_at, oauth_client_id, lens_updated_at";

fn row_to_pairing(row: &rusqlite::Row<'_>) -> rusqlite::Result<Pairing> {
    Ok(Pairing {
        id: row.get(0)?,
        lens_id: row.get(1)?,
        purpose: row.get(2)?,
        agent_name: row.get(3)?,
        ttl_minutes: row.get::<_, i64>(4)? as u32,
        approved_at: row.get(5)?,
        revoked_at: row.get(6)?,
        oauth_client_id: row.get(7)?,
        lens_updated_at: row.get(8)?,
    })
}

/// Approve a pairing for an existing lens. Fails with `UnknownLens` if the
/// lens id does not resolve.
pub fn approve(
    vault: &Vault,
    lens_id: &LensId,
    purpose: &str,
    agent_name: &str,
    ttl_minutes: u32,
) -> Result<Pairing, PairingError> {
    approve_with_client(vault, lens_id, purpose, agent_name, ttl_minutes, None)
}

/// Approve a remote pairing bound to one preregistered OAuth client.
pub fn approve_remote(
    vault: &Vault,
    lens_id: &LensId,
    purpose: &str,
    agent_name: &str,
    ttl_minutes: u32,
    oauth_client_id: &str,
) -> Result<Pairing, PairingError> {
    let _ = crate::oauth::get_client(vault, oauth_client_id)
        .map_err(|_| PairingError::NotFound(format!("OAuth client {oauth_client_id}")))?;
    approve_with_client(
        vault,
        lens_id,
        purpose,
        agent_name,
        ttl_minutes,
        Some(oauth_client_id),
    )
}

fn approve_with_client(
    vault: &Vault,
    lens_id: &LensId,
    purpose: &str,
    agent_name: &str,
    ttl_minutes: u32,
    oauth_client_id: Option<&str>,
) -> Result<Pairing, PairingError> {
    // The exact lens revision is part of the immutable owner grant.
    let approved_lens = lens::get(vault, lens_id).map_err(|e| match e {
        LensError::NotFound(id) => PairingError::UnknownLens(id),
        other => PairingError::Lens(other),
    })?;
    let lens_updated_at = approved_lens.updated_at.to_rfc3339();

    let id = format!("pair_{}", ulid::Ulid::new());
    let approved_at = chrono::Utc::now().to_rfc3339();
    vault.conn().execute(
        "INSERT INTO pairings
           (id, lens_id, purpose, agent_name, ttl_minutes, approved_at,
            oauth_client_id, lens_updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            id,
            lens_id.0,
            purpose,
            agent_name,
            ttl_minutes,
            approved_at,
            oauth_client_id,
            lens_updated_at
        ],
    )?;
    Ok(Pairing {
        id,
        lens_id: lens_id.0.clone(),
        purpose: purpose.to_owned(),
        agent_name: agent_name.to_owned(),
        ttl_minutes,
        approved_at,
        revoked_at: None,
        oauth_client_id: oauth_client_id.map(str::to_owned),
        lens_updated_at: Some(lens_updated_at),
    })
}

/// Resolve the single active owner approval for an OAuth client + lens scope.
pub fn find_remote(
    vault: &Vault,
    oauth_client_id: &str,
    lens_id: &str,
) -> Result<Pairing, PairingError> {
    let mut stmt = vault.conn().prepare(&format!(
        "SELECT {COLS} FROM pairings
         WHERE oauth_client_id = ?1 AND lens_id = ?2 AND revoked_at IS NULL
         ORDER BY approved_at DESC"
    ))?;
    let matches = stmt
        .query_map([oauth_client_id, lens_id], row_to_pairing)?
        .collect::<Result<Vec<_>, _>>()?;
    match matches.as_slice() {
        [pairing] => {
            approved_lens(vault, pairing)?;
            Ok(pairing.clone())
        }
        [] => Err(PairingError::NotFound(format!(
            "remote approval for client {oauth_client_id} and lens {lens_id}"
        ))),
        _ => Err(PairingError::Database(rusqlite::Error::InvalidQuery)),
    }
}

/// Fetch one pairing by id.
pub fn get(vault: &Vault, id: &str) -> Result<Pairing, PairingError> {
    vault
        .conn()
        .query_row(
            &format!("SELECT {COLS} FROM pairings WHERE id = ?1"),
            [id],
            row_to_pairing,
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => PairingError::NotFound(id.to_owned()),
            other => PairingError::Database(other),
        })
}

/// List all pairings, newest first.
pub fn list(vault: &Vault) -> Result<Vec<Pairing>, PairingError> {
    let mut stmt = vault.conn().prepare(&format!(
        "SELECT {COLS} FROM pairings ORDER BY approved_at DESC, id DESC"
    ))?;
    let rows = stmt
        .query_map([], row_to_pairing)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Revoke a pairing. Idempotent-ish: revoking a missing pairing is `NotFound`.
pub fn revoke(vault: &Vault, id: &str) -> Result<(), PairingError> {
    let changed = vault.conn().execute(
        "UPDATE pairings SET revoked_at = ?1 WHERE id = ?2 AND revoked_at IS NULL",
        rusqlite::params![chrono::Utc::now().to_rfc3339(), id],
    )?;
    if changed == 0 {
        // Either the pairing does not exist or it was already revoked.
        get(vault, id)?; // surfaces NotFound if truly absent
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KdfParams;
    use crate::lens::LensPolicy;
    use crate::space::SpaceId;

    const TEST_PARAMS: KdfParams = KdfParams {
        m_cost_kib: 1024,
        t_cost: 1,
        p_cost: 1,
    };

    fn vault_with_lens() -> (tempfile::TempDir, Vault, LensId) {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::create_with_params(&dir.path().join("V.tessera"), "pass", &TEST_PARAMS)
            .expect("create");
        let policy = LensPolicy::new("reader", vec![SpaceId("space_A".into())]);
        let id = lens::create(&vault, &policy).expect("lens");
        (dir, vault, id)
    }

    #[test]
    fn approve_and_get_roundtrip() {
        let (_dir, vault, lens_id) = vault_with_lens();
        let p = approve(&vault, &lens_id, "answer questions", "Claude", 60).expect("approve");
        assert!(p.id.starts_with("pair_"));
        assert!(p.is_active());

        let fetched = get(&vault, &p.id).expect("get");
        assert_eq!(fetched, p);
        assert!(p.lens_updated_at.is_some());
    }

    #[test]
    fn approve_rejects_unknown_lens() {
        let (_dir, vault, _lens) = vault_with_lens();
        let err =
            approve(&vault, &LensId("lens_GHOST".into()), "x", "a", 60).expect_err("must reject");
        assert!(matches!(err, PairingError::UnknownLens(_)));
    }

    #[test]
    fn revoke_makes_inactive() {
        let (_dir, vault, lens_id) = vault_with_lens();
        let p = approve(&vault, &lens_id, "purpose", "agent", 30).expect("approve");
        revoke(&vault, &p.id).expect("revoke");
        assert!(!get(&vault, &p.id).expect("get").is_active());
    }

    #[test]
    fn get_and_revoke_missing_are_not_found() {
        let (_dir, vault, _lens) = vault_with_lens();
        assert!(matches!(
            get(&vault, "pair_NOPE"),
            Err(PairingError::NotFound(_))
        ));
        assert!(matches!(
            revoke(&vault, "pair_NOPE"),
            Err(PairingError::NotFound(_))
        ));
    }

    #[test]
    fn approved_grant_fields_cannot_be_mutated() {
        let (_dir, vault, lens_id) = vault_with_lens();
        let p = approve(&vault, &lens_id, "approved purpose", "agent", 30).expect("approve");
        let error = vault
            .conn()
            .execute(
                "UPDATE pairings SET purpose = 'different task' WHERE id = ?1",
                [&p.id],
            )
            .expect_err("grant mutation must fail");
        assert!(error.to_string().contains("create a new pairing"));

        revoke(&vault, &p.id).expect("revocation remains allowed");
        assert!(!get(&vault, &p.id).expect("get").is_active());
    }

    #[test]
    fn lens_revision_change_makes_pairing_stale() {
        let (_dir, vault, lens_id) = vault_with_lens();
        let p = approve(&vault, &lens_id, "purpose", "agent", 30).expect("approve");
        let mut policy = lens::get(&vault, &lens_id).expect("lens");
        assert!(p.is_current_for(&policy));

        policy.allow_metadata = false;
        lens::update(&vault, &policy).expect("update lens");
        let changed = lens::get(&vault, &lens_id).expect("changed lens");
        assert!(!p.is_current_for(&changed));
    }
}
