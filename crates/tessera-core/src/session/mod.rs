//! Live guardian sessions and their lifecycle.
//!
//! A session row is written when a guardian binds a connection and carries a
//! TTL (`expires_at`). The guardian re-reads [`status`] on every tool call, so
//! a [`revoke`] written by the owner's CLI to the same WAL database takes
//! effect on the next call — no IPC, sub-second latency. Expiry is derived
//! from `expires_at`, so it needs no writer at all.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::pairing::Pairing;
use crate::vault::{Vault, VaultError};

#[derive(Error, Debug)]
pub enum SessionError {
    #[error("session not found: {0}")]
    NotFound(String),
    #[error("vault error: {0}")]
    Vault(#[from] VaultError),
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
}

/// The effective status of a session, combining the stored state with the
/// derived expiry check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatus {
    /// Live and within its TTL.
    Active,
    /// Past its TTL (derived, not stored).
    Expired,
    /// Revoked by the owner.
    Revoked,
    /// Cleanly closed by the guardian.
    Closed,
}

impl SessionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            SessionStatus::Active => "active",
            SessionStatus::Expired => "expired",
            SessionStatus::Revoked => "revoked",
            SessionStatus::Closed => "closed",
        }
    }
}

/// A persisted session row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRecord {
    pub id: String,
    pub pairing_id: String,
    pub lens_id: String,
    pub purpose: String,
    pub agent_name: String,
    pub started_at: String,
    pub expires_at: String,
    pub ended_at: Option<String>,
    pub status: String,
    pub receipt_id: Option<String>,
}

impl SessionRecord {
    /// The effective status, applying the TTL to a still-`active` row.
    pub fn effective_status(&self) -> SessionStatus {
        match self.status.as_str() {
            "revoked" => SessionStatus::Revoked,
            "closed" => SessionStatus::Closed,
            _ => {
                if is_expired(&self.expires_at) {
                    SessionStatus::Expired
                } else {
                    SessionStatus::Active
                }
            }
        }
    }
}

fn is_expired(expires_at: &str) -> bool {
    match expires_at.parse::<chrono::DateTime<chrono::Utc>>() {
        Ok(t) => chrono::Utc::now() >= t,
        // An unparseable timestamp is treated as expired (fail-closed).
        Err(_) => true,
    }
}

const COLS: &str =
    "id, pairing_id, lens_id, purpose, agent_name, started_at, expires_at, ended_at, status, receipt_id";

fn row_to_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<SessionRecord> {
    Ok(SessionRecord {
        id: row.get(0)?,
        pairing_id: row.get(1)?,
        lens_id: row.get(2)?,
        purpose: row.get(3)?,
        agent_name: row.get(4)?,
        started_at: row.get(5)?,
        expires_at: row.get(6)?,
        ended_at: row.get(7)?,
        status: row.get(8)?,
        receipt_id: row.get(9)?,
    })
}

/// Open a live session for a pairing, stamping its TTL from `pairing.ttl_minutes`.
pub fn start(vault: &Vault, pairing: &Pairing) -> Result<SessionRecord, SessionError> {
    let id = format!("sess_{}", ulid::Ulid::new());
    let now = chrono::Utc::now();
    let expires = now + chrono::Duration::minutes(pairing.ttl_minutes as i64);
    let started_at = now.to_rfc3339();
    let expires_at = expires.to_rfc3339();

    vault.conn().execute(
        "INSERT INTO sessions
           (id, pairing_id, lens_id, purpose, agent_name, started_at, expires_at, status)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'active')",
        rusqlite::params![
            id,
            pairing.id,
            pairing.lens_id,
            pairing.purpose,
            pairing.agent_name,
            started_at,
            expires_at
        ],
    )?;

    Ok(SessionRecord {
        id,
        pairing_id: pairing.id.clone(),
        lens_id: pairing.lens_id.clone(),
        purpose: pairing.purpose.clone(),
        agent_name: pairing.agent_name.clone(),
        started_at,
        expires_at,
        ended_at: None,
        status: "active".into(),
        receipt_id: None,
    })
}

/// Fetch one session record.
pub fn get(vault: &Vault, session_id: &str) -> Result<SessionRecord, SessionError> {
    vault
        .conn()
        .query_row(
            &format!("SELECT {COLS} FROM sessions WHERE id = ?1"),
            [session_id],
            row_to_record,
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => SessionError::NotFound(session_id.to_owned()),
            other => SessionError::Database(other),
        })
}

/// The effective status of a session (TTL applied). This is what the guardian
/// calls on every tool call.
pub fn status(vault: &Vault, session_id: &str) -> Result<SessionStatus, SessionError> {
    Ok(get(vault, session_id)?.effective_status())
}

/// Close a session cleanly, recording its finalized receipt id (if any).
pub fn close(
    vault: &Vault,
    session_id: &str,
    receipt_id: Option<&str>,
) -> Result<(), SessionError> {
    vault.conn().execute(
        "UPDATE sessions SET status = 'closed', ended_at = ?1, receipt_id = ?2
         WHERE id = ?3 AND status = 'active'",
        rusqlite::params![chrono::Utc::now().to_rfc3339(), receipt_id, session_id],
    )?;
    Ok(())
}

/// Revoke a session. Takes effect on the guardian's next status check.
pub fn revoke(vault: &Vault, session_id: &str) -> Result<(), SessionError> {
    let changed = vault.conn().execute(
        "UPDATE sessions SET status = 'revoked', ended_at = ?1
         WHERE id = ?2 AND status = 'active'",
        rusqlite::params![chrono::Utc::now().to_rfc3339(), session_id],
    )?;
    if changed == 0 {
        get(vault, session_id)?; // surface NotFound if it truly does not exist
    }
    Ok(())
}

/// Revoke every currently-active session (the `guardian lock` primitive).
/// Returns how many were revoked.
pub fn revoke_all(vault: &Vault) -> Result<usize, SessionError> {
    let changed = vault.conn().execute(
        "UPDATE sessions SET status = 'revoked', ended_at = ?1 WHERE status = 'active'",
        [chrono::Utc::now().to_rfc3339()],
    )?;
    Ok(changed)
}

/// List all sessions, newest first.
pub fn list(vault: &Vault) -> Result<Vec<SessionRecord>, SessionError> {
    let mut stmt = vault.conn().prepare(&format!(
        "SELECT {COLS} FROM sessions ORDER BY started_at DESC, id DESC"
    ))?;
    let rows = stmt
        .query_map([], row_to_record)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KdfParams;
    use crate::lens::{self, LensId, LensPolicy};
    use crate::pairing;
    use crate::space::SpaceId;

    const TEST_PARAMS: KdfParams = KdfParams {
        m_cost_kib: 1024,
        t_cost: 1,
        p_cost: 1,
    };

    fn vault_with_pairing(ttl: u32) -> (tempfile::TempDir, Vault, Pairing) {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::create_with_params(&dir.path().join("V.tessera"), "pass", &TEST_PARAMS)
            .expect("create");
        let lens_id: LensId = lens::create(
            &vault,
            &LensPolicy::new("r", vec![SpaceId("space_A".into())]),
        )
        .expect("lens");
        let p = pairing::approve(&vault, &lens_id, "purpose", "agent", ttl).expect("approve");
        (dir, vault, p)
    }

    #[test]
    fn start_is_active_within_ttl() {
        let (_dir, vault, p) = vault_with_pairing(60);
        let s = start(&vault, &p).expect("start");
        assert_eq!(
            status(&vault, &s.id).expect("status"),
            SessionStatus::Active
        );
    }

    #[test]
    fn zero_ttl_is_immediately_expired() {
        let (_dir, vault, p) = vault_with_pairing(0);
        let s = start(&vault, &p).expect("start");
        assert_eq!(
            status(&vault, &s.id).expect("status"),
            SessionStatus::Expired
        );
    }

    #[test]
    fn revoke_takes_effect() {
        let (_dir, vault, p) = vault_with_pairing(60);
        let s = start(&vault, &p).expect("start");
        revoke(&vault, &s.id).expect("revoke");
        assert_eq!(
            status(&vault, &s.id).expect("status"),
            SessionStatus::Revoked
        );
    }

    #[test]
    fn revoke_all_covers_active_only() {
        let (_dir, vault, p) = vault_with_pairing(60);
        let a = start(&vault, &p).expect("a");
        let b = start(&vault, &p).expect("b");
        close(&vault, &b.id, None).expect("close b");
        // Only the still-active session `a` is revoked.
        assert_eq!(revoke_all(&vault).expect("revoke_all"), 1);
        assert_eq!(status(&vault, &a.id).expect("a"), SessionStatus::Revoked);
        assert_eq!(status(&vault, &b.id).expect("b"), SessionStatus::Closed);
    }

    #[test]
    fn close_records_receipt() {
        let (_dir, vault, p) = vault_with_pairing(60);
        let s = start(&vault, &p).expect("start");
        close(&vault, &s.id, Some("rcpt_1")).expect("close");
        let rec = get(&vault, &s.id).expect("get");
        assert_eq!(rec.receipt_id.as_deref(), Some("rcpt_1"));
        assert_eq!(rec.effective_status(), SessionStatus::Closed);
    }

    #[test]
    fn missing_session_is_not_found() {
        let (_dir, vault, _p) = vault_with_pairing(60);
        assert!(matches!(
            status(&vault, "sess_NOPE"),
            Err(SessionError::NotFound(_))
        ));
    }
}
