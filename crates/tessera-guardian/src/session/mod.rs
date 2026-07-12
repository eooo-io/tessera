//! The bound guardian session: an immutable owner-approved grant snapshot for
//! one connection or HTTP call. The guardian revalidates the pairing and lens
//! revision before disclosure so revocation or policy edits fail on the next
//! call.

use anyhow::{bail, Context, Result};
use tessera_core::lens::LensPolicy;
use tessera_core::pairing::{self, Pairing};
use tessera_core::Vault;

/// A connection's session context: the approved pairing and the lens it binds.
pub struct GuardianSession {
    pub pairing: Pairing,
    pub lens: LensPolicy,
}

impl GuardianSession {
    /// Resolve and validate a pairing, returning the bound session or an error
    /// explaining the refusal. A session is refused when the pairing does not
    /// exist, has been revoked, or references a lens that no longer exists.
    pub fn bind(vault: &Vault, pairing_id: &str) -> Result<Self> {
        let pairing = pairing::get(vault, pairing_id)
            .with_context(|| format!("pairing {pairing_id} is not authorized"))?;

        if !pairing.is_active() {
            bail!("pairing {pairing_id} has been revoked");
        }

        let lens = pairing::approved_lens(vault, &pairing).with_context(|| {
            format!("pairing {pairing_id} does not match its approved lens revision")
        })?;

        Ok(Self { pairing, lens })
    }

    /// Revalidate the immutable grant before a disclosing call. Pairing
    /// revocation, direct grant mutation, lens deletion, and lens revision
    /// changes all fail closed without altering this session's snapshot.
    pub fn authorize_call(&self, vault: &Vault) -> Result<()> {
        let current = pairing::get(vault, &self.pairing.id)
            .with_context(|| format!("pairing {} is no longer authorized", self.pairing.id))?;
        if !current.is_active() {
            bail!("pairing {} has been revoked", self.pairing.id);
        }
        if !current.same_grant_as(&self.pairing) {
            bail!(
                "pairing {} no longer matches its approved grant snapshot",
                self.pairing.id
            );
        }
        pairing::approved_lens(vault, &current).with_context(|| {
            format!(
                "lens {} changed after pairing approval; create a new pairing",
                current.lens_id
            )
        })?;
        Ok(())
    }
}
