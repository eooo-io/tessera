//! The bound guardian session: a validated (pairing → lens) binding for one
//! connection. Constructed once at startup; construction is the gate that
//! refuses unknown lenses and unapproved or revoked pairings.

use anyhow::{bail, Context, Result};
use tessera_core::lens::{self, LensId, LensPolicy};
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

        let lens = lens::get(vault, &LensId(pairing.lens_id.clone())).map_err(|_| {
            anyhow::anyhow!(
                "pairing {pairing_id} references unknown lens {}",
                pairing.lens_id
            )
        })?;

        Ok(Self { pairing, lens })
    }
}
