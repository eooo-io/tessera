# Research: Desktop Owner Workbench Revival

## Donor recovery strategy

**Decision**: Reuse the additive `apps/tessera-desktop/` tree and `docs/desktop-owner-workbench.md` from `50a830f`, then reconcile all overlapping root files manually against `4885608`.

**Rationale**: The donor is one additive commit based before issues #39, #35, and #50. Its application shell is isolated and useful, while its README, CI, architecture note, and `mac/` removal overlap with newer security and portability work.

**Alternatives considered**: Cherry-picking the commit would import stale root state and delete `mac/.gitkeep`. Rebuilding the UI would discard a clean tested artifact and create needless design drift.

## Native state and command boundary

**Decision**: Store one non-serializable `tessera_core::Vault` behind a native mutex. Expose only capability discovery, `open_vault`, and `lock_vault`; serialize lifecycle calls under the same lock and refuse replacement while unlocked.

**Rationale**: A single state owner makes concurrent calls deterministic and lets `Vault` and its zeroizing DEK drop together. React sees only serializable projections, never the state object.

**Alternatives considered**: A frontend-owned token registry adds a replayable capability without value in a single-window first slice. Multiple native vault handles expand state and key lifetime. A general command router or SQL endpoint violates minimum authority.

## Passphrase lifecycle

**Decision**: Permit one transient string in the password input and Tauri IPC for the explicit call. Clear React state in `finally`, wrap the native argument in zeroizing storage before vault open, never log input or underlying errors, and remove the donor logging plugin.

**Rationale**: This is the owner-approved residual boundary in the feature request. It is compatible with `Vault::open(&Path, &str)` and adds no persistent secret.

**Alternatives considered**: A native secure-input window would materially change the UX architecture and still leave process-memory exposure. Keychain persistence and unlock tokens are outside scope and would add new trust and recovery decisions.

## Overview aggregation

**Decision**: Compose public `tessera-core` APIs: `space::list`, `artifact::list_by_state(Pending)`, `session::list` with effective-status filtering, `receipt::verify`, and `recovery::diagnose`. Map diagnostics to `healthy`, `attention`, or `fatal` without returning check details.

**Rationale**: This keeps domain queries inside core and avoids adding database access or metadata-rich records to the desktop adapter.

**Alternatives considered**: Direct SQL in the Tauri crate duplicates schema knowledge and violates the core-only boundary. Returning complete domain objects would over-disclose private metadata.

## Safe refusal and path handling

**Decision**: Rely on current format-v3 `Vault::open` validation, including bundle layout, symlink rejection, migration refusal, manifest version checks, authenticated keyslots, and encrypted database open. Map error variants to a small owner-safe enum and discard source text.

**Rationale**: Post-#89 core already owns the security contract. Reimplementing preflight checks in the adapter risks time-of-check/time-of-use gaps and inconsistent error behavior.

**Alternatives considered**: Frontend filesystem inspection would require prohibited permissions. Adapter-side manifest parsing would reveal paths and duplicate core validation.

## Dependency and build topology

**Decision**: Retain donor lockfiles and dependency families unless compilation proves a focused incompatibility. Keep `src-tauri` as a nested Cargo workspace and remove only the unused native log plugin.

**Rationale**: The donor was built with the repository's Rust 1.97 toolchain and current Tauri 2 family. Independent build topology avoids contaminating root workspace gates with native WebView dependencies.

**Alternatives considered**: Broad upgrades create unrelated supply-chain churn. Adding the Tauri crate to the root workspace would force desktop prerequisites onto all root and CI jobs.

## Decision record reconciliation

**Decision**: Update `docs/desktop-owner-workbench.md` in place. Do not create a new ADR.

**Rationale**: The architectural choice of Tauri, React, core-only domain logic, narrow owner commands, and Guardian separation is unchanged. This slice resolves implementation and secret-lifecycle detail rather than choosing a new system boundary.

**Alternatives considered**: A new ADR would duplicate the existing approved decision and obscure continuity.
