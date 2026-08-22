# Research: Protected Receipt Baseline

## Decision 1: Protect the entire logical receipt in a dedicated container

**Decision**: Store each finalized receipt in a versioned opaque container with
an authenticated encrypted payload. Keep only the existing receipt id, sequence,+keyed predecessor/head tokens, opaque filename, and commit timestamp in the
SQLite recovery index.

**Rationale**: Whole-payload protection covers query text, artifact titles,
purpose, agent/lens identities, policy snapshots, and access detail without a
brittle field-by-field allowlist. A dedicated receipt container retains the
current concurrency and prepared-file recovery design without reusing the blob
store's plaintext content address, which issue #50 already identifies as a
confirmation risk.

**Alternatives considered**:

- Encrypt selected fields: rejected because new receipt fields could silently
  become plaintext and listing would need partial decryption semantics.
- Store receipts as ordinary blobs: rejected because the current blob path is a
  plaintext-content hash and receipt/index recovery needs stable receipt ids.
- Encrypt the entire SQLite database: deferred to #50 because it expands the
  migration, recovery, and portability boundary far beyond #39.

## Decision 2: Use two domain-separated keys derived from the vault DEK

**Decision**: Derive one 32-byte receipt-encryption key and one 32-byte
receipt-authentication key from the existing vault DEK using distinct BLAKE3
derive-key contexts. Zeroize both derived keys after use. Encrypt with the
existing XChaCha20-Poly1305 dependency and authenticate logical chain content
with keyed BLAKE3.

**Rationale**: This meets the local v0.1 threat model without a new dependency,
external service, or second independently rotated secret. Keyslot addition and
removal retain the same DEK, so receipt keys remain portable and stable.

**Alternatives considered**:

- Reuse the DEK directly for both operations: rejected because it violates key
  separation and couples audit semantics to blob encryption.
- Ed25519 signing: deferred because v0.1 does not promise third-party public
  verification; it would add signing-key generation, storage, rotation, trust
  distribution, and compromised-key semantics without solving confidentiality.
- External head anchoring: deferred because ordinary local operation must remain
  offline and because no trusted anchor consumer exists yet.

## Decision 3: Keep logical receipt schemas and version storage separately

**Decision**: Preserve logical receipt schema versions 1 and 2 for owner export.
Introduce protected receipt container version 1 and advance the enclosing vault
format to version 2. New binaries refuse unknown future container versions.

**Rationale**: Storage confidentiality is not a semantic change to the receipt's
disclosure contract. Separate versions avoid inventing receipt schema v3 merely
to represent encryption. Advancing the vault format prevents older binaries
from silently ignoring protected files and attempting incompatible writes.

**Alternatives considered**:

- Keep vault format version 1: rejected because older readers only discover
  `.json` receipt files and cannot safely interpret or continue a protected
  chain.
- Change logical receipt schema to v3: rejected because encryption belongs to
  the container and owner exports remain valid v1/v2 logical records.

## Decision 4: Make legacy migration explicit, complete-chain, and recoverable

**Decision**: `tessera receipts migrate --yes` first verifies the complete
legacy chain, prepares every protected replacement, commits the keyed index and
head in one SQLite transaction, completes deterministic renames, deletes legacy
plaintext files, advances the manifest, and verifies the resulting chain.
Ordinary receipt operations classify legacy storage as unauthenticated and
refuse to append until migration completes.

**Rationale**: Explicit migration makes the plaintext-to-protected transition
visible to the owner, enables a distinct unauthenticated classification, and
prevents mixed-authentication chains. Prepared files plus the durable index make
post-commit recovery deterministic; pre-commit residue can be discarded safely.

**Alternatives considered**:

- Silent migration on vault open: rejected because opening would cause a large
  security-sensitive write with no explicit owner signal and would hide the
  unauthenticated status.
- Migrate one receipt per open: rejected because mixed chains complicate
  guarantees, recovery, and downstream verification.

## Decision 5: Plaintext export stays explicit and owner-visible

**Decision**: `receipts show` and `receipts export` decrypt only after vault
unlock. Export to a file or stdout states that the representation is plaintext
and outside protected vault storage. JSON and standalone HTML remain supported.

**Rationale**: Owners need reviewable records, but an export must not look like
it retains the vault's at-rest confidentiality. The existing export surface is
sufficient once its warning and documentation are corrected.

**Alternatives considered**:

- Automatic decrypted report generation: rejected as an avoidable plaintext
  copy.
- Remove export: rejected because issue #39 requires a reviewable owner form.
