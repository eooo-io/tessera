# Quickstart: Verify Protected Receipts

## Prerequisites

- Rust toolchain from `rust-toolchain.toml`
- A disposable test vault and passphrase
- No private corpus or production vault is required

## Targeted automated proof

```bash
cargo test -p tessera-core receipt::tests -- --nocapture
cargo test -p tessera-cli --test cli receipts -- --nocapture
```

Expected outcomes:

- protected containers contain no receipt sentinels in plaintext;
- editing, middle insertion/deletion, and keyless regeneration fail;
- legacy migration survives every implemented failpoint;
- copied vault verification and continuation pass;
- malformed, inconsistent, unauthenticated, and cryptographically invalid
  fixtures remain distinguishable.

## Owner workflow

```bash
tessera --vault /path/V.tessera receipts verify
tessera --vault /path/V.tessera receipts migrate --yes
tessera --vault /path/V.tessera receipts verify
tessera --vault /path/V.tessera receipts export rcpt_ID --out receipt.json
```

Expected behavior:

1. A legacy vault is classified as unauthenticated and cannot append receipts.
2. Explicit migration verifies legacy state before replacing any receipt.
3. The protected chain verifies after migration.
4. Export states that `receipt.json` is plaintext and must be protected by the
   owner outside the vault.

## Full repository gate

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
cargo test --workspace --all-targets -- --ignored
git diff --check
```

Record any skipped environment-dependent ignored test explicitly. Do not treat
synthetic fixtures as macOS-to-Linux release portability evidence for issue #44.
