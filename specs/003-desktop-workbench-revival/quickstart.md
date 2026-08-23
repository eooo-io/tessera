# Quickstart: Validate the Desktop Owner Workflow

Use only synthetic temporary vaults. Never point development screenshots or tests at a private owner corpus.

## Install and static gates

```bash
cd apps/tessera-desktop
npm ci
npm run typecheck
npm run lint
npm run test:run
npm run build
cargo fmt --manifest-path src-tauri/Cargo.toml -- --check
cargo check --locked --manifest-path src-tauri/Cargo.toml
cargo test --locked --manifest-path src-tauri/Cargo.toml
```

Expected: all checks pass, native tests use test KDF parameters, and frontend tests use a typed mocked invocation boundary.

## Create a synthetic vault

From the repository root, create a temporary format-v3 bundle using the Tessera CLI. Do not pass the passphrase as a command-line argument. Use the CLI's no-echo owner prompt and a disposable path outside the repository.

Populate only synthetic spaces, pending items, sessions, and receipts needed to observe non-zero aggregates. The native adapter's automated tests cover this deterministically.

## Manual macOS smoke

```bash
cd apps/tessera-desktop
npm run tauri dev
```

1. Confirm the initial overview is locked and contains no fixture aggregate.
2. Enter the synthetic bundle path and a wrong passphrase. Confirm bounded guidance, locked state, and an empty passphrase field.
3. Enter the correct passphrase. Confirm only the contract fields in `contracts/native-owner-v1.md` appear.
4. Navigate every other view. Confirm a visible preview label and disabled disconnected mutations.
5. Use keyboard-only navigation, toggle both themes, and resize through compact, medium, desktop, and wide layouts. Confirm visible focus and no page-level horizontal overflow.
6. Lock. Confirm the live overview disappears immediately and repeated lock is harmless.
7. Quit and reopen. Confirm the application starts locked.

## Packaged debug build

```bash
cd apps/tessera-desktop
npm run tauri build -- --debug
```

Inspect generated logs and artifacts using synthetic sentinels. Expected: no passphrase, owner path, private metadata, hash, or receipt identifier is present.

## Regression and specification gates

Run the root workspace commands listed in the active goal, then:

```bash
python3 .specify/scripts/python/check_prerequisites.py --json --require-tasks --include-tasks
```

Review `tasks.md`, the requirement checklist, and the final evidence matrix before publication.
