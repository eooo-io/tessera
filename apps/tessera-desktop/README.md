# Tessera Desktop

Tessera's cross-platform owner workbench uses Tauri 2, React, TypeScript, Vite,
Tailwind CSS 4, DaisyUI 5, and the packaged Factor-E theme snapshot.

## What is live

The overview is connected to three narrowly registered native commands:

- capability discovery;
- open and unlock one existing current format-v3 vault;
- explicitly lock and drop the native vault state.

`tessera-core` validates the bundle and computes the overview. React receives
only format version, space count, pending-review count, active-session count,
protected receipt-chain status and count, and bounded diagnostic status. It
does not receive the vault path after success, records, filenames, titles,
tags, URLs, hashes, blob addresses, receipt payloads or identifiers, database
rows, handles, or cryptographic material.

## What is preview-only

Inbox, spaces, lenses, agents, sessions, receipts, evaluation, and diagnostics
retain donor presentation fixtures. Every such view has a persistent preview
banner, navigation label, and disabled mutation controls. The fixtures never
mix with the live overview and do not prove those workflows are connected.

## Secret boundary

The owner passphrase exists transiently in the password input, the explicit
Tauri IPC message, and native process memory while `Vault::open` runs. React
clears the field in `finally` after success or failure. Native Rust wraps its
owned argument in zeroizing storage. The desktop registers no logging plugin,
telemetry, persistent unlock token, filesystem plugin, shell plugin, SQL
endpoint, or general command router.

This does not protect the passphrase or DEK from a malicious same-user process
that can inspect the unlocked application memory. Application exit drops the
managed native state. See [the full boundary](../../docs/desktop-unlock-boundary.md).

## Theme and responsive behavior

The app consumes the exact packaged `@eooo-io/theme@0.1.0` snapshot under
`vendor/`. Both `eooo-light` and `eooo-dark` are available. The layout retains
compact, medium, desktop, and wide arrangements, visible keyboard focus,
reduced-motion behavior, coarse-pointer target sizing, and no page-level
horizontal overflow.

## Development

```bash
npm ci
npm run typecheck
npm run lint
npm run test:run
npm run build
cargo fmt --manifest-path src-tauri/Cargo.toml -- --check
cargo check --locked --manifest-path src-tauri/Cargo.toml
cargo test --locked --manifest-path src-tauri/Cargo.toml
npm run tauri build -- --debug
```

The debug build produces the macOS `.app` bundle used for local validation.
Installers, signing, notarization, and distribution packaging are deliberately
outside this slice.

Use only synthetic temporary vaults for tests, smoke checks, and screenshots.
