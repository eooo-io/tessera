# Tessera desktop owner workbench

Status: revived first native workflow
Original decision date: 2026-07-14
Revival baseline: 2026-08-23

## Decision continuity

Tessera uses a cross-platform owner workbench built with Tauri 2,
React, TypeScript, Vite, Tailwind CSS 4, and DaisyUI 5. The UI consumes the
packaged `@eooo-io/theme` snapshot and supports `eooo-light` and `eooo-dark`.
CI covers the frontend on Ubuntu and the native boundary on macOS and Ubuntu.

This remains the approved replacement for the dormant SwiftUI direction.
`mac/` is a preserved placeholder, not the app. The donor implementation at
`50a830f3c08874e990d588291220328c7fceb13c` was recovered onto post-#89 main
`488560894d188f97f2365e56cfdc4853a1ad2f00`. The donor itself remains an
immutable source artifact.

No new ADR is needed. The original architecture is unchanged; this revival
adds the format-v3, protected-receipt, and explicit secret-lifecycle constraints
that now exist after issues #39 and #50.

## Security boundaries

There are two distinct interaction planes:

1. The owner workbench invokes narrowly scoped native Rust commands. It never
   receives SQLite handles, unrestricted filesystem access, vault keys, raw
   database rows, hashes, receipt payloads, or a general-purpose shell.
2. Agents continue to use Guardian MCP. The desktop does not bypass, weaken,
   or replace Guardian's lens, pairing, quarantine, session, disclosure, or
   receipt contract.

`tessera-core` is the only domain implementation. React renders a closed typed
projection and does not reproduce vault, policy, receipt, quarantine,
migration, recovery, or evaluation logic.

The complete passphrase and native-state boundary is documented in
[`desktop-unlock-boundary.md`](desktop-unlock-boundary.md).

## Live capability

The first real workflow provides:

- explicit format-v3 vault location and unlock;
- wrong-passphrase, legacy, migration, malformed, future-format, and symlink
  refusal through fixed owner-safe errors;
- a sanitized aggregate containing only format version, counts of spaces,
  pending review items, active sessions, protected receipts, receipt-chain
  verification state, and bounded diagnostics;
- explicit idempotent lock and process-exit state drop.

The native allowlist contains only capability discovery, open, and lock.

## Preview capability

Inbox, spaces, lenses, agents, sessions, receipts, evaluation, and diagnostics
retain presentation fixtures from the donor. They are labeled `Preview` in
navigation, wrapped in a persistent preview banner, and their actions are
disabled. They prove only the responsive shell. They do not claim native data,
successful mutations, or release readiness.

## Responsive baseline

- Compact: 360 to 639 CSS pixels in the packaged app. Navigation uses an explicit modal drawer,
  actions wrap, and content panels stack in workflow order.
- Medium: 640 to 767 CSS pixels. Summary grids use two columns where readable;
  navigation remains compact.
- Desktop: 768 to 1023 CSS pixels. Navigation remains compact while content
  panels gain working room.
- Wide: 1024 CSS pixels and above. Navigation remains visible and the live
  aggregate uses a four-card summary row.
- Coarse pointers receive a 44-pixel target floor.
- The application honors reduced motion and exposes visible keyboard focus.
- No viewport may require horizontal page scrolling. Dense preview tables may
  scroll only inside their labeled container.

## Validation

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
npm run tauri build -- --debug
```

CI retains post-#89 root and portability gates and adds the portable frontend
gate plus native macOS and Ubuntu coverage. Manual validation uses only a
synthetic vault; structural tests are not presented as visual proof.
