# Desktop owner-workbench revival evidence

**Evidence state:** validated local candidate, 2026-08-23. The exact PR head
and platform CI are bound after independent review and publication. All runtime
fixtures are synthetic.

## Commit and recovery provenance

| Role | Exact commit | Evidence |
|---|---|---|
| Post-#89 implementation base | `488560894d188f97f2365e56cfdc4853a1ad2f00` | PR #89 merge commit; exact push workflow [32652727828](https://github.com/eooo-io/tessera/actions/runs/32652727828) passed macOS, Ubuntu, and protected-vault interchange |
| Preserved donor | `50a830f3c08874e990d588291220328c7fceb13c` | One local-only commit, not an ancestor of current main; donor branch and clean worktree remained untouched |
| Revival branch | `skippy/desktop-workbench-revival` | Created directly at the exact base; no competing remote branch or pull request existed at recovery time |
| Final implementation | The exact draft-PR head containing this report | Added after publication; local and remote equality is required before completion |

The donor diff contains 56 paths and 10,910 insertions. Its 51
`apps/tessera-desktop/` files are additive. `docs/desktop-owner-workbench.md` is
also additive. The donor's root README, CI workflow, Guardian design note, and
`mac/.gitkeep` deletion overlap with current architecture and were not applied
blindly.

## Recovery disposition

| Donor area | Disposition | Reason |
|---|---|---|
| Tauri 2 crate, icons, config, CSP, and core-only capability | Revived, then command adapter rewritten | Preserve native shell while replacing fixture-only capability discovery with tested open and lock |
| React, TypeScript, Vite, Tailwind, DaisyUI, theme package | Revived | Existing responsive design and exact packaged theme remain useful |
| Overview | Rewritten | It is now the only live view and accepts only `tessera.desktop.overview.v1` |
| Inbox, spaces, lenses, agents, sessions, receipts, evaluation, diagnostics | Revived as explicit previews | Records remain fixtures; mutation controls are disabled and never report success |
| Frontend tests | Rewritten and expanded | Tests protect lifecycle, passphrase clearing, least disclosure, preview honesty, themes, and keyboard flow |
| Root README | Reconciled | Preserves post-#89 security documentation while replacing the stale SwiftUI repository map |
| Root CI | Reconciled | Preserves all protected-vault portability jobs and adds focused desktop jobs |
| Guardian design note | Deliberately omitted | Historical document remains unchanged; the current desktop decision is maintained separately |
| `mac/.gitkeep` deletion | Deliberately omitted | The preserved dormant placeholder is not part of this revival |

The donor's `bundle.targets = "all"` setting was narrowed to the macOS
application bundle. DMG or installer production would cross this slice's
explicit signing and distribution non-goals and is not required to exercise the
native owner boundary.

## Live versus preview matrix

| Screen or capability | State | Native command | Evidence |
|---|---|---|---|
| Capability discovery | Live | `desktop_capabilities` | Closed command list with no Rust type names or environment detail |
| Vault open and unlock | Live | `open_vault` | `tessera-core::Vault::open`; format-v3, credential, migration, malformed, tamper, and symlink tests |
| Sanitized overview | Live | return from `open_vault` | Exact nine-field projection; no record or path-bearing values |
| Explicit lock | Live | `lock_vault` | Native state drop, repeated lock, concurrent lifecycle, and immediate UI clearing tests |
| Inbox review and import | Preview fixture | None | Preview banner, navigation badge, disabled controls |
| Spaces and lenses | Preview fixture | None | Preview banner, disabled create/inspect actions |
| Pairings and agents | Preview fixture | None | Preview banner, disabled pairing/actions |
| Sessions and revocation | Preview fixture | None | Preview banner, disabled revoke and Guardian lock |
| Receipt inspection | Preview fixture | None | Preview banner, disabled verify action |
| Private evaluation | Preview fixture | None | Preview banner; no private plan access or evaluation run |
| Diagnostics, backup, migration, repair | Preview fixture | None | Preview banner and disabled actions; no readiness claim |

## Tauri command and capability inventory

| Boundary | Exact surface |
|---|---|
| Registered commands | `desktop_capabilities`, `open_vault`, `lock_vault` |
| Main-window capability | `core:default` |
| Filesystem, shell, SQL, or generic execution | None |
| Logging and telemetry plugins | None |
| Native state | One non-serializable `Vault` inside a mutex; dropped on lock or application exit |

The frontend adapter validates every result field and rebuilds a closed object,
discarding unexpected properties. Unknown error payloads are replaced with a
fixed `internal_failure` message.

## Secret lifecycle

The passphrase exists transiently in the owner password input, explicit Tauri
IPC argument, and native process memory. React clears it in `finally` after
success and failure. Native Rust wraps the owned argument in `Zeroizing<String>`.
No command argument or source error is logged, persisted, cached, returned, or
placed in fixtures.

This boundary does not defend an unlocked process against a malicious same-user
process, debugger, memory dump, compromised runtime, swap inspection, or an
external crash collector. It does not claim secure deletion from operating
system, filesystem, SSD, snapshot, or backup layers.

## Validation topology

| Layer | Current local evidence | Final requirement |
|---|---|---|
| Frontend | Fresh `npm ci`, typecheck, lint, 10 Vitest behavior tests, production build; npm audit reports 0 known vulnerabilities | Repeat only if the final source changes |
| Root workspace | Formatting, strict clippy, all-target build, 372 passing all-target tests with 4 expected ignored tests, then all 4 ignored tests passing explicitly | Repeat affected gates if the final source changes |
| Native boundary | Formatting, locked check, strict nested clippy, and 10 focused Rust tests pass | Repeat affected gates if the final source changes |
| Packaged app | Exact debug Tauri command produced the macOS `Tessera.app`; synthetic format-v3 smoke passed | No installer, signing, or distribution claim |
| Responsive and themes | Manual packaged-app checks at compact, medium, desktop, and wide widths; light/dark, keyboard focus, drawer, vertical scrolling, and no horizontal page scrollbar observed | Automated behavior tests cover semantic structure and breakpoints do not substitute for the manual visual check |
| Independent review | Pending final commit | Separate security, acceptance, and UX reviews with no blocking findings |

The final controlled ignored-performance run recorded: 10,000-artifact listing
within its 100 ms budget; 19.30 ms per embedding chunk; 681 ms legacy
migration; 1.17 ms median top-10 query; 25 ms diagnostics; 173 ms repair;
947 ms backup; and 107 ms restore. These are development-machine measurements,
not cross-platform service level guarantees.

A deliberately parallel validation attempt materially distorted two budgets
while the nested Tauri crate was rebuilding: listing reached 384.08 ms,
embedding reached 77.56 ms per chunk, and legacy migration reached 1.98 s. That
contended attempt failed the first two budgets. After the native build completed,
the ignored suite was rerun alone and all four ignored tests passed with the
controlled measurements above. Performance gates should not be run beside a
full native desktop compilation on the same machine.

The donor npm lockfile failed a current clean install and exposed three
transitive advisories. A lock-only, scripts-disabled repair retained the
declared dependency ranges, made `npm ci` reproducible, and reduced the current
audit result to zero known vulnerabilities. No broad dependency modernization
was performed.

## macOS packaged-app smoke

The debug `.app` was launched against a persistent bundle created by the
checked-in format-v3 portability fixture with test KDF parameters. No private
vault was opened.

| Observation | Result |
|---|---|
| Initial state | Locked; search and lock unavailable; live workflow form only |
| Unlock | Native call succeeded; path form disappeared and passphrase field was unmounted |
| Live overview | Format 3, 1 space, 0 pending items, 0 active sessions, 1 verified receipt, healthy bounded diagnostics |
| Explicit lock | Live projection cleared immediately; empty path and passphrase fields returned; repeated lock remains covered by native and frontend tests |
| Theme and focus | Light and dark themes rendered; keyboard Tab produced a visible focus ring on the lock control |
| Preview honesty | Inbox carried a persistent preview warning; every fixture mutation and filter control was disabled |
| Responsive layout | Drawer/navigation and aggregate layout inspected at compact, medium, desktop, and wide widths; vertical scrolling appeared where expected and no horizontal page scrollbar was present |
| Exit | Application was explicitly locked before the packaged window closed; native state-drop behavior is independently covered by Rust test |

The disposable synthetic smoke bundle was not retained as project evidence.

## Platform CI

- Required base commit `488560894d188f97f2365e56cfdc4853a1ad2f00`:
  [green macOS, Ubuntu, and protected-vault workflow](https://github.com/eooo-io/tessera/actions/runs/32652727828).
- Exact PR head:
  [branch-filtered CI](https://github.com/eooo-io/tessera/actions/workflows/ci.yml?query=branch%3Askippy%2Fdesktop-workbench-revival), pending publication.

## Known limitations and deferred workflows

- The first workflow accepts a typed or pasted local path; a native chooser is
  not yet connected.
- Passphrase entry crosses the owner WebView and Tauri IPC transiently.
- Unlock runs as one serialized native command and can occupy its command
  execution thread for the KDF and bounded aggregate checks.
- The overview provides aggregate state only. It does not refresh when another
  process changes the vault; relock and reopen refreshes it.
- Receipt-chain failure is reported only as `invalid` with count zero; detailed
  investigation remains a CLI owner workflow.
- Fixture screens are not evidence of connected inbox, lens, pairing, session,
  receipt, evaluation, diagnostic, backup, migration, or repair behavior.
- No signing, notarization, installer, auto-update, telemetry, cloud service,
  mobile support, distribution, private evaluation, or release work is part of
  this slice.
