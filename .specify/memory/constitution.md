<!--
Sync Impact Report
- Version change: template -> 1.0.0
- Added principles: Owner-Controlled Private Evidence; Default Deny and Minimum
  Disclosure; Exact Provenance and Honest Audit Claims; Portable, Recoverable
  Formats; Test-First Evidence
- Added sections: Security and Data Constraints; Development and Release Gates
- Removed sections: none
- Follow-up TODOs: none
-->
# Tessera Constitution

## Core Principles

### I. Owner-Controlled Private Evidence

All source content, derived content, queries, receipts, and sensitive metadata
MUST remain owner-controlled. Content enters the vault only through an explicit
owner action, remains encrypted at rest, and is never uploaded to a hosted
service by default. Unlock material, decrypted content, and private evaluation
data MUST NOT enter logs, command arguments, repository artifacts, or ordinary
diagnostics. This protects Tessera's core promise: the owner retains possession
and decides what may be disclosed.

### II. Default Deny and Minimum Disclosure

Agent-facing access MUST fail closed. A live, owner-approved pairing and an
immutable lens revision MUST authorize each disclosure. Quarantined, excluded,
over-ceiling, stale, expired, or revoked evidence MUST NOT surface. The system
MUST apply the narrowest allowed disclosure mode and MUST record zero-result and
denied outcomes without inventing evidence. Convenience cannot weaken policy,
quarantine, or revocation boundaries.

### III. Exact Provenance and Honest Audit Claims

Every disclosed byte MUST remain traceable to authenticated stored evidence,
its exact version and range, the effective lens, and the live session that
caused disclosure. Audit mechanisms MUST distinguish consistency, integrity,
authenticity, and non-repudiation. Product language MUST claim only guarantees
demonstrated by the implemented threat model and current verification evidence.
An unkeyed checksum or synthetic test is not proof against an authorized vault
writer.

### IV. Portable, Recoverable Formats

The complete vault bundle MUST remain openable and verifiable on every supported
host using owner-held key material. Format changes MUST be versioned, documented,
backward-aware, crash-safe, and deterministic to recover. Migration MUST preserve
authenticated originals, receipt order, and provenance. Repair MUST never
fabricate missing source evidence or silently discard unverifiable state.

### V. Test-First Evidence

Behavior changes MUST begin with a failing test that represents the relevant
acceptance criterion or adversarial case. Formatting, strict linting, targeted
tests, workspace tests, and applicable ignored performance or fault tests MUST
run after the final change. Static structure, a validator, or prior green CI is
evidence only for what it directly checks. Skipped checks and remaining runtime
proof MUST be reported explicitly.

## Security and Data Constraints

- Use the repository's pinned Rust toolchain and existing cryptographic
  primitives unless an ADR justifies a new dependency.
- Domain-separate keys and authenticated-data contexts for distinct purposes.
- Zeroize derived secret material when it leaves scope.
- Never weaken encrypt-first ordering, quarantine, space isolation, receipt
  completeness, or explicit owner approval to satisfy a test.
- Document attacker capabilities, protected assets, residual leakage, key loss,
  key rotation, export, backup, restore, and cross-host behavior for every
  security-relevant format change.
- Tessera governs context disclosure. It does not grant action authority,
  approve durable memory, or claim control over data after disclosure.

## Development and Release Gates

Requirements record the what and why. Plans and tasks record the implementation
approach. ADRs record consequential architectural choices and rejected options.
Each behavior-changing slice MUST link its issue, specification, implementation,
tests, documentation, and state-bound verification evidence.

Work MUST remain focused on a dependency-ready issue or owner-authorized request.
The implementer MUST inspect current checkout and tracker state, preserve
unrelated changes, and stop when a material security ambiguity needs owner
authority. Merging, tagging, releasing, publishing, or broadening permissions
requires Ezra's exact approval. A release is permitted only when every declared
gate is green at the exact release commit and all limitations are documented.

## Governance

This constitution governs Spec Kit artifacts and implementation work in Tessera.
Platform instructions, Ezra's current authority, repository `AGENTS.md` files,
and canonical project documentation retain their normal higher-precedence scope.

Amendments require a documented rationale, impact analysis, semantic version
change, and Ezra approval when they alter security, authority, data, or release
boundaries. MAJOR versions remove or redefine a principle, MINOR versions add or
materially expand governance, and PATCH versions clarify without changing
meaning. Every feature plan and completion review MUST check compliance. Any
exception requires a named owner, bounded waiver, reason, and expiry or removal
condition.

**Version**: 1.0.0 | **Ratified**: 2026-08-20 | **Last Amended**: 2026-08-20
