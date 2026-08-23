# Data Model: Desktop Owner Workbench Revival

## Native Vault Session

Process-local state with exactly one authoritative variant:

- `Locked`: no vault or derived key is retained.
- `Unlocked`: owns one current-format `Vault` and the most recent sanitized overview.

Transitions:

```text
Locked --open succeeds--> Unlocked
Locked --open fails-----> Locked
Unlocked --open---------> Unlocked (refused, original preserved)
Unlocked --lock---------> Locked
Locked --lock-----------> Locked
Any --application exit--> dropped
```

One mutex serializes transitions. No state variant is serializable or stored on disk.

## Sanitized Overview

Closed projection returned only after all aggregate checks complete:

| Field | Type | Validation |
|---|---|---|
| `state` | literal `unlocked` | Never accepts arbitrary text |
| `formatVersion` | unsigned integer | Must equal current supported format |
| `spaceCount` | unsigned integer | Aggregate only |
| `pendingReviewCount` | unsigned integer | Aggregate only |
| `activeSessionCount` | unsigned integer | Effective, non-expired active sessions only |
| `receiptChain` | `verified` or `invalid` | No receipt identifier or failure detail |
| `receiptCount` | unsigned integer | Aggregate only |
| `diagnosticStatus` | `healthy`, `attention`, or `fatal` | Derived from bounded integrity classes |

If aggregation fails before the state is committed, the candidate vault is dropped and the session remains locked.

## Owner-Safe Error

Serializable failure with exactly:

- `code`: stable enumerated machine value.
- `message`: fixed owner guidance associated with that code.

Allowed codes cover invalid credentials, unsupported format, migration required, invalid bundle, unsafe path, already unlocked, unavailable native state, and internal failure. No dynamic source text is serialized.

## Workbench Capability

Static descriptor of the three registered native operations and the application version. It contains no Rust type names, paths, configuration, or discovered environment detail.

## Preview Capability

Frontend-only presentation record tagged `preview`. It cannot invoke a native mutation. Preview records never enter `Sanitized Overview` and disappear from no live aggregate.
