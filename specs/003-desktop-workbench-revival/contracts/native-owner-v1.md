# Native Owner Contract v1

All command names are explicitly registered. Unknown commands fail at the Tauri boundary. The WebView has only `core:default` capability and receives no filesystem or shell permission.

## `desktop_capabilities`

Input: none.

Success:

```json
{
  "schema": "tessera.desktop.capabilities.v1",
  "appVersion": "0.1.0",
  "ownerCommands": ["desktop_capabilities", "open_vault", "lock_vault"]
}
```

## `open_vault`

Input exists only for the invocation lifetime:

```json
{ "vaultPath": "<owner-selected local bundle>", "passphrase": "<transient secret>" }
```

Success:

```json
{
  "schema": "tessera.desktop.overview.v1",
  "state": "unlocked",
  "formatVersion": 3,
  "spaceCount": 0,
  "pendingReviewCount": 0,
  "activeSessionCount": 0,
  "receiptChain": "verified",
  "receiptCount": 0,
  "diagnosticStatus": "healthy"
}
```

Failure is one fixed code/message pair:

```json
{
  "code": "invalid_credentials",
  "message": "The vault could not be unlocked. Check the passphrase and try again."
}
```

The command never returns the vault path, passphrase, hashes, receipt identifiers, metadata values, rows, stack traces, or nested source errors.

## `lock_vault`

Input: none.

Success:

```json
{ "schema": "tessera.desktop.lock.v1", "state": "locked" }
```

Lock is idempotent. The frontend clears its overview before or as the command begins and remains locked even if the native process becomes unavailable.

## Compatibility

- Contract version v1 accepts format-v3 vaults only.
- Additive result fields require a new schema version unless clients can prove they ignore them safely.
- New native operations require explicit registration, capability review, behavioral tests, and documentation.
