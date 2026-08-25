# Desktop unlock boundary

Status: v0.1 first owner workflow

## Trust boundary

The desktop WebView is an owner interface, not an agent disclosure path. Agents
continue to use Guardian MCP and receive no authority from the desktop process.
The native process is trusted to open a vault on the owner's explicit request.

The WebView may send exactly one vault location and passphrase during
`open_vault`. It receives only the versioned sanitized overview contract. The
native process owns the `tessera_core::Vault`, SQLCipher connection, keyslot
binding, blob store, and zeroizing DEK. Those objects are not serializable and
are never returned through Tauri IPC.

## Passphrase lifecycle

1. The owner types or pastes the passphrase into a password input.
2. React copies it into the explicit `open_vault` invocation.
3. Native Rust immediately wraps its owned string in zeroizing storage and
   passes a borrowed view to `tessera_core::Vault::open`.
4. React clears its passphrase state in `finally`, on success or failure.
5. Rust drops the zeroizing argument when open completes.

The app does not log command arguments or source errors and registers no
logging plugin or telemetry. It stores no passphrase, unlock token, vault path,
or overview in local storage, session storage, IndexedDB, cookies, or a desktop
configuration file.

The passphrase and derived key necessarily exist transiently in process memory.
Tessera does not claim protection against a malicious same-user process,
debugger, memory dump, compromised WebView/runtime, swap inspection, or crash
collector outside Tessera's control while the app is unlocked.

## Native lifecycle

One mutex owns zero or one vault. Open and lock operations serialize. A second
open is refused while a vault is unlocked and cannot replace the original.
Explicit lock removes the live overview immediately, calls native lock, invokes
`Vault::lock`, and drops the handle. Repeated lock is safe. Process exit drops
the managed state and its vault.

## Path and format handling

The WebView has no filesystem plugin or general file handle. The native command
passes the supplied location to current `tessera-core` validation. Core refuses
symlinked bundle components, malformed layouts, legacy formats, future formats,
active format-v3 migration state, unauthenticated keyslots, database tampering,
and wrong passphrases. The adapter maps source errors to fixed owner-safe codes
and never serializes paths or underlying details.

Opening a vault may tighten supported filesystem permissions through the
existing core behavior. The desktop does not modify the vault format, migrate,
repair, back up, or expose data through Guardian.

## Capability inventory

| Surface | Allowed |
|---|---|
| Tauri capability | Main-window association with an empty optional core/plugin permission set |
| Registered commands | `desktop_capabilities`, `open_vault`, `lock_vault` |
| Filesystem plugin | No |
| Shell or process plugin | No |
| SQL or database command | No |
| Logging or telemetry plugin | No |
| Generic command router | No |

Adding a command or permission requires a new owner-workflow slice, explicit
contract tests, capability review, and updated evidence.

Production CSP permits packaged resources and Tauri IPC only. Fixed loopback
HTTP and WebSocket origins are confined to the development CSP. If native lock
completion cannot be confirmed, React clears the protected projection but
enters `restart required`; it neither claims the vault is locked nor permits a
new open attempt in that process.
