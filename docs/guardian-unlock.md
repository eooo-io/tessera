# Guardian unlock and key lifecycle

The Guardian does not read `TESSERA_PASSPHRASE`. A long-lived MCP launcher
must not carry the vault passphrase in its environment, command line, JSON
configuration, logs, or protocol stream.

Exactly one unlock source is required:

1. `--passphrase-fd <n>` — recommended for non-interactive launch;
2. `--passphrase-file <path>` — portable fallback for a private regular file;
3. `--prompt-passphrase` — no-echo prompt on the controlling terminal.

The Guardian reads at most 4,096 UTF-8 bytes, accepts one optional line ending,
rejects empty/multiline/NUL input, opens the vault, and zeroizes the temporary
passphrase buffer. HTTP keeps one root unlocked `Vault` handle and creates
independent request connections by duplicating only the zeroizing DEK; it does
not retain or re-derive from the passphrase. Every DEK copy is dropped and
zeroized with its request/root handle.

## Recommended inherited-descriptor launch

An MCP wrapper should obtain the secret from its local secret mechanism, make
it available on a descriptor numbered 3 or higher, then `exec` the Guardian.
MCP stdin/stdout remain untouched.

Example wrapper shape for zsh/bash on macOS:

```bash
#!/bin/zsh
set -eu
exec 3< <(security find-generic-password -w -s "tessera:work-vault")
exec tessera-guardian \
  --vault "$HOME/Vaults/Work.tessera" \
  --pairing pair_... \
  --passphrase-fd 3
```

Linux secret-service tooling can use the same boundary, for example by
replacing the `security ...` producer with `secret-tool lookup ...`. These are
optional conveniences, not vault-format dependencies. A copied bundle always
remains openable with a passphrase/keyslot alone.
If the external keychain/secret-service lookup is unavailable and produces no
secret, the Guardian rejects the empty/failed descriptor; it never silently
falls back to an environment variable or permanent unlock.

The descriptor is read once. Descriptor 0, 1, and 2 are rejected because they
belong to MCP stdin, MCP stdout, and diagnostics. The Guardian launches no
child process and therefore does not propagate the passphrase to children.
The embedding runtime is loaded in-process.

## Private-file fallback

```bash
umask 077
printf '%s\n' 'vault passphrase' > "$XDG_RUNTIME_DIR/tessera-pass"
tessera-guardian ... --passphrase-file "$XDG_RUNTIME_DIR/tessera-pass"
```

On macOS/Linux the path must be a regular non-symlink file with no group/other
permission bits (`0600` recommended). Delete it after launch. Filesystem
secure-deletion guarantees vary; an inherited pipe/descriptor from a secret
service avoids a persistent plaintext file and is preferred.

## Interactive owner launch

```bash
tessera-guardian ... --prompt-passphrase
```

The prompt reads from the controlling terminal with echo disabled. It does not
consume or write the MCP protocol channel. The owner CLI also uses a no-echo
prompt when `TESSERA_PASSPHRASE` is absent; that environment variable remains
an explicit short-lived CLI automation compatibility path, not a Guardian
startup mechanism.

## Idle and explicit locking

`--idle-lock-seconds` defaults to 900 (15 minutes):

- stdio resets activity for each received MCP message;
- HTTP resets activity only after successful owner-backed authorization/token
  or authenticated MCP activity, so unauthenticated traffic cannot keep the
  vault unlocked;
- expiry causes the Guardian process to exit and drop the DEK;
- clients reconnect by starting/unlocking a new Guardian process. No silent
  background re-unlock occurs.

`tessera guardian lock` revokes active sessions and atomically advances the
vault's durable lock generation. Running stdio and HTTP Guardians poll that
generation at most once per second, reject new HTTP calls immediately after
observing it, exit, and drop their DEKs. A later owner-authorized startup
captures the new generation and opens normally.

## Recovery and rotation

`keyslot.bin` may wrap the same random DEK with multiple passphrases:

```bash
tessera key list
tessera key add
tessera key remove 0 --yes
```

`key add` prompts twice without echo. Before removing an older slot, copy the
complete vault bundle and prove the new/recovery passphrase opens that copy.
The CLI refuses to remove the last slot. Adding/removing a slot does not
re-encrypt blobs; losing every working slot/passphrase makes authenticated
ciphertext unrecoverable. Tessera has no escrow or cloud recovery service.

Passphrase rotation means add a new slot, verify it, then remove the old slot.
DEK rotation/re-encryption is not implemented in v0.1 and must not be implied
by keyslot rotation.

## Threat model and residual risks

Protected:

- passphrase absent from Guardian environment, argv, MCP messages, logs, and
  receipts;
- one-shot bounded secret read with temporary-buffer zeroization;
- no unnecessary child-process inheritance;
- normal exit, idle exit, and explicit lock drop the zeroizing DEK;
- wrong passphrase, insecure secret-file mode, missing descriptor, malformed
  input, and removed keyslot fail closed.

Not protected:

- malware or a debugger with same-user/process-memory access while unlocked;
- kernel compromise, terminal capture, or a compromised local secret service;
- a same-user race against the private-file fallback;
- forensic recovery guarantees for a plaintext passphrase file;
- ciphertext recovery after all keyslots or passphrases are lost.
