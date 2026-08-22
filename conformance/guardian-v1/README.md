# Guardian v1 conformance kit

This portable fixture set targets `tessera.guardian.v1`. It contains no
private vault data and does not claim that v0.2.0 is released. Release evidence
remains gated by issues #44 and #56.

It includes golden discovery, negotiation-failure, empty-result, and hostile
content results; synthetic source fixtures; and Python-standard-library
reference clients for stdio and Streamable HTTP. `receipts/chain.json` is a
synthetic two-session logical receipt export. Its deterministic 64-character
tokens exercise schema shape and linkage only; real format-v2 chain tokens are
keyed and can be authenticated only with the unlocked vault. The sessions
finalize in reverse start order to prove chain order is finalization order, not
session creation order. `golden/concurrent-sessions.json` records the
corresponding consumer-visible isolation invariants.

```sh
cargo test -p tessera-guardian --test consumer_contract
python3 conformance/guardian-v1/clients/stdio_client.py --help
python3 conformance/guardian-v1/clients/http_client.py --help
```

The clients perform only initialize, `ping`, and `tools/list`. Creating an
owner-approved pairing, choosing a lens, and obtaining an OAuth token remain
explicit setup steps; the kit does not bypass them.

Real receipt tokens prove owner-keyed local authenticity and chain linkage only
when verified inside the unlocked vault. The exported fixture cannot provide
that proof. Neither form is an external signature, authenticates the vault
owner to a third party, or can revoke bytes already disclosed.
