# Quickstart: Validate Metadata Privacy

## Safety boundary

Use only disposable synthetic vaults. Do not point the scanner, migration
fault fixtures, or evidence commands at Ezra's private corpus.

## Specification and prerequisites

```bash
python3 .specify/scripts/python/check_prerequisites.py --json
python3 .specify/scripts/python/check_prerequisites.py --json --require-tasks --include-tasks
```

## Targeted validation

```bash
cargo test -p tessera-core db::tests -- --nocapture
cargo test -p tessera-core blob::tests -- --nocapture
cargo test -p tessera-core vault::metadata::tests -- --nocapture
cargo test -p tessera-core --test metadata_privacy -- --nocapture
cargo test -p tessera-core recovery::tests -- --nocapture
cargo test -p tessera-core --test metadata_portability -- --nocapture
cargo test -p tessera-cli metadata_migration -- --nocapture
cargo test -p tessera-core legacy_migration_performance_measurement -- --ignored --nocapture
cargo test -p tessera-core --test metadata_performance -- --ignored --nocapture
```

## Full local gate

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo build --workspace --all-targets
cargo test --workspace --all-targets
cargo test --workspace -- --ignored --nocapture
git diff --check
```

Record exact counts and controlled performance results from the final commit.
If repeated timings vary materially, rerun under the same fixture and report
the range rather than selecting the fastest run.

## Migration operator boundary

The final CLI syntax and recovery messages are defined by implementation and
must satisfy `contracts/migration-state-v1.md`. Migration is explicit,
owner-confirmed, refuses active Guardian sessions, and is run only after a
verified offline copy. Interrupted runs are resumed with the same command.

## Completion boundary

Completion additionally requires an independent security and acceptance review
of the exact final commit, a focused draft pull request closing issue #50, an
issue comment linking evidence, local and remote commit equality, and green
macOS and Ubuntu CI for that exact head. Merging and issue closure remain with
Ezra.
