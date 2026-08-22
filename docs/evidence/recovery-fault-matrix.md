# Recovery fault-injection evidence

Issue #54 requires each recovery boundary to be exercised, not merely described.
This matrix names the automated evidence that runs in the macOS local release
gate and Linux GitHub Actions.

| Required scenario | Automated evidence | Proven boundary |
|---|---|---|
| crash during inbox copy | `inbox::tests::crash_left_partial_copy_is_never_processable` | abandoned `.partial` files are ignored and retained for diagnosis |
| disk full during copy | `inbox::tests::simulated_disk_full_never_exposes_a_partial_staged_file` | no truncated final staging name; owner source remains |
| permission failure | `inbox::tests::staging_permission_failure_preserves_owner_source` | non-zero failure, no staged partial, source unchanged |
| crash during encrypt | `blob::tests::crash_residue_from_encrypt_is_replaced_only_by_authenticated_complete_blob` | unique synced temporary ciphertext; only authenticated final address is readable |
| crash between encrypt/register/version | `inbox::tests::registration_failure_rolls_back_identity_and_keeps_staged_source` | registration/version transaction rolls back; staged source remains; orphan ciphertext is reported |
| extract/chunk failure | `review::tests::processing_errors_block_readiness_until_resolved`, `recovery::tests::corrupted_chunk_is_repairable_and_never_returned_as_content` | item remains pending and corruption is repairable, content-free diagnostic evidence |
| embed interruption/index corruption | `search::tests::reindex_is_resumable_and_preserves_active_index_until_complete`, `index::sqlite_vec::tests::mixed_model_versions_are_refused` | active index survives interruption; mixed spaces fail closed |
| promote interruption | `review::tests::batch_promotion_rolls_back_if_any_item_is_not_pending` | whole batch rolls back |
| receipt finalization crash | `receipt::tests::interrupted_finalization_recovers_only_committed_receipts` | pre-commit residue rolls back; post-commit prepared file recovers deterministically |
| legacy receipt migration interruption | `receipt::tests::interrupted_legacy_migration_recovers_at_every_commit_boundary` | pre-commit restart retains legacy authority; post-commit and post-file restart deterministically complete protected storage |
| protected receipt tampering/insertion/deletion | `receipt::tests::{malformed_and_cryptographically_invalid_containers_are_distinct,missing_middle_receipt_and_keyless_plaintext_regeneration_fail}` | malformed, AEAD-invalid, unindexed inserted, and missing indexed evidence fail closed |
| missing/tampered original | `recovery::tests::missing_authenticated_original_is_fatal_without_fabricated_repair`, `blob::tests::tampered_blob_fails_integrity` | fatal classification; no invented source |
| orphaned blob | `recovery::tests::orphaned_ciphertext_is_reported_and_not_deleted` | repairable evidence retained, never silently deleted |
| missing/duplicate chunks or maps | `recovery::tests::duplicate_chunk_and_embedding_map_rows_are_rejected`, `recovery::tests::corrupted_chunk_is_repairable_and_never_returned_as_content`, and `index::sqlite_vec::tests::delete_removes_from_results_and_len` | duplicates are rejected; missing/corrupt derived rows are detectable/rebuildable |
| stale/missing WAL/SHM | `recovery::tests::backup_restores_same_source_identity_at_new_path` | online backup produces no copied sidecars and reopens/query-verifies independently |
| partial bundle copy | `recovery::tests::partial_bundle_fails_loudly` | missing keyslot prevents open rather than yielding a partial vault |
| backup while Guardian active | `recovery::tests::backup_refuses_an_active_guardian_session` | active sessions fail loudly; idle writer barrier remains supported |
| restore new path/host | `recovery::tests::backup_restores_same_source_identity_at_new_path` | source id/hash, semantic query, and receipt-chain continuity survive path change |
| migration interruption | `db::tests::interrupted_migration_transaction_leaves_no_schema_or_ledger_fragment` | schema and migration ledger roll back together |
| model corruption | `embed::onnx::tests::substituted_model_files_fail_verification_before_load`, CLI model-install rollback test | corrupt weights/tokenizer never activate or load |
| derived rebuild | `recovery::tests::owner_derived_rebuild_preserves_source_identity_and_returns_live_items_to_pending` | source identity and receipts remain; rebuilt items require owner review/reindex |

The matrix does not claim physical power-cut coverage for every filesystem or
storage controller. It does prove Tessera's application-level transaction,
temporary-file, authentication, and fail-closed boundaries on both supported
runtime families.
