//! End-to-end CLI tests. Use the insecure-test KDF profile so Argon2id
//! doesn't dominate test time; the profile is explicitly named as unsafe.

use assert_cmd::Command;
use predicates::prelude::*;

fn tessera(vault: &std::path::Path) -> Command {
    let mut cmd = Command::cargo_bin("tessera").expect("binary");
    cmd.env("TESSERA_VAULT", vault)
        .env("TESSERA_PASSPHRASE", "test-passphrase")
        .env("TESSERA_KDF_PROFILE", "insecure-test");
    cmd
}

#[test]
fn init_creates_vault_bundle() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = dir.path().join("V.tessera");

    tessera(&vault)
        .args(["init"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Vault created"));

    assert!(vault.join("tessera.json").is_file());
    assert!(vault.join("keyslot.bin").is_file());
    assert!(vault.join("vault.db").is_file());
    assert!(vault.join("inbox").is_dir());
}

#[test]
fn init_refuses_existing_vault() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = dir.path().join("V.tessera");

    tessera(&vault).args(["init"]).assert().success();
    tessera(&vault)
        .args(["init"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn keyslot_listing_and_removal_guard_are_owner_visible() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = dir.path().join("V.tessera");
    tessera(&vault).args(["init"]).assert().success();
    tessera(&vault)
        .args(["key", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("1 keyslot").and(predicate::str::contains("0")));
    tessera(&vault)
        .args(["key", "remove", "0"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("re-run with --yes"));
    tessera(&vault)
        .args(["key", "remove", "0", "--yes"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("last keyslot"));
}

#[test]
fn space_create_list_and_tree() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = dir.path().join("V.tessera");
    tessera(&vault).args(["init"]).assert().success();

    let out = tessera(&vault)
        .args(["space", "create", "Clients"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8(out).expect("utf8");
    let parent_id = stdout
        .split_whitespace()
        .find(|w| w.starts_with("space_"))
        .expect("space id in output")
        .to_string();

    tessera(&vault)
        .args(["space", "create", "ClientA", "--parent", &parent_id])
        .assert()
        .success();

    tessera(&vault)
        .args(["space", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Clients").and(predicate::str::contains("ClientA")));

    // Tree renders the child indented under its parent.
    tessera(&vault)
        .args(["space", "tree"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Clients\n  ClientA"));
}

#[test]
fn conversation_run_cli_reports_actionable_per_item_results() {
    struct Parser {
        conversation: tessera_core::conversation::Conversation,
        fail: bool,
    }
    impl tessera_core::conversation::ConversationSourceParser for Parser {
        fn source_product(&self) -> tessera_core::conversation::SourceProduct {
            tessera_core::conversation::SourceProduct::Chatgpt
        }

        fn parser(&self) -> tessera_core::conversation::ComponentVersion {
            tessera_core::conversation::ComponentVersion {
                name: "cli-test".into(),
                version: "1".into(),
            }
        }

        fn normalizer(&self) -> tessera_core::conversation::ComponentVersion {
            tessera_core::conversation::ComponentVersion {
                name: "tessera-conversation".into(),
                version: "1".into(),
            }
        }

        fn parse(
            &self,
            _source: &[u8],
        ) -> Result<
            Vec<tessera_core::conversation::ConversationCandidate>,
            tessera_core::conversation::IngestionIssue,
        > {
            if self.fail {
                return Err(tessera_core::conversation::IngestionIssue::ParserFailure);
            }
            Ok(vec![
                tessera_core::conversation::ConversationCandidate::conversation(
                    self.conversation.clone(),
                ),
                tessera_core::conversation::ConversationCandidate::quarantined(
                    "conv_cli_bad",
                    tessera_core::conversation::IngestionIssue::ChangedFieldType,
                ),
            ])
        }
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = dir.path().join("V.tessera");
    tessera(&vault_path).args(["init"]).assert().success();
    let vault = tessera_core::Vault::open(&vault_path, "test-passphrase").expect("open");
    let space = tessera_core::space::create(&vault, "Conversation CLI", None).expect("space");
    let source = dir.path().join("source.json");
    std::fs::write(&source, b"synthetic source").expect("source");
    tessera_core::inbox::add(&vault, &[source]).expect("stage");
    let intake = tessera_core::inbox::process(&vault, &space).expect("intake");
    let review =
        tessera_core::review::inspect(&vault, &intake.ingested[0].1, 10).expect("source version");
    let archive = tessera_core::conversation::ConversationArchive::from_json(include_str!(
        "../../../tests/fixtures/conversation-tree.json"
    ))
    .expect("fixture");
    let report = tessera_core::conversation::ingest(
        &vault,
        &space,
        &review.artifact_version_id,
        &Parser {
            conversation: archive.conversations[0].clone(),
            fail: false,
        },
        &tessera_core::conversation::IngestionOptions::default(),
    )
    .expect("ingest");
    drop(vault);

    tessera(&vault_path)
        .args(["conversation", "runs"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains(&report.id)
                .and(predicate::str::contains("imported=1"))
                .and(predicate::str::contains("quarantined=1")),
        );
    tessera(&vault_path)
        .args(["conversation", "show", &report.id])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("conv_cli_bad")
                .and(predicate::str::contains("changed_field_type"))
                .and(predicate::str::contains(
                    "action: inspect the source structure and target classification",
                ))
                .and(predicate::str::contains("start a new run")),
        );
    tessera(&vault_path)
        .args(["conversation", "show", &report.id, "--json"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("\"status\": \"completed\"")
                .and(predicate::str::contains("\"safe_error_summary\"")),
        );

    let vault = tessera_core::Vault::open(&vault_path, "test-passphrase").expect("reopen");
    let failed = tessera_core::conversation::ingest(
        &vault,
        &space,
        &review.artifact_version_id,
        &Parser {
            conversation: archive.conversations[0].clone(),
            fail: true,
        },
        &tessera_core::conversation::IngestionOptions::default(),
    )
    .expect("failed report");
    drop(vault);
    tessera(&vault_path)
        .args(["conversation", "show", &failed.id])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("correct or upgrade the source adapter")
                .and(predicate::str::contains("start a new run"))
                .and(predicate::str::contains("resume run").not())
                .and(predicate::str::contains("synthetic source").not()),
        );
}

#[test]
fn inbox_add_status_process_lifecycle() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = dir.path().join("V.tessera");
    tessera(&vault).args(["init"]).assert().success();
    tessera(&vault)
        .args(["space", "create", "Docs"])
        .assert()
        .success();

    let file = dir.path().join("note.md");
    std::fs::write(&file, "A note sentence. Another sentence.").expect("write");

    tessera(&vault)
        .args(["inbox", "add"])
        .arg(&file)
        .assert()
        .success()
        .stdout(predicate::str::contains("Staged"));

    tessera(&vault)
        .args(["inbox", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("note.md"));

    tessera(&vault)
        .args(["inbox", "process"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Ingested").and(predicate::str::contains("art_")));

    tessera(&vault)
        .args(["inbox", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("empty"));
}

#[test]
fn review_accept_all_takes_artifacts_live() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = dir.path().join("V.tessera");
    tessera(&vault).args(["init"]).assert().success();
    tessera(&vault)
        .args(["space", "create", "Docs"])
        .assert()
        .success();

    let file = dir.path().join("a.txt");
    std::fs::write(&file, "Pending body.").expect("write");
    tessera(&vault)
        .args(["inbox", "add"])
        .arg(&file)
        .assert()
        .success();
    tessera(&vault)
        .args(["inbox", "process"])
        .assert()
        .success();

    tessera(&vault)
        .args(["review"])
        .write_stdin("q\n")
        .assert()
        .success()
        .stdout(
            predicate::str::contains("a.txt")
                .and(predicate::str::contains("Pending body"))
                .and(predicate::str::contains("original: encrypted=true"))
                .and(predicate::str::contains("provenance:")),
        );

    // The flag alone displays the batch but does not silently promote it.
    tessera(&vault)
        .args(["review", "--accept-all"])
        .assert()
        .success()
        .stdout(predicate::str::contains("batch cancelled"));

    tessera(&vault)
        .args(["review", "--accept-all"])
        .write_stdin("PROMOTE 1\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("1 artifact"));

    tessera(&vault)
        .args(["review", "--accept-all"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No pending artifacts"));
}

#[test]
fn review_edit_accept_updates_classification_and_audit_actor() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = dir.path().join("V.tessera");
    tessera(&vault_path).args(["init"]).assert().success();
    tessera(&vault_path)
        .args(["space", "create", "Inbox"])
        .assert()
        .success();
    let target_output = tessera(&vault_path)
        .args(["space", "create", "Reviewed"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let target_space = String::from_utf8(target_output)
        .expect("utf8")
        .split_whitespace()
        .find(|part| part.starts_with("space_"))
        .expect("space id")
        .to_owned();

    let file = dir.path().join("edit.txt");
    std::fs::write(&file, "Review and classify this exact content.").expect("write");
    tessera(&vault_path)
        .args(["inbox", "add"])
        .arg(&file)
        .assert()
        .success();
    // Two spaces exist, so choose the initial Inbox id explicitly.
    let vault = tessera_core::Vault::open(&vault_path, "test-passphrase").expect("open");
    let inbox_space = tessera_core::space::list(&vault)
        .expect("spaces")
        .into_iter()
        .find(|space| space.name == "Inbox")
        .expect("inbox space")
        .id
        .0;
    drop(vault);
    tessera(&vault_path)
        .args(["inbox", "process", "--space", &inbox_space])
        .assert()
        .success();

    tessera(&vault_path)
        .args(["review"])
        .write_stdin(format!("e\n{target_space}\nalpha,beta\nrestricted\n"))
        .assert()
        .success()
        .stdout(predicate::str::contains("classification updated"));

    let vault = tessera_core::Vault::open(&vault_path, "test-passphrase").expect("reopen");
    let artifact =
        tessera_core::artifact::list_by_state(&vault, tessera_core::artifact::ArtifactState::Live)
            .expect("live")
            .into_iter()
            .next()
            .expect("artifact");
    assert_eq!(artifact.space_id.0, target_space);
    assert_eq!(artifact.sensitivity, tessera_core::Sensitivity::Restricted);
    assert_eq!(
        tessera_core::artifact::tags_of(&vault, &artifact.id).expect("tags"),
        vec!["alpha".to_string(), "beta".to_string()]
    );
    assert_eq!(
        tessera_core::artifact::latest_transition_actor(&vault, &artifact.id)
            .expect("actor")
            .as_deref(),
        Some("owner:review_edit_accept")
    );
}

#[test]
fn review_batch_refuses_incomplete_without_explicit_override() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = dir.path().join("V.tessera");
    tessera(&vault).args(["init"]).assert().success();
    tessera(&vault)
        .args(["space", "create", "Docs"])
        .assert()
        .success();
    let file = dir.path().join("empty.txt");
    std::fs::write(&file, "").expect("write");
    tessera(&vault)
        .args(["inbox", "add"])
        .arg(&file)
        .assert()
        .success();
    tessera(&vault)
        .args(["inbox", "process"])
        .assert()
        .success();

    tessera(&vault)
        .args(["review", "--accept-all", "--yes"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("refusing bulk promotion"));
    tessera(&vault)
        .args(["review", "--accept-all", "--yes", "--allow-incomplete"])
        .assert()
        .success()
        .stdout(predicate::str::contains("1 artifact(s) → live"));
}

#[test]
fn review_long_preview_retry_skip_and_archive_lifecycle() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = dir.path().join("V.tessera");
    tessera(&vault).args(["init"]).assert().success();
    tessera(&vault)
        .args(["space", "create", "Docs"])
        .assert()
        .success();
    let file = dir.path().join("lifecycle.txt");
    std::fs::write(
        &file,
        "A long owner-only preview stays in memory. Retry is idempotent and skip keeps quarantine.",
    )
    .expect("write");
    tessera(&vault)
        .args(["inbox", "add"])
        .arg(&file)
        .assert()
        .success();
    tessera(&vault)
        .args(["inbox", "process"])
        .assert()
        .success();

    tessera(&vault)
        .args(["review"])
        .write_stdin("p\nr\n\n")
        .assert()
        .success()
        .stdout(
            predicate::str::contains("owner preview")
                .and(predicate::str::contains("processing retry completed"))
                .and(predicate::str::contains("skipped")),
        );
    // Skip preserved pending state, so a second review can archive it.
    tessera(&vault)
        .args(["review"])
        .write_stdin("x\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("archived"));
    let vault = tessera_core::Vault::open(&vault, "test-passphrase").expect("open");
    assert_eq!(
        tessera_core::artifact::list_by_state(
            &vault,
            tessera_core::artifact::ArtifactState::Archived,
        )
        .expect("archived")
        .len(),
        1
    );
}

#[test]
fn review_interactive_single_accept() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = dir.path().join("V.tessera");
    tessera(&vault).args(["init"]).assert().success();
    tessera(&vault)
        .args(["space", "create", "Docs"])
        .assert()
        .success();

    let file = dir.path().join("b.txt");
    std::fs::write(&file, "Interactive body.").expect("write");
    tessera(&vault)
        .args(["inbox", "add"])
        .arg(&file)
        .assert()
        .success();
    tessera(&vault)
        .args(["inbox", "process"])
        .assert()
        .success();

    // 'a' accepts the one pending artifact.
    tessera(&vault)
        .args(["review"])
        .write_stdin("a\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("live"));

    tessera(&vault)
        .args(["review", "--accept-all"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No pending artifacts"));
}

#[test]
fn import_accept_is_one_shot_live() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = dir.path().join("V.tessera");
    tessera(&vault).args(["init"]).assert().success();
    tessera(&vault)
        .args(["space", "create", "Docs"])
        .assert()
        .success();

    let file = dir.path().join("trusted.md");
    std::fs::write(&file, "Pre-trusted content.").expect("write");

    tessera(&vault)
        .args(["import", "--accept"])
        .arg(&file)
        .assert()
        .success()
        .stdout(predicate::str::contains("live"));

    tessera(&vault)
        .args(["review", "--accept-all"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No pending artifacts"));
}

#[test]
fn lens_create_list_show_edit_delete_lifecycle() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = dir.path().join("V.tessera");
    tessera(&vault).args(["init"]).assert().success();

    // Interactive create: answers piped in prompt order. Disclosure "excerpt"
    // triggers the extra max-quote-chars prompt.
    let answers = "Client specs\nspace_A\nexcerpt\n800\nanswer,cite\n\
                   confidential\non_sensitive\n60\ntext/markdown\nspec\npersonal\n";
    let out = tessera(&vault)
        .args(["lens", "create"])
        .write_stdin(answers)
        .assert()
        .success()
        .stdout(predicate::str::contains("Created lens"))
        .get_output()
        .stdout
        .clone();
    let lens_id = String::from_utf8(out)
        .expect("utf8")
        .split_whitespace()
        .find(|w| w.starts_with("lens_"))
        .expect("lens id in output")
        .to_string();

    tessera(&vault)
        .args(["lens", "list"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("Client specs").and(predicate::str::contains("[excerpt]")),
        );

    // `show` emits valid JSON carrying the media_types field.
    let shown = tessera(&vault)
        .args(["lens", "show", &lens_id])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let shown = String::from_utf8(shown).expect("utf8");
    assert!(
        shown.contains("\"media_types\""),
        "media_types present: {shown}"
    );
    assert!(shown.contains("text/markdown"));

    // Edit via --file: rename and widen disclosure to full.
    let edited = shown
        .replace("Client specs", "Renamed")
        .replace("\"excerpt\"", "\"full\"");
    let edit_path = dir.path().join("edit.json");
    std::fs::write(&edit_path, &edited).expect("write");
    tessera(&vault)
        .args(["lens", "edit", &lens_id])
        .arg("--file")
        .arg(&edit_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("Updated lens"));
    tessera(&vault)
        .args(["lens", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Renamed").and(predicate::str::contains("[full]")));

    tessera(&vault)
        .args(["lens", "delete", &lens_id])
        .assert()
        .success()
        .stdout(predicate::str::contains("Deleted lens"));
    tessera(&vault)
        .args(["lens", "show", &lens_id])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn lens_edit_rejects_invalid_policy_with_field_errors() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = dir.path().join("V.tessera");
    tessera(&vault).args(["init"]).assert().success();

    // Summary disclosure skips the max-quote-chars prompt (10 answers).
    let answers = "L\nspace_A\nsummary\nanswer\ninternal\non_sensitive\n60\n\n\n\n";
    let out = tessera(&vault)
        .args(["lens", "create"])
        .write_stdin(answers)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let lens_id = String::from_utf8(out)
        .expect("utf8")
        .split_whitespace()
        .find(|w| w.starts_with("lens_"))
        .expect("lens id")
        .to_string();

    // An empty operations array violates the schema's minItems:1.
    let bad = format!(
        r#"{{"id":"{lens_id}","name":"L","space_ids":["space_A"],"disclosure_mode":"summary","operations":[]}}"#
    );
    let bad_path = dir.path().join("bad.json");
    std::fs::write(&bad_path, bad).expect("write");
    tessera(&vault)
        .args(["lens", "edit", &lens_id])
        .arg("--file")
        .arg(&bad_path)
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("policy rejected").and(predicate::str::contains("operations")),
        );
}

#[test]
fn wrong_passphrase_fails_cleanly() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = dir.path().join("V.tessera");
    tessera(&vault).args(["init"]).assert().success();

    let mut cmd = Command::cargo_bin("tessera").expect("binary");
    cmd.env("TESSERA_VAULT", &vault)
        .env("TESSERA_PASSPHRASE", "wrong")
        .args(["space", "list"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("incorrect passphrase"));
}

#[test]
fn integrity_backup_restore_and_repair_confirmation_are_owner_visible() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = dir.path().join("V.tessera");
    let backup = dir.path().join("Backup.tessera");
    tessera(&vault).args(["init"]).assert().success();

    let diagnostic = tessera(&vault)
        .args(["diag", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: serde_json::Value = serde_json::from_slice(&diagnostic).expect("diagnostic JSON");
    assert_eq!(report["schema"], "tessera.integrity-report.v1");
    assert!(!String::from_utf8(diagnostic)
        .unwrap()
        .contains("test-passphrase"));

    tessera(&vault)
        .arg("backup")
        .arg(&backup)
        .assert()
        .success()
        .stdout(predicate::str::contains("Backup verified"));
    tessera(&backup)
        .args(["diag", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("tessera.integrity-report.v1"));
    tessera(&vault)
        .arg("backup")
        .arg(&backup)
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));

    tessera(&vault)
        .args(["repair-derived"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("without --yes"));
    tessera(&vault)
        .args(["repair-derived", "--yes"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Derived rebuild complete"));
}
