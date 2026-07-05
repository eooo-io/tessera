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
