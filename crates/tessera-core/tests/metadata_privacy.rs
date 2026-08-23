//! Locked-vault black-box confidentiality and permission checks for issue #50.

use std::path::{Path, PathBuf};

use tessera_core::crypto::KdfParams;
use tessera_core::{artifact, lens, receipt, space, LensPolicy, Vault};

const TEST_PARAMS: KdfParams = KdfParams {
    m_cost_kib: 1024,
    t_cost: 1,
    p_cost: 1,
};

fn files_under(root: &Path) -> Vec<PathBuf> {
    fn collect(path: &Path, files: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(path).expect("read directory") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                collect(&path, files);
            } else {
                files.push(path);
            }
        }
    }
    let mut files = Vec::new();
    collect(root, &mut files);
    files.sort();
    files
}

fn locked_path_class(relative: &Path, is_dir: bool) -> Option<&'static str> {
    let parts = relative
        .components()
        .map(|part| part.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    match parts.as_slice() {
        [name] if is_dir && matches!(name.as_str(), "blobs" | "receipts" | "inbox") => {
            Some("stable-directory")
        }
        [name]
            if !is_dir
                && matches!(
                    name.as_str(),
                    "tessera.json" | "keyslot.bin" | "vault.db" | "vault.db-wal" | "vault.db-shm"
                ) =>
        {
            Some("stable-file")
        }
        [root, shard]
            if is_dir
                && root == "blobs"
                && shard.len() == 2
                && shard.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
        {
            Some("blob-shard")
        }
        [root, shard, address]
            if !is_dir
                && root == "blobs"
                && shard.len() == 2
                && shard.bytes().all(|byte| byte.is_ascii_hexdigit())
                && address.len() == 64
                && address.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
        {
            Some("opaque-blob")
        }
        [root, receipt]
            if !is_dir
                && root == "receipts"
                && receipt.starts_with("rcpt_")
                && receipt.ends_with(".trc") =>
        {
            Some("opaque-receipt-with-ulid-time")
        }
        _ => None,
    }
}

fn assert_documented_locked_path_inventory(root: &Path) {
    fn visit(root: &Path, path: &Path, classes: &mut Vec<&'static str>) {
        for entry in std::fs::read_dir(path).expect("read locked path inventory") {
            let entry = entry.expect("locked path entry");
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path).expect("locked path metadata");
            let relative = path.strip_prefix(root).expect("relative locked path");
            let class = locked_path_class(relative, metadata.is_dir()).unwrap_or_else(|| {
                panic!("undocumented locked-visible path: {}", relative.display())
            });
            classes.push(class);
            if metadata.is_dir() {
                visit(root, &path, classes);
            } else {
                assert!(
                    metadata.len() > 0,
                    "empty durable file: {}",
                    relative.display()
                );
            }
        }
    }
    let mut classes = Vec::new();
    visit(root, root, &mut classes);
    for required in [
        "stable-directory",
        "stable-file",
        "blob-shard",
        "opaque-blob",
        "opaque-receipt-with-ulid-time",
    ] {
        assert!(classes.contains(&required), "missing path class {required}");
    }
}

fn assert_absent_from_locked_bundle(root: &Path, sentinel: &str) {
    for file in files_under(root) {
        assert!(
            !file
                .strip_prefix(root)
                .expect("relative")
                .to_string_lossy()
                .contains(sentinel),
            "sentinel leaked through path {}",
            file.display()
        );
        let bytes = std::fs::read(&file).expect("read bundle file");
        assert!(
            !bytes
                .windows(sentinel.len())
                .any(|window| window == sentinel.as_bytes()),
            "sentinel leaked through bytes in {}",
            file.display()
        );
    }
}

#[test]
fn synthetic_metadata_inventory_and_confirmation_guesses_are_absent_when_locked() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("Privacy.tessera");
    let sentinels = [
        "PRIVATE-SPACE-SENTINEL-ISSUE50",
        "PRIVATE-FILENAME-SENTINEL-ISSUE50.md",
        "PRIVATE-TAG-SENTINEL-ISSUE50",
        "PRIVATE-LENS-SENTINEL-ISSUE50",
        "PRIVATE-PURPOSE-SENTINEL-ISSUE50",
        "PRIVATE-AGENT-SENTINEL-ISSUE50",
        "PRIVATE-CONTENT-SENTINEL-ISSUE50",
    ];

    let vault =
        Vault::create_with_params(&path, "privacy-passphrase", &TEST_PARAMS).expect("create vault");
    let space = space::create(&vault, sentinels[0], None).expect("space");
    let (artifact_id, version) = artifact::register_encrypted_bytes(
        &vault,
        &space,
        sentinels[1],
        "text/markdown",
        artifact::Sensitivity::Restricted,
        sentinels[6].as_bytes(),
    )
    .expect("artifact");
    artifact::register_encrypted_bytes(
        &vault,
        &space,
        "known-present-candidate.md",
        "text/markdown",
        artifact::Sensitivity::Restricted,
        b"candidate-document-042",
    )
    .expect("known-present confirmation candidate");
    artifact::tag(&vault, &artifact_id, sentinels[2]).expect("tag");
    let policy = LensPolicy::new(sentinels[3], vec![space]);
    lens::create(&vault, &policy).expect("lens");
    receipt::Session::open(
        &vault,
        receipt::AgentRef {
            agent_id: "synthetic-agent-id".into(),
            name: sentinels[5].into(),
        },
        &policy,
        sentinels[4],
        false,
    )
    .expect("receipt session")
    .finalize()
    .expect("receipt finalize");
    let backup = directory.path().join("PrivacyBackup.tessera");
    tessera_core::recovery::backup(&vault, &backup).expect("protected backup");
    drop(vault);

    for root in [&path, &backup] {
        for sentinel in sentinels {
            assert_absent_from_locked_bundle(root, sentinel);
        }
        assert_absent_from_locked_bundle(root, &version.blob_hash);

        for candidate in 0..100 {
            let guess = format!("candidate-document-{candidate:03}");
            let public_hash = blake3::hash(guess.as_bytes()).to_hex().to_string();
            assert_absent_from_locked_bundle(root, &public_hash);
        }
    }
}

#[test]
fn locked_visible_paths_match_the_documented_structural_allowlist() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("PathInventory.tessera");
    let vault =
        Vault::create_with_params(&path, "privacy-passphrase", &TEST_PARAMS).expect("create vault");
    let space = space::create(&vault, "synthetic path inventory", None).expect("space");
    artifact::register_encrypted_bytes(
        &vault,
        &space,
        "synthetic.md",
        "text/markdown",
        artifact::Sensitivity::Internal,
        b"synthetic path inventory content",
    )
    .expect("artifact");
    let policy = LensPolicy::new("path inventory", vec![space]);
    receipt::Session::open(
        &vault,
        receipt::AgentRef {
            agent_id: "synthetic-path-agent".into(),
            name: "Synthetic path agent".into(),
        },
        &policy,
        "path inventory",
        false,
    )
    .expect("receipt session")
    .finalize()
    .expect("receipt");
    let backup = directory.path().join("PathInventoryBackup.tessera");
    tessera_core::recovery::backup(&vault, &backup).expect("protected backup");
    drop(vault);

    assert_documented_locked_path_inventory(&path);
    assert_documented_locked_path_inventory(&backup);
}

#[test]
fn intentional_inbox_plaintext_is_the_only_allowed_sentinel_exposure() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("InboxBoundary.tessera");
    let vault =
        Vault::create_with_params(&path, "privacy-passphrase", &TEST_PARAMS).expect("create vault");
    let sentinel = "INTENTIONAL-INBOX-PLAINTEXT-SENTINEL-ISSUE50";
    let source = directory.path().join("owner-source.md");
    std::fs::write(&source, sentinel).expect("source");
    let staged = tessera_core::inbox::add(&vault, &[source]).expect("stage");
    drop(vault);

    let matching_files = files_under(&path)
        .into_iter()
        .filter(|file| {
            let bytes = std::fs::read(file).expect("read bundle file");
            bytes
                .windows(sentinel.len())
                .any(|window| window == sentinel.as_bytes())
        })
        .collect::<Vec<_>>();
    assert_eq!(matching_files, staged);
    assert!(matching_files[0].starts_with(path.join("inbox")));
}

#[cfg(unix)]
#[test]
fn bundle_directories_and_files_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("Permissions.tessera");
    let vault =
        Vault::create_with_params(&path, "privacy-passphrase", &TEST_PARAMS).expect("create vault");
    let space = space::create(&vault, "permissions", None).expect("space");
    artifact::register_encrypted_bytes(
        &vault,
        &space,
        "permissions.md",
        "text/markdown",
        artifact::Sensitivity::Restricted,
        b"permission protected content",
    )
    .expect("artifact");
    drop(vault);

    fn check(path: &Path) {
        for entry in std::fs::read_dir(path).expect("read directory") {
            let path = entry.expect("entry").path();
            let mode = std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o077,
                0,
                "non-owner permissions on {}",
                path.display()
            );
            if path.is_dir() {
                check(&path);
            }
        }
    }
    let root_mode = std::fs::metadata(&path)
        .expect("root metadata")
        .permissions()
        .mode();
    assert_eq!(root_mode & 0o077, 0);
    check(&path);
}
