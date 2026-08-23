use std::path::Path;
use std::sync::Mutex;

use serde::Serialize;
use tessera_core::artifact::ArtifactState;
use tessera_core::recovery::IntegrityClass;
use tessera_core::session::SessionStatus;
use tessera_core::vault::{ManifestError, VaultError, FORMAT_VERSION};
use tessera_core::Vault;
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopCapabilities {
    pub schema: &'static str,
    pub app_version: &'static str,
    pub owner_commands: [&'static str; 3],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptChainStatus {
    Verified,
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticStatus {
    Healthy,
    Attention,
    Fatal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SanitizedOverview {
    pub schema: &'static str,
    pub state: &'static str,
    pub format_version: u32,
    pub space_count: u64,
    pub pending_review_count: u64,
    pub active_session_count: u64,
    pub receipt_chain: ReceiptChainStatus,
    pub receipt_count: u64,
    pub diagnostic_status: DiagnosticStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LockResult {
    pub schema: &'static str,
    pub state: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerErrorCode {
    InvalidCredentials,
    UnsupportedFormat,
    MigrationRequired,
    InvalidBundle,
    UnsafePath,
    AlreadyUnlocked,
    NativeStateUnavailable,
    InternalFailure,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnerSafeError {
    pub code: OwnerErrorCode,
    pub message: &'static str,
}

#[derive(Default)]
pub struct OwnerState {
    vault: Mutex<Option<Vault>>,
}

impl OwnerState {
    pub fn capabilities(&self) -> DesktopCapabilities {
        DesktopCapabilities {
            schema: "tessera.desktop.capabilities.v1",
            app_version: env!("CARGO_PKG_VERSION"),
            owner_commands: ["desktop_capabilities", "open_vault", "lock_vault"],
        }
    }

    pub fn open(
        &self,
        path: &Path,
        passphrase: String,
    ) -> Result<SanitizedOverview, OwnerSafeError> {
        let passphrase = Zeroizing::new(passphrase);
        let mut state = self
            .vault
            .lock()
            .map_err(|_| OwnerSafeError::native_state_unavailable())?;
        if state.is_some() {
            return Err(OwnerSafeError::already_unlocked());
        }

        let candidate =
            Vault::open(path, passphrase.as_str()).map_err(OwnerSafeError::from_vault)?;
        let overview = sanitized_overview(&candidate)?;
        *state = Some(candidate);
        Ok(overview)
    }

    pub fn lock(&self) -> Result<LockResult, OwnerSafeError> {
        let mut state = self
            .vault
            .lock()
            .map_err(|_| OwnerSafeError::native_state_unavailable())?;
        if let Some(mut vault) = state.take() {
            vault.lock();
        }
        Ok(LockResult {
            schema: "tessera.desktop.lock.v1",
            state: "locked",
        })
    }
}

impl OwnerSafeError {
    fn new(code: OwnerErrorCode, message: &'static str) -> Self {
        Self { code, message }
    }

    fn from_vault(error: VaultError) -> Self {
        match error {
            VaultError::BadPassphrase => Self::new(
                OwnerErrorCode::InvalidCredentials,
                "The vault could not be unlocked. Check the passphrase and try again.",
            ),
            VaultError::MetadataMigrationRequired => Self::new(
                OwnerErrorCode::MigrationRequired,
                "This vault requires an owner-approved migration before the desktop can open it.",
            ),
            VaultError::Manifest(ManifestError::UnsupportedVersion { .. }) => Self::new(
                OwnerErrorCode::UnsupportedFormat,
                "This vault format is not supported by this version of Tessera.",
            ),
            VaultError::Io(ref source) if source.kind() == std::io::ErrorKind::InvalidData => {
                Self::new(
                    OwnerErrorCode::UnsafePath,
                    "The selected bundle contains an unsafe filesystem entry and was refused.",
                )
            }
            VaultError::NotFound(_)
            | VaultError::Manifest(_)
            | VaultError::Database(_)
            | VaultError::Blob(_)
            | VaultError::Crypto(_)
            | VaultError::Io(_)
            | VaultError::KeyslotBindingMismatch => Self::new(
                OwnerErrorCode::InvalidBundle,
                "The selected bundle could not be validated as a current Tessera vault.",
            ),
            VaultError::AlreadyExists(_)
            | VaultError::Locked
            | VaultError::KeyslotStateUnavailable => Self::new(
                OwnerErrorCode::InternalFailure,
                "The desktop could not complete the vault operation. The vault remains locked.",
            ),
        }
    }

    fn already_unlocked() -> Self {
        Self::new(
            OwnerErrorCode::AlreadyUnlocked,
            "Lock the current vault before opening another one.",
        )
    }

    fn native_state_unavailable() -> Self {
        Self::new(
            OwnerErrorCode::NativeStateUnavailable,
            "The native vault state is unavailable. Restart Tessera before trying again.",
        )
    }

    fn internal_failure() -> Self {
        Self::new(
            OwnerErrorCode::InternalFailure,
            "The desktop could not build a safe overview. The vault remains locked.",
        )
    }
}

fn sanitized_overview(vault: &Vault) -> Result<SanitizedOverview, OwnerSafeError> {
    let space_count = tessera_core::space::list(vault)
        .map_err(|_| OwnerSafeError::internal_failure())?
        .len() as u64;
    let pending_review_count = tessera_core::artifact::list_by_state(vault, ArtifactState::Pending)
        .map_err(|_| OwnerSafeError::internal_failure())?
        .len() as u64;
    let active_session_count = tessera_core::session::list(vault)
        .map_err(|_| OwnerSafeError::internal_failure())?
        .into_iter()
        .filter(|session| session.effective_status() == SessionStatus::Active)
        .count() as u64;
    let (receipt_chain, receipt_count) = match tessera_core::receipt::verify(vault) {
        Ok(count) => (ReceiptChainStatus::Verified, count as u64),
        Err(_) => (ReceiptChainStatus::Invalid, 0),
    };
    let diagnostic_status = match tessera_core::recovery::diagnose(vault) {
        Ok(report) if report.has_fatal() => DiagnosticStatus::Fatal,
        Ok(report) if report.is_healthy() => DiagnosticStatus::Healthy,
        Ok(report)
            if report
                .checks
                .iter()
                .any(|check| check.class == IntegrityClass::Repairable) =>
        {
            DiagnosticStatus::Attention
        }
        Ok(_) => DiagnosticStatus::Attention,
        Err(_) => DiagnosticStatus::Fatal,
    };

    Ok(SanitizedOverview {
        schema: "tessera.desktop.overview.v1",
        state: "unlocked",
        format_version: FORMAT_VERSION,
        space_count,
        pending_review_count,
        active_session_count,
        receipt_chain,
        receipt_count,
        diagnostic_status,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::{Arc, Barrier};
    use std::thread;

    use serde_json::Value;
    use tessera_core::artifact::{self, Sensitivity};
    use tessera_core::crypto::KdfParams;
    use tessera_core::lens::{self, LensPolicy};
    use tessera_core::pairing;
    use tessera_core::receipt::{self, AgentRef};
    use tessera_core::session::{self, SessionStatus};
    use tessera_core::space;
    use tessera_core::vault::{VaultManifest, FORMAT_VERSION};

    use super::*;

    const TEST_PARAMS: KdfParams = KdfParams {
        m_cost_kib: 1024,
        t_cost: 1,
        p_cost: 1,
    };
    const PASSPHRASE: &str = "synthetic-desktop-passphrase";

    fn synthetic_vault() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("Synthetic.tessera");
        let vault = Vault::create_with_params(&path, PASSPHRASE, &TEST_PARAMS).expect("create");
        let space = space::create(&vault, "SYNTHETIC-SPACE", None).expect("space");
        artifact::register_encrypted_bytes(
            &vault,
            &space,
            "SYNTHETIC-PENDING.txt",
            "text/plain",
            Sensitivity::Restricted,
            b"SYNTHETIC-CONTENT",
        )
        .expect("pending artifact");
        let policy = LensPolicy::new("SYNTHETIC-LENS", vec![space]);
        let lens_id = lens::create(&vault, &policy).expect("lens");
        let approved =
            pairing::approve(&vault, &lens_id, "synthetic purpose", "synthetic agent", 60)
                .expect("pairing");
        let live = session::start(&vault, &approved).expect("active session");
        assert_eq!(live.effective_status(), SessionStatus::Active);
        receipt::Session::open(
            &vault,
            AgentRef {
                agent_id: "synthetic-agent".into(),
                name: "Synthetic agent".into(),
            },
            &policy,
            "synthetic receipt",
            false,
        )
        .expect("receipt session")
        .finalize()
        .expect("receipt");
        drop(vault);
        (dir, path)
    }

    fn keys(value: &Value) -> BTreeSet<String> {
        value.as_object().expect("object").keys().cloned().collect()
    }

    #[test]
    fn current_format_open_returns_only_the_sanitized_aggregate_contract() {
        let (_dir, path) = synthetic_vault();
        let state = OwnerState::default();
        let overview = state.open(&path, PASSPHRASE.into()).expect("open");

        assert_eq!(overview.format_version, FORMAT_VERSION);
        assert_eq!(overview.space_count, 1);
        assert_eq!(overview.pending_review_count, 1);
        assert_eq!(overview.active_session_count, 1);
        assert_eq!(overview.receipt_chain, ReceiptChainStatus::Verified);
        assert_eq!(overview.receipt_count, 1);

        let serialized = serde_json::to_value(&overview).expect("serialize");
        assert_eq!(
            keys(&serialized),
            [
                "activeSessionCount",
                "diagnosticStatus",
                "formatVersion",
                "pendingReviewCount",
                "receiptChain",
                "receiptCount",
                "schema",
                "spaceCount",
                "state",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect()
        );
        let text = serialized.to_string();
        for forbidden in [
            PASSPHRASE,
            "Synthetic.tessera",
            "SYNTHETIC-SPACE",
            "SYNTHETIC-PENDING",
            "synthetic-agent",
            "rcpt_",
            "blob",
            "hash",
            "sqlite",
        ] {
            assert!(
                !text.contains(forbidden),
                "serialized forbidden value: {forbidden}"
            );
        }
    }

    #[test]
    fn wrong_passphrase_is_bounded_and_leaves_state_locked() {
        let (_dir, path) = synthetic_vault();
        let state = OwnerState::default();
        let error = state
            .open(&path, "WRONG-SECRET-SENTINEL".into())
            .expect_err("refuse");
        assert_eq!(error.code, OwnerErrorCode::InvalidCredentials);
        let serialized = serde_json::to_string(&error).expect("serialize");
        assert!(!serialized.contains("WRONG-SECRET-SENTINEL"));
        assert!(state.lock().is_ok());
    }

    #[test]
    fn plaintext_passphrase_is_absent_from_vault_generated_artifacts() {
        let (_dir, path) = synthetic_vault();
        let needle = PASSPHRASE.as_bytes();
        let mut pending = vec![path];

        while let Some(candidate) = pending.pop() {
            let metadata = std::fs::symlink_metadata(&candidate).expect("artifact metadata");
            if metadata.is_dir() {
                pending.extend(
                    std::fs::read_dir(&candidate)
                        .expect("artifact directory")
                        .map(|entry| entry.expect("artifact entry").path()),
                );
            } else if metadata.is_file() {
                let bytes = std::fs::read(&candidate).expect("artifact bytes");
                assert!(
                    !bytes.windows(needle.len()).any(|window| window == needle),
                    "plaintext passphrase found in a generated vault artifact"
                );
            }
        }
    }

    #[test]
    fn legacy_future_migration_and_malformed_vaults_are_refused() {
        for (version, expected) in [
            (FORMAT_VERSION - 1, OwnerErrorCode::MigrationRequired),
            (FORMAT_VERSION + 1, OwnerErrorCode::UnsupportedFormat),
        ] {
            let (_dir, path) = synthetic_vault();
            let manifest_path = path.join("tessera.json");
            let mut manifest = VaultManifest::load(&manifest_path).expect("manifest");
            manifest.format_version = version;
            std::fs::write(&manifest_path, serde_json::to_vec(&manifest).expect("json"))
                .expect("write manifest");
            let error = OwnerState::default()
                .open(&path, PASSPHRASE.into())
                .expect_err("refuse");
            assert_eq!(error.code, expected);
        }

        let (_dir, path) = synthetic_vault();
        std::fs::write(path.join(".metadata-migration-v3"), b"in-progress").expect("marker");
        let error = OwnerState::default()
            .open(&path, PASSPHRASE.into())
            .expect_err("refuse");
        assert_eq!(error.code, OwnerErrorCode::MigrationRequired);

        let malformed = tempfile::tempdir().expect("malformed");
        std::fs::write(malformed.path().join("tessera.json"), b"not-json").expect("manifest");
        let error = OwnerState::default()
            .open(malformed.path(), PASSPHRASE.into())
            .expect_err("refuse malformed");
        assert_eq!(error.code, OwnerErrorCode::InvalidBundle);

        let (_dir, path) = synthetic_vault();
        let mut keyslot = std::fs::read(path.join("keyslot.bin")).expect("keyslot");
        let last = keyslot.last_mut().expect("keyslot byte");
        *last ^= 0x5a;
        std::fs::write(path.join("keyslot.bin"), keyslot).expect("tamper keyslot");
        let error = OwnerState::default()
            .open(&path, PASSPHRASE.into())
            .expect_err("refuse tamper");
        assert!(matches!(
            error.code,
            OwnerErrorCode::InvalidBundle | OwnerErrorCode::InvalidCredentials
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_bundle_and_component_are_refused() {
        use std::os::unix::fs::symlink;

        let (_dir, path) = synthetic_vault();
        let links = tempfile::tempdir().expect("links");
        let bundle_link = links.path().join("Linked.tessera");
        symlink(&path, &bundle_link).expect("bundle symlink");
        let error = OwnerState::default()
            .open(&bundle_link, PASSPHRASE.into())
            .expect_err("refuse bundle symlink");
        assert_eq!(error.code, OwnerErrorCode::UnsafePath);

        let (_dir, path) = synthetic_vault();
        let manifest = path.join("tessera.json");
        let real_manifest = path.join("manifest.real");
        std::fs::rename(&manifest, &real_manifest).expect("move manifest");
        symlink(&real_manifest, &manifest).expect("component symlink");
        let error = OwnerState::default()
            .open(&path, PASSPHRASE.into())
            .expect_err("refuse");
        assert_eq!(error.code, OwnerErrorCode::UnsafePath);
    }

    #[test]
    fn lock_is_idempotent_and_second_open_preserves_original_state() {
        let (_first_dir, first_path) = synthetic_vault();
        let (_second_dir, second_path) = synthetic_vault();
        let state = OwnerState::default();
        state.open(&first_path, PASSPHRASE.into()).expect("first");
        let error = state
            .open(&second_path, PASSPHRASE.into())
            .expect_err("second refused");
        assert_eq!(error.code, OwnerErrorCode::AlreadyUnlocked);
        assert_eq!(state.lock().expect("lock").state, "locked");
        for _ in 0..100 {
            assert_eq!(state.lock().expect("repeat lock").state, "locked");
        }
        state
            .open(&second_path, PASSPHRASE.into())
            .expect("open after lock");
    }

    #[test]
    fn concurrent_opens_select_exactly_one_authoritative_vault() {
        let (_first_dir, first_path) = synthetic_vault();
        let (_second_dir, second_path) = synthetic_vault();
        let state = Arc::new(OwnerState::default());
        let barrier = Arc::new(Barrier::new(3));
        let handles = [first_path, second_path].map(|path| {
            let state = Arc::clone(&state);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                state.open(&path, PASSPHRASE.into())
            })
        });
        barrier.wait();
        let results = handles.map(|handle| handle.join().expect("thread"));
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(error) if error.code == OwnerErrorCode::AlreadyUnlocked))
                .count(),
            1
        );
        state.lock().expect("lock winner");
    }

    #[test]
    fn concurrent_open_and_lock_end_in_a_defined_recoverable_state() {
        let (_dir, path) = synthetic_vault();
        let state = Arc::new(OwnerState::default());
        let barrier = Arc::new(Barrier::new(3));
        let opening = {
            let state = Arc::clone(&state);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                state.open(&path, PASSPHRASE.into())
            })
        };
        let locking = {
            let state = Arc::clone(&state);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                state.lock()
            })
        };
        barrier.wait();
        assert!(opening.join().expect("open thread").is_ok());
        assert!(locking.join().expect("lock thread").is_ok());
        state.lock().expect("final lock");
    }

    #[test]
    fn dropping_owner_state_releases_the_native_vault() {
        let (_dir, path) = synthetic_vault();
        {
            let state = OwnerState::default();
            state.open(&path, PASSPHRASE.into()).expect("open");
        }
        let reopened = Vault::open(&path, PASSPHRASE).expect("reopen after state drop");
        assert!(!reopened.is_locked());
    }

    #[test]
    fn capabilities_are_static_and_do_not_expose_rust_type_names() {
        let serialized =
            serde_json::to_value(OwnerState::default().capabilities()).expect("serialize");
        assert_eq!(serialized["schema"], "tessera.desktop.capabilities.v1");
        assert_eq!(
            serialized["ownerCommands"],
            serde_json::json!(["desktop_capabilities", "open_vault", "lock_vault"])
        );
        assert!(!serialized.to_string().contains("tessera_core"));
    }

    #[test]
    fn webview_capability_and_production_csp_are_least_privilege() {
        let capability: Value = serde_json::from_str(include_str!("../capabilities/default.json"))
            .expect("capability json");
        assert_eq!(capability["permissions"], serde_json::json!([]));

        let config: Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).expect("tauri config json");
        let production_csp = config["app"]["security"]["csp"]
            .as_str()
            .expect("production csp");
        let development_csp = config["app"]["security"]["devCsp"]
            .as_str()
            .expect("development csp");
        assert!(!production_csp.contains("127.0.0.1"));
        assert!(!production_csp.contains("ws://"));
        assert!(development_csp.contains("http://127.0.0.1:1420"));
        assert!(development_csp.contains("ws://127.0.0.1:1420"));

        let capability_text = capability.to_string();
        for forbidden in [
            "core:default",
            "fs:",
            "shell:",
            "sql:",
            "path:",
            "image:",
            "process:",
        ] {
            assert!(
                !capability_text.contains(forbidden),
                "forbidden permission: {forbidden}"
            );
        }
    }
}
