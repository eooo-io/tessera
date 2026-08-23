//! Vault initialization, open, lock/unlock.

pub mod manifest;
pub(crate) mod metadata;
pub(crate) mod permissions;

pub use manifest::{
    CryptoParams, EmbeddingModelEntry, ManifestError, VaultManifest, FORMAT_VERSION,
};
pub use metadata::{MetadataMigrationError, MetadataMigrationReport};

use std::path::{Path, PathBuf};

use rusqlite::Connection;
use thiserror::Error;

use crate::blob::{BlobError, BlobStore};
use crate::crypto::{CryptoError, Dek, KdfParams, KeyslotFile};
use crate::db::DbError;

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("vault already exists at {0}")]
    AlreadyExists(PathBuf),
    #[error("vault not found at {0}")]
    NotFound(PathBuf),
    #[error("incorrect passphrase")]
    BadPassphrase,
    #[error("vault is locked")]
    Locked,
    #[error("vault metadata migration is required; run `tessera metadata migrate --yes`")]
    MetadataMigrationRequired,
    #[error("manifest error: {0}")]
    Manifest(#[from] ManifestError),
    #[error("database error: {0}")]
    Database(#[from] DbError),
    #[error("blob store error: {0}")]
    Blob(#[from] BlobError),
    #[error("crypto error: {0}")]
    Crypto(CryptoError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<CryptoError> for VaultError {
    fn from(e: CryptoError) -> Self {
        match e {
            CryptoError::BadPassphrase => VaultError::BadPassphrase,
            other => VaultError::Crypto(other),
        }
    }
}

/// Handle to an open vault bundle. Content access requires an unlocked DEK;
/// `lock()` discards it (zeroized on drop).
pub struct Vault {
    path: PathBuf,
    manifest: VaultManifest,
    conn: Connection,
    blobs: BlobStore,
    dek: Option<Dek>,
}

impl Vault {
    /// Create a new vault at `path` with production KDF parameters.
    pub fn create(path: &Path, passphrase: &str) -> Result<Self, VaultError> {
        Self::create_with_params(path, passphrase, &KdfParams::DEFAULT)
    }

    /// Create a new vault with explicit KDF parameters (tests, tuning).
    pub fn create_with_params(
        path: &Path,
        passphrase: &str,
        params: &KdfParams,
    ) -> Result<Self, VaultError> {
        if path.join("tessera.json").exists() {
            return Err(VaultError::AlreadyExists(path.to_path_buf()));
        }
        permissions::directory(path)?;
        for dir in ["receipts", "inbox"] {
            permissions::directory(&path.join(dir))?;
        }

        let (keyslots, dek) = KeyslotFile::create(passphrase, params)?;
        keyslots.save(&path.join("keyslot.bin"))?;

        let mut manifest = VaultManifest::new(chrono::Utc::now());
        manifest.crypto.kdf_m_cost_kib = params.m_cost_kib;
        manifest.crypto.kdf_t_cost = params.t_cost;
        manifest.crypto.kdf_p_cost = params.p_cost;
        manifest.save(&path.join("tessera.json"))?;

        let conn = crate::db::open_database(&path.join("vault.db"), &dek)?;
        permissions::file(&path.join("vault.db"))?;
        metadata::initialize_from_manifest(&conn, &manifest)?;
        let blobs = BlobStore::open(&path.join("blobs"))?;

        Ok(Self {
            path: path.to_path_buf(),
            manifest,
            conn,
            blobs,
            dek: Some(dek),
        })
    }

    /// Open and unlock an existing vault.
    pub fn open(path: &Path, passphrase: &str) -> Result<Self, VaultError> {
        let manifest_path = path.join("tessera.json");
        if !manifest_path.is_file() {
            return Err(VaultError::NotFound(path.to_path_buf()));
        }
        permissions::validate_bundle_layout(path)?;
        permissions::harden_tree(path)?;
        let mut manifest = VaultManifest::load(&manifest_path)?;
        if manifest.format_version < FORMAT_VERSION || metadata::migration_in_progress(path) {
            return Err(VaultError::MetadataMigrationRequired);
        }

        let keyslots = KeyslotFile::load(&path.join("keyslot.bin"))?;
        let dek = keyslots.unlock(passphrase)?;

        let conn = crate::db::open_database(&path.join("vault.db"), &dek)?;
        metadata::hydrate_manifest(&conn, &mut manifest)?;
        let blobs = BlobStore::open(&path.join("blobs"))?;

        Ok(Self {
            path: path.to_path_buf(),
            manifest,
            conn,
            blobs,
            dek: Some(dek),
        })
    }

    /// Lock the vault, discarding the DEK (zeroized on drop).
    pub fn lock(&mut self) {
        self.dek = None;
    }

    /// Whether the vault is currently locked.
    pub fn is_locked(&self) -> bool {
        self.dek.is_none()
    }

    /// Add a recovery/rotation keyslot wrapping the existing DEK. Source blobs
    /// are not re-encrypted; every keyslot unlocks the same portable vault.
    pub fn add_keyslot(&self, passphrase: &str, params: &KdfParams) -> Result<usize, VaultError> {
        let mut keyslots = KeyslotFile::load(&self.path.join("keyslot.bin"))?;
        keyslots.add_slot(self.dek()?, passphrase, params)?;
        keyslots.save(&self.path.join("keyslot.bin"))?;
        Ok(keyslots.slot_count() - 1)
    }

    /// Remove one keyslot. The keyslot layer refuses removal of the last slot.
    pub fn remove_keyslot(&self, index: usize) -> Result<(), VaultError> {
        let mut keyslots = KeyslotFile::load(&self.path.join("keyslot.bin"))?;
        keyslots.remove_slot(index)?;
        keyslots.save(&self.path.join("keyslot.bin"))?;
        Ok(())
    }

    pub fn keyslot_count(&self) -> Result<usize, VaultError> {
        Ok(KeyslotFile::load(&self.path.join("keyslot.bin"))?.slot_count())
    }

    /// Open another database connection using the already-unlocked DEK. This
    /// supports concurrent in-process Guardian requests without retaining or
    /// re-reading the passphrase. Each duplicated DEK zeroizes on drop.
    pub fn reopen_unlocked(&self) -> Result<Self, VaultError> {
        let mut manifest = VaultManifest::load(&self.path.join("tessera.json"))?;
        if manifest.format_version < FORMAT_VERSION || metadata::migration_in_progress(&self.path) {
            return Err(VaultError::MetadataMigrationRequired);
        }
        let conn = crate::db::open_database(&self.path.join("vault.db"), self.dek()?)?;
        metadata::hydrate_manifest(&conn, &mut manifest)?;
        let blobs = BlobStore::open(&self.path.join("blobs"))?;
        Ok(Self {
            path: self.path.clone(),
            manifest,
            conn,
            blobs,
            dek: Some(self.dek()?.duplicate()),
        })
    }

    /// The unlocked DEK, or `VaultError::Locked`.
    pub(crate) fn dek(&self) -> Result<&Dek, VaultError> {
        self.dek.as_ref().ok_or(VaultError::Locked)
    }

    /// The vault bundle path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The parsed manifest.
    pub fn manifest(&self) -> &VaultManifest {
        &self.manifest
    }

    /// Embedding models registered inside protected vault metadata.
    pub fn embedding_models(&self) -> Result<Vec<EmbeddingModelEntry>, VaultError> {
        Ok(metadata::embedding_models(&self.conn)?)
    }

    pub(crate) fn register_embedding_model(
        &self,
        entry: EmbeddingModelEntry,
    ) -> Result<(), VaultError> {
        metadata::register_embedding_model(&self.conn, entry)?;
        Ok(())
    }

    /// Explicitly convert a legacy vault to protected metadata format v3.
    /// Ordinary `open` never performs this persistent-format transition.
    pub fn migrate_metadata(
        path: &Path,
        passphrase: &str,
    ) -> Result<MetadataMigrationReport, MetadataMigrationError> {
        metadata::migrate(path, passphrase)
    }

    /// Persist a supported format transition and keep this open handle in
    /// sync. Receipt migration is the sole production caller.
    pub(crate) fn set_format_version_for_migration(
        &mut self,
        version: u32,
    ) -> Result<(), VaultError> {
        if version == 0
            || version > FORMAT_VERSION
            || (version < self.manifest.format_version && !cfg!(test))
        {
            return Err(VaultError::Manifest(ManifestError::UnsupportedVersion {
                found: version,
                supported: FORMAT_VERSION,
            }));
        }
        let previous = self.manifest.format_version;
        self.manifest.format_version = version;
        if let Err(error) = self.manifest.save(&self.path.join("tessera.json")) {
            self.manifest.format_version = previous;
            return Err(error.into());
        }
        Ok(())
    }

    /// The vault database connection.
    pub(crate) fn conn(&self) -> &Connection {
        &self.conn
    }

    /// The encrypted blob store.
    pub(crate) fn blobs(&self) -> &BlobStore {
        &self.blobs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PARAMS: KdfParams = KdfParams {
        m_cost_kib: 1024,
        t_cost: 1,
        p_cost: 1,
    };

    fn create_vault(dir: &Path) -> Vault {
        Vault::create_with_params(&dir.join("V.tessera"), "passphrase", &TEST_PARAMS)
            .expect("create")
    }

    #[test]
    fn create_produces_full_bundle_layout() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = create_vault(dir.path());
        let root = vault.path();

        for entry in ["tessera.json", "keyslot.bin", "vault.db"] {
            assert!(root.join(entry).is_file(), "missing file: {entry}");
        }
        for entry in ["blobs", "receipts", "inbox"] {
            assert!(root.join(entry).is_dir(), "missing dir: {entry}");
        }
        assert!(!vault.is_locked());
    }

    #[test]
    fn create_then_reopen_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = {
            let vault = create_vault(dir.path());
            vault.path().to_path_buf()
        };

        let reopened = Vault::open(&path, "passphrase").expect("open");
        assert!(!reopened.is_locked());
        assert_eq!(reopened.manifest().format_version, FORMAT_VERSION);
        assert!(reopened.manifest().created_at.is_some());
    }

    #[test]
    fn create_refuses_existing_vault() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = create_vault(dir.path());
        let path = vault.path().to_path_buf();
        drop(vault);

        assert!(matches!(
            Vault::create_with_params(&path, "other", &TEST_PARAMS),
            Err(VaultError::AlreadyExists(_))
        ));
    }

    #[test]
    fn open_missing_vault_is_not_found() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(matches!(
            Vault::open(&dir.path().join("nope.tessera"), "x"),
            Err(VaultError::NotFound(_))
        ));
    }

    #[test]
    fn open_with_wrong_passphrase_is_bad_passphrase() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = create_vault(dir.path()).path().to_path_buf();

        assert!(matches!(
            Vault::open(&path, "wrong"),
            Err(VaultError::BadPassphrase)
        ));
    }

    #[test]
    fn recovery_keyslot_add_open_remove_rotation_workflow() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("V.tessera");
        let vault = Vault::create_with_params(&path, "primary", &TEST_PARAMS).expect("create");
        assert_eq!(vault.keyslot_count().expect("count"), 1);
        let recovery_index = vault
            .add_keyslot("recovery", &TEST_PARAMS)
            .expect("add recovery");
        assert_eq!(recovery_index, 1);
        drop(vault);

        let via_recovery = Vault::open(&path, "recovery").expect("recovery opens");
        via_recovery.remove_keyslot(0).expect("remove primary");
        drop(via_recovery);
        assert!(matches!(
            Vault::open(&path, "primary"),
            Err(VaultError::BadPassphrase)
        ));
        let rotated = Vault::open(&path, "recovery").expect("recovery remains");
        assert!(rotated.remove_keyslot(0).is_err(), "last slot is protected");
    }

    #[test]
    fn reopened_unlocked_handle_has_independent_connection_and_zeroizing_dek() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("V.tessera");
        let vault = Vault::create_with_params(&path, "primary", &TEST_PARAMS).expect("create");
        let reopened = vault.reopen_unlocked().expect("reopen unlocked");
        drop(vault);
        crate::space::create(&reopened, "Concurrent", None).expect("independent connection");
        assert_eq!(crate::space::list(&reopened).expect("list").len(), 1);
    }

    #[test]
    fn copied_bundle_opens_at_new_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let original = create_vault(dir.path()).path().to_path_buf();

        // Simulate rsync/drive copy to a different location.
        let copy = dir.path().join("Copied.tessera");
        copy_dir(&original, &copy);

        let vault = Vault::open(&copy, "passphrase").expect("open copy");
        assert_eq!(vault.path(), copy.as_path());
    }

    #[test]
    fn open_vault_components_work_together() {
        // The vault's DB is migrated and its blob store encrypts with the
        // unlocked DEK — across a close/reopen boundary.
        let dir = tempfile::tempdir().expect("tempdir");
        let (path, hash) = {
            let vault = create_vault(dir.path());
            let hash = vault
                .blobs()
                .put(vault.dek().expect("unlocked"), b"integration")
                .expect("put");
            (vault.path().to_path_buf(), hash)
        };

        let vault = Vault::open(&path, "passphrase").expect("reopen");
        let version = crate::db::migrations::schema_version(vault.conn()).expect("schema version");
        assert!(version >= 1, "database not migrated");
        assert_eq!(
            vault
                .blobs()
                .get(vault.dek().expect("unlocked"), &hash)
                .expect("get"),
            b"integration"
        );
    }

    #[test]
    fn lock_discards_dek() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut vault = create_vault(dir.path());

        assert!(vault.dek().is_ok());
        vault.lock();
        assert!(vault.is_locked());
        assert!(matches!(vault.dek(), Err(VaultError::Locked)));
    }

    #[cfg(unix)]
    #[test]
    fn open_rejects_symbolic_links_inside_bundle() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = create_vault(dir.path()).path().to_path_buf();
        let original = path.join("blobs");
        let relocated = path.join("real-blobs");
        std::fs::rename(&original, &relocated).expect("relocate blobs");
        symlink(&relocated, &original).expect("symlink fixture");
        assert!(Vault::open(&path, "passphrase").is_err());
    }

    fn copy_dir(from: &Path, to: &Path) {
        std::fs::create_dir_all(to).expect("mkdir");
        for entry in std::fs::read_dir(from).expect("read_dir") {
            let entry = entry.expect("entry");
            let target = to.join(entry.file_name());
            if entry.path().is_dir() {
                copy_dir(&entry.path(), &target);
            } else {
                std::fs::copy(entry.path(), &target).expect("copy");
            }
        }
    }
}
