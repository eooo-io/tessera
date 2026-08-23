//! Encrypted blob store with protected logical hashes and keyed opaque paths.
//!
//! A blob's unlocked logical identity remains the lowercase hex BLAKE3 hash
//! of its plaintext. The locked-visible path is a vault-keyed token over that
//! hash. Container v2 is `TSB2 || nonce || ciphertext+tag`, with the magic and
//! opaque address bound as AEAD associated data.
//! See `spec/vault-format.md` §5.

use std::io::Write;
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use thiserror::Error;

use crate::crypto::Dek;

const NONCE_LEN: usize = 24;
const CONTAINER_MAGIC: &[u8; 4] = b"TSB2";

#[derive(Error, Debug)]
pub enum BlobError {
    #[error("blob not found: {0}")]
    NotFound(String),
    #[error("integrity check failed for blob: {0}")]
    IntegrityError(String),
    #[error("encryption error: {0}")]
    EncryptionError(String),
    #[error("unrecognized file blocks protected blob migration: {0}")]
    UnrecognizedMigrationResidue(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Protected logical content identity (lowercase hex BLAKE3 of plaintext).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BlobHash(pub String);

/// Content-addressed encrypted blob store rooted at a `blobs/` directory.
pub struct BlobStore {
    root: PathBuf,
}

impl BlobStore {
    /// Open a store rooted at `root` (created if missing).
    pub fn open(root: &Path) -> Result<Self, BlobError> {
        crate::vault::permissions::directory(root)?;
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    /// Store plaintext, returning its address. Deduplicates: identical
    /// plaintext is written once; re-putting authenticates the existing
    /// container and then returns the same logical hash.
    pub fn put(&self, dek: &Dek, plaintext: &[u8]) -> Result<BlobHash, BlobError> {
        let hash = BlobHash(blake3::hash(plaintext).to_hex().to_string());
        let address = self.opaque_address(dek, &hash);
        let path = self.path_for_address(&address);
        if path.is_file() {
            self.get(dek, &hash)?;
            return Ok(hash);
        }

        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let encryption_key = dek.blob_encryption_key_v2();
        let cipher = XChaCha20Poly1305::new(encryption_key.as_ref().into());
        let sealed = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &container_aad(&address),
                },
            )
            .map_err(|e| BlobError::EncryptionError(e.to_string()))?;

        let mut container = Vec::with_capacity(CONTAINER_MAGIC.len() + NONCE_LEN + sealed.len());
        container.extend_from_slice(CONTAINER_MAGIC);
        container.extend_from_slice(&nonce);
        container.extend_from_slice(&sealed);

        crate::vault::permissions::directory(path.parent().expect("sharded path has parent"))?;
        let tmp = path.with_extension(format!("tmp.{}", ulid::Ulid::new()));
        let write_result = (|| -> Result<(), std::io::Error> {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)?;
            crate::vault::permissions::file(&tmp)?;
            file.write_all(&container)?;
            file.sync_all()?;
            std::fs::rename(&tmp, &path)?;
            std::fs::File::open(path.parent().expect("sharded path has parent"))?.sync_all()?;
            Ok(())
        })();
        if let Err(error) = write_result {
            let _ = std::fs::remove_file(&tmp);
            return Err(error.into());
        }
        Ok(hash)
    }

    /// Decrypt and return a blob's plaintext, verifying both the AEAD tag
    /// and the content address.
    pub fn get(&self, dek: &Dek, hash: &BlobHash) -> Result<Vec<u8>, BlobError> {
        let address = self.opaque_address(dek, hash);
        let path = self.path_for_address(&address);
        if !path.is_file() {
            return Err(BlobError::NotFound(hash.0.clone()));
        }
        let container = std::fs::read(&path)?;
        let (actual, plaintext) = decrypt_v2_container(dek, &address, &container)?;
        if actual != *hash {
            return Err(BlobError::IntegrityError(hash.0.clone()));
        }
        Ok(plaintext)
    }

    /// Whether a blob with this address exists.
    pub fn exists(&self, dek: &Dek, hash: &BlobHash) -> bool {
        self.path_for_address(&self.opaque_address(dek, hash))
            .is_file()
    }

    /// Remove a blob. Missing blobs are an error (`NotFound`).
    pub fn delete(&self, dek: &Dek, hash: &BlobHash) -> Result<(), BlobError> {
        let path = self.path_for_address(&self.opaque_address(dek, hash));
        if !path.is_file() {
            return Err(BlobError::NotFound(hash.0.clone()));
        }
        std::fs::remove_file(path)?;
        Ok(())
    }

    /// Vault-specific locked-visible address for a protected logical hash.
    pub(crate) fn opaque_address(&self, dek: &Dek, hash: &BlobHash) -> String {
        let address_key = dek.blob_address_key();
        blake3::keyed_hash(&address_key, hash.0.as_bytes())
            .to_hex()
            .to_string()
    }

    fn path_for_address(&self, address: &str) -> PathBuf {
        let shard = address.get(..2).unwrap_or("00");
        self.root.join(shard).join(address)
    }

    /// Convert every authenticated legacy blob, including orphans, to the
    /// protected v2 container and keyed path. Repeating this operation is a
    /// no-op. Unknown files fail closed instead of being silently discarded.
    pub(crate) fn migrate_legacy_blobs(&self, dek: &Dek) -> Result<usize, BlobError> {
        let mut files = Vec::new();
        collect_files(&self.root, &mut files)?;
        files.sort();
        let mut converted = 0;

        for path in files {
            if !path.is_file() {
                continue;
            }
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| {
                    BlobError::UnrecognizedMigrationResidue(path.display().to_string())
                })?;
            let bytes = std::fs::read(&path)?;
            if bytes.starts_with(CONTAINER_MAGIC) {
                if !is_lower_hex_64(name) || path != self.path_for_address(name) {
                    return Err(BlobError::UnrecognizedMigrationResidue(
                        path.display().to_string(),
                    ));
                }
                let (logical, _) = decrypt_v2_container(dek, name, &bytes)?;
                if self.opaque_address(dek, &logical) != name {
                    return Err(BlobError::IntegrityError(logical.0));
                }
                continue;
            }

            if let Some(hash) = legacy_temporary_hash(name) {
                let expected_parent = self.root.join(&hash[..2]);
                if path.parent() != Some(expected_parent.as_path()) {
                    return Err(BlobError::UnrecognizedMigrationResidue(
                        path.display().to_string(),
                    ));
                }
                std::fs::remove_file(&path)?;
                continue;
            }
            if !is_lower_hex_64(name) || path != self.root.join(&name[..2]).join(name) {
                return Err(BlobError::UnrecognizedMigrationResidue(
                    path.display().to_string(),
                ));
            }

            let hash = BlobHash(name.to_owned());
            let plaintext = decrypt_legacy_container(dek, &hash, &bytes)?;
            let migrated = self.put(dek, &plaintext)?;
            if migrated != hash || self.get(dek, &hash)? != plaintext {
                return Err(BlobError::IntegrityError(hash.0));
            }
            std::fs::remove_file(&path)?;
            if let Some(parent) = path.parent() {
                std::fs::File::open(parent)?.sync_all()?;
            }
            converted += 1;
        }
        Ok(converted)
    }

    #[cfg(test)]
    pub(crate) fn put_legacy_test(
        &self,
        dek: &Dek,
        plaintext: &[u8],
    ) -> Result<BlobHash, BlobError> {
        let hash = BlobHash(blake3::hash(plaintext).to_hex().to_string());
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let cipher = XChaCha20Poly1305::new(dek.as_bytes().into());
        let sealed = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: hash.0.as_bytes(),
                },
            )
            .map_err(|error| BlobError::EncryptionError(error.to_string()))?;
        let path = self.root.join(&hash.0[..2]).join(&hash.0);
        crate::vault::permissions::directory(path.parent().expect("legacy shard parent"))?;
        let mut container = nonce.to_vec();
        container.extend_from_slice(&sealed);
        std::fs::write(path, container)?;
        crate::vault::permissions::file(&self.root.join(&hash.0[..2]).join(&hash.0))?;
        Ok(hash)
    }
}

fn container_aad(address: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(CONTAINER_MAGIC.len() + address.len());
    aad.extend_from_slice(CONTAINER_MAGIC);
    aad.extend_from_slice(address.as_bytes());
    aad
}

fn decrypt_legacy_container(
    dek: &Dek,
    hash: &BlobHash,
    container: &[u8],
) -> Result<Vec<u8>, BlobError> {
    if container.len() < NONCE_LEN + 16 {
        return Err(BlobError::IntegrityError(hash.0.clone()));
    }
    let (nonce, sealed) = container.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(dek.as_bytes().into());
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: sealed,
                aad: hash.0.as_bytes(),
            },
        )
        .map_err(|_| BlobError::IntegrityError(hash.0.clone()))?;
    if blake3::hash(&plaintext).to_hex().to_string() != hash.0 {
        return Err(BlobError::IntegrityError(hash.0.clone()));
    }
    Ok(plaintext)
}

fn decrypt_v2_container(
    dek: &Dek,
    address: &str,
    container: &[u8],
) -> Result<(BlobHash, Vec<u8>), BlobError> {
    if container.len() < CONTAINER_MAGIC.len() + NONCE_LEN + 16
        || &container[..CONTAINER_MAGIC.len()] != CONTAINER_MAGIC
    {
        return Err(BlobError::IntegrityError(address.to_owned()));
    }
    let nonce_start = CONTAINER_MAGIC.len();
    let sealed_start = nonce_start + NONCE_LEN;
    let encryption_key = dek.blob_encryption_key_v2();
    let cipher = XChaCha20Poly1305::new(encryption_key.as_ref().into());
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&container[nonce_start..sealed_start]),
            Payload {
                msg: &container[sealed_start..],
                aad: &container_aad(address),
            },
        )
        .map_err(|_| BlobError::IntegrityError(address.to_owned()))?;
    let logical = BlobHash(blake3::hash(&plaintext).to_hex().to_string());
    Ok((logical, plaintext))
}

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn legacy_temporary_hash(name: &str) -> Option<&str> {
    let (hash, suffix) = name.split_once(".tmp.")?;
    (is_lower_hex_64(hash) && !suffix.is_empty()).then_some(hash)
}

fn collect_files(root: &Path, files: &mut Vec<PathBuf>) -> Result<(), std::io::Error> {
    if !root.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "symbolic links are not permitted in the blob store",
            ));
        }
        if file_type.is_dir() {
            collect_files(&path, files)?;
        } else if file_type.is_file() {
            files.push(path);
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unsupported filesystem entry in the blob store",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Dek, KdfParams, KeyslotFile};

    const TEST_PARAMS: KdfParams = KdfParams {
        m_cost_kib: 1024,
        t_cost: 1,
        p_cost: 1,
    };

    fn test_dek() -> Dek {
        let (_file, dek) = KeyslotFile::create("test", &TEST_PARAMS).expect("create");
        dek
    }

    fn store() -> (tempfile::TempDir, BlobStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = BlobStore::open(&dir.path().join("blobs")).expect("open");
        (dir, store)
    }

    #[test]
    fn put_get_round_trip() {
        let (_dir, store) = store();
        let dek = test_dek();

        let hash = store.put(&dek, b"the quick brown fox").expect("put");
        let plain = store.get(&dek, &hash).expect("get");
        assert_eq!(plain, b"the quick brown fox");
    }

    #[test]
    fn crash_residue_from_encrypt_is_replaced_only_by_authenticated_complete_blob() {
        let (_dir, store) = store();
        let dek = test_dek();
        let plaintext = b"complete source after interrupted encryption";
        let expected = BlobHash(blake3::hash(plaintext).to_hex().to_string());
        let address = store.opaque_address(&dek, &expected);
        let final_path = store.path_for_address(&address);
        std::fs::create_dir_all(final_path.parent().expect("shard")).expect("shard");
        let temporary = final_path.with_extension("tmp.crash-residue");
        std::fs::write(&temporary, b"truncated ciphertext crash residue").expect("fault injection");

        let actual = store.put(&dek, plaintext).expect("retry put");
        assert_eq!(actual, expected);
        assert!(
            temporary.exists(),
            "untrusted crash residue is not silently deleted"
        );
        assert_eq!(
            store.get(&dek, &actual).expect("authenticated get"),
            plaintext
        );
    }

    #[test]
    fn logical_hash_is_blake3_but_path_is_keyed_and_sharded() {
        let (dir, store) = store();
        let dek = test_dek();

        let hash = store.put(&dek, b"content").expect("put");
        assert_eq!(hash.0, blake3::hash(b"content").to_hex().to_string());
        let address = store.opaque_address(&dek, &hash);
        let expected_path = dir.path().join("blobs").join(&address[..2]).join(address);
        assert!(expected_path.is_file(), "blob not at sharded path");
    }

    #[test]
    fn locked_visible_address_is_keyed_and_cross_vault_unlinkable() {
        let (_dir, store) = store();
        let first = test_dek();
        let second = test_dek();
        let logical = BlobHash(blake3::hash(b"guessable content").to_hex().to_string());

        let first_address = store.opaque_address(&first, &logical);
        let second_address = store.opaque_address(&second, &logical);

        assert_ne!(first_address, logical.0);
        assert_ne!(second_address, logical.0);
        assert_ne!(first_address, second_address);
        assert_eq!(first_address.len(), 64);
        assert!(first_address.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn public_content_hash_is_absent_from_blob_path_and_container() {
        let (dir, store) = store();
        let dek = test_dek();
        let plaintext = b"KNOWN-GUESSED-DOCUMENT-CONTENT";
        let logical = store.put(&dek, plaintext).expect("put");
        let public_hash = logical.0.as_bytes();
        let address = store.opaque_address(&dek, &logical);
        let path = dir.path().join("blobs").join(&address[..2]).join(address);
        let raw = std::fs::read(&path).expect("read container");

        assert!(path.is_file());
        assert!(!path.to_string_lossy().contains(&logical.0));
        assert!(!raw
            .windows(public_hash.len())
            .any(|bytes| bytes == public_hash));
    }

    #[test]
    fn identical_plaintext_deduplicates() {
        let (dir, store) = store();
        let dek = test_dek();

        let h1 = store.put(&dek, b"same bytes").expect("put 1");
        let h2 = store.put(&dek, b"same bytes").expect("put 2");
        assert_eq!(h1, h2);

        let count = walkdir_count_files(&dir.path().join("blobs"));
        assert_eq!(count, 1, "expected exactly one blob file");
    }

    #[test]
    fn legacy_conversion_authenticates_then_removes_public_address() {
        let (dir, store) = store();
        let dek = test_dek();
        let plaintext = b"LEGACY-BLOB-MIGRATION-SENTINEL";
        let hash = store.put_legacy_test(&dek, plaintext).expect("legacy put");
        let legacy = dir.path().join("blobs").join(&hash.0[..2]).join(&hash.0);

        assert_eq!(store.migrate_legacy_blobs(&dek).expect("migrate"), 1);
        assert!(!legacy.exists());
        assert_eq!(store.get(&dek, &hash).expect("read v2"), plaintext);
        assert_eq!(store.migrate_legacy_blobs(&dek).expect("repeat"), 0);
    }

    #[test]
    fn legacy_conversion_fails_closed_on_tamper_and_unknown_residue() {
        let (_dir, store) = store();
        let dek = test_dek();
        let hash = store
            .put_legacy_test(&dek, b"legacy tamper target")
            .expect("legacy put");
        let path = store.root.join(&hash.0[..2]).join(&hash.0);
        let mut bytes = std::fs::read(&path).expect("read");
        *bytes.last_mut().expect("last") ^= 0xff;
        std::fs::write(&path, bytes).expect("tamper");
        assert!(matches!(
            store.migrate_legacy_blobs(&dek),
            Err(BlobError::IntegrityError(_))
        ));

        std::fs::remove_file(path).expect("remove fixture");
        std::fs::write(store.root.join("unexpected-file"), b"unknown").expect("unknown");
        assert!(matches!(
            store.migrate_legacy_blobs(&dek),
            Err(BlobError::UnrecognizedMigrationResidue(_))
        ));
    }

    #[test]
    fn migration_rejects_v2_container_at_a_public_or_wrong_address() {
        let (_directory, store) = store();
        let dek = test_dek();
        let hash = store
            .put(&dek, b"v2 relocation migration target")
            .expect("put");
        let opaque = store.opaque_address(&dek, &hash);
        let source = store.path_for_address(&opaque);
        let public = store.root.join(&hash.0[..2]).join(&hash.0);
        std::fs::create_dir_all(public.parent().expect("public shard")).expect("shard");
        std::fs::rename(source, public).expect("relocate");

        assert!(matches!(
            store.migrate_legacy_blobs(&dek),
            Err(BlobError::IntegrityError(_))
        ));
    }

    #[test]
    fn wrong_dek_cannot_read_blob() {
        let (_dir, store) = store();
        let dek = test_dek();
        let other_dek = test_dek();

        let hash = store.put(&dek, b"secret material").expect("put");
        assert!(store.get(&other_dek, &hash).is_err());
    }

    #[test]
    fn plaintext_never_appears_on_disk() {
        let (dir, store) = store();
        let dek = test_dek();
        let secret = b"EXTREMELY-DISTINCTIVE-SECRET-MARKER-0451";

        let hash = store.put(&dek, secret).expect("put");
        let address = store.opaque_address(&dek, &hash);
        let raw = std::fs::read(dir.path().join("blobs").join(&address[..2]).join(address))
            .expect("read raw");
        assert!(
            !raw.windows(secret.len()).any(|w| w == secret),
            "plaintext found in on-disk blob"
        );
    }

    #[test]
    fn tampered_blob_fails_integrity() {
        let (dir, store) = store();
        let dek = test_dek();

        let hash = store.put(&dek, b"tamper target").expect("put");
        let address = store.opaque_address(&dek, &hash);
        let path = dir.path().join("blobs").join(&address[..2]).join(address);
        let mut raw = std::fs::read(&path).expect("read");
        let last = raw.len() - 1;
        raw[last] ^= 0xFF;
        std::fs::write(&path, &raw).expect("write");

        assert!(matches!(
            store.get(&dek, &hash),
            Err(BlobError::IntegrityError(_))
        ));
    }

    #[test]
    fn blob_cannot_be_relocated_to_another_address() {
        // Moving a valid encrypted container to a different address must
        // fail: the address is bound into the AEAD as associated data.
        let (dir, store) = store();
        let dek = test_dek();

        let h1 = store.put(&dek, b"first blob").expect("put 1");
        let h2 = store.put(&dek, b"second blob").expect("put 2");

        let a1 = store.opaque_address(&dek, &h1);
        let a2 = store.opaque_address(&dek, &h2);
        let p1 = dir.path().join("blobs").join(&a1[..2]).join(a1);
        let p2 = dir.path().join("blobs").join(&a2[..2]).join(a2);
        std::fs::copy(&p1, &p2).expect("copy over");

        assert!(matches!(
            store.get(&dek, &h2),
            Err(BlobError::IntegrityError(_))
        ));
    }

    #[test]
    fn exists_and_delete() {
        let (_dir, store) = store();
        let dek = test_dek();

        let hash = store.put(&dek, b"ephemeral").expect("put");
        assert!(store.exists(&dek, &hash));
        store.delete(&dek, &hash).expect("delete");
        assert!(!store.exists(&dek, &hash));
        assert!(matches!(
            store.get(&dek, &hash),
            Err(BlobError::NotFound(_))
        ));
        assert!(matches!(
            store.delete(&dek, &hash),
            Err(BlobError::NotFound(_))
        ));
    }

    #[test]
    fn empty_blob_round_trips() {
        let (_dir, store) = store();
        let dek = test_dek();

        let hash = store.put(&dek, b"").expect("put");
        assert_eq!(store.get(&dek, &hash).expect("get"), Vec::<u8>::new());
    }

    #[test]
    fn one_megabyte_blob_round_trips() {
        let (_dir, store) = store();
        let dek = test_dek();
        let big: Vec<u8> = (0..1_048_576u32).map(|i| (i % 251) as u8).collect();

        let hash = store.put(&dek, &big).expect("put");
        assert_eq!(store.get(&dek, &hash).expect("get"), big);
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(16))]

        #[test]
        fn prop_encrypt_decrypt_round_trip(
            data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..65536)
        ) {
            let (_dir, store) = store();
            let dek = test_dek();
            let hash = store.put(&dek, &data).expect("put");
            proptest::prop_assert_eq!(store.get(&dek, &hash).expect("get"), data);
        }
    }

    fn walkdir_count_files(root: &Path) -> usize {
        fn walk(dir: &Path, count: &mut usize) {
            for entry in std::fs::read_dir(dir).expect("read_dir") {
                let entry = entry.expect("entry");
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, count);
                } else {
                    *count += 1;
                }
            }
        }
        let mut count = 0;
        walk(root, &mut count);
        count
    }
}
