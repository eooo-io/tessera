//! Encrypted blob store — content-addressed, XChaCha20-Poly1305.
//!
//! A blob's identity is the lowercase hex BLAKE3 hash of its plaintext,
//! stored at `blobs/<first two hex chars>/<full hash>`. On-disk container:
//! 24-byte random nonce || ciphertext+tag, AAD = the blob's hash.
//! See `spec/vault-format.md` §5.

use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use thiserror::Error;

use crate::crypto::Dek;

const NONCE_LEN: usize = 24;

#[derive(Error, Debug)]
pub enum BlobError {
    #[error("blob not found: {0}")]
    NotFound(String),
    #[error("integrity check failed for blob: {0}")]
    IntegrityError(String),
    #[error("encryption error: {0}")]
    EncryptionError(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Typed wrapper for a blob address (lowercase hex BLAKE3 of plaintext).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BlobHash(pub String);

/// Content-addressed encrypted blob store rooted at a `blobs/` directory.
pub struct BlobStore {
    root: PathBuf,
}

impl BlobStore {
    /// Open a store rooted at `root` (created if missing).
    pub fn open(root: &Path) -> Result<Self, BlobError> {
        std::fs::create_dir_all(root)?;
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    /// Store plaintext, returning its address. Deduplicates: identical
    /// plaintext is written once; re-putting is a cheap no-op.
    pub fn put(&self, dek: &Dek, plaintext: &[u8]) -> Result<BlobHash, BlobError> {
        let hash = BlobHash(blake3::hash(plaintext).to_hex().to_string());
        let path = self.path_for(&hash);
        if path.is_file() {
            return Ok(hash);
        }

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
            .map_err(|e| BlobError::EncryptionError(e.to_string()))?;

        let mut container = Vec::with_capacity(NONCE_LEN + sealed.len());
        container.extend_from_slice(&nonce);
        container.extend_from_slice(&sealed);

        std::fs::create_dir_all(path.parent().expect("sharded path has parent"))?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &container)?;
        std::fs::rename(&tmp, &path)?;
        Ok(hash)
    }

    /// Decrypt and return a blob's plaintext, verifying both the AEAD tag
    /// and the content address.
    pub fn get(&self, dek: &Dek, hash: &BlobHash) -> Result<Vec<u8>, BlobError> {
        let path = self.path_for(hash);
        if !path.is_file() {
            return Err(BlobError::NotFound(hash.0.clone()));
        }
        let container = std::fs::read(&path)?;
        if container.len() < NONCE_LEN {
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

        // Defense in depth: the address must match the decrypted content.
        if blake3::hash(&plaintext).to_hex().to_string() != hash.0 {
            return Err(BlobError::IntegrityError(hash.0.clone()));
        }
        Ok(plaintext)
    }

    /// Whether a blob with this address exists.
    pub fn exists(&self, hash: &BlobHash) -> bool {
        self.path_for(hash).is_file()
    }

    /// Remove a blob. Missing blobs are an error (`NotFound`).
    pub fn delete(&self, hash: &BlobHash) -> Result<(), BlobError> {
        let path = self.path_for(hash);
        if !path.is_file() {
            return Err(BlobError::NotFound(hash.0.clone()));
        }
        std::fs::remove_file(path)?;
        Ok(())
    }

    /// Filesystem path for an address (does not check existence).
    fn path_for(&self, hash: &BlobHash) -> PathBuf {
        let shard = hash.0.get(..2).unwrap_or("00");
        self.root.join(shard).join(&hash.0)
    }
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
    fn address_is_blake3_of_plaintext_with_sharded_path() {
        let (dir, store) = store();
        let dek = test_dek();

        let hash = store.put(&dek, b"content").expect("put");
        assert_eq!(hash.0, blake3::hash(b"content").to_hex().to_string());
        let expected_path = dir.path().join("blobs").join(&hash.0[..2]).join(&hash.0);
        assert!(expected_path.is_file(), "blob not at sharded path");
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
    fn wrong_dek_cannot_read_blob() {
        let (_dir, store) = store();
        let dek = test_dek();
        let other_dek = test_dek();

        let hash = store.put(&dek, b"secret material").expect("put");
        assert!(matches!(
            store.get(&other_dek, &hash),
            Err(BlobError::IntegrityError(_))
        ));
    }

    #[test]
    fn plaintext_never_appears_on_disk() {
        let (dir, store) = store();
        let dek = test_dek();
        let secret = b"EXTREMELY-DISTINCTIVE-SECRET-MARKER-0451";

        let hash = store.put(&dek, secret).expect("put");
        let raw = std::fs::read(dir.path().join("blobs").join(&hash.0[..2]).join(&hash.0))
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
        let path = dir.path().join("blobs").join(&hash.0[..2]).join(&hash.0);
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

        let p1 = dir.path().join("blobs").join(&h1.0[..2]).join(&h1.0);
        let p2 = dir.path().join("blobs").join(&h2.0[..2]).join(&h2.0);
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
        assert!(store.exists(&hash));
        store.delete(&hash).expect("delete");
        assert!(!store.exists(&hash));
        assert!(matches!(
            store.get(&dek, &hash),
            Err(BlobError::NotFound(_))
        ));
        assert!(matches!(store.delete(&hash), Err(BlobError::NotFound(_))));
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
