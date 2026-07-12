//! Key management: LUKS-style keyslots wrapping the vault DEK.
//!
//! `keyslot.bin` holds a list of slots. Each slot wraps the same 256-bit
//! Data Encryption Key (DEK) with XChaCha20-Poly1305 under a slot key
//! derived from a passphrase via Argon2id (per-slot parameters and salt).
//! Adding/removing an unlock method touches only this file — never blobs.
//! Binary layout: `spec/vault-format.md` §4.

use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::CryptoError;

const MAGIC: &[u8; 4] = b"TSK1";
/// Serialized slot size: 3×u32 params + 16 salt + 24 nonce + 48 wrapped DEK.
const SLOT_LEN: usize = 12 + 16 + 24 + 48;

/// Derive a 32-byte slot key from a passphrase (zeroized on drop).
fn derive_slot_key(
    passphrase: &str,
    salt: &[u8; 16],
    params: &KdfParams,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let argon_params = Params::new(params.m_cost_kib, params.t_cost, params.p_cost, Some(32))
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut())
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
    Ok(key)
}

/// Argon2id cost parameters for one keyslot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    /// Production defaults per the v3 plan / manifest defaults.
    pub const DEFAULT: KdfParams = KdfParams {
        m_cost_kib: 65536,
        t_cost: 3,
        p_cost: 4,
    };
}

/// The vault Data Encryption Key. Zeroed from memory on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Dek {
    bytes: [u8; 32],
}

impl Dek {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    pub(crate) fn duplicate(&self) -> Self {
        Self { bytes: self.bytes }
    }
}

/// One keyslot: per-slot KDF params, salt, nonce, and the wrapped DEK.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Keyslot {
    params: KdfParams,
    salt: [u8; 16],
    nonce: [u8; 24],
    /// 32-byte DEK ciphertext + 16-byte Poly1305 tag.
    wrapped_dek: [u8; 48],
}

/// The parsed `keyslot.bin` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyslotFile {
    slots: Vec<Keyslot>,
}

impl KeyslotFile {
    /// Generate a fresh random DEK and wrap it in a first slot under
    /// `passphrase`.
    pub fn create(passphrase: &str, params: &KdfParams) -> Result<(Self, Dek), CryptoError> {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let dek = Dek { bytes };

        let mut file = Self { slots: Vec::new() };
        file.add_slot(&dek, passphrase, params)?;
        Ok((file, dek))
    }

    /// Try `passphrase` against every slot; return the DEK on first match.
    pub fn unlock(&self, passphrase: &str) -> Result<Dek, CryptoError> {
        for slot in &self.slots {
            let key = derive_slot_key(passphrase, &slot.salt, &slot.params)?;
            let cipher = XChaCha20Poly1305::new(key.as_ref().into());
            if let Ok(plain) =
                cipher.decrypt(XNonce::from_slice(&slot.nonce), slot.wrapped_dek.as_ref())
            {
                let mut plain = Zeroizing::new(plain);
                if plain.len() == 32 {
                    let mut bytes = [0u8; 32];
                    bytes.copy_from_slice(&plain);
                    plain.zeroize();
                    return Ok(Dek { bytes });
                }
            }
        }
        Err(CryptoError::BadPassphrase)
    }

    /// Wrap the existing DEK under an additional passphrase.
    pub fn add_slot(
        &mut self,
        dek: &Dek,
        passphrase: &str,
        params: &KdfParams,
    ) -> Result<(), CryptoError> {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);

        let key = derive_slot_key(passphrase, &salt, params)?;
        let cipher = XChaCha20Poly1305::new(key.as_ref().into());
        let sealed = cipher
            .encrypt(XNonce::from_slice(&nonce), dek.as_bytes().as_ref())
            .map_err(|e| CryptoError::Encryption(e.to_string()))?;
        let wrapped_dek: [u8; 48] = sealed
            .try_into()
            .map_err(|_| CryptoError::Encryption("unexpected wrapped DEK length".into()))?;

        self.slots.push(Keyslot {
            params: *params,
            salt,
            nonce,
            wrapped_dek,
        });
        Ok(())
    }

    /// Remove a slot by index. Refuses to remove the final slot (that would
    /// make the vault permanently unopenable).
    pub fn remove_slot(&mut self, index: usize) -> Result<(), CryptoError> {
        if index >= self.slots.len() {
            return Err(CryptoError::InvalidFormat(format!(
                "no keyslot at index {index}"
            )));
        }
        if self.slots.len() == 1 {
            return Err(CryptoError::InvalidFormat(
                "refusing to remove the last keyslot".into(),
            ));
        }
        self.slots.remove(index);
        Ok(())
    }

    pub fn slot_count(&self) -> usize {
        self.slots.len()
    }

    /// Parse `keyslot.bin`.
    pub fn load(path: &Path) -> Result<Self, CryptoError> {
        let bytes = std::fs::read(path)?;
        if bytes.len() < 5 || &bytes[0..4] != MAGIC {
            return Err(CryptoError::InvalidFormat("bad magic".into()));
        }
        let count = bytes[4] as usize;
        if bytes.len() != 5 + count * SLOT_LEN {
            return Err(CryptoError::InvalidFormat(format!(
                "expected {} bytes for {count} slot(s), found {}",
                5 + count * SLOT_LEN,
                bytes.len()
            )));
        }

        let read_u32 = |b: &[u8]| u32::from_le_bytes(b.try_into().expect("4-byte slice"));
        let mut slots = Vec::with_capacity(count);
        for i in 0..count {
            let s = &bytes[5 + i * SLOT_LEN..5 + (i + 1) * SLOT_LEN];
            slots.push(Keyslot {
                params: KdfParams {
                    m_cost_kib: read_u32(&s[0..4]),
                    t_cost: read_u32(&s[4..8]),
                    p_cost: read_u32(&s[8..12]),
                },
                salt: s[12..28].try_into().expect("16-byte salt"),
                nonce: s[28..52].try_into().expect("24-byte nonce"),
                wrapped_dek: s[52..100].try_into().expect("48-byte wrapped DEK"),
            });
        }
        Ok(Self { slots })
    }

    /// Write `keyslot.bin` (atomic: temp file + rename).
    pub fn save(&self, path: &Path) -> Result<(), CryptoError> {
        if self.slots.len() > u8::MAX as usize {
            return Err(CryptoError::InvalidFormat("too many keyslots".into()));
        }
        let mut bytes = Vec::with_capacity(5 + self.slots.len() * SLOT_LEN);
        bytes.extend_from_slice(MAGIC);
        bytes.push(self.slots.len() as u8);
        for slot in &self.slots {
            bytes.extend_from_slice(&slot.params.m_cost_kib.to_le_bytes());
            bytes.extend_from_slice(&slot.params.t_cost.to_le_bytes());
            bytes.extend_from_slice(&slot.params.p_cost.to_le_bytes());
            bytes.extend_from_slice(&slot.salt);
            bytes.extend_from_slice(&slot.nonce);
            bytes.extend_from_slice(&slot.wrapped_dek);
        }

        let tmp = path.with_extension("bin.tmp");
        std::fs::write(&tmp, &bytes)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cheap Argon2id parameters so tests stay fast; production defaults are
    /// exercised only through `KdfParams::DEFAULT` constants.
    const TEST_PARAMS: KdfParams = KdfParams {
        m_cost_kib: 1024,
        t_cost: 1,
        p_cost: 1,
    };

    #[test]
    fn create_then_unlock_returns_same_dek() {
        let (file, dek) = KeyslotFile::create("correct horse", &TEST_PARAMS).expect("create");
        let unlocked = file.unlock("correct horse").expect("unlock");
        assert_eq!(unlocked.as_bytes(), dek.as_bytes());
    }

    #[test]
    fn wrong_passphrase_is_bad_passphrase_error() {
        let (file, _dek) = KeyslotFile::create("correct horse", &TEST_PARAMS).expect("create");
        match file.unlock("battery staple") {
            Err(CryptoError::BadPassphrase) => {}
            other => panic!("expected BadPassphrase, got {:?}", other.map(|_| "Dek")),
        }
    }

    #[test]
    fn two_vaults_same_passphrase_have_different_deks() {
        let (_f1, d1) = KeyslotFile::create("same", &TEST_PARAMS).expect("create");
        let (_f2, d2) = KeyslotFile::create("same", &TEST_PARAMS).expect("create");
        assert_ne!(d1.as_bytes(), d2.as_bytes());
    }

    #[test]
    fn add_slot_unlocks_same_dek_with_second_passphrase() {
        let (mut file, dek) = KeyslotFile::create("primary", &TEST_PARAMS).expect("create");
        file.add_slot(&dek, "recovery", &TEST_PARAMS).expect("add");
        assert_eq!(file.slot_count(), 2);

        let via_primary = file.unlock("primary").expect("primary");
        let via_recovery = file.unlock("recovery").expect("recovery");
        assert_eq!(via_primary.as_bytes(), dek.as_bytes());
        assert_eq!(via_recovery.as_bytes(), dek.as_bytes());
    }

    #[test]
    fn remove_slot_revokes_that_passphrase() {
        let (mut file, dek) = KeyslotFile::create("old", &TEST_PARAMS).expect("create");
        file.add_slot(&dek, "new", &TEST_PARAMS).expect("add");
        file.remove_slot(0).expect("remove");

        assert!(matches!(
            file.unlock("old"),
            Err(CryptoError::BadPassphrase)
        ));
        assert_eq!(file.unlock("new").expect("new").as_bytes(), dek.as_bytes());
    }

    #[test]
    fn cannot_remove_last_slot() {
        let (mut file, _dek) = KeyslotFile::create("only", &TEST_PARAMS).expect("create");
        assert!(file.remove_slot(0).is_err());
        assert_eq!(file.slot_count(), 1);
    }

    #[test]
    fn save_load_round_trip_preserves_unlock() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("keyslot.bin");

        let (mut file, dek) = KeyslotFile::create("primary", &TEST_PARAMS).expect("create");
        file.add_slot(&dek, "recovery", &TEST_PARAMS).expect("add");
        file.save(&path).expect("save");

        let loaded = KeyslotFile::load(&path).expect("load");
        assert_eq!(loaded, file);
        assert_eq!(
            loaded.unlock("recovery").expect("unlock").as_bytes(),
            dek.as_bytes()
        );
    }

    #[test]
    fn load_rejects_garbage_and_truncation() {
        let dir = tempfile::tempdir().expect("tempdir");

        let garbage = dir.path().join("garbage.bin");
        std::fs::write(&garbage, b"not a keyslot file").expect("write");
        assert!(matches!(
            KeyslotFile::load(&garbage),
            Err(CryptoError::InvalidFormat(_))
        ));

        // Valid file, truncated mid-slot.
        let truncated = dir.path().join("truncated.bin");
        let (file, _dek) = KeyslotFile::create("p", &TEST_PARAMS).expect("create");
        file.save(&truncated).expect("save");
        let bytes = std::fs::read(&truncated).expect("read");
        std::fs::write(&truncated, &bytes[..bytes.len() - 10]).expect("truncate");
        assert!(matches!(
            KeyslotFile::load(&truncated),
            Err(CryptoError::InvalidFormat(_))
        ));
    }

    #[test]
    fn dek_type_guarantees_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<Dek>();
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(8))]

        /// Any passphrase (including empty/unicode) round-trips: create then
        /// unlock yields the identical DEK, and a differing passphrase fails.
        #[test]
        fn prop_wrap_unwrap_round_trip(pass in ".{0,64}", other in ".{1,64}") {
            let (file, dek) = KeyslotFile::create(&pass, &TEST_PARAMS).expect("create");
            let unlocked = file.unlock(&pass).expect("unlock");
            proptest::prop_assert_eq!(unlocked.as_bytes(), dek.as_bytes());

            if other != pass {
                proptest::prop_assert!(matches!(
                    file.unlock(&other),
                    Err(CryptoError::BadPassphrase)
                ));
            }
        }
    }
}
