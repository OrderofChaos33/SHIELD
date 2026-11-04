//! Layer 0 — Secure storage key derivation & SQLCipher binding.
//!
//! The hardware root of trust never hands SHIELD a general-purpose
//! secret it can keep. The platform layer (Swift / Kotlin) uses the
//! enclave to *unwrap* a random master seed — iOS: a Secure-Enclave P-256
//! key performs the unwrap of a Keychain-stored wrapped seed (the
//! Enclave holds ECC keys, not symmetric secrets); Android: a StrongBox /
//! TEE Keystore AES key unwraps it via the Keystore cipher. The seed
//! exists in Rust memory only for this derivation, is zeroized after,
//! and the derived SQLCipher key is held in `Zeroizing` memory.
//!
//! Derivation: HKDF-SHA256, salt `N-SHIELD_SQLCIPHER_SALT_V1`,
//! info `sqlite_aes_256_gcm_derived_key` — domain-separated from every
//! other SHIELD key (Layer 1 uses `shield-l1-v1-*`, passphrase storage
//! uses `shield-l3-storage-v1`).

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub struct SecureStorageManager;

impl SecureStorageManager {
    /// Derive the 256-bit SQLCipher key (hex, for the `x'...'` PRAGMA form)
    /// from a hardware-unwrapped master seed.
    pub fn derive_sqlcipher_key(hardware_master_seed: &[u8]) -> Result<Zeroizing<String>, String> {
        if hardware_master_seed.len() < 16 {
            return Err("hardware master seed too short: refusing to derive a weak key".into());
        }
        let salt = b"N-SHIELD_SQLCIPHER_SALT_V1";
        let info = b"sqlite_aes_256_gcm_derived_key";
        let hk = Hkdf::<Sha256>::new(Some(salt), hardware_master_seed);
        let mut okm = Zeroizing::new([0u8; 32]);
        hk.expand(info, okm.as_mut())
            .map_err(|e| format!("HKDF expansion failed: {e:?}"))?;
        Ok(Zeroizing::new(hex::encode(*okm)))
    }

    /// Non-secret fingerprint of a derived key (SHA-256 of the key bytes,
    /// hex). Safe to show in the audit dashboard so the user can confirm
    /// "same key as last session" without the key ever being displayed.
    pub fn key_fingerprint(hex_key: &str) -> String {
        let bytes = hex::decode(hex_key).unwrap_or_default();
        let mut h = Sha256::new();
        h.update(&bytes);
        hex::encode(h.finalize())
    }

    /// Open an encrypted SQLCipher database with the derived key.
    ///
    /// PRAGMA order matters and differs from a naive reading: `key` first,
    /// cipher parameters second (they must be set before the first real
    /// read/write touches a page), validation query LAST.
    #[cfg(feature = "sqlcipher-store")]
    pub fn open_secure_database(
        db_path: &str,
        hex_key: &str,
    ) -> rusqlite::Result<rusqlite::Connection> {
        let conn = rusqlite::Connection::open(db_path)?;
        conn.execute_batch(&format!("PRAGMA key = \"x'{hex_key}'\";"))?;
        conn.execute_batch(
            "PRAGMA cipher_page_size = 4096;
             PRAGMA kdf_iter = 256000;",
        )?;
        conn.query_row("SELECT count(*) FROM sqlite_master;", [], |row| {
            row.get::<_, i64>(0)
        })?;
        Ok(conn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic_and_256_bit_hex() {
        let a = SecureStorageManager::derive_sqlcipher_key(&[7u8; 32]).unwrap();
        let b = SecureStorageManager::derive_sqlcipher_key(&[7u8; 32]).unwrap();
        assert_eq!(*a, *b);
        assert_eq!(a.len(), 64, "32 bytes hex-encoded");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn different_seed_different_key() {
        let a = SecureStorageManager::derive_sqlcipher_key(&[7u8; 32]).unwrap();
        let b = SecureStorageManager::derive_sqlcipher_key(&[8u8; 32]).unwrap();
        assert_ne!(*a, *b);
    }

    #[test]
    fn short_seed_refused() {
        assert!(SecureStorageManager::derive_sqlcipher_key(&[1u8; 8]).is_err());
    }

    #[test]
    fn domain_separation_from_storage_passphrase_key() {
        // Same input material, different domain => different key.
        // (The L3 passphrase provider uses info "shield-l3-storage-v1".)
        let sqlcipher = SecureStorageManager::derive_sqlcipher_key(&[9u8; 32]).unwrap();
        let hk = Hkdf::<Sha256>::new(Some(b"N-SHIELD_SQLCIPHER_SALT_V1"), &[9u8; 32]);
        let mut other = [0u8; 32];
        hk.expand(b"shield-l3-storage-v1", &mut other).unwrap();
        assert_ne!(*sqlcipher, hex::encode(other));
    }

    #[test]
    fn fingerprint_is_not_the_key() {
        let key = SecureStorageManager::derive_sqlcipher_key(&[3u8; 32]).unwrap();
        let fp = SecureStorageManager::key_fingerprint(&key);
        assert_ne!(fp, *key);
        assert_eq!(fp.len(), 64);
    }
}
