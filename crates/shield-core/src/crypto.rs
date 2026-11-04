//! Layer 0 — Key provision.
//!
//! On a device, a `KeyProvider` is backed by Secure Enclave / StrongBox:
//! the key operation happens in hardware and app memory never holds a
//! general-purpose master secret. In dev/test, `SoftwareKeyProvider`
//! derives the storage key from a passphrase with HKDF-SHA256 — behind
//! the `software-keys` feature, and refused in release builds.

use hkdf::Hkdf;
use sha2::Sha256;

pub trait KeyProvider {
    /// 32-byte storage key material for Layer 3.
    fn storage_key(&self) -> [u8; 32];
    /// Human-readable backing, for the audit dashboard ("enclave" /
    /// "software-dev"). Never a key, never an identifier.
    fn backing(&self) -> &'static str;
}

#[cfg(feature = "software-keys")]
pub struct SoftwareKeyProvider {
    key: [u8; 32],
}

#[cfg(feature = "software-keys")]
impl SoftwareKeyProvider {
    pub fn from_passphrase(passphrase: &str, salt: &[u8; 16]) -> Self {
        #[cfg(debug_assertions)]
        {
            let hk = Hkdf::<Sha256>::new(Some(salt), passphrase.as_bytes());
            let mut key = [0u8; 32];
            hk.expand(b"shield-l3-storage-v1", &mut key)
                .expect("hkdf len");
            Self { key }
        }
        #[cfg(not(debug_assertions))]
        {
            panic!(
                "SoftwareKeyProvider is forbidden in release builds: use an enclave KeyProvider"
            );
        }
    }
}

#[cfg(feature = "software-keys")]
impl KeyProvider for SoftwareKeyProvider {
    fn storage_key(&self) -> [u8; 32] {
        self.key
    }
    fn backing(&self) -> &'static str {
        "software-dev"
    }
}

/// OS-entropy bytes for nonces and session material in production wiring.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    getrandom::getrandom(&mut out).expect("OS entropy must be available");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "software-keys")]
    #[test]
    fn software_provider_is_deterministic_per_passphrase() {
        let a = SoftwareKeyProvider::from_passphrase("correct horse", &[1u8; 16]);
        let b = SoftwareKeyProvider::from_passphrase("correct horse", &[1u8; 16]);
        let c = SoftwareKeyProvider::from_passphrase("wrong horse", &[1u8; 16]);
        assert_eq!(a.storage_key(), b.storage_key());
        assert_ne!(a.storage_key(), c.storage_key());
        assert_eq!(a.backing(), "software-dev");
    }
}
