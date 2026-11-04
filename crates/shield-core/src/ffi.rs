//! UniFFI surface — the only way Swift/Kotlin code touches the core.
//!
//! Proc-macro bindings (`#[uniffi::export]`), no hand-written JNI/ObjC.
//! Generate bindings with:
//!   cargo run -p shield-core --bin uniffi-bindgen -- \
//!     generate --library <libshield_core> --language swift --out-dir mobile/ios/bindings
//!   (and --language kotlin for Android). See docs/UNIFFI.md.
//!
//! Exported handles:
//! - `ShieldPipelineHandle` — Layer 2 feature-space injector.
//! - `BleProxyHandle` — the Layer 1 device sequence gate, shared by the
//!   native-radio shells (the radio itself is platform code).
//! - `SecureStorageHandle` — Layer 0 SQLCipher key derivation/init.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::audit::hex;
use crate::ble::DeviceSeqTracker;
use crate::crypto::random_bytes;
use crate::dsp::FeatureVector;
use crate::keystore::SecureStorageManager;
use crate::perturb::AdversarialFeatureInjector;

#[derive(Debug, uniffi::Error)]
pub enum ShieldFfiError {
    DerivationFailed { message: String },
    NotInitialized,
    InvalidInput { message: String },
}

impl std::fmt::Display for ShieldFfiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DerivationFailed { message } => write!(f, "key derivation failed: {message}"),
            Self::NotInitialized => write!(f, "secure storage not initialized"),
            Self::InvalidInput { message } => write!(f, "invalid input: {message}"),
        }
    }
}
impl std::error::Error for ShieldFfiError {}

/// FFI record mirroring the blueprint's FeatureVector shape
/// (band_powers naming) so Swift/Kotlin call sites read naturally.
#[derive(uniffi::Record)]
pub struct FfiFeatureVector {
    pub timestamp_ms: u64,
    pub band_powers: Vec<f32>,
    pub channel_count: u32,
}

// ---------------------------------------------------------------- Layer 2

#[derive(uniffi::Object)]
pub struct ShieldPipelineHandle {
    injector: AdversarialFeatureInjector,
    seed: [u8; 32],
}

#[uniffi::export]
pub fn create_shield_pipeline(epsilon: f32, channel_count: u32) -> Arc<ShieldPipelineHandle> {
    Arc::new(ShieldPipelineHandle {
        injector: AdversarialFeatureInjector::new(epsilon, channel_count as usize),
        seed: random_bytes::<32>(),
    })
}

#[uniffi::export]
impl ShieldPipelineHandle {
    /// Sanitize one feature slice. Per-slice seed = session seed mixed
    /// with the timestamp, so slices never share a noise draw and each
    /// draw is reproducible from (seed, timestamp) for audit.
    pub fn process_slice(
        &self,
        band_powers: Vec<f32>,
        timestamp: u64,
        channel_count: u32,
    ) -> FfiFeatureVector {
        let mut hasher = Sha256::new();
        hasher.update(self.seed);
        hasher.update(timestamp.to_le_bytes());
        let slice_seed: [u8; 32] = hasher.finalize().into();
        let input = FeatureVector {
            values: band_powers,
            n_channels: channel_count as usize,
            deltas: Vec::new(),
            timestamp_ms: timestamp,
        };
        let out = self.injector.perturb_features(input, &slice_seed);
        FfiFeatureVector {
            timestamp_ms: out.timestamp_ms,
            band_powers: out.values,
            channel_count,
        }
    }

    pub fn epsilon(&self) -> f32 {
        self.injector.epsilon()
    }
}

// ---------------------------------------------------------------- Layer 1

#[derive(uniffi::Object)]
pub struct BleProxyHandle {
    trackers: Mutex<HashMap<String, DeviceSeqTracker>>,
    dropped: Mutex<u64>,
}

#[uniffi::export]
impl BleProxyHandle {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            trackers: Mutex::new(HashMap::new()),
            dropped: Mutex::new(0),
        })
    }

    /// Gate one device packet (u16 BE seq in the first 2 bytes is the
    /// caller's framing; here the seq arrives already parsed).
    /// Returns true if the packet is fresh and may be processed.
    pub fn validate_sequence(&self, characteristic_id: String, seq: u16) -> bool {
        let fresh = self
            .trackers
            .lock()
            .unwrap()
            .entry(characteristic_id)
            .or_default()
            .check_and_advance(seq);
        if !fresh {
            *self.dropped.lock().unwrap() += 1;
        }
        fresh
    }

    pub fn dropped_count(&self) -> u64 {
        *self.dropped.lock().unwrap()
    }
}

// ---------------------------------------------------------------- Layer 0

struct SecureStoreState {
    db_path: String,
    key_hex: Zeroizing<String>,
}

#[derive(uniffi::Object)]
pub struct SecureStorageHandle {
    state: Mutex<Option<SecureStoreState>>,
}

#[uniffi::export]
impl SecureStorageHandle {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(None),
        })
    }

    /// Derive the SQLCipher key from a hardware-unwrapped master seed
    /// (the platform layer obtains the seed via Secure Enclave /
    /// StrongBox unwrap; it transits memory only for this call).
    /// With feature `sqlcipher-store`, also opens the database once to
    /// prove the key works before returning success.
    pub fn initialize_encrypted_store(
        &self,
        db_path: String,
        hardware_seed: Vec<u8>,
    ) -> Result<(), ShieldFfiError> {
        let key = SecureStorageManager::derive_sqlcipher_key(&hardware_seed)
            .map_err(|message| ShieldFfiError::DerivationFailed { message })?;
        #[cfg(feature = "sqlcipher-store")]
        {
            SecureStorageManager::open_secure_database(&db_path, &key).map_err(|e| {
                ShieldFfiError::DerivationFailed {
                    message: e.to_string(),
                }
            })?;
        }
        *self.state.lock().unwrap() = Some(SecureStoreState {
            db_path,
            key_hex: key,
        });
        Ok(())
    }

    pub fn is_initialized(&self) -> bool {
        self.state.lock().unwrap().is_some()
    }

    /// Non-secret key fingerprint for the audit dashboard.
    pub fn key_fingerprint(&self) -> Option<String> {
        self.state
            .lock()
            .unwrap()
            .as_ref()
            .map(|s| SecureStorageManager::key_fingerprint(&s.key_hex))
    }

    pub fn db_path(&self) -> Option<String> {
        self.state
            .lock()
            .unwrap()
            .as_ref()
            .map(|s| s.db_path.clone())
    }
}

// Keep `hex` used even in non-sqlcipher builds (fingerprint path uses it via keystore).
#[allow(dead_code)]
fn _hex_keep(v: &[u8]) -> String {
    hex(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipeline_handle_perturbs_within_epsilon() {
        let h = create_shield_pipeline(0.09, 8);
        let input: Vec<f32> = (0..40).map(|i| (i as f32 % 7.0) / 20.0).collect();
        let out = h.process_slice(input.clone(), 1234, 8);
        assert_eq!(out.band_powers.len(), 40);
        for (a, b) in input.iter().zip(&out.band_powers) {
            assert!((a - b).abs() <= 0.09 + 1e-6);
        }
        // Non alpha/gamma coordinates are untouched.
        for (i, (a, b)) in input.iter().zip(&out.band_powers).enumerate() {
            if i % 5 != 2 && i % 5 != 4 {
                assert_eq!(a, b);
            }
        }
    }

    #[test]
    fn ble_handle_gates_replays() {
        let h = BleProxyHandle::new();
        assert!(h.validate_sequence("char-1".into(), 10));
        assert!(h.validate_sequence("char-1".into(), 11));
        assert!(!h.validate_sequence("char-1".into(), 11));
        assert_eq!(h.dropped_count(), 1);
        // A different characteristic has its own sequence space.
        assert!(h.validate_sequence("char-2".into(), 11));
    }

    #[test]
    fn secure_storage_handle_lifecycle() {
        let h = SecureStorageHandle::new();
        assert!(!h.is_initialized());
        h.initialize_encrypted_store("shield.db".into(), vec![5u8; 32])
            .unwrap();
        assert!(h.is_initialized());
        assert_eq!(h.key_fingerprint().unwrap().len(), 64);
        assert!(h
            .initialize_encrypted_store("x.db".into(), vec![1u8; 4])
            .is_err());
    }
}
