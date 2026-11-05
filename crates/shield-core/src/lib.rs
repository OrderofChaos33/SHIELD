//! SHIELD core — local-first neuro-defense.
//!
//! Hard rules enforced by this crate's API surface:
//! 1. `RawFrame` never leaves the crate. Apps receive `FeatureVector`s only.
//! 2. There is no network code in this crate.
//! 3. Release is log-then-release: `pipeline::Shield::release_slice`
//!    appends to the Merkle audit log before returning any data.

pub mod agent_binding;
#[cfg(feature = "async-pipeline")]
pub mod async_pipeline;
pub mod attest;
pub mod audit;
pub mod ble;
#[cfg(feature = "ble-radio")]
pub mod ble_proxy;
pub mod calibration;
pub mod crypto;
pub mod dsp;
pub mod ffi;
pub mod keystore;
pub mod mirrorfield;
pub mod perturb;
pub mod pipeline;
pub mod prng;
pub mod storage;

uniffi::setup_scaffolding!();

pub use attest::{AttestationToken, Predicate};
pub use audit::{AuditEvent, AuditLog, InclusionProof, MerkleAuditLog, Receipt};
pub use calibration::{CalibrationProfile, EpsilonCalibrator};
pub use dsp::{FeatureVector, RawFrame};
pub use mirrorfield::{
    sanitize_advertisement, Advertisement, Mirrorfield, PeerVerdict, Posture, ProbeAction,
    ProbeEvent, ProbeKind, MIRROR_EPSILON,
};
pub use pipeline::{Grant, ReleasedSlice, Shield, ShieldError};
