//! The Shield pipeline — where the layers meet.
//!
//! Contract:
//! - No grant, no slice. Grants are per-app, per-scope, explicit.
//! - Log-then-release: the audit event is appended BEFORE the sanitized
//!   vector is returned, so every release has a receipt by construction.
//! - Raw frames enter; only scrambled + perturbed features leave.

use std::collections::HashMap;

use crate::attest::{fatigue_index, record_commitment, AttestationToken, Predicate};
use crate::audit::{AuditEvent, AuditLog};
use crate::calibration::{CalibrationProfile, EpsilonCalibrator};
use crate::crypto::KeyProvider;
use crate::dsp::{
    extract_features, BiometricTopographyStripper, FeatureVector, RawFrame, TopographyScrambler,
};
use crate::perturb::{dummy_identity_weights, perturb, PerturbationConfig};
use crate::storage::{EncryptedStore, StoredRecord};

#[derive(Debug, PartialEq)]
pub enum ShieldError {
    NoGrant { app_id: String, scope: String },
    Store,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Grant {
    pub app_id: String,
    pub scope: String, // "features" | "attestation"
}

#[derive(Debug, Clone)]
pub struct ReleasedSlice {
    pub features: FeatureVector,
    /// Receipt: index into the audit log for this release.
    pub audit_index: usize,
    pub audit_root_hex: String,
    pub epsilon_applied: f32,
}

pub struct Shield {
    scrambler: TopographyScrambler,
    stripper: BiometricTopographyStripper,
    session_seed: [u8; 32],
    cfg: PerturbationConfig,
    grants: HashMap<(String, String), Grant>,
    baseline: Option<Vec<f32>>,
    pub audit: AuditLog,
    pub store: EncryptedStore,
    calibrator: EpsilonCalibrator,
    /// Rolling raw-feature windows for the calibrator (last 30).
    feature_windows: Vec<Vec<f32>>,
    /// The ε actually applied to the most recent sanitize.
    pub last_epsilon: f32,
    pub last_calibration: Option<CalibrationProfile>,
}

impl Shield {
    pub fn new(session_seed: [u8; 32], n_channels: usize, provider: &dyn KeyProvider) -> Self {
        // The identity direction the stripper nulls is the dummy identity
        // decoder's weight vector: the direction a third-party decoder
        // would read identity from is projected out before release.
        let identity_dir = dummy_identity_weights(n_channels * 5, n_channels);
        Self {
            stripper: BiometricTopographyStripper::from_identity_direction(&identity_dir),
            scrambler: TopographyScrambler::from_session_seed(&session_seed, n_channels * 5),
            session_seed,
            cfg: PerturbationConfig::default(),
            grants: HashMap::new(),
            baseline: None,
            audit: AuditLog::new(),
            store: EncryptedStore::new(provider),
            calibrator: EpsilonCalibrator::default(),
            feature_windows: Vec::new(),
            last_epsilon: PerturbationConfig::default().epsilon,
            last_calibration: None,
        }
    }

    pub fn with_epsilon(mut self, epsilon: f32) -> Self {
        self.cfg = PerturbationConfig { epsilon };
        self
    }

    pub fn grant(&mut self, app_id: &str, scope: &str) {
        let g = Grant {
            app_id: app_id.to_string(),
            scope: scope.to_string(),
        };
        self.grants.insert((g.app_id.clone(), g.scope.clone()), g);
    }

    pub fn revoke(&mut self, app_id: &str, scope: &str) {
        self.grants.remove(&(app_id.to_string(), scope.to_string()));
    }

    pub fn has_grant(&self, app_id: &str, scope: &str) -> bool {
        self.grants
            .contains_key(&(app_id.to_string(), scope.to_string()))
    }

    fn require_grant(&self, app_id: &str, scope: &str) -> Result<(), ShieldError> {
        if self
            .grants
            .contains_key(&(app_id.to_string(), scope.to_string()))
        {
            Ok(())
        } else {
            Err(ShieldError::NoGrant {
                app_id: app_id.to_string(),
                scope: scope.to_string(),
            })
        }
    }

    /// Full Layer 2 pipeline on a raw frame (internal + attestation use).
    /// ε is calibrated per call: the raw features join the rolling
    /// window, and once >= 5 windows exist the calibrator's adjusted ε
    /// replaces the static base ε for this sanitize. The ε actually
    /// used is recorded in `last_epsilon` and written to the audit log
    /// by the caller — a receipt always states the real ε, never a nominal one.
    fn sanitize(&mut self, frame: &RawFrame) -> (FeatureVector, Vec<f32>) {
        let raw = extract_features(frame);
        self.feature_windows.push(raw.clone());
        if self.feature_windows.len() > 30 {
            self.feature_windows.remove(0);
        }
        if self.feature_windows.len() >= 5 {
            if let Ok(profile) = self.calibrator.calibrate(&self.feature_windows) {
                self.last_epsilon = profile.adjusted_epsilon;
                self.cfg = PerturbationConfig {
                    epsilon: profile.adjusted_epsilon,
                };
                self.last_calibration = Some(profile);
            }
        }
        if self.baseline.is_none() {
            self.baseline = Some(raw.clone());
        }
        let baseline = self.baseline.clone().unwrap();
        // Order: scramble (session rotation) -> strip (null identity
        // direction) -> perturb (bounded adversarial noise).
        let scrambled = self.scrambler.apply(&raw);
        let stripped = self
            .stripper
            .strip_identity(&scrambled)
            .expect("feature dim matches stripper by construction");
        let (perturbed, _) = perturb(&stripped, frame.n_channels(), self.cfg, &self.session_seed);
        let baseline_stripped = self
            .stripper
            .strip_identity(&self.scrambler.apply(&baseline))
            .expect("feature dim matches stripper by construction");
        let deltas: Vec<f32> = perturbed
            .iter()
            .zip(&baseline_stripped)
            .map(|(a, b)| a - b)
            .collect();
        (
            FeatureVector {
                values: perturbed,
                n_channels: frame.n_channels(),
                deltas,
                timestamp_ms: frame.timestamp_ms,
            },
            raw,
        )
    }

    /// Release a sanitized feature slice to an authorized local app.
    /// Audit-log append happens first; the returned slice carries its receipt.
    pub fn release_slice(
        &mut self,
        app_id: &str,
        frame: &RawFrame,
    ) -> Result<ReleasedSlice, ShieldError> {
        self.require_grant(app_id, "features")?;
        let (features, _raw) = self.sanitize(frame);
        // Persist the released features (sealed) and commit to them.
        let payload = serde_json::to_vec(&features).map_err(|_| ShieldError::Store)?;
        let commitment = record_commitment(&payload);
        self.store
            .append(StoredRecord {
                kind: "features".into(),
                timestamp_ms: frame.timestamp_ms,
                payload,
            })
            .map_err(|_| ShieldError::Store)?;
        // Log-then-release.
        let audit_index = self.audit.append(AuditEvent {
            timestamp_ms: frame.timestamp_ms,
            app_id: app_id.to_string(),
            scope: "features".into(),
            epsilon: self.cfg.epsilon,
            record_commitment: commitment,
        });
        let root = self.audit.root_hex();
        Ok(ReleasedSlice {
            features,
            audit_index,
            audit_root_hex: root,
            epsilon_applied: self.cfg.epsilon,
        })
    }

    /// Issue an attestation token for an external verifier. The fatigue
    /// index is computed internally and never returned; the token carries
    /// only the boolean. Also audit-logged (proof events are releases too).
    pub fn attest_fatigue(
        &mut self,
        requester: &str,
        frame: &RawFrame,
        threshold: f32,
    ) -> Result<AttestationToken, ShieldError> {
        self.require_grant(requester, "attestation")?;
        let (_features, raw) = self.sanitize(frame);
        let idx = fatigue_index(&raw, frame.n_channels());
        let payload = serde_json::to_vec(&raw).map_err(|_| ShieldError::Store)?;
        let commitment = record_commitment(&payload);
        self.store
            .append(StoredRecord {
                kind: "attest-input".into(),
                timestamp_ms: frame.timestamp_ms,
                payload,
            })
            .map_err(|_| ShieldError::Store)?;
        let audit_index = self.audit.append(AuditEvent {
            timestamp_ms: frame.timestamp_ms,
            app_id: requester.to_string(),
            scope: "attestation".into(),
            epsilon: 0.0,
            record_commitment: commitment.clone(),
        });
        Ok(AttestationToken::issue(
            Predicate::FatigueBelow,
            threshold,
            idx,
            commitment,
            audit_index,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SoftwareKeyProvider;

    fn frame(ts: u64) -> RawFrame {
        let sr = 256.0;
        let ch: Vec<f32> = (0..256)
            .map(|i| {
                (2.0 * std::f32::consts::PI * 10.0 * i as f32 / sr).sin()
                    + 0.5 * (2.0 * std::f32::consts::PI * 20.0 * i as f32 / sr).sin()
            })
            .collect();
        RawFrame::new(sr, vec![ch.clone(), ch], ts)
    }

    fn shield() -> (Shield, SoftwareKeyProvider) {
        let p = SoftwareKeyProvider::from_passphrase("pw", &[3u8; 16]);
        let s = Shield::new([42u8; 32], 2, &p);
        (s, p)
    }

    #[test]
    fn no_grant_no_slice() {
        let (mut s, _p) = shield();
        assert!(matches!(
            s.release_slice("focus-timer", &frame(0)),
            Err(ShieldError::NoGrant { .. })
        ));
        // And crucially: nothing was logged for a denied request's data.
        assert_eq!(s.audit.len(), 0);
    }

    #[test]
    fn granted_release_is_logged_with_verifiable_receipt() {
        let (mut s, _p) = shield();
        s.grant("focus-timer", "features");
        let slice = s.release_slice("focus-timer", &frame(1000)).unwrap();
        assert_eq!(slice.audit_index, 0);
        assert_eq!(s.audit.len(), 1);
        let proof = s.audit.inclusion_proof(slice.audit_index).unwrap();
        assert!(AuditLog::verify_inclusion(
            &s.audit.root(),
            &s.audit.events[slice.audit_index],
            &proof
        ));
        assert_eq!(slice.features.values.len(), 10);
    }

    #[test]
    fn revoked_grant_denies_again() {
        let (mut s, _p) = shield();
        s.grant("app", "features");
        assert!(s.release_slice("app", &frame(0)).is_ok());
        s.revoke("app", "features");
        assert!(s.release_slice("app", &frame(1)).is_err());
    }

    #[test]
    fn attestation_requires_its_own_scope() {
        let (mut s, _p) = shield();
        s.grant("employer-app", "features"); // wrong scope on purpose
        assert!(s.attest_fatigue("employer-app", &frame(0), 1.0).is_err());
        s.grant("employer-app", "attestation");
        let token = s.attest_fatigue("employer-app", &frame(0), 100.0).unwrap();
        assert!(token.holds);
        assert_eq!(token.predicate, "fatigue_below");
    }
}
