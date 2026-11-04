//! Layer 3 (part 2) — Attestation tokens.
//!
//! The token is the ONLY object designed to leave the device. It carries
//! a commitment to a stored record, a predicate name, a threshold, and
//! the boolean result — never a feature value. The Circom circuit in
//! `circuits/attestation.circom` proves the same predicate over the
//! committed private input; this envelope is what the proof binds to
//! (commitment + audit index), mirroring the sig-binding pattern:
//! a proof detached from its envelope must not verify against another.

use serde::{Deserialize, Serialize};

use crate::audit::{hex, sha256};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum Predicate {
    /// fatigue_index < threshold
    FatigueBelow,
}

impl Predicate {
    pub fn name(&self) -> &'static str {
        match self {
            Predicate::FatigueBelow => "fatigue_below",
        }
    }
}

/// Fatigue index from a *raw internal* feature vector:
/// (theta + delta) / (alpha + beta) relative power, averaged over
/// channels. Computed inside the core; the index itself never leaves.
pub fn fatigue_index(raw_features: &[f32], n_channels: usize) -> f32 {
    if n_channels == 0 {
        return 0.0;
    }
    let mut acc = 0.0f32;
    for c in 0..n_channels {
        let base = c * 5;
        let num = raw_features[base] + raw_features[base + 1];
        let den = (raw_features[base + 2] + raw_features[base + 3]).max(1e-9);
        acc += num / den;
    }
    acc / n_channels as f32
}

/// Commitment to a stored record's canonical bytes.
pub fn record_commitment(record_bytes: &[u8]) -> String {
    hex(&sha256(record_bytes))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttestationToken {
    pub predicate: String,
    pub threshold_milli: u32, // threshold * 1000, integer for circuit parity
    pub holds: bool,
    pub record_commitment: String,
    /// Index of this attestation's event in the Layer 4 audit log.
    pub audit_index: usize,
}

impl AttestationToken {
    /// Build a token. `holds` is computed here from the private index —
    /// callers pass the index in, they never receive it back.
    pub fn issue(
        predicate: Predicate,
        threshold: f32,
        private_index: f32,
        record_commitment: String,
        audit_index: usize,
    ) -> Self {
        Self {
            predicate: predicate.name().to_string(),
            threshold_milli: (threshold * 1000.0) as u32,
            holds: private_index < threshold,
            record_commitment,
            audit_index,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fatigue_index_math() {
        // delta .1 theta .2 alpha .3 beta .2 gamma .2 -> (0.3)/(0.5)=0.6
        let f = fatigue_index(&[0.1, 0.2, 0.3, 0.2, 0.2], 1);
        assert!((f - 0.6).abs() < 1e-6);
    }

    #[test]
    fn token_reveals_only_the_boolean() {
        let t = AttestationToken::issue(Predicate::FatigueBelow, 1.0, 0.42, "abc".into(), 3);
        assert!(t.holds);
        let json = serde_json::to_string(&t).unwrap();
        assert!(
            !json.contains("0.42"),
            "private index leaked into token: {json}"
        );
    }

    #[test]
    fn token_threshold_failure() {
        let t = AttestationToken::issue(Predicate::FatigueBelow, 0.5, 0.9, "abc".into(), 0);
        assert!(!t.holds);
    }
}
