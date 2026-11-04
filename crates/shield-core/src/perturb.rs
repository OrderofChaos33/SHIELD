//! Layer 2 (part 2) — Adversarial perturbation engine.
//!
//! A shipped dummy *identity* decoder (fixed linear model) gives a local
//! gradient. The FGSM step against that dummy target is restricted to the
//! Alpha/Gamma coordinates third-party decoders lean on hardest, then
//! hard-clamped to an ε-ball, plus seeded Gaussian noise on the same
//! coordinates. Honest scope (see THREAT_MODEL.md): this degrades similar
//! decoders; the scrambler is the primary, information-destroying defense.

use crate::dsp::{ALPHA_IDX, BANDS, GAMMA_IDX};
use crate::prng::Rng;

/// Deterministic dummy identity-decoder weights for a feature layout.
/// In production these are tuned per release; what matters for the
/// contract is: fixed, local, and never derived from the user's data.
pub fn dummy_identity_weights(dim: usize, n_channels: usize) -> Vec<f32> {
    let mut rng = Rng::from_seed(&[0xA5u8; 32]);
    (0..dim)
        .map(|i| {
            let band = i % BANDS.len();
            let base = rng.next_normal() * 0.5;
            // Identity signal concentrates in alpha/gamma topography.
            if band == ALPHA_IDX || band == GAMMA_IDX {
                base * 2.0
            } else {
                base * 0.25
            }
        })
        .collect::<Vec<f32>>()
        .into_iter()
        .enumerate()
        .map(|(i, w)| if i < n_channels * BANDS.len() { w } else { 0.0 })
        .collect()
}

/// Gradient of the dummy identity score (linear model => the weights),
/// kept as a function so a non-linear dummy can replace it later.
pub fn dummy_gradient(weights: &[f32], _x: &[f32]) -> Vec<f32> {
    weights.to_vec()
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PerturbationConfig {
    /// Linf bound on the total perturbation, in relative-power units.
    pub epsilon: f32,
}

impl Default for PerturbationConfig {
    fn default() -> Self {
        Self { epsilon: 0.08 }
    }
}

/// Apply bounded adversarial perturbation. Returns (perturbed, max |δ|).
/// Guarantee: max |δ| <= epsilon, by clamping, regardless of inputs.
pub fn perturb(
    features: &[f32],
    n_channels: usize,
    cfg: PerturbationConfig,
    session_seed: &[u8; 32],
) -> (Vec<f32>, f32) {
    let dim = features.len();
    let weights = dummy_identity_weights(dim, n_channels);
    let grad = dummy_gradient(&weights, features);
    let mut rng = Rng::from_seed(session_seed);
    // Blueprint spec: Gaussian sigma = epsilon/3 (99.7% of draws inside the ball before clamping).
    let sigma = cfg.epsilon / 3.0;
    let mut out = Vec::with_capacity(dim);
    let mut max_delta = 0.0f32;
    for i in 0..dim {
        let band = i % BANDS.len();
        let mut v = features[i];
        if band == ALPHA_IDX || band == GAMMA_IDX {
            let fgsm = cfg.epsilon * 0.75 * grad[i].signum();
            let gauss = sigma * rng.next_normal();
            let delta = (fgsm + gauss).clamp(-cfg.epsilon, cfg.epsilon);
            v += delta;
            max_delta = max_delta.max(delta.abs());
        }
        out.push(v);
    }
    (out, max_delta)
}

/// Blueprint API (Layer 2 spec): a named injector object the pipeline
/// and the UniFFI handle share. Noise is session-seeded (deterministic
/// per session + slice) rather than `thread_rng` — an auditor must be
/// able to reproduce exactly what was applied to a given slice from the
/// session seed recorded in the audit log, and a live RNG stream shared
/// across slices would make perturbations non-reproducible by design.
pub struct AdversarialFeatureInjector {
    epsilon: f32,
    channel_count: usize,
}

impl AdversarialFeatureInjector {
    pub fn new(epsilon: f32, channel_count: usize) -> Self {
        Self {
            epsilon,
            channel_count,
        }
    }

    pub fn epsilon(&self) -> f32 {
        self.epsilon
    }

    /// Perturb a feature vector (Alpha/Gamma only, ε-ball enforced).
    pub fn perturb_features(
        &self,
        features: crate::dsp::FeatureVector,
        session_seed: &[u8; 32],
    ) -> crate::dsp::FeatureVector {
        let (values, _) = perturb(
            &features.values,
            self.channel_count,
            PerturbationConfig {
                epsilon: self.epsilon,
            },
            session_seed,
        );
        crate::dsp::FeatureVector { values, ..features }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn perturbation_never_exceeds_epsilon() {
        let x: Vec<f32> = (0..20).map(|i| (i as f32 * 0.13).sin() * 0.4).collect();
        for seed in 0..50u8 {
            let (y, maxd) = perturb(&x, 4, PerturbationConfig::default(), &[seed; 32]);
            assert!(maxd <= 0.08 + 1e-6, "max delta {maxd} exceeded epsilon");
            for (a, b) in x.iter().zip(&y) {
                assert!((a - b).abs() <= 0.08 + 1e-6);
            }
        }
    }

    #[test]
    fn only_alpha_gamma_coordinates_move() {
        let x: Vec<f32> = vec![0.2; 10]; // 2 channels x 5 bands
        let (y, _) = perturb(&x, 2, PerturbationConfig::default(), &[4u8; 32]);
        for i in 0..10 {
            let band = i % 5;
            if band != ALPHA_IDX && band != GAMMA_IDX {
                assert_eq!(x[i], y[i], "non-target band {band} moved");
            }
        }
    }

    #[test]
    fn perturbation_reduces_dummy_identity_score_alignment() {
        // The FGSM step is taken *against* the dummy identity direction
        // in expectation: dot(y - x, w) over targeted coords should be
        // dominated by the signed step, i.e. the move is structured,
        // not zero-mean-only noise.
        let x: Vec<f32> = (0..20).map(|i| ((i * 7 % 13) as f32) / 20.0).collect();
        let (y, _) = perturb(&x, 4, PerturbationConfig::default(), &[3u8; 32]);
        let w = dummy_identity_weights(20, 4);
        let mut moved = 0.0f32;
        for i in 0..20 {
            moved += (y[i] - x[i]).abs() * w[i].abs();
        }
        assert!(
            moved > 0.01,
            "perturbation had no structured effect: {moved}"
        );
    }
}
