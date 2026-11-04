//! Layer 2 (part 1) — DSP: pre-clean, bandpower, topography scrambling.
//!
//! Output is *relative* band power per channel — absolute amplitude, a
//! strong identity cue, is discarded here and never returns.

use crate::prng::Rng;
use serde::{Deserialize, Serialize};

/// Frequency bands (Hz): Delta, Theta, Alpha, Beta, Gamma.
pub const BANDS: [(&str, f32, f32); 5] = [
    ("delta", 0.5, 4.0),
    ("theta", 4.0, 8.0),
    ("alpha", 8.0, 13.0),
    ("beta", 13.0, 30.0),
    ("gamma", 30.0, 50.0),
];
pub const ALPHA_IDX: usize = 2;
pub const GAMMA_IDX: usize = 4;

/// A raw multichannel frame. Deliberately NOT exported from the crate
/// root for return to callers — it moves only from Layer 1 into Layer 2.
#[derive(Debug, Clone)]
pub struct RawFrame {
    pub sample_rate_hz: f32,
    pub channels: Vec<Vec<f32>>,
    pub timestamp_ms: u64,
}

impl RawFrame {
    pub fn new(sample_rate_hz: f32, channels: Vec<Vec<f32>>, timestamp_ms: u64) -> Self {
        Self {
            sample_rate_hz,
            channels,
            timestamp_ms,
        }
    }
    pub fn n_channels(&self) -> usize {
        self.channels.len()
    }
    pub fn n_features(&self) -> usize {
        self.channels.len() * BANDS.len()
    }
}

/// The only telemetry-shaped object that may leave the core.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FeatureVector {
    /// Channel-major relative band powers (possibly scrambled/perturbed).
    pub values: Vec<f32>,
    pub n_channels: usize,
    /// Deltas vs. this session's baseline, same layout. Relative shifts
    /// are what legitimate local apps need; absolutes are what they don't.
    pub deltas: Vec<f32>,
    pub timestamp_ms: u64,
}

impl FeatureVector {
    pub fn band(&self, channel: usize, band: usize) -> f32 {
        self.values[channel * BANDS.len() + band]
    }
}

/// Soft-clip artifacts at ±k·σ and demean each channel.
pub fn pre_clean(frame: &RawFrame, k: f32) -> Vec<Vec<f32>> {
    frame
        .channels
        .iter()
        .map(|ch| {
            if ch.is_empty() {
                return Vec::new();
            }
            let mean = ch.iter().sum::<f32>() / ch.len() as f32;
            let var = ch.iter().map(|x| (x - mean).powi(2)).sum::<f32>() / ch.len() as f32;
            let sigma = var.sqrt().max(1e-9);
            let lo = mean - k * sigma;
            let hi = mean + k * sigma;
            ch.iter().map(|x| x.clamp(lo, hi) - mean).collect()
        })
        .collect()
}

/// DFT bandpower (naive DFT over band bins — frames are small and this
/// keeps the core dependency-free and auditable).
pub fn bandpower(samples: &[f32], sample_rate_hz: f32) -> [f32; 5] {
    let n = samples.len();
    if n == 0 {
        return [0.0; 5];
    }
    let mut powers = [0.0f32; 5];
    let max_bin = n / 2;
    for bin in 1..=max_bin {
        let freq = bin as f32 * sample_rate_hz / n as f32;
        let band = BANDS
            .iter()
            .position(|&(_, lo, hi)| freq >= lo && freq < hi);
        if let Some(b) = band {
            let mut re = 0.0f32;
            let mut im = 0.0f32;
            for (i, &x) in samples.iter().enumerate() {
                let ang = -2.0 * std::f32::consts::PI * bin as f32 * i as f32 / n as f32;
                re += x * ang.cos();
                im += x * ang.sin();
            }
            powers[b] += re * re + im * im;
        }
    }
    let total: f32 = powers.iter().sum();
    if total > 0.0 {
        for p in powers.iter_mut() {
            *p /= total;
        }
    }
    powers
}

/// Raw (unscrambled) feature extraction: pre-clean -> bandpower, flattened.
pub fn extract_features(frame: &RawFrame) -> Vec<f32> {
    let cleaned = pre_clean(frame, 4.0);
    let mut out = Vec::with_capacity(frame.n_features());
    for ch in &cleaned {
        out.extend_from_slice(&bandpower(ch, frame.sample_rate_hz));
    }
    out
}

/// An orthogonal matrix (QᵀQ = I) derived from a session seed.
/// Multiplying features by Q preserves norms and within-session geometry
/// while destroying the absolute cross-session topography (brainprint).
pub struct TopographyScrambler {
    q: Vec<Vec<f32>>, // row-major, dim x dim
    pub dim: usize,
}

impl TopographyScrambler {
    pub fn from_session_seed(seed: &[u8; 32], dim: usize) -> Self {
        let mut rng = Rng::from_seed(seed);
        // Random matrix -> Gram–Schmidt -> orthogonal Q. Computed in f64
        // and cast down: in pure f32 the orthogonality error at dim=10
        // measured 2.6e-4, above the 1e-4 the tests (and any verifier
        // relying on norm preservation) should be able to assume.
        let mut cols: Vec<Vec<f64>> = (0..dim)
            .map(|_| (0..dim).map(|_| rng.next_normal() as f64).collect())
            .collect();
        for j in 0..dim {
            for i in 0..j {
                let dot: f64 = cols[j].iter().zip(&cols[i]).map(|(a, b)| a * b).sum();
                let u = cols[i].clone();
                for (v, ui) in cols[j].iter_mut().zip(&u) {
                    *v -= dot * ui;
                }
            }
            let norm = cols[j].iter().map(|x| x * x).sum::<f64>().sqrt().max(1e-12);
            for v in cols[j].iter_mut() {
                *v /= norm;
            }
        }
        let cols: Vec<Vec<f32>> = cols
            .iter()
            .map(|c| c.iter().map(|v| *v as f32).collect())
            .collect();
        // Store row-major where row r = coefficients across basis cols.
        let mut q = vec![vec![0.0f32; dim]; dim];
        for (c, col) in cols.iter().enumerate() {
            for (r, &v) in col.iter().enumerate() {
                q[r][c] = v;
            }
        }
        Self { q, dim }
    }

    pub fn apply(&self, x: &[f32]) -> Vec<f32> {
        assert_eq!(x.len(), self.dim, "feature dim must match scrambler");
        self.q
            .iter()
            .map(|row| row.iter().zip(x).map(|(a, b)| a * b).sum())
            .collect()
    }

    /// Max |QᵀQ − I| — for tests/diagnostics.
    pub fn orthogonality_error(&self) -> f32 {
        let mut worst = 0.0f32;
        for i in 0..self.dim {
            for j in 0..self.dim {
                let mut dot = 0.0f32;
                for k in 0..self.dim {
                    dot += self.q[k][i] * self.q[k][j];
                }
                let expect = if i == j { 1.0 } else { 0.0 };
                worst = worst.max((dot - expect).abs());
            }
        }
        worst
    }
}

/// Biometric topography stripper (Layer 2 spec, nalgebra form).
///
/// Holds a projection matrix P and maps feature vectors through it.
/// The production constructor builds P = I − Σ vᵢvᵢᵀ from identity
/// directions vᵢ (orthonormalized internally): any component of the
/// feature vector lying along an identity direction is *nulled*, not
/// rotated — that information is destroyed, which is the point.
/// Properties: P is symmetric, idempotent (P² = P), and P·vᵢ = 0.
pub struct BiometricTopographyStripper {
    projection_matrix: nalgebra::DMatrix<f32>,
}

impl BiometricTopographyStripper {
    pub fn new(projection_matrix: nalgebra::DMatrix<f32>) -> Self {
        Self { projection_matrix }
    }

    /// Build the nulling projection from raw (not necessarily
    /// orthonormal) identity directions.
    pub fn nulling(identity_dirs: &[Vec<f32>]) -> Self {
        assert!(
            !identity_dirs.is_empty(),
            "need at least one identity direction"
        );
        let dim = identity_dirs[0].len();
        // Gram–Schmidt the directions.
        let mut ortho: Vec<Vec<f32>> = Vec::new();
        for dir in identity_dirs {
            assert_eq!(dir.len(), dim);
            let mut v = dir.clone();
            for u in &ortho {
                let dot: f32 = v.iter().zip(u).map(|(a, b)| a * b).sum();
                for i in 0..dim {
                    v[i] -= dot * u[i];
                }
            }
            let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt();
            if norm > 1e-6 {
                ortho.push(v.iter().map(|x| x / norm).collect());
            }
        }
        let mut p = nalgebra::DMatrix::<f32>::identity(dim, dim);
        for u in &ortho {
            let uv = nalgebra::DVector::from_vec(u.clone());
            p -= &uv * uv.transpose();
        }
        Self {
            projection_matrix: p,
        }
    }

    pub fn from_identity_direction(dir: &[f32]) -> Self {
        Self::nulling(&[dir.to_vec()])
    }

    pub fn projection_matrix(&self) -> &nalgebra::DMatrix<f32> {
        &self.projection_matrix
    }

    /// Project a feature vector into the identity-nulled subspace.
    pub fn strip_identity(&self, channel_data: &[f32]) -> Result<Vec<f32>, String> {
        let rows = self.projection_matrix.nrows();
        if channel_data.len() != rows {
            return Err(format!(
                "Dimension mismatch: data {} vs projection {rows}",
                channel_data.len()
            ));
        }
        let vector = nalgebra::DVector::from_row_slice(channel_data);
        let projected = &self.projection_matrix * vector;
        Ok(projected.as_slice().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sine_frame(freq: f32, sr: f32, n: usize, channels: usize) -> RawFrame {
        let ch: Vec<f32> = (0..n)
            .map(|i| (2.0 * std::f32::consts::PI * freq * i as f32 / sr).sin())
            .collect();
        RawFrame::new(sr, vec![ch; channels], 0)
    }

    #[test]
    fn alpha_tone_lands_in_alpha_band() {
        let frame = sine_frame(10.0, 256.0, 256, 1);
        let feats = extract_features(&frame);
        assert!(
            feats[ALPHA_IDX] > 0.9,
            "alpha rel power was {}",
            feats[ALPHA_IDX]
        );
    }

    #[test]
    fn relative_powers_sum_to_one_per_channel() {
        let frame = sine_frame(20.0, 256.0, 256, 2);
        let feats = extract_features(&frame);
        for c in 0..2 {
            let s: f32 = feats[c * 5..c * 5 + 5].iter().sum();
            assert!((s - 1.0).abs() < 1e-4);
        }
    }

    #[test]
    fn scrambler_is_orthogonal() {
        let q = TopographyScrambler::from_session_seed(&[5u8; 32], 10);
        assert!(
            q.orthogonality_error() < 1e-4,
            "err {}",
            q.orthogonality_error()
        );
    }

    #[test]
    fn scrambler_preserves_norm() {
        let q = TopographyScrambler::from_session_seed(&[5u8; 32], 10);
        let x: Vec<f32> = (0..10).map(|i| i as f32 * 0.1).collect();
        let y = q.apply(&x);
        let nx = x.iter().map(|v| v * v).sum::<f32>().sqrt();
        let ny = y.iter().map(|v| v * v).sum::<f32>().sqrt();
        assert!((nx - ny).abs() < 1e-4);
    }

    #[test]
    fn different_sessions_scramble_differently() {
        let x: Vec<f32> = (0..10).map(|i| (i as f32 * 0.37).sin()).collect();
        let a = TopographyScrambler::from_session_seed(&[1u8; 32], 10).apply(&x);
        let b = TopographyScrambler::from_session_seed(&[2u8; 32], 10).apply(&x);
        let dist: f32 = a
            .iter()
            .zip(&b)
            .map(|(u, v)| (u - v).powi(2))
            .sum::<f32>()
            .sqrt();
        assert!(dist > 0.5, "cross-session distance too small: {dist}");
    }

    #[test]
    fn same_session_preserves_relative_shift_direction() {
        // Within one session, Q is fixed and linear: Q(x2)-Q(x1) == Q(x2-x1).
        let q = TopographyScrambler::from_session_seed(&[9u8; 32], 5);
        let x1 = vec![0.2, 0.3, 0.1, 0.25, 0.15];
        let x2 = vec![0.25, 0.28, 0.12, 0.2, 0.15];
        let lhs: Vec<f32> = q
            .apply(&x2)
            .iter()
            .zip(&q.apply(&x1))
            .map(|(a, b)| a - b)
            .collect();
        let rhs = q.apply(&x2.iter().zip(&x1).map(|(a, b)| a - b).collect::<Vec<_>>());
        for (a, b) in lhs.iter().zip(&rhs) {
            assert!((a - b).abs() < 1e-5);
        }
    }
}

#[cfg(test)]
mod stripper_tests {
    use super::*;

    #[test]
    fn identity_direction_is_nulled() {
        let dir = vec![0.6f32, 0.8, 0.0, 0.0, 0.0];
        let s = BiometricTopographyStripper::from_identity_direction(&dir);
        let out = s.strip_identity(&dir).unwrap();
        for v in out {
            assert!(v.abs() < 1e-5, "identity component survived: {v}");
        }
    }

    #[test]
    fn orthogonal_component_survives() {
        let dir = vec![1.0f32, 0.0, 0.0];
        let s = BiometricTopographyStripper::from_identity_direction(&dir);
        let out = s.strip_identity(&[0.0, 3.0, -2.0]).unwrap();
        assert!((out[0]).abs() < 1e-6);
        assert!((out[1] - 3.0).abs() < 1e-5);
        assert!((out[2] + 2.0).abs() < 1e-5);
    }

    #[test]
    fn projection_is_idempotent() {
        let s = BiometricTopographyStripper::from_identity_direction(&[0.5, 0.5, 0.5, 0.5]);
        let x = vec![1.0f32, 0.2, -0.4, 0.9];
        let once = s.strip_identity(&x).unwrap();
        let twice = s.strip_identity(&once).unwrap();
        for (a, b) in once.iter().zip(&twice) {
            assert!((a - b).abs() < 1e-5);
        }
    }

    #[test]
    fn dimension_mismatch_errors() {
        let s = BiometricTopographyStripper::from_identity_direction(&[1.0, 0.0]);
        assert!(s.strip_identity(&[1.0, 2.0, 3.0]).is_err());
    }
}
