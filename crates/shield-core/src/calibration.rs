//! Inter-subject variability calibration (Layer 2 support).
//!
//! ε cannot be static: a noise level that is harmless on a clean,
//! high-SNR brain destroys a low-SNR user's local apps, and a gentle
//! ε on a clean signal is a sieve for cloud decoders. This calibrator
//! estimates the live noise floor (per-dimension variance over a
//! rolling window of feature vectors) and the signal dynamic range,
//! then scales ε = range / (noise_floor · target_snr), hard-clamped
//! to [min_epsilon, max_epsilon].
//!
//! Behavior contract:
//! - Noisy / artifact-heavy stream  -> ε scales DOWN (protect local utility).
//! - Stable, clean, strong stream  -> ε scales UP (max adversarial strength).
//! - ε NEVER leaves [min, max], whatever the stream does.
//!
//! Call-site rule (pipeline): the calibrator needs >= 3 windows —
//! with 1 window the variance is degenerately zero. Until then the
//! pipeline uses its configured base ε.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationProfile {
    pub baseline_noise_floor: f32,
    pub signal_dynamic_range: f32,
    pub adjusted_epsilon: f32,
}

pub struct EpsilonCalibrator {
    min_epsilon: f32,
    max_epsilon: f32,
    target_snr_ratio: f32,
}

impl Default for EpsilonCalibrator {
    /// Bounds chosen against relative-power features (values in [0,1]):
    /// 0.02 is the floor below which perturbation is cosmetic;
    /// 0.15 is the ceiling above which local-app distortion dominates.
    fn default() -> Self {
        Self::new(0.02, 0.15, 20.0)
    }
}

impl EpsilonCalibrator {
    pub fn new(min_epsilon: f32, max_epsilon: f32, target_snr_ratio: f32) -> Self {
        Self {
            min_epsilon,
            max_epsilon,
            target_snr_ratio,
        }
    }

    pub fn bounds(&self) -> (f32, f32) {
        (self.min_epsilon, self.max_epsilon)
    }

    /// Evaluate a rolling window of band-power feature vectors.
    pub fn calibrate(
        &self,
        recent_feature_windows: &[Vec<f32>],
    ) -> Result<CalibrationProfile, String> {
        if recent_feature_windows.is_empty() {
            return Err("Insufficient window data for calibration".into());
        }
        let channel_count = recent_feature_windows[0].len();
        if recent_feature_windows
            .iter()
            .any(|w| w.len() != channel_count)
        {
            return Err("Inconsistent window dimensions".into());
        }
        let window_count = recent_feature_windows.len();

        // 1. Mean power per feature dimension.
        let mut mean_vector = vec![0.0f32; channel_count];
        for window in recent_feature_windows {
            for (i, val) in window.iter().enumerate() {
                mean_vector[i] += val;
            }
        }
        for val in mean_vector.iter_mut() {
            *val /= window_count as f32;
        }

        // 2. Variance per dimension (noise-floor proxy), aggregated.
        let mut variance_vector = vec![0.0f32; channel_count];
        for window in recent_feature_windows {
            for (i, val) in window.iter().enumerate() {
                let diff = val - mean_vector[i];
                variance_vector[i] += diff * diff;
            }
        }
        for val in variance_vector.iter_mut() {
            *val /= window_count as f32;
        }
        let global_variance: f32 = variance_vector.iter().sum::<f32>() / channel_count as f32;
        let baseline_noise_floor = global_variance.sqrt();

        // 3. Dynamic range of the active signal.
        let mut min_val = f32::MAX;
        let mut max_val = f32::MIN;
        for window in recent_feature_windows {
            for val in window {
                min_val = min_val.min(*val);
                max_val = max_val.max(*val);
            }
        }
        let signal_dynamic_range = (max_val - min_val).max(1e-5);

        // 4. Scale ε, clamped to operational bounds. A zero noise floor
        // (perfectly stable stream) yields +inf pre-clamp -> max ε,
        // which is the intended "clean signal, full strength" branch.
        let calculated_epsilon = (signal_dynamic_range
            / (baseline_noise_floor * self.target_snr_ratio))
            .clamp(self.min_epsilon, self.max_epsilon);

        Ok(CalibrationProfile {
            baseline_noise_floor,
            signal_dynamic_range,
            adjusted_epsilon: calculated_epsilon,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stable_windows() -> Vec<Vec<f32>> {
        (0..10)
            .map(|_| vec![0.10, 0.20, 0.35, 0.20, 0.15])
            .collect()
    }

    fn noisy_windows() -> Vec<Vec<f32>> {
        // Jitter WITHIN the same overall range as the stable fixture:
        // energy swaps between dimensions window-to-window (muscle
        // artifact proxy). Holding range constant matters — the first
        // version of this fixture also inflated dynamic range, which
        // cancels the variance effect in the ε formula and made both
        // fixtures clamp to max ε. That was a fixture bug, not an
        // algorithm bug; the algorithm is the spec's, unchanged.
        (0..10)
            .map(|i| {
                if i % 2 == 0 {
                    vec![0.0, 0.35]
                } else {
                    vec![0.35, 0.0]
                }
            })
            .collect()
    }

    #[test]
    fn empty_windows_error() {
        assert!(EpsilonCalibrator::default().calibrate(&[]).is_err());
    }

    #[test]
    fn epsilon_always_within_bounds() {
        let cal = EpsilonCalibrator::default();
        for windows in [stable_windows(), noisy_windows()] {
            let p = cal.calibrate(&windows).unwrap();
            assert!(p.adjusted_epsilon >= 0.02 && p.adjusted_epsilon <= 0.15);
        }
    }

    #[test]
    fn stable_signal_gets_stronger_epsilon_than_noisy() {
        let cal = EpsilonCalibrator::default();
        let stable = cal.calibrate(&stable_windows()).unwrap();
        let noisy = cal.calibrate(&noisy_windows()).unwrap();
        assert!(
            stable.adjusted_epsilon > noisy.adjusted_epsilon,
            "stable {} should exceed noisy {}",
            stable.adjusted_epsilon,
            noisy.adjusted_epsilon
        );
        assert!(noisy.baseline_noise_floor > stable.baseline_noise_floor);
    }

    #[test]
    fn inconsistent_dimensions_error() {
        let cal = EpsilonCalibrator::default();
        let windows = vec![vec![0.1, 0.2], vec![0.1]];
        assert!(cal.calibrate(&windows).is_err());
    }
}
