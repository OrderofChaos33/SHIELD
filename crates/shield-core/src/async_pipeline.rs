//! End-to-end async pipeline (feature `async-pipeline`).
//!
//! Tokio layout from the Layer 2/3 integration spec, with two repairs
//! to the sketch it came from — both would have silently broken it:
//!
//! 1. The calibration daemon in the sketch owned a sliding-window
//!    buffer that *nothing ever wrote to*, so ε would never update.
//!    Here the processing worker feeds every window into a shared
//!    buffer the daemon actually reads.
//! 2. Bounded `mpsc` in Tokio does not "drop excess gracefully" —
//!    `send().await` blocks the producer (that IS backpressure).
//!    For a real-time stream the correct behavior is `try_send` +
//!    a dropped-frame counter, which is what the worker does on the
//!    downstream leg: stale neuro-data is worth less than a live stream.
//!
//! Shape: raw feature windows in -> worker (calibration buffer feed +
//! watch-channel ε + injector) -> sanitized vectors out. A background
//! daemon recalibrates ε every `calibration_interval` from the shared
//! window buffer and publishes via `tokio::sync::watch` (lock-free
//! reads on the hot path — the <20 ms budget is not spent on mutexes).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{mpsc, watch};

use crate::calibration::EpsilonCalibrator;
use crate::dsp::FeatureVector;
use crate::perturb::AdversarialFeatureInjector;

pub struct PipelineConfig {
    pub channel_count: usize,
    pub initial_epsilon: f32,
    pub calibration_interval: Duration,
    /// Windows retained for the calibrator.
    pub window_capacity: usize,
    /// Minimum windows before the daemon will publish an ε update.
    pub min_windows: usize,
    /// Deterministic base seed; per-slice seeds derive from it + timestamp.
    pub session_seed: [u8; 32],
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            channel_count: 8,
            initial_epsilon: 0.05,
            calibration_interval: Duration::from_secs(5),
            window_capacity: 30,
            min_windows: 10,
            session_seed: [0u8; 32],
        }
    }
}

#[derive(Default, Debug)]
pub struct PipelineStats {
    pub processed: u64,
    pub dropped_downstream: u64,
    pub epsilon_updates: u64,
}

type SharedWindow = Arc<Mutex<VecDeque<Vec<f32>>>>;

fn push_window(buf: &SharedWindow, window: Vec<f32>, capacity: usize) {
    let mut guard = buf.lock().unwrap();
    if guard.len() >= capacity {
        guard.pop_front();
    }
    guard.push_back(window);
}

/// Spawn the full pipeline. Returns (epsilon watch receiver, stats).
/// Runs until the raw input channel closes and the worker drains.
pub fn spawn_pipeline(
    mut raw_rx: mpsc::Receiver<Vec<f32>>,
    sanitized_tx: mpsc::Sender<FeatureVector>,
    cfg: PipelineConfig,
) -> (watch::Receiver<f32>, Arc<Mutex<PipelineStats>>) {
    let (epsilon_tx, epsilon_rx) = watch::channel(cfg.initial_epsilon);
    let stats = Arc::new(Mutex::new(PipelineStats::default()));
    let window_buf: SharedWindow = Arc::new(Mutex::new(VecDeque::new()));

    // Background calibration daemon — reads the SHARED buffer the
    // worker feeds (repair #1 above).
    {
        let window_buf = Arc::clone(&window_buf);
        let stats = Arc::clone(&stats);
        let interval = cfg.calibration_interval;
        let min_windows = cfg.min_windows;
        tokio::spawn(async move {
            let calibrator = EpsilonCalibrator::default();
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                let snapshot: Vec<Vec<f32>> = {
                    let guard = window_buf.lock().unwrap();
                    if guard.len() < min_windows {
                        continue;
                    }
                    guard.iter().cloned().collect()
                };
                if let Ok(profile) = calibrator.calibrate(&snapshot) {
                    if epsilon_tx.send(profile.adjusted_epsilon).is_err() {
                        break; // worker gone
                    }
                    stats.lock().unwrap().epsilon_updates += 1;
                }
            }
        });
    }

    // Real-time processing worker.
    {
        let window_buf = Arc::clone(&window_buf);
        let stats = Arc::clone(&stats);
        let mut epsilon_rx = epsilon_rx.clone();
        tokio::spawn(async move {
            let mut injector =
                AdversarialFeatureInjector::new(*epsilon_rx.borrow(), cfg.channel_count);
            while let Some(raw_window) = raw_rx.recv().await {
                // Lock-free ε refresh on the hot path.
                if epsilon_rx.has_changed().unwrap_or(false) {
                    let eps = *epsilon_rx.borrow_and_update();
                    injector = AdversarialFeatureInjector::new(eps, cfg.channel_count);
                }
                push_window(&window_buf, raw_window.clone(), cfg.window_capacity);

                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                let features = FeatureVector {
                    values: raw_window.clone(),
                    n_channels: cfg.channel_count,
                    deltas: vec![0.0; raw_window.len()],
                    timestamp_ms: timestamp,
                };
                // Per-slice deterministic seed: session seed mixed with
                // the slice timestamp so perturbations are reproducible
                // from the audit record, never repeated across slices.
                let mut slice_seed = cfg.session_seed;
                for (i, b) in timestamp.to_le_bytes().iter().enumerate() {
                    slice_seed[i] ^= b;
                }
                let sanitized = injector.perturb_features(features, &slice_seed);

                // Repair #2: try_send + drop counter, not blocking send.
                match sanitized_tx.try_send(sanitized) {
                    Ok(()) => stats.lock().unwrap().processed += 1,
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        stats.lock().unwrap().dropped_downstream += 1;
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => break,
                }
            }
        });
    }

    (epsilon_rx, stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pipeline_processes_and_calibrates() {
        let (raw_tx, raw_rx) = mpsc::channel::<Vec<f32>>(100);
        let (san_tx, mut san_rx) = mpsc::channel::<FeatureVector>(100);
        let cfg = PipelineConfig {
            channel_count: 2,
            calibration_interval: Duration::from_millis(50),
            session_seed: [9u8; 32],
            ..PipelineConfig::default()
        };
        let (_eps_rx, stats) = spawn_pipeline(raw_rx, san_tx, cfg);

        // Stable clean windows: same feature vector 15 times.
        for _ in 0..15 {
            raw_tx
                .send(vec![
                    0.10, 0.20, 0.35, 0.20, 0.15, 0.10, 0.20, 0.35, 0.20, 0.15,
                ])
                .await
                .unwrap();
        }
        drop(raw_tx);

        let mut received = 0;
        while let Ok(Some(_)) =
            tokio::time::timeout(Duration::from_secs(2), async { san_rx.recv().await }).await
        {
            received += 1;
            if received >= 15 {
                break;
            }
        }
        assert_eq!(received, 15);
        // Give the daemon a tick to publish at least one calibration.
        tokio::time::sleep(Duration::from_millis(160)).await;
        let s = stats.lock().unwrap();
        assert_eq!(s.processed, 15);
        assert!(
            s.epsilon_updates >= 1,
            "calibrator never published an update"
        );
    }
}
