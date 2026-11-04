//! Latency budget test (Layer 2 spec): the feature-space pipeline —
//! extract, scramble, strip, perturb — must run far inside the 20 ms
//! real-time budget on commodity hardware. This test asserts the mean
//! per-frame cost over 200 frames stays under 20 ms on the CI machine;
//! in practice it is sub-millisecond (feature space, not time series).

use shield_core::crypto::SoftwareKeyProvider;
use shield_core::{RawFrame, Shield};
use std::time::Instant;

#[test]
fn feature_pipeline_inside_20ms_budget() {
    let provider = SoftwareKeyProvider::from_passphrase("pw", &[6u8; 16]);
    let mut shield = Shield::new([13u8; 32], 8, &provider);
    shield.grant("bench-app", "features");

    let sr = 256.0;
    let mk_frame = |ts: u64| {
        let channels: Vec<Vec<f32>> = (0..8)
            .map(|c| {
                (0..256)
                    .map(|i| {
                        let t = i as f32 / sr;
                        (2.0 * std::f32::consts::PI * (8.0 + c as f32) * t).sin()
                    })
                    .collect()
            })
            .collect();
        RawFrame::new(sr, channels, ts)
    };

    // Warm-up (baseline + calibration window).
    for i in 0..10 {
        let _ = shield.release_slice("bench-app", &mk_frame(i)).unwrap();
    }

    let start = Instant::now();
    let n = 200;
    for i in 0..n {
        let _ = shield
            .release_slice("bench-app", &mk_frame(100 + i))
            .unwrap();
    }
    let mean_ms = start.elapsed().as_secs_f64() * 1000.0 / n as f64;
    assert!(
        mean_ms < 20.0,
        "mean per-frame cost {mean_ms:.3} ms exceeds the 20 ms budget"
    );
}
