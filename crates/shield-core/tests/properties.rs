//! Property-based invariant suite (Execution Standard §2).
//! Randomized inputs, invariant assertions — the Rust counterpart of
//! Foundry's stateful invariant campaigns. CI runs these at
//! PROPTEST_CASES=4096; local default is 256.
//!
//! Invariants covered: INV-L1-04, INV-L2-02, INV-L2-05, INV-L4-02,
//! INV-L5-03, INV-L5-06.

use proptest::prelude::*;
use shield_core::audit::{hex, sha256, AuditEvent, AuditLog};
use shield_core::ble::DeviceSeqTracker;
use shield_core::dsp::TopographyScrambler;
use shield_core::perturb::{perturb, PerturbationConfig};

use shield_core::mirrorfield::{
    DecoyPersona, MirrorfieldConfig, ProbeDetector, ProbeEvent, ProbeKind,
};

fn feature_vec(max_dim: usize) -> impl Strategy<Value = Vec<f32>> {
    prop::collection::vec(-1.0f32..1.0, 5..=max_dim).prop_map(|mut v| {
        // Feature vectors are channel-major in groups of 5 bands.
        let rem = v.len() % 5;
        if rem != 0 {
            v.truncate(v.len() - rem);
        }
        if v.is_empty() {
            v = vec![0.1; 5];
        }
        v
    })
}

proptest! {
    /// INV-L2-05: no input, no seed, no epsilon in range escapes the ball.
    #[test]
    fn perturbation_always_within_epsilon(
        features in feature_vec(40),
        seed in any::<[u8; 32]>(),
        eps_milli in 10u32..200,
    ) {
        let epsilon = eps_milli as f32 / 1000.0;
        let n_channels = features.len() / 5;
        let (out, max_delta) = perturb(
            &features,
            n_channels,
            PerturbationConfig { epsilon },
            &seed,
        );
        prop_assert!(max_delta <= epsilon + 1e-6);
        for (a, b) in features.iter().zip(&out) {
            prop_assert!((a - b).abs() <= epsilon + 1e-6);
        }
        // INV-L2-06 under randomization: non-target bands never move.
        for i in 0..features.len() {
            if i % 5 != 2 && i % 5 != 4 {
                prop_assert_eq!(features[i], out[i]);
            }
        }
    }

    /// INV-L2-02: scrambling preserves norms for arbitrary vectors/dims.
    #[test]
    fn scrambler_preserves_norm(
        x in prop::collection::vec(-2.0f32..2.0, 5..=25),
        seed in any::<[u8; 32]>(),
    ) {
        let q = TopographyScrambler::from_session_seed(&seed, x.len());
        prop_assert!(q.orthogonality_error() < 1e-3);
        let y = q.apply(&x);
        let nx = x.iter().map(|v| v * v).sum::<f32>().sqrt();
        let ny = y.iter().map(|v| v * v).sum::<f32>().sqrt();
        prop_assert!((nx - ny).abs() < 1e-2, "norm drift {} vs {}", nx, ny);
    }

    /// INV-L4-02: every leaf of a random-sized log proves inclusion.
    #[test]
    fn audit_inclusion_always_verifies(n in 1usize..40, salt in any::<u64>()) {
        let mut log = AuditLog::new();
        for i in 0..n {
            log.append(AuditEvent {
                timestamp_ms: salt.wrapping_add(i as u64),
                app_id: format!("app-{}", i % 3),
                scope: "features".into(),
                epsilon: 0.08,
                record_commitment: hex(&sha256(format!("r-{salt}-{i}").as_bytes())),
            });
        }
        let root = log.root();
        for i in 0..n {
            let proof = log.inclusion_proof(i).unwrap();
            prop_assert!(AuditLog::verify_inclusion(&root, &log.events[i], &proof));
            // And a receipt issued for it verifies end-to-end.
            prop_assert!(log.receipt(i).unwrap().verify());
        }
    }

    /// INV-L1-04: a replayed or stale u16 sequence is never accepted,
    /// whatever the starting epoch; the immediate successor always is
    /// (including across the wrap).
    #[test]
    fn device_seq_never_accepts_replay(start in any::<u16>(), steps in 1u16..200) {
        let mut t = DeviceSeqTracker::default();
        prop_assert!(t.check_and_advance(start));
        let mut cur = start;
        for _ in 0..steps {
            let next = cur.wrapping_add(1);
            prop_assert!(t.check_and_advance(next), "successor {} after {} rejected", next, cur);
            prop_assert!(!t.check_and_advance(next), "replay of {} accepted", next);
            prop_assert!(!t.check_and_advance(cur), "stale {} accepted", cur);
            cur = next;
        }
    }

    /// INV-L5-06: probe scores and verdicts never decrease, whatever
    /// sequence of probe events a peer generates.
    #[test]
    fn probe_scores_never_decrease(
        kinds in prop::collection::vec(0usize..8, 1..40),
    ) {
        const KINDS: [ProbeKind; 8] = [
            ProbeKind::ConnectAttempt,
            ProbeKind::PairingAttempt,
            ProbeKind::ServiceDiscovery,
            ProbeKind::CharacteristicRead,
            ProbeKind::CharacteristicWrite,
            ProbeKind::CanaryTouch,
            ProbeKind::MalformedFrame,
            ProbeKind::ReconnectBurst,
        ];
        let mut d = ProbeDetector::new(MirrorfieldConfig::default());
        let mut prev_score = 0u32;
        let mut prev_verdict = shield_core::mirrorfield::PeerVerdict::Unknown;
        for (i, k) in kinds.iter().enumerate() {
            let v = d.observe(&ProbeEvent {
                peer_id: "peer".into(),
                kind: KINDS[*k],
                target: Some(format!("uuid-{}", i % 3)),
                timestamp_ms: i as u64 * 100,
            });
            prop_assert!(d.score("peer") >= prev_score, "score decreased");
            prop_assert!(v >= prev_verdict, "verdict decreased");
            prev_score = d.score("peer");
            prev_verdict = v;
        }
    }

    /// INV-L5-03 (determinism half): persona output is a pure function
    /// of (seed, serve count) — two personas with the same seed emit
    /// identical mirror sequences; frame-independence holds by API
    /// construction and is covered by unit + integration tests.
    #[test]
    fn mirror_is_frame_independent(
        seed in any::<[u8; 32]>(),
        serves in 1usize..8,
    ) {
        let mut a = DecoyPersona::new(seed, &["canary-x"], 2);
        let mut b = DecoyPersona::new(seed, &["canary-x"], 2);
        for i in 0..serves {
            let fa = a.synthetic_features(2, 1_000 + i as u64);
            let fb = b.synthetic_features(2, 9_999 + i as u64);
            prop_assert_eq!(fa.values.len(), 10);
            prop_assert_eq!(fa.values, fb.values);
        }
    }
}
