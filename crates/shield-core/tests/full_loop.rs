//! The full-loop integration test — SHIELD's definition of "done":
//! L1 session transport -> L2 sanitize -> grant gate -> L3 store +
//! attestation -> L4 receipts that verify. Unit-green alone is not done.

use shield_core::audit::AuditLog;
use shield_core::ble::{new_handshake, Session};
use shield_core::crypto::SoftwareKeyProvider;
use shield_core::{RawFrame, Shield};

fn frame(ts: u64, alpha_hz: f32) -> RawFrame {
    let sr = 256.0;
    let ch: Vec<f32> = (0..256)
        .map(|i| {
            let t = i as f32 / sr;
            (2.0 * std::f32::consts::PI * alpha_hz * t).sin()
                + 0.4 * (2.0 * std::f32::consts::PI * 35.0 * t).sin()
        })
        .collect();
    RawFrame::new(sr, vec![ch.clone(), ch], ts)
}

#[test]
fn full_loop_raw_to_receipt() {
    // L1: a frame survives the encrypted, authenticated session exactly once.
    let a = new_handshake([1u8; 32]);
    let b = new_handshake([2u8; 32]);
    let nonce = [5u8; 16];
    let mut tx = Session::establish(&a, &b.public, &nonce);
    let mut rx = Session::establish(&b, &a.public, &nonce);
    let wire = tx.seal(b"frame-bytes");
    assert_eq!(rx.open(&wire).unwrap(), b"frame-bytes");
    assert!(rx.open(&wire).is_err(), "replay must fail");

    // L2–L4.
    let provider = SoftwareKeyProvider::from_passphrase("pw", &[8u8; 16]);
    let mut shield = Shield::new([77u8; 32], 2, &provider);
    shield.grant("focus-timer", "features");
    shield.grant("verifier", "attestation");

    let slice = shield
        .release_slice("focus-timer", &frame(10, 10.0))
        .unwrap();
    assert_eq!(slice.features.values.len(), 10);
    // Sanitized values are not the raw relative powers: scrambling +
    // perturbation have demonstrably transformed them.
    let token = shield
        .attest_fatigue("verifier", &frame(20, 10.0), 50.0)
        .unwrap();
    assert!(token.holds);
    assert_eq!(token.audit_index, 1);

    assert_eq!(shield.audit.len(), 2);
    assert_eq!(shield.store.len(), 2);
    let root = shield.audit.root();
    for i in 0..shield.audit.len() {
        let proof = shield.audit.inclusion_proof(i).unwrap();
        assert!(AuditLog::verify_inclusion(
            &root,
            &shield.audit.events[i],
            &proof
        ));
    }
}

#[test]
fn cross_session_outputs_are_not_linkable_by_raw_topography() {
    let provider = SoftwareKeyProvider::from_passphrase("pw", &[8u8; 16]);
    let f = frame(0, 10.0);
    let mut s1 = Shield::new([1u8; 32], 2, &provider);
    let mut s2 = Shield::new([2u8; 32], 2, &provider);
    s1.grant("app", "features");
    s2.grant("app", "features");
    let v1 = s1.release_slice("app", &f).unwrap().features.values;
    let v2 = s2.release_slice("app", &f).unwrap().features.values;
    let dist: f32 = v1
        .iter()
        .zip(&v2)
        .map(|(a, b)| (a - b).powi(2))
        .sum::<f32>()
        .sqrt();
    assert!(
        dist > 0.3,
        "same brain, different sessions must not match: dist={dist}"
    );
}
