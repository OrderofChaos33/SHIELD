//! shield-cli — end-to-end demonstration on a synthetic headset.
//!
//! Flow proven here, in order:
//! 1. Layer 1: X25519 handshake, sealed frame over a mock transport,
//!    opened on the phone side; a replayed copy of the same frame is dropped.
//! 2. Layer 2+4: grant-checked, audit-logged release of a sanitized
//!    feature slice to a local app.
//! 3. Layer 3+4: an attestation token for an external requester —
//!    boolean only — also audit-logged.
//! 4. Receipt check: the audit root + inclusion proofs verify.

use shield_core::audit::AuditLog;
use shield_core::ble::{new_handshake, MockTransport, Session, Transport};
use shield_core::crypto::SoftwareKeyProvider;
use shield_core::{RawFrame, Shield};

fn synthetic_frame(ts: u64) -> RawFrame {
    let sr = 256.0;
    let mk = |phase: f32| -> Vec<f32> {
        (0..256)
            .map(|i| {
                let t = i as f32 / sr;
                (2.0 * std::f32::consts::PI * 10.0 * t + phase).sin()
                    + 0.6 * (2.0 * std::f32::consts::PI * 6.0 * t).sin()
                    + 0.3 * (2.0 * std::f32::consts::PI * 40.0 * t).sin()
            })
            .collect()
    };
    RawFrame::new(sr, vec![mk(0.0), mk(0.7), mk(1.4), mk(2.1)], ts)
}

fn main() {
    println!("SHIELD — end-to-end demo (synthetic headset, no real telemetry)\n");

    // ---- Layer 1: session + framed transport + replay drop ----
    let headset = new_handshake([101u8; 32]);
    let phone = new_handshake([202u8; 32]);
    let nonce = [7u8; 16];
    let mut tx = Session::establish(&headset, &phone.public, &nonce);
    let mut rx = Session::establish(&phone, &headset.public, &nonce);

    let frame = synthetic_frame(1_700_000_000_000);
    let payload = {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&frame.timestamp_ms.to_le_bytes());
        for ch in &frame.channels {
            for s in ch {
                bytes.extend_from_slice(&s.to_le_bytes());
            }
        }
        bytes
    };
    let wire = tx.seal(&payload);
    let mut transport = MockTransport::default();
    transport.inbox.push(wire.clone());
    transport.inbox.push(wire.clone()); // attacker replays the capture
    let first = transport.poll().unwrap();
    let opened = rx.open(&first).expect("first frame must open");
    assert_eq!(opened, payload);
    let replay = transport.poll().unwrap();
    let replay_result = rx.open(&replay);
    println!("[L1] sealed frame opened ok ({} bytes)", opened.len());
    println!(
        "[L1] replayed frame -> {:?} (dropped)",
        replay_result.unwrap_err()
    );

    // ---- Layers 2–4: shielded release + attestation ----
    let provider = SoftwareKeyProvider::from_passphrase("demo-passphrase", &[9u8; 16]);
    let mut shield = Shield::new([42u8; 32], 4, &provider);

    // No grant yet: denied, and nothing is logged.
    match shield.release_slice("focus-timer", &frame) {
        Err(e) => println!("[L2] ungranted app denied: {e:?}"),
        Ok(_) => panic!("ungranted release must never succeed"),
    }

    shield.grant("focus-timer", "features");
    shield.grant("wellness-verifier", "attestation");

    let slice = shield
        .release_slice("focus-timer", &frame)
        .expect("granted release");
    println!(
        "[L2] sanitized slice released: {} features, epsilon={}, audit_index={}",
        slice.features.values.len(),
        slice.epsilon_applied,
        slice.audit_index
    );
    println!("[L2] first features: {:?}", &slice.features.values[..5]);

    let token = shield
        .attest_fatigue("wellness-verifier", &frame, 2.5)
        .expect("granted attestation");
    println!("[L3] attestation token (the only thing that leaves the device):");
    println!("     {}", serde_json::to_string_pretty(&token).unwrap());

    // ---- Receipt verification ----
    let root = shield.audit.root();
    for idx in 0..shield.audit.len() {
        let proof = shield.audit.inclusion_proof(idx).unwrap();
        let ok = AuditLog::verify_inclusion(&root, &shield.audit.events[idx], &proof);
        assert!(ok, "audit inclusion proof {idx} must verify");
    }
    println!(
        "[L4] audit log: {} events, root={}, all inclusion proofs verify",
        shield.audit.len(),
        shield.audit.root_hex()
    );
    println!(
        "[L3] encrypted store: {} sealed records, backing={}",
        shield.store.len(),
        shield.store.backing
    );
    println!("\nFull loop verified: raw -> sanitized -> token -> receipt. Raw frames never left the core.");
}
