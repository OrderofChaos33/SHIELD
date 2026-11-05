//! Mirrorfield full-loop test — the L5 definition of "done":
//! a prober enumerates our stack, trips a canary, gets quarantined,
//! and from that moment can never pull real data again — while the
//! audit log proves the order of every step and every receipt
//! verifies. NO FREE DATA throughout: an ungranted prober gets
//! nothing, not even the mirror.

use shield_core::crypto::SoftwareKeyProvider;
use shield_core::mirrorfield::{Mirrorfield, Posture, ProbeEvent, ProbeKind};
use shield_core::{RawFrame, Shield};

const CANARIES: [&str; 2] = ["canary-uuid-alpha", "canary-uuid-beta"];

fn frame(ts: u64) -> RawFrame {
    let sr = 256.0;
    let ch: Vec<f32> = (0..256)
        .map(|i| (2.0 * std::f32::consts::PI * 10.0 * i as f32 / sr).sin())
        .collect();
    RawFrame::new(sr, vec![ch.clone(), ch], ts)
}

fn read(peer: &str, target: &str, ts: u64) -> ProbeEvent {
    ProbeEvent {
        peer_id: peer.into(),
        kind: ProbeKind::CharacteristicRead,
        target: Some(target.into()),
        timestamp_ms: ts,
    }
}

#[test]
fn mirrorfield_full_loop() {
    let provider = SoftwareKeyProvider::from_passphrase("pw", &[8u8; 16]);
    let mut shield = Shield::new([77u8; 32], 2, &provider);
    let mut mf = Mirrorfield::new([9u8; 32], &CANARIES, 2);

    // A legitimate granted app works normally through the router.
    shield.grant("focus-timer", "features");
    let real = mf
        .serve_consumer(&mut shield, "focus-timer", &frame(0))
        .unwrap();
    assert_eq!(shield.audit.events[real.audit_index].scope, "features");

    // An ungranted stranger enumerates: distinct characteristics in a
    // tight window. Every probe is logged BEFORE any response exists.
    for i in 0..6 {
        let out = mf.observe_probe(
            &mut shield.audit,
            &read("prober", &format!("real-uuid-{i}"), 100 + i * 10),
        );
        assert_eq!(shield.audit.events[out.audit_index].app_id, "prober");
    }
    assert_eq!(mf.posture(), Posture::Alert);

    // NO FREE DATA: the ungranted prober asks for features and gets
    // nothing — no real slice, no mirror, no new release event.
    let len_before = shield.audit.len();
    assert!(mf
        .serve_consumer(&mut shield, "prober", &frame(200))
        .is_err());
    assert_eq!(shield.audit.len(), len_before);

    // The prober keeps enumerating and touches a canary: quarantine.
    let out = mf.observe_probe(&mut shield.audit, &read("prober", "canary-uuid-alpha", 300));
    assert!(mf.is_quarantined("prober"));
    assert_eq!(
        shield.audit.events[out.audit_index].scope,
        "mirrorfield:probe:canary_touch"
    );

    // Twist: the prober was actually a granted app gone rogue.
    shield.grant("prober", "features");
    let mirror = mf
        .serve_consumer(&mut shield, "prober", &frame(400))
        .unwrap();
    assert_eq!(
        shield.audit.events[mirror.audit_index].scope,
        "features:mirror"
    );
    assert_ne!(mirror.features.values, real.features.values);

    // Panic: even the good app is mirrored until the owner clears.
    mf.panic(&mut shield.audit, 500);
    let locked = mf
        .serve_consumer(&mut shield, "focus-timer", &frame(600))
        .unwrap();
    assert_eq!(
        shield.audit.events[locked.audit_index].scope,
        "features:mirror"
    );
    mf.owner_clear(&mut shield.audit, 700);
    let resumed = mf
        .serve_consumer(&mut shield, "focus-timer", &frame(800))
        .unwrap();
    assert_eq!(shield.audit.events[resumed.audit_index].scope, "features");
    // …but the prober stays quarantined after the clear.
    let still = mf
        .serve_consumer(&mut shield, "prober", &frame(900))
        .unwrap();
    assert_eq!(
        shield.audit.events[still.audit_index].scope,
        "features:mirror"
    );

    // Every event in the log carries a receipt that verifies.
    for i in 0..shield.audit.len() {
        let receipt = shield.audit.receipt(i).unwrap();
        assert!(receipt.verify(), "receipt {i} must verify");
    }
}
