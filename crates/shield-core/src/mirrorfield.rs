//! Layer 5 — Mirrorfield: active defense on the owner's own perimeter.
//!
//! Scope (founder rule, 2026-11-05: never break the law, ever): this
//! layer DETECTS probing of our own stack, DECEIVES probers with a
//! synthetic persona, HARDENS our own advertisements, and LOCKS DOWN
//! our own releases. It contains nothing that transmits interference,
//! disables, deauthenticates, or degrades another party's device.
//!
//! Pieces:
//! - [`ProbeDetector`] scores per-peer probing behavior (connection
//!   attempts, enumeration, malformed frames, canary touches).
//! - [`DecoyPersona`] is a synthetic BLE identity: rotating persona
//!   IDs and watermarked canary characteristics. A watermark found in
//!   leaked data attributes the leak to the decoy path that served it.
//! - [`sanitize_advertisement`] strips identifying fields from OUR
//!   advertisements before broadcast.
//! - [`Mirrorfield`] is the posture state machine (Normal → Alert →
//!   Lockdown) that routes consumers: trusted peers get the normal
//!   governed pipeline; quarantined peers — and everyone during
//!   Lockdown — get persona-synthetic mirror features, audit-logged
//!   like any other release. The mirror path never reads the real
//!   frame (INV-L5-03): a hostile consumer is talking to the mirror,
//!   and the mirror doesn't know anything real.
//!
//! NO FREE DATA (founder rule, 2026-11-05): the mirror is a degraded
//! service under an EXISTING grant, not a handout. A consumer with no
//! `features` grant receives nothing at all — real, mirror, or decoy —
//! regardless of posture or quarantine state (INV-L5-02).

use std::collections::{HashMap, HashSet};

use crate::audit::{hex, sha256, AuditEvent, AuditLog};
use crate::dsp::FeatureVector;
use crate::pipeline::{ReleasedSlice, Shield, ShieldError};
use crate::prng::Rng;

/// ε recorded on mirror releases: maximum obfuscation, stated honestly
/// on the receipt — the values are synthetic, and the receipt's scope
/// (`features:mirror`) says so to any verifier who checks.
pub const MIRROR_EPSILON: f32 = 0.15;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeKind {
    ConnectAttempt,
    PairingAttempt,
    ServiceDiscovery,
    CharacteristicRead,
    CharacteristicWrite,
    CanaryTouch,
    MalformedFrame,
    ReconnectBurst,
}

impl ProbeKind {
    /// Suspicion weight. Reading one characteristic is normal; a
    /// canary touch is definitive — the canary is never advertised to
    /// legitimate consumers, so only enumeration finds it.
    fn weight(&self) -> u32 {
        match self {
            ProbeKind::ConnectAttempt => 1,
            ProbeKind::ServiceDiscovery => 2,
            ProbeKind::CharacteristicRead => 1,
            ProbeKind::CharacteristicWrite => 3,
            ProbeKind::PairingAttempt => 4,
            ProbeKind::ReconnectBurst => 4,
            ProbeKind::MalformedFrame => 6,
            ProbeKind::CanaryTouch => 100,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            ProbeKind::ConnectAttempt => "connect_attempt",
            ProbeKind::PairingAttempt => "pairing_attempt",
            ProbeKind::ServiceDiscovery => "service_discovery",
            ProbeKind::CharacteristicRead => "characteristic_read",
            ProbeKind::CharacteristicWrite => "characteristic_write",
            ProbeKind::CanaryTouch => "canary_touch",
            ProbeKind::MalformedFrame => "malformed_frame",
            ProbeKind::ReconnectBurst => "reconnect_burst",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProbeEvent {
    pub peer_id: String,
    pub kind: ProbeKind,
    /// Characteristic UUID for read/write/canary events.
    pub target: Option<String>,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum PeerVerdict {
    #[default]
    Unknown = 0,
    Suspicious = 1,
    Hostile = 2,
}

#[derive(Debug, Clone, Copy)]
pub struct MirrorfieldConfig {
    pub suspicious_threshold: u32,
    pub hostile_threshold: u32,
    /// Distinct characteristics read inside the window ⇒ enumeration.
    pub enumeration_distinct_threshold: usize,
    pub enumeration_window_ms: u64,
}

impl Default for MirrorfieldConfig {
    fn default() -> Self {
        Self {
            suspicious_threshold: 8,
            hostile_threshold: 20,
            enumeration_distinct_threshold: 6,
            enumeration_window_ms: 10_000,
        }
    }
}

#[derive(Default)]
struct PeerRecord {
    score: u32,
    verdict: PeerVerdict,
    quarantined: bool,
    /// (timestamp, characteristic) read history for enumeration checks.
    reads: Vec<(u64, String)>,
    canary_touches: u32,
}

/// Scores probing behavior per peer. Scores are monotonic (INV-L5-06):
/// observing more events never lowers a score or a verdict.
pub struct ProbeDetector {
    cfg: MirrorfieldConfig,
    peers: HashMap<String, PeerRecord>,
}

impl ProbeDetector {
    pub fn new(cfg: MirrorfieldConfig) -> Self {
        Self {
            cfg,
            peers: HashMap::new(),
        }
    }

    pub fn score(&self, peer_id: &str) -> u32 {
        self.peers.get(peer_id).map(|p| p.score).unwrap_or(0)
    }

    pub fn verdict(&self, peer_id: &str) -> PeerVerdict {
        self.peers
            .get(peer_id)
            .map(|p| p.verdict)
            .unwrap_or(PeerVerdict::Unknown)
    }

    pub fn is_quarantined(&self, peer_id: &str) -> bool {
        self.peers
            .get(peer_id)
            .map(|p| p.quarantined)
            .unwrap_or(false)
    }

    /// Feed one observed event. Returns the peer's verdict afterwards.
    pub fn observe(&mut self, ev: &ProbeEvent) -> PeerVerdict {
        let rec = self.peers.entry(ev.peer_id.clone()).or_default();
        rec.score = rec.score.saturating_add(ev.kind.weight());

        if let (ProbeKind::CharacteristicRead, Some(target)) = (ev.kind, &ev.target) {
            rec.reads.push((ev.timestamp_ms, target.clone()));
            // Enumeration: many DISTINCT characteristics inside the window.
            let window_start = ev
                .timestamp_ms
                .saturating_sub(self.cfg.enumeration_window_ms);
            let distinct: HashSet<&String> = rec
                .reads
                .iter()
                .filter(|(ts, _)| *ts >= window_start)
                .map(|(_, uuid)| uuid)
                .collect();
            if distinct.len() >= self.cfg.enumeration_distinct_threshold {
                rec.score = rec.score.saturating_add(10);
            }
        }

        if ev.kind == ProbeKind::CanaryTouch {
            rec.canary_touches += 1;
            rec.quarantined = true; // INV-L5-01
        }
        if rec.score >= self.cfg.hostile_threshold {
            rec.quarantined = true;
        }

        let new_verdict = if rec.quarantined || rec.score >= self.cfg.hostile_threshold {
            PeerVerdict::Hostile
        } else if rec.score >= self.cfg.suspicious_threshold {
            PeerVerdict::Suspicious
        } else {
            PeerVerdict::Unknown
        };
        if new_verdict > rec.verdict {
            rec.verdict = new_verdict;
        }
        rec.verdict
    }
}

/// A watermarked decoy characteristic. The watermark is
/// `sha256(persona_seed ‖ uuid)` truncated — stable per seed (so a
/// leaked value can be attributed) and unique per characteristic.
#[derive(Debug, Clone, PartialEq)]
pub struct CanaryCharacteristic {
    pub uuid: String,
    pub watermark: String,
    pub value: Vec<u8>,
}

/// The synthetic identity a prober meets. Everything it serves is a
/// deterministic function of the persona seed — no real data is ever
/// an input (INV-L5-03).
pub struct DecoyPersona {
    seed: [u8; 32],
    canaries: Vec<CanaryCharacteristic>,
    serve_counter: u64,
    baseline: Vec<f32>,
}

impl DecoyPersona {
    pub fn new(seed: [u8; 32], canary_uuids: &[&str], n_channels: usize) -> Self {
        let canaries = canary_uuids
            .iter()
            .map(|uuid| {
                let mut material = seed.to_vec();
                material.extend_from_slice(uuid.as_bytes());
                let watermark = hex(&sha256(&material)[..8]);
                let mut rng = Rng::from_seed(&sha256(&material));
                let mut value = vec![0u8; 8];
                rng.fill_bytes(&mut value);
                CanaryCharacteristic {
                    uuid: (*uuid).to_string(),
                    watermark,
                    value,
                }
            })
            .collect();
        // Persona baseline: pleasant, plausible, entirely invented.
        let mut rng = Rng::from_seed(&sha256(&seed));
        let baseline: Vec<f32> = (0..n_channels * 5)
            .map(|_| 0.1 + 0.15 * rng.next_f32())
            .collect();
        Self {
            seed,
            canaries,
            serve_counter: 0,
            baseline,
        }
    }

    /// Rotating persona identifier: stable within an epoch hour,
    /// different across epochs (same pattern as the agentic binding).
    pub fn persona_id(&self, epoch_hour: u64) -> String {
        let mut material = self.seed.to_vec();
        material.extend_from_slice(b"persona");
        material.extend_from_slice(&epoch_hour.to_le_bytes());
        hex(&sha256(&material)[..8])
    }

    pub fn canaries(&self) -> &[CanaryCharacteristic] {
        &self.canaries
    }

    /// The watermark for a characteristic UUID, if it is one of ours.
    pub fn canary_watermark(&self, uuid: &str) -> Option<&str> {
        self.canaries
            .iter()
            .find(|c| c.uuid == uuid)
            .map(|c| c.watermark.as_str())
    }

    /// Next synthetic feature vector. Pure function of (seed, serve
    /// counter, timestamp): two calls with the same counter state and
    /// timestamp agree, and no real frame is ever consulted.
    pub fn synthetic_features(&mut self, n_channels: usize, timestamp_ms: u64) -> FeatureVector {
        self.serve_counter += 1;
        let mut material = self.seed.to_vec();
        material.extend_from_slice(b"mirror");
        material.extend_from_slice(&self.serve_counter.to_le_bytes());
        let mut rng = Rng::from_seed(&sha256(&material));
        let values: Vec<f32> = self
            .baseline
            .iter()
            .map(|b| (b + 0.05 * rng.next_normal()).clamp(0.0, 1.0))
            .collect();
        let deltas: Vec<f32> = values
            .iter()
            .zip(&self.baseline)
            .map(|(a, b)| a - b)
            .collect();
        FeatureVector {
            values,
            n_channels,
            deltas,
            timestamp_ms,
        }
    }
}

/// A BLE advertisement as the OS would broadcast it. Represents OUR
/// advertisement — sanitizing it is hardening, not interference.
#[derive(Debug, Clone, PartialEq)]
pub struct Advertisement {
    pub device_name: Option<String>,
    pub service_uuids: Vec<String>,
    pub manufacturer_data: Option<Vec<u8>>,
    pub tx_power_level: Option<i8>,
}

/// Strip identifying fields from our own advertisement (INV-L5-04):
/// no device name, no manufacturer data, tx power hidden, and only
/// the primary service UUID remains. Returns the sanitized copy plus
/// the list of field names that were stripped, for the audit log.
pub fn sanitize_advertisement(
    adv: &Advertisement,
    primary_service_uuid: &str,
) -> (Advertisement, Vec<String>) {
    let mut stripped = Vec::new();
    if adv.device_name.is_some() {
        stripped.push("device_name".to_string());
    }
    if adv.manufacturer_data.is_some() {
        stripped.push("manufacturer_data".to_string());
    }
    if adv.tx_power_level.is_some() {
        stripped.push("tx_power_level".to_string());
    }
    if adv.service_uuids.len() > 1 || adv.service_uuids.iter().any(|u| u != primary_service_uuid) {
        stripped.push("extra_service_uuids".to_string());
    }
    (
        Advertisement {
            device_name: None,
            service_uuids: vec![primary_service_uuid.to_string()],
            manufacturer_data: None,
            tx_power_level: None,
        },
        stripped,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Posture {
    Normal,
    Alert,
    Lockdown,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ProbeAction {
    /// Nothing changed.
    None,
    /// Peer crossed into Suspicious; posture raised to Alert.
    RaisedAlert,
    /// Peer quarantined (canary touch or hostile threshold).
    Quarantined,
}

#[derive(Debug, Clone)]
pub struct ProbeOutcome {
    pub verdict: PeerVerdict,
    pub action: ProbeAction,
    /// Audit index of the probe event — logged BEFORE any response.
    pub audit_index: usize,
}

/// The Mirrorfield guard: detector + persona + posture, wired to the
/// pipeline's audit log so every probe and every mirror release is a
/// receipt, in order.
pub struct Mirrorfield {
    detector: ProbeDetector,
    persona: DecoyPersona,
    posture: Posture,
    n_channels: usize,
}

impl Mirrorfield {
    pub fn new(persona_seed: [u8; 32], canary_uuids: &[&str], n_channels: usize) -> Self {
        Self {
            detector: ProbeDetector::new(MirrorfieldConfig::default()),
            persona: DecoyPersona::new(persona_seed, canary_uuids, n_channels),
            posture: Posture::Normal,
            n_channels,
        }
    }

    pub fn with_config(mut self, cfg: MirrorfieldConfig) -> Self {
        self.detector = ProbeDetector::new(cfg);
        self
    }

    pub fn posture(&self) -> Posture {
        self.posture
    }

    pub fn verdict(&self, peer_id: &str) -> PeerVerdict {
        self.detector.verdict(peer_id)
    }

    pub fn is_quarantined(&self, peer_id: &str) -> bool {
        self.detector.is_quarantined(peer_id)
    }

    pub fn persona(&mut self) -> &mut DecoyPersona {
        &mut self.persona
    }

    /// Observe a probe event against OUR stack. The event is appended
    /// to the audit log FIRST (INV-L5-01); only then is the verdict
    /// computed and posture updated.
    pub fn observe_probe(&mut self, audit: &mut AuditLog, ev: &ProbeEvent) -> ProbeOutcome {
        // A canary touch is only recognizable via the persona's list —
        // resolve the effective kind before logging so the log is exact.
        let effective_kind = if ev.kind == ProbeKind::CharacteristicRead
            && ev
                .target
                .as_deref()
                .map(|t| self.persona.canary_watermark(t).is_some())
                .unwrap_or(false)
        {
            ProbeKind::CanaryTouch
        } else {
            ev.kind
        };
        let commitment = hex(&sha256(
            format!(
                "{}|{}|{}",
                ev.peer_id,
                effective_kind.label(),
                ev.target.as_deref().unwrap_or("")
            )
            .as_bytes(),
        ));
        let audit_index = audit.append(AuditEvent {
            timestamp_ms: ev.timestamp_ms,
            app_id: ev.peer_id.clone(),
            scope: format!("mirrorfield:probe:{}", effective_kind.label()),
            epsilon: 0.0,
            record_commitment: commitment,
        });

        let effective = ProbeEvent {
            kind: effective_kind,
            ..ev.clone()
        };
        let was_quarantined = self.detector.is_quarantined(&ev.peer_id);
        let verdict = self.detector.observe(&effective);
        let now_quarantined = self.detector.is_quarantined(&ev.peer_id);

        let action = if now_quarantined && !was_quarantined {
            if self.posture == Posture::Normal {
                self.posture = Posture::Alert;
            }
            ProbeAction::Quarantined
        } else if verdict == PeerVerdict::Suspicious && self.posture == Posture::Normal {
            self.posture = Posture::Alert;
            ProbeAction::RaisedAlert
        } else {
            ProbeAction::None
        };
        ProbeOutcome {
            verdict,
            action,
            audit_index,
        }
    }

    /// Owner panic: immediate Lockdown, audit-logged (INV-L5-07).
    pub fn panic(&mut self, audit: &mut AuditLog, timestamp_ms: u64) -> usize {
        let idx = audit.append(AuditEvent {
            timestamp_ms,
            app_id: "owner".into(),
            scope: "mirrorfield:panic".into(),
            epsilon: 0.0,
            record_commitment: hex(&sha256(b"mirrorfield-panic")),
        });
        self.posture = Posture::Lockdown;
        idx
    }

    /// Owner clear: the ONLY exit from Lockdown (INV-L5-07). Peer
    /// scores and quarantines are kept — clearing posture doesn't
    /// forgive a prober.
    pub fn owner_clear(&mut self, audit: &mut AuditLog, timestamp_ms: u64) -> usize {
        let idx = audit.append(AuditEvent {
            timestamp_ms,
            app_id: "owner".into(),
            scope: "mirrorfield:owner_clear".into(),
            epsilon: 0.0,
            record_commitment: hex(&sha256(b"mirrorfield-owner-clear")),
        });
        self.posture = Posture::Normal;
        idx
    }

    /// Route a consumer's feature request. Trusted, granted consumers
    /// in Normal/Alert posture get the real governed pipeline.
    /// Quarantined consumers — and ALL consumers in Lockdown — get
    /// persona-synthetic mirror features, audit-logged under scope
    /// `features:mirror` before return (INV-L5-02). The mirror path
    /// never touches the frame's contents.
    ///
    /// NO FREE DATA: mirror service requires an existing `features`
    /// grant. An ungranted consumer — quarantined or not, any
    /// posture — receives `Err(NoGrant)` and zero bytes.
    pub fn serve_consumer(
        &mut self,
        shield: &mut Shield,
        consumer_id: &str,
        frame: &crate::dsp::RawFrame,
    ) -> Result<ReleasedSlice, ShieldError> {
        let mirrored =
            self.posture == Posture::Lockdown || self.detector.is_quarantined(consumer_id);
        if !mirrored {
            return shield.release_slice(consumer_id, frame);
        }
        if !shield.has_grant(consumer_id, "features") {
            return Err(ShieldError::NoGrant {
                app_id: consumer_id.to_string(),
                scope: "features".into(),
            });
        }
        let features = self
            .persona
            .synthetic_features(self.n_channels, frame.timestamp_ms);
        let payload = serde_json::to_vec(&features).map_err(|_| ShieldError::Store)?;
        let commitment = crate::attest::record_commitment(&payload);
        let audit_index = shield.audit.append(AuditEvent {
            timestamp_ms: frame.timestamp_ms,
            app_id: consumer_id.to_string(),
            scope: "features:mirror".into(),
            epsilon: MIRROR_EPSILON,
            record_commitment: commitment,
        });
        let root = shield.audit.root_hex();
        Ok(ReleasedSlice {
            features,
            audit_index,
            audit_root_hex: root,
            epsilon_applied: MIRROR_EPSILON,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SoftwareKeyProvider;
    use crate::dsp::RawFrame;

    const CANARIES: [&str; 2] = ["canary-uuid-alpha", "canary-uuid-beta"];

    fn frame(ts: u64, freq: f32) -> RawFrame {
        let sr = 256.0;
        let ch: Vec<f32> = (0..256)
            .map(|i| (2.0 * std::f32::consts::PI * freq * i as f32 / sr).sin())
            .collect();
        RawFrame::new(sr, vec![ch.clone(), ch], ts)
    }

    fn field() -> Mirrorfield {
        Mirrorfield::new([9u8; 32], &CANARIES, 2)
    }

    fn shield() -> (Shield, SoftwareKeyProvider) {
        let p = SoftwareKeyProvider::from_passphrase("pw", &[3u8; 16]);
        (Shield::new([42u8; 32], 2, &p), p)
    }

    fn read_ev(peer: &str, target: &str, ts: u64) -> ProbeEvent {
        ProbeEvent {
            peer_id: peer.into(),
            kind: ProbeKind::CharacteristicRead,
            target: Some(target.into()),
            timestamp_ms: ts,
        }
    }

    #[test]
    fn canary_touch_quarantines_and_logs_first() {
        let mut mf = field();
        let mut audit = AuditLog::new();
        let out = mf.observe_probe(&mut audit, &read_ev("prober", "canary-uuid-alpha", 100));
        assert_eq!(out.verdict, PeerVerdict::Hostile);
        assert_eq!(out.action, ProbeAction::Quarantined);
        assert!(mf.is_quarantined("prober"));
        // Logged, at the returned index, with the canary scope.
        assert_eq!(out.audit_index, 0);
        assert_eq!(audit.events[0].scope, "mirrorfield:probe:canary_touch");
        assert_eq!(mf.posture(), Posture::Alert);
    }

    #[test]
    fn enumeration_within_window_raises_alert() {
        let mut mf = field();
        let mut audit = AuditLog::new();
        let mut last = None;
        for i in 0..6 {
            last = Some(mf.observe_probe(
                &mut audit,
                &read_ev("scanner", &format!("real-uuid-{i}"), 1_000 + i * 10),
            ));
        }
        let out = last.unwrap();
        // 6 reads (6) + enumeration bonus (10) = 16 ≥ suspicious 8.
        assert_eq!(out.verdict, PeerVerdict::Suspicious);
        assert_eq!(mf.posture(), Posture::Alert);
        assert!(!mf.is_quarantined("scanner"));
    }

    #[test]
    fn scoring_is_monotonic() {
        let mut d = ProbeDetector::new(MirrorfieldConfig::default());
        let evs = [
            ProbeKind::ConnectAttempt,
            ProbeKind::ServiceDiscovery,
            ProbeKind::MalformedFrame,
            ProbeKind::PairingAttempt,
        ];
        let mut prev_score = 0;
        let mut prev_verdict = PeerVerdict::Unknown;
        for (i, kind) in evs.iter().enumerate() {
            let v = d.observe(&ProbeEvent {
                peer_id: "p".into(),
                kind: *kind,
                target: None,
                timestamp_ms: i as u64,
            });
            assert!(d.score("p") >= prev_score);
            assert!(v >= prev_verdict);
            prev_score = d.score("p");
            prev_verdict = v;
        }
    }

    #[test]
    fn persona_rotation_and_watermark_stability() {
        let a = DecoyPersona::new([9u8; 32], &CANARIES, 2);
        let b = DecoyPersona::new([9u8; 32], &CANARIES, 2);
        assert_eq!(a.persona_id(100), a.persona_id(100));
        assert_ne!(a.persona_id(100), a.persona_id(101));
        // Watermarks stable across instances with the same seed…
        assert_eq!(
            a.canary_watermark("canary-uuid-alpha"),
            b.canary_watermark("canary-uuid-alpha")
        );
        // …unique per characteristic…
        assert_ne!(
            a.canary_watermark("canary-uuid-alpha"),
            a.canary_watermark("canary-uuid-beta")
        );
        // …and absent for non-canary UUIDs.
        assert_eq!(a.canary_watermark("real-uuid"), None);
        // Different seed, different watermarks (attribution is seed-bound).
        let c = DecoyPersona::new([10u8; 32], &CANARIES, 2);
        assert_ne!(
            a.canary_watermark("canary-uuid-alpha"),
            c.canary_watermark("canary-uuid-alpha")
        );
    }

    #[test]
    fn advertisement_sanitizer_strips_identity() {
        let adv = Advertisement {
            device_name: Some("Court's Headset".into()),
            service_uuids: vec!["primary".into(), "extra-1".into(), "extra-2".into()],
            manufacturer_data: Some(vec![1, 2, 3]),
            tx_power_level: Some(-4),
        };
        let (clean, stripped) = sanitize_advertisement(&adv, "primary");
        assert!(clean.device_name.is_none());
        assert!(clean.manufacturer_data.is_none());
        assert!(clean.tx_power_level.is_none());
        assert_eq!(clean.service_uuids, vec!["primary".to_string()]);
        assert_eq!(stripped.len(), 4);
    }

    #[test]
    fn mirror_output_ignores_real_frame() {
        // Two identical Mirrorfield+Shield setups; in each, the same
        // consumer is quarantined, then served while presenting a
        // DIFFERENT real frame. The mirror values must be identical —
        // they are a function of (persona seed, serve counter) only.
        let run = |freq: f32| -> Vec<f32> {
            let mut mf = field();
            let (mut s, _p) = shield();
            s.grant("bad-app", "features"); // mirror service is under-grant only
            mf.observe_probe(&mut s.audit, &read_ev("bad-app", "canary-uuid-beta", 0));
            let m = mf
                .serve_consumer(&mut s, "bad-app", &frame(500, freq))
                .unwrap();
            assert_eq!(s.audit.events[m.audit_index].scope, "features:mirror");
            assert_eq!(m.epsilon_applied, MIRROR_EPSILON);
            assert_eq!(m.features.values.len(), 10);
            m.features.values
        };
        assert_eq!(run(10.0), run(40.0));
    }

    #[test]
    fn quarantined_peer_gets_mirror_not_real() {
        let mut mf = field();
        let (mut s, _p) = shield();
        s.grant("bad-app", "features");
        // Real release first (baseline for comparison).
        let real = s.release_slice("bad-app", &frame(0, 10.0)).unwrap();
        // Now the app gets caught touching a canary.
        mf.observe_probe(&mut s.audit, &read_ev("bad-app", "canary-uuid-alpha", 10));
        let mirror = mf
            .serve_consumer(&mut s, "bad-app", &frame(20, 10.0))
            .unwrap();
        assert_ne!(mirror.features.values, real.features.values);
        assert_eq!(s.audit.events[mirror.audit_index].scope, "features:mirror");
        // And the mirror receipt verifies like any other.
        let receipt = s.audit.receipt(mirror.audit_index).unwrap();
        assert!(receipt.verify());
    }

    #[test]
    fn quarantined_without_grant_gets_nothing() {
        // NO FREE DATA: a caught prober with no grant doesn't even get
        // the mirror — it gets an error and zero bytes, and no release
        // event of any scope is appended for it.
        let mut mf = field();
        let (mut s, _p) = shield();
        mf.observe_probe(&mut s.audit, &read_ev("prober", "canary-uuid-alpha", 0));
        assert!(mf.is_quarantined("prober"));
        let before = s.audit.len();
        let res = mf.serve_consumer(&mut s, "prober", &frame(10, 10.0));
        assert!(matches!(res, Err(ShieldError::NoGrant { .. })));
        assert_eq!(s.audit.len(), before); // only the probe event exists
        assert!(s
            .audit
            .events
            .iter()
            .all(|e| e.scope != "features:mirror" && e.scope != "features"));
    }

    #[test]
    fn panic_lockdown_mirrors_everyone() {
        let mut mf = field();
        let (mut s, _p) = shield();
        s.grant("good-app", "features");
        mf.panic(&mut s.audit, 0);
        assert_eq!(mf.posture(), Posture::Lockdown);
        let slice = mf
            .serve_consumer(&mut s, "good-app", &frame(1, 10.0))
            .unwrap();
        assert_eq!(s.audit.events[slice.audit_index].scope, "features:mirror");
    }

    #[test]
    fn panic_lockdown_and_owner_clear() {
        let mut mf = field();
        let mut audit = AuditLog::new();
        mf.panic(&mut audit, 100);
        assert_eq!(mf.posture(), Posture::Lockdown);
        // Probe events never clear lockdown (INV-L5-07).
        mf.observe_probe(&mut audit, &read_ev("someone", "real-uuid", 200));
        assert_eq!(mf.posture(), Posture::Lockdown);
        mf.owner_clear(&mut audit, 300);
        assert_eq!(mf.posture(), Posture::Normal);
        let scopes: Vec<&str> = audit.events.iter().map(|e| e.scope.as_str()).collect();
        assert!(scopes.contains(&"mirrorfield:panic"));
        assert!(scopes.contains(&"mirrorfield:owner_clear"));
    }

    #[test]
    fn trusted_granted_consumer_gets_real_pipeline() {
        let mut mf = field();
        let (mut s, _p) = shield();
        s.grant("good-app", "features");
        let slice = mf
            .serve_consumer(&mut s, "good-app", &frame(0, 10.0))
            .unwrap();
        assert_eq!(s.audit.events[slice.audit_index].scope, "features");
        // Ungranted + unquarantined still hits the grant gate.
        assert!(mf
            .serve_consumer(&mut s, "stranger", &frame(0, 10.0))
            .is_err());
    }
}
