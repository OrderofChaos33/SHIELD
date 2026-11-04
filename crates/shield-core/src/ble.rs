//! Layer 1 — Hardened BLE Intercept Proxy (protocol core).
//!
//! X25519 handshake -> HKDF-SHA256 session keys -> per-frame AES-256-GCM
//! with an HMAC-SHA256 tag and a monotonic sequence number. Frames that
//! fail authentication, replay, or fall outside the sequence window are
//! dropped before decryption of the payload is trusted.
//!
//! Real radios sit behind [`Transport`]; tests use [`MockTransport`].

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, PartialEq, Eq)]
pub enum BleError {
    AuthFailed,
    Replay { seq: u64 },
    OutOfWindow { seq: u64, last_seen: u64 },
    Malformed,
    NoSession,
}

/// Monotonic sequence tracker: the replay defense. Accepts only
/// strictly-increasing sequence numbers; every duplicate, rollback, or
/// replayed capture is rejected.
#[derive(Debug, Default)]
pub struct SequenceTracker {
    pub last_seen: Option<u64>,
    pub accepted: u64,
    pub rejected: u64,
}

impl SequenceTracker {
    pub fn check_and_advance(&mut self, seq: u64) -> Result<(), BleError> {
        match self.last_seen {
            Some(last) if seq == last => {
                self.rejected += 1;
                Err(BleError::Replay { seq })
            }
            Some(last) if seq < last => {
                self.rejected += 1;
                Err(BleError::OutOfWindow {
                    seq,
                    last_seen: last,
                })
            }
            _ => {
                self.last_seen = Some(seq);
                self.accepted += 1;
                Ok(())
            }
        }
    }
}

/// Sequence gate for *device-side* u16 packet counters (the framing
/// many BCI headsets actually emit: first 2 bytes = big-endian seq).
/// Uses serial-number arithmetic so the 65535 -> 0 wrap is a valid
/// next packet, while replays and stale packets are rejected.
/// The first packet seen is always accepted (it defines the epoch).
#[derive(Debug, Default)]
pub struct DeviceSeqTracker {
    pub last: Option<u16>,
    pub accepted: u64,
    pub rejected: u64,
}

impl DeviceSeqTracker {
    /// Returns true if the packet is fresh and should be processed.
    pub fn check_and_advance(&mut self, seq: u16) -> bool {
        match self.last {
            None => {
                self.last = Some(seq);
                self.accepted += 1;
                true
            }
            Some(last) => {
                let diff = seq.wrapping_sub(last);
                if diff == 0 || diff >= 32_768 {
                    self.rejected += 1;
                    false
                } else {
                    self.last = Some(seq);
                    self.accepted += 1;
                    true
                }
            }
        }
    }
}

/// One side of a Layer-1 session.
pub struct Session {
    enc_key: [u8; 32],
    mac_key: [u8; 32],
    session_id: [u8; 4],
    send_seq: u64,
    pub tracker: SequenceTracker,
}

/// Result of an ECDH handshake performed by both sides.
pub struct Handshake {
    pub secret: StaticSecret,
    pub public: PublicKey,
}

pub fn new_handshake(secret_bytes: [u8; 32]) -> Handshake {
    let secret = StaticSecret::from(secret_bytes);
    let public = PublicKey::from(&secret);
    Handshake { secret, public }
}

impl Session {
    /// Derive a session from the ECDH shared secret. Both peers call this
    /// with the same shared secret and session nonce and get the same keys.
    pub fn derive(shared_secret: &[u8; 32], session_nonce: &[u8; 16]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(session_nonce), shared_secret);
        let mut enc_key = [0u8; 32];
        let mut mac_key = [0u8; 32];
        hk.expand(b"shield-l1-v1-enc", &mut enc_key)
            .expect("hkdf len");
        hk.expand(b"shield-l1-v1-mac", &mut mac_key)
            .expect("hkdf len");
        let mut session_id = [0u8; 4];
        session_id.copy_from_slice(&session_nonce[..4]);
        Self {
            enc_key,
            mac_key,
            session_id,
            send_seq: 0,
            tracker: SequenceTracker::default(),
        }
    }

    pub fn establish(mine: &Handshake, peer_public: &PublicKey, session_nonce: &[u8; 16]) -> Self {
        let shared = mine.secret.diffie_hellman(peer_public);
        Self::derive(shared.as_bytes(), session_nonce)
    }

    fn tag(&self, seq: u64, nonce: &[u8; 12], ciphertext: &[u8]) -> [u8; 32] {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.mac_key).expect("hmac key");
        mac.update(&self.session_id);
        mac.update(&seq.to_le_bytes());
        mac.update(nonce);
        mac.update(ciphertext);
        mac.finalize().into_bytes().into()
    }

    /// Seal a plaintext payload into a wire frame:
    /// `session_id(4) || seq(8) || nonce(12) || ciphertext || tag(32)`
    pub fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
        self.send_seq += 1;
        let seq = self.send_seq;
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..4].copy_from_slice(&self.session_id);
        nonce_bytes[4..].copy_from_slice(&seq.to_le_bytes());
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.enc_key));
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext,
                    aad: &self.session_id,
                },
            )
            .expect("aes-gcm encrypt");
        let tag = self.tag(seq, &nonce_bytes, &ciphertext);
        let mut frame = Vec::with_capacity(4 + 8 + 12 + ciphertext.len() + 32);
        frame.extend_from_slice(&self.session_id);
        frame.extend_from_slice(&seq.to_le_bytes());
        frame.extend_from_slice(&nonce_bytes);
        frame.extend_from_slice(&ciphertext);
        frame.extend_from_slice(&tag);
        frame
    }

    /// Open a wire frame. Order matters: parse -> HMAC verify ->
    /// sequence check -> decrypt. Any failure drops the frame.
    pub fn open(&mut self, frame: &[u8]) -> Result<Vec<u8>, BleError> {
        if frame.len() < 4 + 8 + 12 + 32 {
            return Err(BleError::Malformed);
        }
        if frame[..4] != self.session_id {
            return Err(BleError::NoSession); // unsolicited / foreign broadcast: drop
        }
        let seq = u64::from_le_bytes(frame[4..12].try_into().unwrap());
        let nonce_bytes: [u8; 12] = frame[12..24].try_into().unwrap();
        let (ciphertext, tag) = frame[24..].split_at(frame.len() - 24 - 32);
        let expected = self.tag(seq, &nonce_bytes, ciphertext);
        // Constant-time-ish comparison via HMAC verify path:
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.mac_key).expect("hmac key");
        mac.update(&self.session_id);
        mac.update(&seq.to_le_bytes());
        mac.update(&nonce_bytes);
        mac.update(ciphertext);
        if mac.verify_slice(tag).is_err() || expected != tag {
            return Err(BleError::AuthFailed);
        }
        self.tracker.check_and_advance(seq)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.enc_key));
        cipher
            .decrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: ciphertext,
                    aad: &self.session_id,
                },
            )
            .map_err(|_| BleError::AuthFailed)
    }
}

/// Radio abstraction. Platform shells implement this over CoreBluetooth /
/// Android BLE; the core never touches an OS radio API directly.
pub trait Transport {
    fn send(&mut self, frame: &[u8]);
    fn poll(&mut self) -> Option<Vec<u8>>;
}

/// In-memory transport pair for tests and the CLI demo.
#[derive(Default)]
pub struct MockTransport {
    pub inbox: Vec<Vec<u8>>,
    pub sent: Vec<Vec<u8>>,
}

impl Transport for MockTransport {
    fn send(&mut self, frame: &[u8]) {
        self.sent.push(frame.to_vec());
    }
    fn poll(&mut self) -> Option<Vec<u8>> {
        if self.inbox.is_empty() {
            None
        } else {
            Some(self.inbox.remove(0))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (Session, Session) {
        let alice = new_handshake([11u8; 32]);
        let bob = new_handshake([22u8; 32]);
        let nonce = [3u8; 16];
        (
            Session::establish(&alice, &bob.public, &nonce),
            Session::establish(&bob, &alice.public, &nonce),
        )
    }

    #[test]
    fn round_trip_frame() {
        let (mut tx, mut rx) = pair();
        let frame = tx.seal(b"eeg-frame-1");
        assert_eq!(rx.open(&frame).unwrap(), b"eeg-frame-1");
    }

    #[test]
    fn replayed_frame_is_dropped() {
        let (mut tx, mut rx) = pair();
        let frame = tx.seal(b"eeg-frame-1");
        assert!(rx.open(&frame).is_ok());
        assert_eq!(rx.open(&frame), Err(BleError::Replay { seq: 1 }));
    }

    #[test]
    fn tampered_frame_fails_auth() {
        let (mut tx, mut rx) = pair();
        let mut frame = tx.seal(b"eeg-frame-1");
        let n = frame.len();
        frame[n - 40] ^= 0xFF;
        assert_eq!(rx.open(&frame), Err(BleError::AuthFailed));
    }

    #[test]
    fn foreign_session_frame_is_dropped() {
        let (mut tx, _rx) = pair();
        let other_alice = new_handshake([99u8; 32]);
        let other_bob = new_handshake([22u8; 32]);
        let mut other_rx = Session::establish(&other_bob, &other_alice.public, &[9u8; 16]);
        let frame = tx.seal(b"secret");
        assert_eq!(other_rx.open(&frame), Err(BleError::NoSession));
    }

    #[test]
    fn out_of_order_old_frame_rejected() {
        let (mut tx, mut rx) = pair();
        let f1 = tx.seal(b"one");
        let f2 = tx.seal(b"two");
        assert!(rx.open(&f2).is_ok());
        assert!(matches!(rx.open(&f1), Err(BleError::OutOfWindow { .. })));
    }
}

#[cfg(test)]
mod device_seq_tests {
    use super::*;

    #[test]
    fn wraparound_is_accepted_replay_is_not() {
        let mut t = DeviceSeqTracker::default();
        assert!(t.check_and_advance(65534));
        assert!(t.check_and_advance(65535));
        assert!(t.check_and_advance(0), "wrap 65535 -> 0 must be fresh");
        assert!(t.check_and_advance(1));
        assert!(!t.check_and_advance(1), "exact replay");
        assert!(!t.check_and_advance(65535), "stale pre-wrap packet");
        assert!(!t.check_and_advance(0), "stale replay after wrap");
        assert_eq!(t.accepted, 4);
        assert_eq!(t.rejected, 3);
    }
}
