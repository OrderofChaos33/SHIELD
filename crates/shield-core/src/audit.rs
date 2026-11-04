//! Layer 4 — Immutable local Merkle audit log.
//!
//! Every release / proof event is appended BEFORE the release happens
//! (enforced by `pipeline`). Leaves are SHA-256 hashes of the canonical
//! event bytes; inclusion proofs verify offline against the root.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditEvent {
    pub timestamp_ms: u64,
    pub app_id: String,
    pub scope: String,
    /// Epsilon applied to this release (0.0 for proof-only events).
    pub epsilon: f32,
    /// Commitment of the record this event refers to (hex sha256).
    pub record_commitment: String,
}

impl AuditEvent {
    pub fn leaf_hash(&self) -> [u8; 32] {
        let canonical = format!(
            "{}|{}|{}|{:.6}|{}",
            self.timestamp_ms, self.app_id, self.scope, self.epsilon, self.record_commitment
        );
        sha256(canonical.as_bytes())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProof {
    pub leaf_index: usize,
    /// (sibling hash, sibling_is_left)
    pub path: Vec<([u8; 32], bool)>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AuditLog {
    leaves: Vec<[u8; 32]>,
    pub events: Vec<AuditEvent>,
}

impl AuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Append an event. Returns its index — the receipt handle.
    pub fn append(&mut self, event: AuditEvent) -> usize {
        self.leaves.push(event.leaf_hash());
        self.events.push(event);
        self.leaves.len() - 1
    }

    fn level_up(level: &[[u8; 32]]) -> Vec<[u8; 32]> {
        level
            .chunks(2)
            .map(|pair| {
                let right = if pair.len() == 2 { pair[1] } else { pair[0] };
                let mut buf = Vec::with_capacity(64);
                buf.extend_from_slice(&pair[0]);
                buf.extend_from_slice(&right);
                sha256(&buf)
            })
            .collect()
    }

    pub fn root(&self) -> [u8; 32] {
        if self.leaves.is_empty() {
            return sha256(b"shield-empty-log");
        }
        let mut level = self.leaves.clone();
        while level.len() > 1 {
            level = Self::level_up(&level);
        }
        level[0]
    }

    pub fn root_hex(&self) -> String {
        hex(&self.root())
    }

    pub fn inclusion_proof(&self, index: usize) -> Option<InclusionProof> {
        if index >= self.leaves.len() {
            return None;
        }
        let mut path = Vec::new();
        let mut level = self.leaves.clone();
        let mut idx = index;
        while level.len() > 1 {
            let sibling = if idx % 2 == 0 {
                if idx + 1 < level.len() {
                    (level[idx + 1], false)
                } else {
                    (level[idx], false)
                }
            } else {
                (level[idx - 1], true)
            };
            path.push(sibling);
            level = Self::level_up(&level);
            idx /= 2;
        }
        Some(InclusionProof {
            leaf_index: index,
            path,
        })
    }

    pub fn verify_inclusion(root: &[u8; 32], event: &AuditEvent, proof: &InclusionProof) -> bool {
        let mut acc = event.leaf_hash();
        for (sibling, sibling_is_left) in &proof.path {
            let mut buf = Vec::with_capacity(64);
            if *sibling_is_left {
                buf.extend_from_slice(sibling);
                buf.extend_from_slice(&acc);
            } else {
                buf.extend_from_slice(&acc);
                buf.extend_from_slice(sibling);
            }
            acc = sha256(&buf);
        }
        &acc == root
    }
}

/// A cryptographic receipt for one audit event — the object the user
/// (or a verifier they choose) checks. Binds the event, its leaf, the
/// log root at issuance, and an inclusion proof. A receipt verifies
/// offline and proves "this release happened, with this ε, to this app,
/// and nothing about it was altered after the fact."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub event: AuditEvent,
    pub leaf_index: usize,
    pub leaf_hash_hex: String,
    pub root_hex: String,
    pub proof: InclusionProof,
}

impl AuditLog {
    pub fn receipt(&self, index: usize) -> Option<Receipt> {
        let event = self.events.get(index)?.clone();
        let proof = self.inclusion_proof(index)?;
        Some(Receipt {
            leaf_hash_hex: hex(&event.leaf_hash()),
            event,
            leaf_index: index,
            root_hex: self.root_hex(),
            proof,
        })
    }
}

impl Receipt {
    pub fn verify(&self) -> bool {
        let root_bytes: Option<[u8; 32]> = hex::decode(&self.root_hex)
            .ok()
            .and_then(|v| v.try_into().ok());
        match root_bytes {
            Some(root) => {
                hex(&self.event.leaf_hash()) == self.leaf_hash_hex
                    && AuditLog::verify_inclusion(&root, &self.event, &self.proof)
            }
            None => false,
        }
    }
}

/// Blueprint-compatible facade (Layer 4 spec naming): a leaves-only
/// Merkle log with `append_event` / `compute_root`. New code should use
/// [`AuditLog`], which adds events, inclusion proofs, and receipts;
/// this facade exists so integrations written against the spec's API
/// shape compile unchanged. Note the spec version's empty root is
/// `[0u8; 32]`; `AuditLog` uses a domain-separated empty root instead,
/// so the two roots differ for an empty log and match nowhere else
/// either (different leaf encoding) — do not mix them in one log.
pub struct MerkleAuditLog {
    inner: AuditLog,
}

impl Default for MerkleAuditLog {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleAuditLog {
    pub fn new() -> Self {
        Self {
            inner: AuditLog::new(),
        }
    }

    /// Append an event; returns its leaf hash.
    pub fn append_event(&mut self, event: &AuditEvent) -> [u8; 32] {
        let idx = self.inner.append(event.clone());
        self.inner.events[idx].leaf_hash()
    }

    pub fn compute_root(&self) -> [u8; 32] {
        self.inner.root()
    }

    pub fn receipt(&self, index: usize) -> Option<Receipt> {
        self.inner.receipt(index)
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(i: u64) -> AuditEvent {
        AuditEvent {
            timestamp_ms: 1_700_000_000_000 + i,
            app_id: "focus-timer".into(),
            scope: "features".into(),
            epsilon: 0.08,
            record_commitment: hex(&sha256(format!("record-{i}").as_bytes())),
        }
    }

    #[test]
    fn empty_root_is_stable() {
        assert_eq!(AuditLog::new().root(), AuditLog::new().root());
    }

    #[test]
    fn root_changes_on_append() {
        let mut log = AuditLog::new();
        let r0 = log.root();
        log.append(ev(0));
        assert_ne!(r0, log.root());
    }

    #[test]
    fn inclusion_proofs_verify_for_all_leaves() {
        let mut log = AuditLog::new();
        for i in 0..17 {
            log.append(ev(i));
        }
        let root = log.root();
        for i in 0..17 {
            let proof = log.inclusion_proof(i).unwrap();
            assert!(
                AuditLog::verify_inclusion(&root, &log.events[i], &proof),
                "leaf {i}"
            );
        }
    }

    #[test]
    fn tampered_event_fails_verification() {
        let mut log = AuditLog::new();
        log.append(ev(0));
        let proof = log.inclusion_proof(0).unwrap();
        let mut bad = ev(0);
        bad.app_id = "attacker-app".into();
        assert!(!AuditLog::verify_inclusion(&log.root(), &bad, &proof));
    }
}
