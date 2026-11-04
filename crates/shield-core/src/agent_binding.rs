//! Agentic protocol binding — attestations for agent networks.
//!
//! External autonomous agents and task-auction registries (A2A-style)
//! may need to verify a SHIELD attestation. What they get is an
//! *envelope*, engineered to leak nothing else:
//!
//! - The signer is a local Ed25519 key; its public key is the only
//!   long-lived identifier, and even it is presented per-registry
//!   alongside a rotating ephemeral ID.
//! - `ephemeral_id` = SHA-256(binding_seed ‖ registry_id ‖ epoch_day),
//!   truncated. Unlinkable across registries and across days, stable
//!   within one registry-day so a registry can rate-limit duplicates.
//! - The envelope contains NO session id, NO device id, NO app id,
//!   NO MAC, NO timestamps finer than issuance/expiry, NO feature data.
//! - Signature covers the canonical envelope bytes: an envelope cannot
//!   be re-bound to a different commitment, root, or expiry.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::attest::AttestationToken;
use crate::audit::hex;

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex(&h.finalize())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttestationEnvelope {
    pub version: u8,
    pub ephemeral_id: String,
    pub predicate: String,
    pub threshold_milli: u32,
    pub holds: bool,
    pub record_commitment: String,
    pub audit_root_hex: String,
    pub audit_index: usize,
    pub issued_ms: u64,
    pub expires_ms: u64,
    pub nonce_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignedEnvelope {
    pub envelope: AttestationEnvelope,
    pub signer_pubkey_hex: String,
    pub signature_hex: String,
}

pub struct AgentBinding {
    signing_key: SigningKey,
    binding_seed: [u8; 32],
}

impl AgentBinding {
    /// In production the seed + signing key are generated on-device and
    /// stored wrapped by the Layer 0 enclave — never in this repo.
    pub fn from_seeds(signing_seed: [u8; 32], binding_seed: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&signing_seed),
            binding_seed,
        }
    }

    pub fn public_key_hex(&self) -> String {
        hex(self.signing_key.verifying_key().as_bytes())
    }

    /// Rotating pseudonymous ID for one registry for one UTC day.
    pub fn ephemeral_id(&self, registry_id: &str, epoch_day: u64) -> String {
        let mut material = Vec::new();
        material.extend_from_slice(&self.binding_seed);
        material.extend_from_slice(registry_id.as_bytes());
        material.extend_from_slice(&epoch_day.to_le_bytes());
        format!("shield:eph:{}", &sha256_hex(&material)[..32])
    }

    pub fn bind(
        &self,
        token: &AttestationToken,
        audit_root_hex: &str,
        registry_id: &str,
        now_ms: u64,
        ttl_ms: u64,
    ) -> SignedEnvelope {
        let epoch_day = now_ms / 86_400_000;
        let nonce_material = format!(
            "{}|{}|{}",
            token.record_commitment, token.audit_index, now_ms
        );
        let envelope = AttestationEnvelope {
            version: 1,
            ephemeral_id: self.ephemeral_id(registry_id, epoch_day),
            predicate: token.predicate.clone(),
            threshold_milli: token.threshold_milli,
            holds: token.holds,
            record_commitment: token.record_commitment.clone(),
            audit_root_hex: audit_root_hex.to_string(),
            audit_index: token.audit_index,
            issued_ms: now_ms,
            expires_ms: now_ms + ttl_ms,
            nonce_hex: sha256_hex(nonce_material.as_bytes())[..16].to_string(),
        };
        let canonical = serde_json::to_vec(&envelope).expect("envelope serializes");
        let signature = self.signing_key.sign(&canonical);
        SignedEnvelope {
            envelope,
            signer_pubkey_hex: self.public_key_hex(),
            signature_hex: hex(&signature.to_bytes()),
        }
    }

    /// Verify a signed envelope: signature valid under the stated key
    /// and not expired at `now_ms`. (Trust in the key itself — e.g. via
    /// an agent-card listing — is the registry's policy layer, not this
    /// function's.)
    pub fn verify(signed: &SignedEnvelope, now_ms: u64) -> bool {
        if now_ms > signed.envelope.expires_ms {
            return false;
        }
        let Ok(pk_bytes) = hex::decode(&signed.signer_pubkey_hex) else {
            return false;
        };
        let Ok(pk_arr): Result<[u8; 32], _> = pk_bytes.try_into() else {
            return false;
        };
        let Ok(vk) = VerifyingKey::from_bytes(&pk_arr) else {
            return false;
        };
        let Ok(sig_bytes) = hex::decode(&signed.signature_hex) else {
            return false;
        };
        let Ok(sig_arr): Result<[u8; 64], _> = sig_bytes.try_into() else {
            return false;
        };
        let sig = Signature::from_bytes(&sig_arr);
        let Ok(canonical) = serde_json::to_vec(&signed.envelope) else {
            return false;
        };
        vk.verify(&canonical, &sig).is_ok()
    }

    /// The A2A agent-card skill entry a registry lists for this user.
    /// Deliberately minimal: a capability, a predicate set, a key.
    pub fn agent_card_skill(&self) -> serde_json::Value {
        serde_json::json!({
            "id": "shield.attestation.verify",
            "name": "SHIELD Attestation Verification",
            "description": "Verify signed SHIELD zero-knowledge compliance envelopes (fatigue_below). Envelopes carry no telemetry, no session metadata, and a rotating per-registry ephemeral ID.",
            "signer_pubkey_hex": self.public_key_hex(),
            "predicates": ["fatigue_below"],
            "envelope_version": 1
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> AgentBinding {
        AgentBinding::from_seeds([11u8; 32], [22u8; 32])
    }

    fn token() -> AttestationToken {
        AttestationToken {
            predicate: "fatigue_below".into(),
            threshold_milli: 2500,
            holds: true,
            record_commitment: "deadbeef".into(),
            audit_index: 4,
        }
    }

    #[test]
    fn signed_envelope_verifies_and_tampering_fails() {
        let b = binding();
        let signed = b.bind(&token(), "root123", "registry-a", 1_700_000_000_000, 60_000);
        assert!(AgentBinding::verify(&signed, 1_700_000_030_000));
        let mut bad = signed.clone();
        bad.envelope.holds = false;
        assert!(!AgentBinding::verify(&bad, 1_700_000_030_000));
    }

    #[test]
    fn expired_envelope_fails() {
        let b = binding();
        let signed = b.bind(&token(), "root123", "registry-a", 1_000_000, 1_000);
        assert!(!AgentBinding::verify(&signed, 2_000_000));
    }

    #[test]
    fn ephemeral_ids_rotate_across_registries_and_days_only() {
        let b = binding();
        let a1 = b.ephemeral_id("registry-a", 100);
        let a2 = b.ephemeral_id("registry-a", 100);
        let other_registry = b.ephemeral_id("registry-b", 100);
        let other_day = b.ephemeral_id("registry-a", 101);
        assert_eq!(a1, a2);
        assert_ne!(a1, other_registry);
        assert_ne!(a1, other_day);
    }

    #[test]
    fn envelope_carries_no_session_metadata() {
        let b = binding();
        let signed = b.bind(&token(), "root123", "registry-a", 1_700_000_000_000, 60_000);
        let json = serde_json::to_string(&signed).unwrap().to_lowercase();
        for forbidden in [
            "session", "device", "mac", "app_id", "\"user\"", "imei", "serial",
        ] {
            assert!(
                !json.contains(forbidden),
                "envelope leaked '{forbidden}': {json}"
            );
        }
    }
}
