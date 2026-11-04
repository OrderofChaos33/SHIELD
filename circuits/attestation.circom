pragma circom 2.1.6;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/poseidon.circom";

/*
 * SHIELD Layer 3 — attestation circuit v0.1
 *
 * Proves, without revealing any telemetry:
 *   fatigue_milli < threshold_milli
 * where fatigue_milli is bound to a public commitment:
 *   commitment == Poseidon(fatigue_milli, record_salt)
 *
 * The commitment is the circuit-side counterpart of the Rust core's
 * attestation envelope (crates/shield-core/src/attest.rs). Binding the
 * proof to (commitment, threshold) means a proof cannot be detached
 * and replayed against a different record or a looser threshold.
 *
 * Public:  commitment, threshold_milli
 * Private: fatigue_milli, record_salt
 *
 * Status: written + specified; compile/prove in CI is Phase 1
 * (see docs/ROADMAP.md). Do not claim otherwise.
 */
template FatigueBelow(nBits) {
    signal input fatigue_milli;
    signal input record_salt;
    signal input commitment;
    signal input threshold_milli;
    signal output holds;

    // Bind the private value to the public commitment.
    component hasher = Poseidon(2);
    hasher.inputs[0] <== fatigue_milli;
    hasher.inputs[1] <== record_salt;
    hasher.out === commitment;

    // Strict less-than over nBits.
    component lt = LessThan(nBits);
    lt.in[0] <== fatigue_milli;
    lt.in[1] <== threshold_milli;
    holds <== lt.out;
}

component main { public [commitment, threshold_milli] } = FatigueBelow(32);
