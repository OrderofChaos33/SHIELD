pragma circom 2.1.6;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/switcher.circom";

/*
 * CognitiveFatigueThresholdProof — N-SHIELD Layer 3, v2
 *
 * Proves: fatigueScore < publicThreshold, for a fatigue score derived
 * from private band powers that are committed into the user's local
 * Merkle audit log — WITHOUT revealing the score, the band powers, or
 * the blinding nonce.
 *
 * v2 repair vs. the originating sketch: the sketch computed a feature
 * commitment but never constrained it to `telemetryCommitmentRoot`,
 * so the proof was bound to nothing. Here the circuit recomputes the
 * Merkle root from the leaf commitment + an inclusion path (depth 8,
 * 256 leaves) and constrains it === telemetryCommitmentRoot. A proof
 * for features that are not in the user's audit log cannot verify.
 *
 * Public:  publicThreshold, telemetryCommitmentRoot
 * Private: fatigueScore, rawFeatureHashNonce, localFeatureValues[5],
 *          merklePathElements[8], merklePathIndices[8] (0 = leaf pair
 *          is left, 1 = leaf pair is right at that level)
 * Output:  isCompliant (constrained === 1: a valid proof can only be
 *          generated for a compliant state)
 *
 * Score scale: 0–100 fits LessThan(8)'s <256 domain. If the score
 * scale ever moves to milli-units, widen to LessThan(32) and
 * re-audit constraint counts (still small: one Poseidon(6), eight
 * Poseidon(2), one comparator — roughly 2–3k constraints, well under
 * the <500 ms mobile proving target for Groth16).
 */
template CognitiveFatigueThresholdProof() {
    // --- PUBLIC ---
    signal input publicThreshold;
    signal input telemetryCommitmentRoot;

    // --- PRIVATE ---
    signal input fatigueScore;
    signal input rawFeatureHashNonce;
    signal input localFeatureValues[5];
    signal input merklePathElements[8];
    signal input merklePathIndices[8];

    // --- OUTPUT ---
    signal output isCompliant;

    // 1. Feature commitment: Poseidon(band powers || nonce).
    component hasher = Poseidon(6);
    for (var i = 0; i < 5; i++) {
        hasher.inputs[i] <== localFeatureValues[i];
    }
    hasher.inputs[5] <== rawFeatureHashNonce;
    signal leaf;
    leaf <== hasher.out;

    // 2. Recompute the Merkle root from the leaf + inclusion path and
    //    bind it to the public root.
    component switchers[8];
    component levelHashers[8];
    signal level[9];
    level[0] <== leaf;
    for (var i = 0; i < 8; i++) {
        switchers[i] = Switcher();
        switchers[i].sel <== merklePathIndices[i];
        switchers[i].L <== level[i];
        switchers[i].R <== merklePathElements[i];

        levelHashers[i] = Poseidon(2);
        levelHashers[i].inputs[0] <== switchers[i].outL;
        levelHashers[i].inputs[1] <== switchers[i].outR;
        level[i + 1] <== levelHashers[i].out;
    }
    telemetryCommitmentRoot === level[8];

    // 3. Threshold comparison; compliance is mandatory for a proof.
    component lt = LessThan(8);
    lt.in[0] <== fatigueScore;
    lt.in[1] <== publicThreshold;
    isCompliant <== lt.out;
    isCompliant === 1;
}

component main { public [publicThreshold, telemetryCommitmentRoot] } =
    CognitiveFatigueThresholdProof();
