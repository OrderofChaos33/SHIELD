# Circuits — Layer 3 ZKP attestation

## What lives here

`cognitive_fatigue.circom` — the production circuit (v2). Proves
`fatigueScore < publicThreshold` for private band powers, and —
the v2 repair — recomputes the Merkle root in-circuit from the
feature commitment + an 8-level inclusion path and constrains it
equal to the public `telemetryCommitmentRoot`. The originating
sketch computed a commitment but never bound it to the root; a
proof unbound to the audit log proves nothing about *this* user's
*recorded* data, so that binding is now the circuit's center.

`attestation.circom` — the simpler v1 envelope circuit (commitment =
Poseidon(fatigue, salt)), kept for reference and small-device
experiments. Prefer v2 for anything external.

## Intended flow (Phase 1 target)

```bash
# Requires circom 2.1.6+, snarkjs, and a powers-of-tau file (never commit one).
circom attestation.circom --r1cs --wasm --sym
snarkjs groth16 setup attestation.r1cs pot.ptau attestation.zkey
snarkjs groth16 prove attestation.zkey witness.wtns proof.json public.json
snarkjs groth16 verify verification_key.json public.json proof.json
```

On-device proving targets rapidsnark; snarkjs is the reference path.

## Binding rule

The public inputs are `(commitment, threshold_milli)`. The Rust core's
`AttestationToken` carries the same commitment and its audit-log index.
A verifier must check all three together: proof validity, commitment
match with the token, and the token's audit index resolving in the
user's Merkle log (when the user chooses to show it). A proof alone,
detached from its envelope, proves nothing about *this* record.

## Test vectors

`test_vectors.json` gives one passing and one failing input set over a
toy salt so the Phase 1 CI job can assert both branches of the circuit.
Fatigue values there are synthetic, like everything else in this repo.
