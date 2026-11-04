# SHIELD — Core Invariants

Per Execution Standard §1: written before (or with) the code, each
invariant has a stable ID and a named enforcing test. A change to any
line here in a commit that also changes code must state its reason.

## Layer 1 — BLE session & sequence gates

| ID | Invariant | Enforced by |
|---|---|---|
| INV-L1-01 | A frame whose HMAC fails is never decrypted-trusted or delivered. | `ble::tests::tampered_frame_fails_auth` |
| INV-L1-02 | A replayed frame (same seq) is always rejected. | `ble::tests::replayed_frame_is_dropped`, `full_loop` |
| INV-L1-03 | A frame from a foreign session is dropped before parsing. | `ble::tests::foreign_session_frame_is_dropped` |
| INV-L1-04 | Device u16 sequences: strictly-forward (serial arithmetic) packets accepted, incl. the 65535→0 wrap; duplicates/stale always rejected. | `ble::device_seq_tests::wraparound_is_accepted_replay_is_not`, `properties::device_seq_never_accepts_replay` |
| INV-L1-05 | Sequence state is per-characteristic/per-session; one stream's epoch never validates another's. | `ffi::tests::ble_handle_gates_replays` |

## Layer 2 — DSP, scrambling, perturbation, calibration

| ID | Invariant | Enforced by |
|---|---|---|
| INV-L2-01 | Per-channel relative band powers sum to 1 (±1e-4). | `dsp::tests::relative_powers_sum_to_one_per_channel` |
| INV-L2-02 | The scrambler is orthogonal: ‖Qx‖ = ‖x‖ and max ‖QᵀQ − I‖ < 1e-4 at any dim. | `dsp::tests::scrambler_is_orthogonal`, `scrambler_preserves_norm`, `properties::scrambler_preserves_norm` |
| INV-L2-03 | The same input under two different session seeds produces unlinkable outputs (distance > threshold). | `dsp::tests::different_sessions_scramble_differently`, `full_loop::cross_session_outputs_are_not_linkable_by_raw_topography` |
| INV-L2-04 | The stripper nulls the identity direction (P·v_id ≈ 0) and is idempotent (P² = P). | `dsp::stripper_tests::*` |
| INV-L2-05 | Perturbation never exceeds the ε-ball: ∀i, ‖δᵢ‖ ≤ ε, for any input and seed. | `perturb::tests::perturbation_never_exceeds_epsilon`, `properties::perturbation_always_within_epsilon` |
| INV-L2-06 | Perturbation touches Alpha/Gamma coordinates only. | `perturb::tests::only_alpha_gamma_coordinates_move`, `ffi::tests::pipeline_handle_perturbs_within_epsilon` |
| INV-L2-07 | Calibrated ε always lies in [min_epsilon, max_epsilon]; stable streams get ε ≥ noisy streams' ε at equal range. | `calibration::tests::*` |
| INV-L2-08 | Mean per-frame Layer 2 pipeline cost < 20 ms. | `tests/latency.rs` |

## Layer 3 — Storage & attestation

| ID | Invariant | Enforced by |
|---|---|---|
| INV-L3-01 | Sealed records never appear as plaintext on disk. | `storage::tests::disk_bytes_do_not_contain_plaintext` |
| INV-L3-02 | A record sealed under key A cannot be opened under key B. | `storage::tests::wrong_key_cannot_open` |
| INV-L3-03 | The SQLCipher key derivation is deterministic per seed, domain-separated from every other SHIELD key, and refuses short seeds. | `keystore::tests::*` |
| INV-L3-04 | An attestation token contains the predicate boolean and commitment — never the private index/value it was computed from. | `attest::tests::token_reveals_only_the_boolean` |
| INV-L3-05 | Release requires a grant for the exact (app, scope); attestation scope ≠ features scope. Denied releases append nothing to the audit log. | `pipeline::tests::no_grant_no_slice`, `attestation_requires_its_own_scope`, `revoked_grant_denies_again` |

## Layer 4 — Audit log & receipts

| ID | Invariant | Enforced by |
|---|---|---|
| INV-L4-01 | Every granted release/attestation appends exactly one audit event BEFORE the data is returned (log-then-release). | `pipeline::tests::granted_release_is_logged_with_verifiable_receipt` |
| INV-L4-02 | For every leaf i, the inclusion proof for i verifies against the current root. | `audit::tests::inclusion_proofs_verify_for_all_leaves`, `properties::audit_inclusion_always_verifies` |
| INV-L4-03 | Tampering with any event field invalidates its receipt/proof. | `audit::tests::tampered_event_fails_verification` |
| INV-L4-04 | The root is a pure function of the leaf sequence: appending changes it; two logs with equal leaf sequences have equal roots. | `audit::tests::root_changes_on_append`, `empty_root_is_stable` |

## Agentic binding

| ID | Invariant | Enforced by |
|---|---|---|
| INV-AG-01 | A signed envelope verifies iff unaltered and unexpired; any field tamper fails. | `agent_binding::tests::signed_envelope_verifies_and_tampering_fails`, `expired_envelope_fails` |
| INV-AG-02 | Ephemeral IDs are equal within (registry, day) and unequal across either dimension. | `agent_binding::tests::ephemeral_ids_rotate_across_registries_and_days_only` |
| INV-AG-03 | The serialized envelope contains no session/device/user metadata fields, ever. | `agent_binding::tests::envelope_carries_no_session_metadata` |
