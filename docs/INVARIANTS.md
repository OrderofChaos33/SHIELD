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

## Layer 5 — Mirrorfield (active defense, own perimeter only)

Added 2026-11-05 with the Mirrorfield build. Scope is strictly the
owner's own stack: detection, decoy, hardening, lockdown. No function
in this layer transmits anything intended to interfere with, disable,
or degrade another party's device (founder rule, 2026-11-05: never
break the law, ever).

| ID | Invariant | Enforced by |
|---|---|---|
| INV-L5-01 | A canary-characteristic touch always marks the peer Hostile + quarantined, and the probe event is appended to the audit log BEFORE any response is served. | `mirrorfield::tests::canary_touch_quarantines_and_logs_first`, `mirrorfield_loop` |
| INV-L5-02 | A quarantined peer never receives real sanitized data. NO FREE DATA (founder rule, 2026-11-05): no consumer without an existing `features` grant receives anything at all — mirror features are a degraded service UNDER a grant, never a handout; ungranted peers get `NoGrant` and zero bytes. In Lockdown posture, granted consumers receive mirror features only; ungranted receive nothing. | `mirrorfield::tests::quarantined_peer_gets_mirror_not_real`, `quarantined_without_grant_gets_nothing`, `panic_lockdown_mirrors_everyone`, `mirrorfield_loop` |
| INV-L5-03 | Mirror features are a pure function of (persona seed, serve counter): identical across different real frames, and the mirror path never reads frame contents. | `mirrorfield::tests::mirror_output_ignores_real_frame`, `properties::mirror_is_frame_independent` |
| INV-L5-04 | A sanitized advertisement carries no device name, no manufacturer data, and at most the primary service UUID. | `mirrorfield::tests::advertisement_sanitizer_strips_identity` |
| INV-L5-05 | Persona IDs are equal within an epoch hour and unequal across epochs; canary watermarks are unique per characteristic and stable per persona seed (leak attribution). | `mirrorfield::tests::persona_rotation_and_watermark_stability` |
| INV-L5-06 | Probe scoring is monotonic: observing additional probe events never lowers a peer's score or verdict. | `mirrorfield::tests::scoring_is_monotonic`, `properties::probe_scores_never_decrease` |
| INV-L5-07 | Panic enters Lockdown immediately and is audit-logged; Lockdown exits only via explicit owner clear, which is also audit-logged. Probe events alone never exit Lockdown. | `mirrorfield::tests::panic_lockdown_and_owner_clear` |
