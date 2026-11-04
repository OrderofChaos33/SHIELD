# SHIELD — Roadmap & Honest Status

Updated 2026-11-04. Rule: a box is checked only when the full loop it
belongs to is tested end-to-end, not when the unit exists.

## Phase 0 — Core (this commit)

- [x] Layer 0: HKDF SQLCipher key derivation from hardware-unwrapped seed (zeroize, domain-separated); SQLCipher open compiles behind `sqlcipher-store`
- [x] Layer 1: X25519 + HKDF session handshake, HMAC frames, replay window (mock transport)
- [x] Layer 1: wraparound-safe u16 device sequence gate; btleplug proxy behind `ble-radio` (CI-compiled)
- [x] Layer 2: bandpower DSP, artifact soft-clip, orthogonal topography scrambler
- [x] Layer 2: nalgebra identity-nulling topography stripper (P·v = 0, idempotent), wired into the pipeline
- [x] Layer 2: FGSM + Gaussian adversarial perturbation, ε-ball enforced
- [x] Layer 2: inter-subject ε calibration (noise-floor / dynamic-range), applied per release and recorded on receipts
- [x] Layer 2: async Tokio pipeline (watch-channel ε, shared calibration buffer, try_send drop-counted backpressure) behind `async-pipeline`
- [x] Layer 2: latency budget test — mean per-frame cost < 20 ms
- [x] Layer 3: AES-256-GCM encrypted local store (software key provider, dev/test)
- [x] Layer 3: attestation token envelope in core
- [x] Layer 4: Merkle audit log, inclusion proofs, log-then-release API, cryptographic receipts, spec-shaped `MerkleAuditLog` facade
- [x] Agentic binding: Ed25519-signed, metadata-free attestation envelopes, rotating ephemeral IDs, agent-card skill entry
- [x] UniFFI proc-macro handles (pipeline / BLE gate / storage) + bindgen binary + UDL reference
- [x] End-to-end CLI demo + integration test of the full loop
- [x] Circom circuits written + specified (`circuits/`), incl. v2 fatigue proof with in-circuit Merkle binding

## Phase 1 — Prove the crypto claims

- [ ] Compile `attestation.circom` in CI; generate + verify a proof with snarkjs on test vectors
- [ ] Bind the ZK commitment to the audit-log index (Poseidon commitment, circuit-side)
- [ ] Property tests: scrambler orthogonality across 1,000 random sessions; perturbation bound fuzzing
- [ ] External adversarial review of Layer 1 framing (even a friendly one)

## Phase 2 — Real hardware (lead device: Kyocera DuraForce Pro 3)

- [ ] Android BLE central (Kotlin shell) against a real Muse / OpenBCI — lead platform
- [ ] CoreBluetooth `Transport` (iOS shell) against a real Muse / OpenBCI
- [ ] Android Keystore unwrap (StrongBox if present on the unit, else TEE — recorded honestly in the dashboard), Secure Enclave unwrap (iOS)
- [ ] On-device latency + proving-time measurements on the DuraForce Pro 3, recorded in `mobile/android/README.md`
- [ ] Session-key rotation timer + frame-count trigger on device

## Phase 3 — Product surface

- [ ] Grant manager UI: per-app, per-scope, expiring grants
- [ ] Receipt dashboard: Merkle root, per-app counts, inclusion-proof viewer
- [ ] SQLCipher backend behind the `Store` trait
- [ ] UniFFI bindings replacing the hand-written FFI stubs in the shells

## Phase 4 — Hardening

- [ ] rapidsnark on-device proving (fatigue predicate < 3 s on a mid-tier phone)
- [ ] Noise-protocol framing review; consider full Noise_XX handshake
- [ ] Reproducible builds; signed releases; no binary blobs in the repo

## Explicit non-goals

- No cloud sync. No accounts. No analytics. No "SHIELD community dataset."
- No raw-data export "for debugging." If it's needed, it happens on a
  bench device with synthetic headsets, not on the founder's head.
- No support for streaming raw telemetry to "trusted" third parties.
  Trusted third parties get proofs, like everyone else.
