# SHIELD — Sovereign Mobile Neuro-Defense Stack

**Project N-SHIELD · Private, local-first, zero-trust**

SHIELD is a personal, sovereign middleware daemon that sits between a
consumer BCI headset (OpenBCI, Muse, Neurosity-class devices) and every
other app on your phone. Raw neural telemetry never leaves the device.
Third-party apps never see your brainprint. What leaves SHIELD — only to
apps *you* authorize, on-device — is a sanitized feature vector, and what
leaves the device at all is, by design, only a zero-knowledge proof token.

> Intelligence proposes. Nothing raw disposes — unless you sign for it.

## The rule

**Default: denied.** No app, service, or background process receives a
telemetry slice without (1) an explicit per-app grant, (2) the DSP +
adversarial pipeline running, and (3) an entry in the local Merkle audit
log you can verify yourself.

## Architecture

| Layer | Name | What it guarantees |
|---|---|---|
| 0 | Secure Hardware Enclave | Keys are derived in / sealed to Apple Secure Enclave or Android StrongBox. Keys never enter app memory in plaintext form on a real device build. |
| 1 | Hardened BLE Intercept Proxy | ECDH (X25519) session handshake, HKDF-derived session keys, HMAC-authenticated frames, monotonic sequence tracking. Replay, injection, and unsolicited broadcast packets are dropped. |
| 2 | DSP & Adversarial Perturbation Engine | Bandpower features (Δ Θ Α Β Γ), artifact stripping, a session-keyed **orthogonal topography scrambler** that destroys cross-session brainprint identity while preserving relative state shifts, and bounded (ε-ball) FGSM + Gaussian perturbation targeted at the Alpha/Gamma bands third-party decoders lean on. |
| 3 | Local Enclave & ZKP Attestation | Processed state lives only in AES-256-GCM encrypted local storage keyed from Layer 0. Circom circuits prove boolean statements (e.g. `fatigue < threshold`) without revealing any input. |
| 4 | Immutable Local Merkle Audit Log | Every feature-slice release is hashed (app, scope, noise level, timestamp) into an on-device Merkle tree. The receipt dashboard is the log root + inclusion proofs — verifiable offline, by you. |

Full spec: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) ·
Threat model: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) ·
Roadmap & honest status: [`docs/ROADMAP.md`](docs/ROADMAP.md)

## Status — read this first

This is a **working core, not a finished product.**

**Verified today (automated tests: 55 passing, `cargo test --workspace`;
async variant 56 with `--features async-pipeline`):**
- Layer 0: HKDF-SHA256 SQLCipher key derivation from a hardware-unwrapped
  seed (zeroized, domain-separated, fingerprintable without exposure);
  SQLCipher open path compiles under `--features sqlcipher-store`.
- Layer 1 session handshake (X25519 + HKDF), authenticated frames,
  replay / out-of-window rejection, plus the wraparound-safe u16 device
  sequence gate (65535 → 0 is fresh, replays are not).
- Layer 2 full DSP pipeline on synthetic EEG: bandpower extraction,
  orthogonal scrambling, nalgebra identity-nulling projection
  (P·v_identity = 0, idempotent), bounded adversarial perturbation
  (‖δ‖∞ ≤ ε by construction), and **SNR-driven ε calibration** —
  the ε on every audit receipt is the calibrated one actually applied.
- Layer 2 latency: mean per-frame pipeline cost asserted < 20 ms
  (`tests/latency.rs`).
- Layer 3 AES-256-GCM encrypted local store round-trip with an
  enclave-key *interface* (software key provider for dev/test).
- Layer 4 Merkle append, root, inclusion proofs, and **cryptographic
  receipts** (`Receipt::verify`) — plus the spec-shaped
  `MerkleAuditLog` facade (`append_event` / `compute_root`).
- Agentic binding: Ed25519-signed attestation envelopes for A2A
  registries with rotating per-registry ephemeral IDs and a tested
  no-session-metadata guarantee.
- UniFFI handles for all of the above (pipeline / BLE gate / storage),
  exercised by unit tests through the same code the shells will call.
- End-to-end loop: synthetic raw stream → sanitized vector → attestation
  token → audit receipt that verifies. See `crates/shield-cli`.

**Not yet real (do not believe anyone who says otherwise):**
- No real headset has been paired yet. The btleplug proxy
  (`--features ble-radio`) is API-verified against btleplug 0.11.8 and
  compiled in CI; in this dev VM its compile waits on system
  `libdbus-1-dev`. On phones, the shells own the radio (native BLE).
- Secure Enclave / StrongBox unwrap is a platform flow (documented in
  the shells), not yet device-tested code.
- The Circom circuits in `circuits/` are written and specified; they
  have not yet been compiled with `circom` / proven with `snarkjs` in CI.
- Android / iOS apps are documented interface shells with reference
  call sites, not store builds.

**Primary target device: Kyocera DuraForce Pro 3 (Android).**
Android is the lead platform; budgets (20 ms sanitize, < 500 ms
proving) are set for this rugged mid-tier device class, not flagships.
See `mobile/android/README.md`.

## Quickstart

```bash
# Rust stable required
cargo test  --workspace          # full test suite
cargo run   -p shield-cli        # end-to-end demo: raw -> sanitized -> proof token -> receipt
```

## Repo layout

```
crates/shield-core/   Rust core: ble, dsp, perturb, crypto, storage, audit, attest
crates/shield-cli/    Demo / verification CLI (synthetic device)
circuits/             Circom ZKP circuits (Layer 3)
mobile/ios/           Swift shell (Secure Enclave + CoreBluetooth target)
mobile/android/       Kotlin shell (StrongBox + Android BLE target)
docs/                 Architecture, threat model, roadmap, ADRs
```

## Sovereignty rules (non-negotiable)

1. **No telemetry, no analytics, no cloud.** Not ours, not anyone's.
2. **No raw EEG leaves the core.** Ever. The API surface physically has
   no method that returns raw frames to an app.
3. **Private by default.** This repository is personal infrastructure.
   Treat every commit as if a future adversary will read it: no secrets,
   no real telemetry captures, no device identifiers in the tree.
4. **Working, or it doesn't ship.** A layer is "done" when its full loop
   is tested end-to-end, not when its unit tests are green.

## License

See `LICENSE` in this repository.
