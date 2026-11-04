# SHIELD — Architecture Specification

Version 0.1 · 2026-11-04 · Status: core implemented, platform layers in progress

## Design posture

Zero-trust, local-first, single-user. SHIELD assumes the phone's app
ecosystem, the BLE radio environment, and any network are hostile. It
assumes the hardware enclave is not. Everything else must prove itself
per session, per frame, per feature-slice request.

## Data flow

```
Headset ──BLE──▶ [L1 Proxy] ──raw frames (in-core only)──▶ [L2 DSP]
                                                              │
                                            sanitized feature vector
                                                              ▼
                                          [L3 Encrypted local store]
                                                              │
                        ┌─────────────────────┬───────────────┘
                        ▼                     ▼
              Authorized local app     [L3 ZKP generator]
              (feature slice,          proof token only
               grant-checked)                │
                        │                    ▼ external service
                        ▼
                  [L4 Merkle audit log] ◀── every release, every proof
```

Raw frames exist only inside `shield-core` memory between L1 and L2.
There is no public API that returns them. This is enforced by type:
`RawFrame` is not `pub` outside the core crate.

## Layer 0 — Secure Hardware Enclave

Interface: `crypto::KeyProvider`.

- `derive_storage_key()` — returns a 32-byte key material handle used to
  key the Layer 3 store. On device: derived inside Secure Enclave /
  StrongBox and released only as an opaque operation. In dev/test:
  `SoftwareKeyProvider` derives from a user passphrase via HKDF-SHA256 —
  **clearly labelled, never used in a release build** (`release` profile
  + `software-keys` feature gate refuses to compile together; see ADR-002).
- Session keys for Layer 1 are ephemeral and never touch Layer 0.

## Layer 1 — Hardened BLE Intercept Proxy (`ble` module)

Threats: passive capture of weakly-authenticated BLE advertisements,
MitM injection, replay of captured frames, MAC-based tracking.

Protocol (v0.1, Noise-inspired, deliberately minimal):

1. Pairing: X25519 ECDH between phone and proxy-paired device identity.
2. `HKDF-SHA256(shared, salt=session_nonce, info="shield-l1-v1")`
   → frame-auth key + frame-encryption key.
3. Every frame: `seq (u64, monotonic) ‖ nonce ‖ ciphertext ‖ HMAC-SHA256`.
4. Receiver enforces: HMAC first, then sequence window
   (`seq > last_seen`, gaps logged, duplicates and replays dropped),
   then decrypt. Unsolicited broadcasts (no live session) are dropped
   before parsing.
5. Ephemeral rotation: session keys rotate every 15 minutes or 65,536
   frames, whichever first; rotation is a fresh ECDH, not a re-key of
   the same secret. Device MAC randomization is requested from the OS
   BLE stack where the platform allows it (mobile shell responsibility).

Implementation status: handshake, framing, HMAC, sequence/replay logic
implemented and tested against `MockTransport`. Real BLE is a platform
`Transport` implementation, pending in the mobile shells.

## Layer 2 — DSP & Adversarial Perturbation (`dsp`, `perturb` modules)

Input: `RawFrame` — multichannel samples, `sample_rate_hz`, channel labels.
Output: `FeatureVector` — per-band relative powers + state deltas. Nothing else.

Pipeline:

1. **Pre-clean.** Per-channel demeaning; soft amplitude clipping at
   ±4σ (blink / motion artifact suppression without hard dropouts).
2. **Bandpower.** DFT bandpower over Δ (0.5–4), Θ (4–8), Α (8–13),
   Β (13–30), Γ (30–50 Hz), normalized to relative power so absolute
   amplitude (a strong identity cue) is discarded at this step already.
3. **Topography scrambler.** The channel×band feature matrix is flattened
   and multiplied by an orthogonal matrix **Q** derived from the session
   key (deterministic PRNG → Gram–Schmidt). Properties relied on:
   - ‖Qx‖ = ‖x‖ — energy and relative geometry are preserved, so a
     *local, authorized* app tracking state *within* a session still works.
   - Q changes every session — the absolute topography that identifies a
     person across sessions (their "brainprint") does not survive.
   - Q never leaves the core. Without Q, cross-session linkage requires
     solving for an unknown orthogonal transform per session.
4. **Adversarial perturbation.** A local dummy decoder (fixed linear
   model shipped in the core) provides a gradient of a dummy identity
   target w.r.t. the feature vector. FGSM step `δ = ε · sign(∇)` is
   computed, restricted to Alpha/Gamma coordinates, and hard-clamped to
   the ε-ball (`‖δ‖∞ ≤ ε`, default ε = 0.08 relative-power units),
   plus seeded Gaussian noise (σ = ε/4) on the same coordinates.
   The perturbation is *maximal against the dummy identity model*;
   honest limitation: transfer to an unknown third-party decoder is
   probabilistic, not guaranteed — see THREAT_MODEL.md §3.2.
5. **State deltas.** The released vector includes deltas vs. the
   session's own baseline (relative shifts), which is what legitimate
   focus / fatigue apps actually need.

## Layer 3 — Enclave storage & ZKP attestation (`storage`, `attest`)

- Storage: append-only records, each sealed with AES-256-GCM
  (random 96-bit nonce per record, AAD = record type + timestamp).
  On-disk format is a local file in the app sandbox; a SQLCipher
  backend is planned behind the same `Store` trait (ADR-003).
- Attestation: Circom circuit `circuits/attestation.circom` proves,
  for a committed feature record, a boolean predicate — v0.1:
  `fatigue_index < threshold` — revealing only (predicate, threshold,
  commitment). Proof generation is local (snarkjs / rapidsnark on
  device target). The Rust core produces the *attestation token*
  envelope (commitment + predicate + audit-log index) that the circuit
  binds to; see `attest` module and the circuit README for the exact
  binding (`sig_digest`-style Poseidon commitment is a circuit-side
  TODO, tracked in ROADMAP).

## Layer 4 — Merkle audit log (`audit` module)

- Event: `(timestamp, app_id, scope, epsilon_applied, record_commitment)`.
- SHA-256 Merkle tree, append-only, root checkpointed into the Layer 3
  store after every append. Inclusion proofs are O(log n) and verify
  offline.
- The user-facing receipt dashboard (mobile shell) renders: current
  root, per-app release counts, and a one-tap inclusion proof for any
  event. **Design goal: the user can prove to themselves that the set
  of things that left the core is exactly the set they approved.**

## Cross-cutting

- **No network in the core.** `shield-core` has no HTTP client and no
  sockets. The mobile shells may transmit *proof tokens only*, and that
  path does not import the core's storage or raw types.
- **Determinism for tests, entropy for life.** Every randomized
  component takes a seeded PRNG in tests and an OS-entropy seed in
  production wiring.
- **Fail closed.** Any HMAC failure, sequence anomaly, grant miss, or
  store-decrypt failure drops the frame / denies the slice. There is
  no "permissive mode."

## Addenda (integrated from the Layer 0–4 production blueprints)

- **Calibration (Layer 2 support, `calibration.rs`).** ε is not static.
  An `EpsilonCalibrator` estimates the live noise floor (per-dimension
  variance over a rolling 30-window buffer) and dynamic range, and sets
  ε = range / (noise_floor · target_snr), clamped to [0.02, 0.15].
  Noisy, artifact-heavy streams scale ε *down* to protect authorized
  local apps; clean stable streams scale it *up*. The ε printed on a
  receipt is the calibrated ε actually applied to that slice.
- **Async pipeline (`async_pipeline.rs`, feature `async-pipeline`).**
  Tokio shape for the daemon form factor: bounded mpsc in, a watch
  channel carrying ε updates to the worker lock-free, and a downstream
  leg using `try_send` + a drop counter (real-time data drops stale
  frames rather than blocking the stream). The calibration daemon reads
  the *same* window buffer the worker feeds — a daemon calibrating a
  buffer nothing writes to would be a silent no-op, and was the first
  bug caught in the sketch this was built from.
- **Receipts (Layer 4, `audit.rs`).** `AuditLog::receipt(i)` issues a
  `Receipt { event, leaf_index, leaf_hash, root, inclusion_proof }`
  with `Receipt::verify()`. `MerkleAuditLog` provides the spec-shaped
  facade (`append_event` / `compute_root`) over the same log.
- **Agentic binding (`agent_binding.rs`).** For A2A registries: an
  Ed25519-signed envelope over (ephemeral_id, predicate, threshold,
  holds, record commitment, audit root + index, expiry, nonce).
  Ephemeral IDs rotate per registry per UTC day and are unlinkable
  across both. The envelope schema has no field capable of carrying
  session or device metadata, and a test enforces that.
- **SQLCipher (Layer 0/3, `keystore.rs`, feature `sqlcipher-store`).**
  HKDF-SHA256(salt `N-SHIELD_SQLCIPHER_SALT_V1`, info
  `sqlite_aes_256_gcm_derived_key`) over the hardware-unwrapped master
  seed → hex key → `PRAGMA key = "x'...'"`, cipher parameters set
  before the first page touch, validation query last. The sealed-record
  store remains the default backend; SQLCipher lands behind the same
  surface per ADR-003.
