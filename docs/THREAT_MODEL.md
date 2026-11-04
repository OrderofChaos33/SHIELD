# SHIELD — Threat Model

Version 0.1 · 2026-11-04

## Assets

1. Raw EEG / neural telemetry (the thing itself).
2. Brainprint — the cross-session identifiable topography derivable from (1).
3. Inferred states: subvocal / speech intent, emotional valence,
   attention, fatigue — current or future decoder capability.
4. Session keys, storage keys, identity of paired devices.
5. The audit log's completeness (a log that silently omits a release is
   worse than no log).

## Adversaries

| # | Adversary | Capability assumed |
|---|---|---|
| A1 | Passive BLE sniffer | Within ~10 m, captures all advertisements / weakly encrypted traffic. |
| A2 | Active BLE attacker | Injection, replay, MitM attempts against the headset link. |
| A3 | Curious / hostile third-party app (on- or off-device) | Receives or buys feature data; runs state-of-the-art ML decoders; attempts re-identification and state inference beyond what the user consented to. |
| A4 | Cloud service demanding "verification" | Wants raw logs uploaded; is honest-but-curious at best. |
| A5 | Data broker with multi-session datasets | Correlates feature vectors across time / apps to rebuild identity. |
| A6 | Lost / seized device attacker | Has the hardware, not the passphrase / biometric. |

Out of scope (v0.1): a fully compromised OS / rooted device with the
enclave itself breached; nation-state lab attacks on the handset;
coercion. SHIELD raises the cost of everything below that line; it does
not claim to defeat that line.

## Defenses mapped to adversaries

- **A1 / A2 → Layer 1.** ECDH session from pairing, per-frame HMAC,
  monotonic sequence window, drop-by-default for unsolicited packets.
  A sniffer gets ciphertext + metadata, not telemetry.
- **A3 / A5 → Layer 2.** Relative-power features only; session-keyed
  orthogonal scrambling (brainprint does not persist across sessions);
  bounded adversarial perturbation aimed at identity decoding.
- **A4 → Layer 3.** The answer to "upload your logs" is a ZK proof of a
  boolean predicate. Raw logs have no export path.
- **A6 → Layers 0 + 3.** Enclave-derived keys + AES-256-GCM at rest;
  without the enclave operation, the store is ciphertext.
- **All → Layer 4.** Every release is logged before it happens
  (log-then-release ordering in the core API), so a release without a
  receipt is a bug by construction, and receipts verify offline.

## Known limitations — stated plainly

1. **Metadata leaks exist.** BLE timing, packet sizes, and the mere
   presence of a headset are visible to A1. SHIELD protects content,
   not existence.
2. **Adversarial perturbation is not a proof.** §3.2 of the field, in
   plain terms: FGSM noise tuned against our dummy model degrades
   *similar* decoders substantially in testing and *dissimilar*
   decoders unpredictably. The scrambler (an information-destroying
   transform for absolute topography) is the primary defense; the
   perturbation is a second, probabilistic layer. Do not invert this.
3. **Within-session linkage is intact by design.** An authorized app
   can track your state across one session — that's the product. It
   cannot (via SHIELD's outputs) link that session to yesterday's.
4. **The enclave is trusted.** If Secure Enclave / StrongBox falls,
   Layer 3 falls. Layer 1 session keys are ephemeral and unaffected.
5. **Compelled unlocking defeats local encryption.** True of every
   local-first design; noted, not solved.

## Security practices for this repo

- No real telemetry, ever, in tests, fixtures, issues, or commits.
  Synthetic signals only.
- No secrets in the tree. Keys in tests are fixed, published, test-only.
- Dependencies are pinned (`Cargo.lock` committed) and kept minimal:
  every crate is a supply-chain decision (see `docs/ADR-001-deps.md`).
- Any change touching `ble`, `crypto`, `storage`, or `audit` requires
  a second-pass adversarial review before merge — even solo, especially solo:
  write the attack you'd run, add it as a test, then merge.
