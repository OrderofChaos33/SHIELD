# ADR-002 — Key provision: enclave or nothing (in release)

Status: accepted · 2026-11-04

- Production builds use a platform `KeyProvider`: Secure Enclave (iOS)
  or StrongBox (Android). The storage-key operation happens in hardware.
- `SoftwareKeyProvider` (passphrase + HKDF) exists for development and
  tests only. It **panics in release profile** even if compiled in, so a
  misconfigured release build fails loudly instead of silently storing
  the crown jewels behind a passphrase-derived key in app memory.
- Layer 1 session keys are a separate domain: ephemeral, ECDH-derived,
  rotated on time/frame-count triggers, never persisted, never derived
  from the storage key. Compromise of one domain must not imply the other.
