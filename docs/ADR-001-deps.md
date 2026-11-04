# ADR-001 — Core dependency policy

Status: accepted · 2026-11-04

Every dependency is a supply-chain decision. The core's list is kept
deliberately short, all from the RustCrypto / dalek ecosystem plus serde:

| Crate | Why | If removed |
|---|---|---|
| `sha2` | Merkle log, commitments, HKDF/HMAC primitives | No audit log — not removable |
| `hmac` | Layer 1 frame authentication | Not removable |
| `hkdf` | Session + storage key derivation | Not removable |
| `x25519-dalek` | Layer 1 ECDH handshake | Not removable |
| `aes-gcm` | Frame + record encryption (AES-256-GCM) | Not removable |
| `serde` / `serde_json` | Feature-vector / token serialization | Convenience; replaceable |
| `getrandom` | OS entropy for nonces | Not removable |
| `nalgebra` | Topography stripper projection (Layer 2 spec) | Hand-rolled matmul; kept for auditability of the linear algebra |
| `uniffi` | Swift/Kotlin bindings via proc macros (no hand JNI/ObjC) | Manual FFI — rejected, error-prone |
| `zeroize` | SQLCipher key + seed hygiene in memory | Not removable on the key path |
| `hex` | SQLCipher `x'...'` key form, fingerprints | Trivial; replaceable |
| `ed25519-dalek` | Agentic envelope signing (same family as SINCOR's control-plane signing) | Not removable on the binding path |
| `btleplug` + `tokio` + `futures` (optional, `ble-radio` / `async-pipeline`) | Desktop BLE proxy + async pipeline | Feature-gated; core builds without them |
| `rusqlite` + bundled SQLCipher (optional, `sqlcipher-store`) | Layer 3 SQLCipher backend | Feature-gated; sealed-record store is the default |

Explicitly absent, on purpose: no HTTP client, no async runtime, no
telemetry/analytics crate, no general-purpose FFT (the naive DFT keeps
Layer 2 auditable at this frame size).

New dependency = a line in this table, in the same commit.
