# ADR-003 — Storage: sealed records now, SQLCipher behind the same surface

Status: accepted · 2026-11-04

v0.1 stores individually AES-256-GCM-sealed records in a length-prefixed
local file (`storage.rs`). This is real encryption with per-record
nonces and AAD binding today — not a placeholder.

SQLCipher (the directive's original pick) remains the Phase 3 target
for queryable encrypted storage, introduced behind the same
`EncryptedStore` surface so the pipeline and audit layers do not change
when it lands. Until then, no SQL surface exists to inject into, which
is its own small security property.
