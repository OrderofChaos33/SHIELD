# UniFFI binding — how the shells call the core

The core uses UniFFI **proc macros** (`#[uniffi::export]` in
`crates/shield-core/src/ffi.rs`). There is no hand-written JNI or
Objective-C bridge, and no runtime UDL: `crates/shield-core/src/nshield.udl`
is kept as a human-readable reference of the exported surface only —
the proc-macro annotations are the source of truth.

## Exported surface

| Handle | Layer | Key calls |
|---|---|---|
| `createShieldPipeline(epsilon, channelCount)` -> `ShieldPipelineHandle` | 2 | `processSlice(bandPowers, timestamp, channelCount)`, `epsilon()` |
| `BleProxyHandle` | 1 | `validateSequence(characteristicId, seq)`, `droppedCount()` |
| `SecureStorageHandle` | 0/3 | `initializeEncryptedStore(dbPath, hardwareSeed)`, `isInitialized()`, `keyFingerprint()` |

## Generate bindings

```bash
# Build the library first (produces libshield_core.{so,dylib})
cargo build -p shield-core

# Swift
cargo run -p shield-core --bin uniffi-bindgen -- generate \
  --library target/debug/libshield_core.so \
  --language swift --out-dir mobile/ios/bindings

# Kotlin
cargo run -p shield-core --bin uniffi-bindgen -- generate \
  --library target/debug/libshield_core.so \
  --language kotlin --out-dir mobile/android/bindings
```

Generated bindings are build artifacts — they are not committed; the
shells' READMEs pin the generation commands into their build steps
(xcframework / AAR packaging is Phase 2 work, see ROADMAP).

## Threading

All handles are `Send + Sync`. `processSlice` is designed for a
background dispatch queue / coroutine dispatcher: it is pure CPU,
feature-space, and measured far inside the 20 ms budget
(`crates/shield-core/tests/latency.rs`). Never call it on the BLE
callback thread if that thread also feeds the radio — queue first
(the async pipeline in `async_pipeline.rs` is the reference shape).
