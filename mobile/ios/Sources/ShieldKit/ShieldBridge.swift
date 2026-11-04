// Reference call sites for the UniFFI-generated Swift bindings
// (generated into mobile/ios/bindings — see docs/UNIFFI.md).
// This file is a documented usage sketch for the shell; the generated
// module is imported as `shield_core` in the real app target.

// import shield_core
//
// // Layer 2 — create once, call per slice off the main thread:
// let pipeline = createShieldPipeline(epsilon: 0.09, channelCount: 8)
// let sanitized = pipeline.processSlice(
//     bandPowers: currentBandPowerArray,
//     timestamp: UInt64(Date().timeIntervalSince1970 * 1000),
//     channelCount: 8
// )
//
// // Layer 1 — gate notifications by characteristic:
// let bleProxy = BleProxyHandle()
// let fresh = bleProxy.validateSequence(characteristicId: "FFE1", seq: seq)
// if !fresh { /* replay or stale — dropped, see bleProxy.droppedCount() */ }
//
// // Layer 0 — after Secure-Enclave unwrap of the master seed:
// let storage = SecureStorageHandle()
// try storage.initializeEncryptedStore(dbPath: dbPath, hardwareSeed: seedBytes)
// assert(storage.isInitialized())
