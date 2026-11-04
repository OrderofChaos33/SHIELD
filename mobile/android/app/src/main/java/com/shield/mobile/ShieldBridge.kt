package com.shield.mobile

// Reference call sites for the UniFFI-generated Kotlin bindings
// (generated into mobile/android/bindings — see docs/UNIFFI.md).
// Types below (ShieldPipelineHandle, BleProxyHandle,
// SecureStorageHandle, FfiFeatureVector) are the generated ones in
// package `uniffi.shield_core`.
//
// import uniffi.shield_core.createShieldPipeline
// import uniffi.shield_core.BleProxyHandle
// import uniffi.shield_core.SecureStorageHandle

/**
 * Layer 2 usage, mirroring the spec's Swift/Kotlin example:
 * create once at daemon start, call per slice on a background dispatcher.
 */
/*
val pipeline = createShieldPipeline(epsilon = 0.09f, channelCount = 8u)
val sanitized = pipeline.processSlice(
    bandPowers = currentBandPowerArray,          // List<Float>, channels x 5 bands
    timestamp = System.currentTimeMillis().toULong(),
    channelCount = 8u,
)
// sanitized.bandPowers -> SQLCipher store / authorized local UI only.

/** Layer 1: gate every BLE notification before assembling frames. */
val bleProxy = BleProxyHandle()
fun onNotification(characteristicId: String, seq: Int, payload: ByteArray): Boolean {
    val fresh = bleProxy.validateSequence(characteristicId, seq.toUShort())
    if (!fresh) return false // replay / stale: dropped, counted in bleProxy.droppedCount()
    // ... hand payload to the Layer 1 session + Layer 2 ...
    return true
}

/** Layer 0: initialize once, after Keystore unwrap of the master seed. */
val storage = SecureStorageHandle()
fun initStorage(dbPath: String, hardwareSeed: ByteArray) {
    storage.initializeEncryptedStore(dbPath, hardwareSeed.toList())
    check(storage.isInitialized())
    // storage.keyFingerprint() is safe to display; the key never is.
}
*/
