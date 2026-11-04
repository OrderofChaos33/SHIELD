# SHIELD iOS shell — secondary target

The founder's device is Android (Kyocera DuraForce Pro 3); iOS is
maintained as the second platform because the architecture is
cross-platform by design, not because it is the launch target.

## Responsibilities (mirrors the Android shell)

1. **Radio.** CoreBluetooth central; `NSBluetoothAlwaysUsageDescription`
   with honest copy: "SHIELD intercepts your headset so other apps can't."
2. **Sequence gate + session.** Same core handles via UniFFI Swift bindings.
3. **Enclave.** Secure Enclave P-256 key (biometric/passcode access
   control) unwraps the Keychain-stored master seed — the Enclave holds
   ECC keys, so the symmetric seed is *wrapped by*, not stored in, it.
   The unwrapped seed transits once into
   `SecureStorageHandle.initializeEncryptedStore`.
4. **UI.** Grant manager + receipt dashboard, same information contract
   as Android (root, per-app counts, fingerprint, enclave backing).

## Swift call example (from the Layer 2 spec)

```swift
let pipeline = createShieldPipeline(epsilon: 0.09, channelCount: 8)
let sanitizedVector = pipeline.processSlice(
    bandPowers: currentBandPowerArray,
    timestamp: UInt64(Date().timeIntervalSince1970 * 1000),
    channelCount: 8
)
// Feed sanitizedVector.bandPowers into local SQLCipher storage or
// authorized local UI — and nothing else, ever.
```
