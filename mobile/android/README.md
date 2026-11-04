# SHIELD Android shell — PRIMARY target

**Reference device: Kyocera DuraForce Pro 3 (founder's phone).**
Android-first is a decision, not an accident: SHIELD is built and
performance-validated against this device class — rugged mid-tier
Snapdragon, arm64-v8a, Android 13-era — not against a flagship lab phone.

## Budgets on this device class

- Layer 2 sanitize: **< 20 ms** per slice (core test asserts the mean;
  re-measure on-device in Phase 2 and record the number here).
- Groth16 proving (fatigue circuit, ~2–3k constraints): **< 500 ms**
  target with rapidsnark; snarkjs-in-WebView is the fallback and must
  be measured honestly before any claim is made.
- Battery: BLE + DSP daemon must survive as a foreground service with
  a visible notification (Android requirement, and honest UX: the user
  should always see when SHIELD is intercepting).

## Responsibilities of this shell (and only this shell)

1. **Radio.** Android BLE central (BluetoothLeScanner / BluetoothGatt).
   Runtime permissions: `BLUETOOTH_SCAN` + `BLUETOOTH_CONNECT`
   (Android 12+), never location permission — request
   `neverForLocation` in the manifest.
2. **Sequence gate + session crypto.** Every notification goes through
   `BleProxyHandle.validateSequence` (core) and the Layer 1 session
   before samples are assembled into frames.
3. **Enclave.** Android Keystore key in StrongBox where available
   (DuraForce Pro 3: fall back to TEE if StrongBox is absent — query
   `KeyInfo.isInsideSecureHardware()` / security level and RECORD
   which one is in use in the audit dashboard; never claim StrongBox
   silently). The Keystore AES key unwraps the master seed; the seed
   transits to `SecureStorageHandle.initializeEncryptedStore` once.
4. **RPA rotation.** Request resolvable-private-address rotation from
   the OS stack; the shell cannot force the chipset's rotation
   interval and the UI must say so if asked.
5. **UI.** Grant manager, receipt dashboard (Merkle root + per-app
   counts + key fingerprint + enclave backing actually in use).

## Pairing posture

Reject unauthenticated pairing for the headset bond where the headset
supports it; where it does not (most consumer BCI gear), say so in the
UI and rely on the Layer 1 authenticated tunnel — link pairing is a
convenience here, never the security boundary.
