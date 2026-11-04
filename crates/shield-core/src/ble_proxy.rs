//! Layer 1 radio proxy — btleplug implementation (feature `ble-radio`).
//!
//! Runs the app as a BLE *central*: scan -> connect to the target BCI
//! peripheral -> discover services -> subscribe to NOTIFY telemetry
//! characteristics -> gate every notification through the wraparound-
//! safe [`DeviceSeqTracker`] (keyed by the full characteristic UUID
//! string — never a truncated hash) -> hand surviving payloads to the
//! secured-packet buffer that Layer 2 drains.
//!
//! Corrections vs. the original blueprint sketch, all deliberate:
//! - `ok_or(...)`, not the non-existent `okOfString`.
//! - One notification stream per peripheral (btleplug semantics),
//!   consumed in a single loop — not one spawned stream per characteristic.
//! - u16 sequence handling uses serial-number arithmetic (see
//!   `DeviceSeqTracker`); a naive `seq <= last` rejects the legitimate
//!   65535 -> 0 wrap and accepts nothing after it.
//! - The tracker map is keyed by the full UUID, not `uuid as u16`
//!   (truncation collides unrelated characteristics).
//!
//! Platform honesty: btleplug's mobile support is limited. This proxy
//! targets the desktop / companion-daemon form factor today. On Android
//! and iOS the shells own the radio (native BLE) and reuse the exact
//! same sequence gate + Layer 1 session crypto from this crate — see
//! `ffi::BleProxyHandle`.
//!
//! Pairing posture: link-layer "Just Works" pairing is NOT trusted.
//! Even on a paired link, payloads only become telemetry after the
//! Layer 1 session (X25519 + HMAC, `ble::Session`) authenticates them.
//! RPA rotation is requested from the OS BLE stack by the mobile
//! shells; a Rust central cannot command the phone's MAC rotation, and
//! this module does not pretend otherwise.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use btleplug::api::{Central, CharPropFlags, Manager as _, Peripheral as _, ScanFilter};
use btleplug::platform::Manager;
use futures::StreamExt;
use tokio::time::{sleep, Duration};

use crate::ble::DeviceSeqTracker;

#[derive(Default)]
pub struct ProxyStats {
    pub accepted: u64,
    pub dropped_replay_or_stale: u64,
    pub dropped_malformed: u64,
}

pub struct BleInterceptorProxy {
    seq_trackers: Arc<Mutex<HashMap<String, DeviceSeqTracker>>>,
    secured_buffer: Arc<Mutex<Vec<Vec<u8>>>>,
    pub stats: Arc<Mutex<ProxyStats>>,
}

impl Default for BleInterceptorProxy {
    fn default() -> Self {
        Self::new()
    }
}

impl BleInterceptorProxy {
    pub fn new() -> Self {
        Self {
            seq_trackers: Arc::new(Mutex::new(HashMap::new())),
            secured_buffer: Arc::new(Mutex::new(Vec::new())),
            stats: Arc::new(Mutex::new(ProxyStats::default())),
        }
    }

    /// Gate one raw notification value. Returns true if it survived.
    /// Frame layout (device-side): seq u16 BE || payload.
    pub fn gate_notification(&self, characteristic_uuid: &str, value: &[u8]) -> bool {
        if value.len() < 3 {
            self.stats.lock().unwrap().dropped_malformed += 1;
            return false;
        }
        let seq = u16::from_be_bytes([value[0], value[1]]);
        let fresh = {
            let mut trackers = self.seq_trackers.lock().unwrap();
            trackers
                .entry(characteristic_uuid.to_string())
                .or_default()
                .check_and_advance(seq)
        };
        if !fresh {
            self.stats.lock().unwrap().dropped_replay_or_stale += 1;
            return false;
        }
        self.stats.lock().unwrap().accepted += 1;
        self.process_secured_packet(&value[2..]);
        true
    }

    fn process_secured_packet(&self, payload: &[u8]) {
        self.secured_buffer.lock().unwrap().push(payload.to_vec());
    }

    /// Drain payloads that survived the gate, for Layer 2.
    pub fn drain_secured(&self) -> Vec<Vec<u8>> {
        std::mem::take(&mut *self.secured_buffer.lock().unwrap())
    }

    /// Scan for a target peripheral by name fragment, connect, and
    /// consume its telemetry notifications through the gate until the
    /// stream ends (disconnect).
    pub async fn scan_and_intercept(
        &self,
        target_name: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let manager = Manager::new().await?;
        let adapters = manager.adapters().await?;
        let central = adapters
            .into_iter()
            .next()
            .ok_or("No Bluetooth adapters found")?;

        central.start_scan(ScanFilter::default()).await?;
        sleep(Duration::from_secs(2)).await;

        for peripheral in central.peripherals().await? {
            let Some(props) = peripheral.properties().await? else {
                continue;
            };
            let matched = props.local_name.iter().any(|n| n.contains(target_name));
            if !matched {
                continue;
            }
            central.stop_scan().await?;
            peripheral.connect().await?;
            peripheral.discover_services().await?;
            self.monitor_characteristics(&peripheral).await?;
            break;
        }
        Ok(())
    }

    async fn monitor_characteristics<P: Peripheral>(
        &self,
        peripheral: &P,
    ) -> Result<(), Box<dyn std::error::Error>> {
        for characteristic in peripheral.characteristics() {
            if characteristic.properties.contains(CharPropFlags::NOTIFY) {
                peripheral.subscribe(&characteristic).await?;
            }
        }
        let mut stream = peripheral.notifications().await?;
        while let Some(data) = stream.next().await {
            self.gate_notification(&data.uuid.to_string(), &data.value);
        }
        Ok(())
    }
}
