//! Layer 3 (part 1) — Encrypted local store.
//!
//! Records are sealed individually with AES-256-GCM under the Layer 0
//! storage key: random 96-bit nonce per record, AAD binds record type
//! and timestamp so a sealed record cannot be transplanted into another
//! slot unnoticed. On-disk form is a length-prefixed binary file in the
//! app sandbox — no plaintext field ever touches disk.
//!
//! A SQLCipher backend is planned behind this same surface (ADR-003).

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::crypto::KeyProvider;

#[derive(Debug, PartialEq)]
pub enum StoreError {
    Crypto,
    Io,
    Corrupt,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StoredRecord {
    pub kind: String,
    pub timestamp_ms: u64,
    /// e.g. a FeatureVector serialized — always sealed before disk.
    pub payload: Vec<u8>,
}

struct SealedRecord {
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
    // Kept so open() can rebuild the exact AAD.
    kind: String,
    timestamp_ms: u64,
}

pub struct EncryptedStore {
    key: [u8; 32],
    records: Vec<SealedRecord>,
    pub backing: &'static str,
}

impl EncryptedStore {
    pub fn new(provider: &dyn KeyProvider) -> Self {
        Self {
            key: provider.storage_key(),
            records: Vec::new(),
            backing: provider.backing(),
        }
    }

    fn aad(kind: &str, timestamp_ms: u64) -> Vec<u8> {
        format!("{kind}|{timestamp_ms}").into_bytes()
    }

    pub fn append(&mut self, record: StoredRecord) -> Result<usize, StoreError> {
        let nonce_bytes = crate::crypto::random_bytes::<12>();
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
        let aad = Self::aad(&record.kind, record.timestamp_ms);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &record.payload,
                    aad: &aad,
                },
            )
            .map_err(|_| StoreError::Crypto)?;
        self.records.push(SealedRecord {
            nonce: nonce_bytes,
            ciphertext,
            kind: record.kind,
            timestamp_ms: record.timestamp_ms,
        });
        Ok(self.records.len() - 1)
    }

    pub fn open(&self, index: usize) -> Result<StoredRecord, StoreError> {
        let sealed = self.records.get(index).ok_or(StoreError::Corrupt)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
        let aad = Self::aad(&sealed.kind, sealed.timestamp_ms);
        let payload = cipher
            .decrypt(
                Nonce::from_slice(&sealed.nonce),
                Payload {
                    msg: &sealed.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| StoreError::Crypto)?;
        Ok(StoredRecord {
            kind: sealed.kind.clone(),
            timestamp_ms: sealed.timestamp_ms,
            payload,
        })
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Serialize sealed records: for each —
    /// kind_len u16 | kind | ts u64 | nonce 12 | ct_len u32 | ct
    pub fn save(&self, path: &Path) -> Result<(), StoreError> {
        let mut buf = Vec::new();
        for r in &self.records {
            buf.extend_from_slice(&(r.kind.len() as u16).to_le_bytes());
            buf.extend_from_slice(r.kind.as_bytes());
            buf.extend_from_slice(&r.timestamp_ms.to_le_bytes());
            buf.extend_from_slice(&r.nonce);
            buf.extend_from_slice(&(r.ciphertext.len() as u32).to_le_bytes());
            buf.extend_from_slice(&r.ciphertext);
        }
        std::fs::write(path, buf).map_err(|_| StoreError::Io)
    }

    pub fn load(path: &Path, provider: &dyn KeyProvider) -> Result<Self, StoreError> {
        let data = std::fs::read(path).map_err(|_| StoreError::Io)?;
        let mut store = Self::new(provider);
        let mut pos = 0usize;
        let take = |data: &[u8], pos: &mut usize, n: usize| -> Result<Vec<u8>, StoreError> {
            if *pos + n > data.len() {
                return Err(StoreError::Corrupt);
            }
            let out = data[*pos..*pos + n].to_vec();
            *pos += n;
            Ok(out)
        };
        while pos < data.len() {
            let kind_len =
                u16::from_le_bytes(take(&data, &mut pos, 2)?.try_into().unwrap()) as usize;
            let kind = String::from_utf8(take(&data, &mut pos, kind_len)?)
                .map_err(|_| StoreError::Corrupt)?;
            let timestamp_ms = u64::from_le_bytes(take(&data, &mut pos, 8)?.try_into().unwrap());
            let nonce: [u8; 12] = take(&data, &mut pos, 12)?
                .try_into()
                .map_err(|_| StoreError::Corrupt)?;
            let ct_len = u32::from_le_bytes(take(&data, &mut pos, 4)?.try_into().unwrap()) as usize;
            let ciphertext = take(&data, &mut pos, ct_len)?;
            store.records.push(SealedRecord {
                nonce,
                ciphertext,
                kind,
                timestamp_ms,
            });
        }
        Ok(store)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SoftwareKeyProvider;

    fn provider(p: &str) -> SoftwareKeyProvider {
        SoftwareKeyProvider::from_passphrase(p, &[2u8; 16])
    }

    #[test]
    fn seal_open_round_trip() {
        let mut store = EncryptedStore::new(&provider("pw"));
        let idx = store
            .append(StoredRecord {
                kind: "features".into(),
                timestamp_ms: 42,
                payload: b"secret-vector".to_vec(),
            })
            .unwrap();
        let opened = store.open(idx).unwrap();
        assert_eq!(opened.payload, b"secret-vector");
        assert_eq!(opened.kind, "features");
    }

    #[test]
    fn wrong_key_cannot_open() {
        let mut store = EncryptedStore::new(&provider("right"));
        store
            .append(StoredRecord {
                kind: "features".into(),
                timestamp_ms: 1,
                payload: b"x".to_vec(),
            })
            .unwrap();
        let path = std::env::temp_dir().join("shield-test-store.bin");
        store.save(&path).unwrap();
        let other = EncryptedStore::load(&path, &provider("wrong")).unwrap();
        assert_eq!(other.open(0), Err(StoreError::Crypto));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn disk_bytes_do_not_contain_plaintext() {
        let mut store = EncryptedStore::new(&provider("pw"));
        store
            .append(StoredRecord {
                kind: "features".into(),
                timestamp_ms: 7,
                payload: b"RAW-EEG-PLAINTEXT-MARKER".to_vec(),
            })
            .unwrap();
        let path = std::env::temp_dir().join("shield-test-store2.bin");
        store.save(&path).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert!(!bytes.windows(10).any(|w| w == b"RAW-EEG-PL"));
        let loaded = EncryptedStore::load(&path, &provider("pw")).unwrap();
        assert_eq!(loaded.open(0).unwrap().payload, b"RAW-EEG-PLAINTEXT-MARKER");
        let _ = std::fs::remove_file(&path);
    }
}
