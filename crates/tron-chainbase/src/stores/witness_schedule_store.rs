//! WitnessScheduleStore — directory name `witness_schedule`.
//!
//! **Note the underscore**: java-tron uses `witness_schedule` (with `_`)
//! not `witness-schedule` (with `-`). This is the only store whose
//! directory name uses an underscore — every other store uses hyphens.
//! Easy to mis-spell.
//!
//! Holds two fixed-key entries ("species" in the Java code):
//!
//! | Key (UTF-8 bytes)            | Value                                  |
//! |------------------------------|----------------------------------------|
//! | `"active_witnesses"`         | concatenated 21-byte SR addresses      |
//! | `"current_shuffled_witnesses"`| concatenated 21-byte SR addresses     |
//!
//! Each value is a flat byte buffer: N witness addresses with no length
//! prefix or separator. The receiver divides `len(bytes) / 21` to count
//! entries — so an empty witness list is an empty value (not absent).
//!
//! Source: `WitnessScheduleStore.saveData` / `getData`.

use std::sync::Arc;

use tron_crypto::address::{Address, ADDRESS_LENGTH};

use crate::backend::KvBackend;
use crate::stores::StoreError;

pub const DB_NAME: &str = "witness_schedule";

/// "Species" keys exposed as constants so consumers can never mis-spell
/// them. (They are UTF-8 bytes; java-tron writes them via `.getBytes()`.)
pub mod keys {
    pub const ACTIVE_WITNESSES: &[u8] = b"active_witnesses";
    pub const CURRENT_SHUFFLED_WITNESSES: &[u8] = b"current_shuffled_witnesses";
}

pub struct WitnessScheduleStore {
    backend: Arc<dyn KvBackend>,
}

impl WitnessScheduleStore {
    pub const DB_NAME: &'static str = DB_NAME;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    /// Pack a witness list into the flat 21*N-byte buffer java-tron
    /// expects, and write it under `species`. Use [`keys::ACTIVE_WITNESSES`]
    /// or [`keys::CURRENT_SHUFFLED_WITNESSES`] for the species.
    pub fn save(&self, species: &[u8], witnesses: &[Address]) {
        let mut buf = Vec::with_capacity(witnesses.len() * ADDRESS_LENGTH);
        for addr in witnesses {
            buf.extend_from_slice(addr.as_bytes());
        }
        self.backend.put(species, &buf);
    }

    /// Read a packed witness list. Returns `Ok(None)` if the species
    /// hasn't been written yet; errors if the stored buffer length isn't
    /// a multiple of 21.
    pub fn load(&self, species: &[u8]) -> Result<Option<Vec<Address>>, StoreError> {
        let Some(bytes) = self.backend.get(species) else {
            return Ok(None);
        };
        if bytes.len() % ADDRESS_LENGTH != 0 {
            return Err(StoreError::InvalidValueLength {
                got: bytes.len(),
                expected: 0, // any multiple of 21
            });
        }
        let mut out = Vec::with_capacity(bytes.len() / ADDRESS_LENGTH);
        for chunk in bytes.chunks(ADDRESS_LENGTH) {
            let mut buf = [0u8; ADDRESS_LENGTH];
            buf.copy_from_slice(chunk);
            out.push(Address::from_raw(buf));
        }
        Ok(Some(out))
    }

    pub fn save_active(&self, witnesses: &[Address]) {
        self.save(keys::ACTIVE_WITNESSES, witnesses);
    }

    pub fn load_active(&self) -> Result<Option<Vec<Address>>, StoreError> {
        self.load(keys::ACTIVE_WITNESSES)
    }

    pub fn save_shuffled(&self, witnesses: &[Address]) {
        self.save(keys::CURRENT_SHUFFLED_WITNESSES, witnesses);
    }

    pub fn load_shuffled(&self) -> Result<Option<Vec<Address>>, StoreError> {
        self.load(keys::CURRENT_SHUFFLED_WITNESSES)
    }
}
