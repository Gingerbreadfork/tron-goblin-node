//! ExchangeStore (`exchange`) + ExchangeV2Store (`exchange-v2`).
//!
//! Both store Bancor-style exchanges keyed by an 8-byte big-endian `i64`
//! exchange ID. The split exists for a historical fork: V2 added a
//! second balance field. java-tron writes new exchanges to V2 only; V1
//! is read-only legacy.
//!
//! Source: `ExchangeStore` / `ExchangeV2Store` + `ExchangeCapsule.calculateDbKey`.

use std::sync::Arc;

use prost::Message;
use tron_proto::Exchange;

use crate::backend::KvBackend;
use crate::stores::StoreError;

pub const DB_NAME_V1: &str = "exchange";
pub const DB_NAME_V2: &str = "exchange-v2";

fn exchange_key(id: i64) -> [u8; 8] {
    id.to_be_bytes()
}

pub struct ExchangeStore {
    backend: Arc<dyn KvBackend>,
}

impl ExchangeStore {
    pub const DB_NAME: &'static str = DB_NAME_V1;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    pub fn key_for(id: i64) -> [u8; 8] {
        exchange_key(id)
    }

    pub fn put(&self, id: i64, exchange: &Exchange) -> Result<(), StoreError> {
        self.backend.put(&Self::key_for(id), &exchange.encode_to_vec())?;
        Ok(())
    }

    pub fn get(&self, id: i64) -> Result<Option<Exchange>, StoreError> {
        let Some(bytes) = self.backend.get(&Self::key_for(id))? else {
            return Ok(None);
        };
        Ok(Some(Exchange::decode(bytes.as_slice())?))
    }

    pub fn all(&self) -> Result<Vec<(i64, Exchange)>, StoreError> {
        let mut out = Vec::new();
        for (k, v) in self.backend.scan_all()? {
            if k.len() != 8 {
                continue;
            }
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&k);
            let id = i64::from_be_bytes(buf);
            let ex = Exchange::decode(v.as_slice())?;
            out.push((id, ex));
        }
        Ok(out)
    }
}

pub struct ExchangeV2Store {
    backend: Arc<dyn KvBackend>,
}

impl ExchangeV2Store {
    pub const DB_NAME: &'static str = DB_NAME_V2;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    pub fn key_for(id: i64) -> [u8; 8] {
        exchange_key(id)
    }

    pub fn put(&self, id: i64, exchange: &Exchange) -> Result<(), StoreError> {
        self.backend.put(&Self::key_for(id), &exchange.encode_to_vec())?;
        Ok(())
    }

    pub fn get(&self, id: i64) -> Result<Option<Exchange>, StoreError> {
        let Some(bytes) = self.backend.get(&Self::key_for(id))? else {
            return Ok(None);
        };
        Ok(Some(Exchange::decode(bytes.as_slice())?))
    }

    pub fn all(&self) -> Result<Vec<(i64, Exchange)>, StoreError> {
        let mut out = Vec::new();
        for (k, v) in self.backend.scan_all()? {
            if k.len() != 8 {
                continue;
            }
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&k);
            let id = i64::from_be_bytes(buf);
            let ex = Exchange::decode(v.as_slice())?;
            out.push((id, ex));
        }
        Ok(out)
    }
}
