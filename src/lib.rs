mod tests;
mod impls;
mod traits;

use std::fmt::Debug;
use std::fmt::Formatter;

use libipld::codec_impl::IpldCodec;
use cid::Cid;
use chrono::Utc;
use did_key::{DIDKey, generate, Ed25519KeyPair};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    UnInitalized,
    Static,
    Dynamic,
    Reference,
    DeadReference,
}

pub struct Sata {
    cid: Cid,
    kind: Kind,
    encoding: IpldCodec, 
    updated: i64,
    data: Vec<u8>,
    encrypted: bool,
    from: DIDKey,
    to: Vec<DIDKey>,
}

impl Default for Sata {
    fn default() -> Self {
        let default_keypair = generate::<Ed25519KeyPair>(None);
        Sata {
            cid: Cid::default(),
            kind: Kind::UnInitalized,
            encoding: IpldCodec::DagJson,
            updated: Utc::now().timestamp_nanos(),
            data: Vec::new(),
            encrypted: false,
            from: default_keypair,
            to: vec![],
        }
    }
}

impl Debug for Sata {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "Sata {{ cid: {:?}, kind: {:?}, encoding: {:?}, updated: {:?}, data: {:?}, encrypted: {:?} to: [redacted], from: [redacted] }}",
            self.cid, self.kind, self.encoding, self.updated, self.data, self.encrypted)
    }
}

impl From<Vec<u8>> for Sata {
    fn from(data: Vec<u8>) -> Self {
        Self {
            data,
            ..Default::default()
        }
    }
}