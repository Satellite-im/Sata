mod tests;
mod impls;
mod traits;
mod errors;
mod dag_jose;

use libipld::codec_impl::IpldCodec;
use libipld::Cid;
use did_key::DIDKey;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    UnInitalized,
    Static,
    Dynamic,
    Reference,
    DeadReference,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    UnInitalized,
    Encoded,
    Decoded,
    Encrypted,
}

pub struct Sata {
    cid: Cid,
    kind: Kind,
    encoding: IpldCodec, 
    updated: i64,
    data: Vec<u8>,
    doc: Vec<u8>,
    state: State,
    sender: DIDKey,
    recipients: Vec<DIDKey>,
}