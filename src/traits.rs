use did_key::DIDKey;
use libipld::IpldCodec;

use crate::{Sata, errors::SataError};

pub trait Time {
    fn clock_update(&mut self);
    fn get_time(&self) -> i64;
}

pub trait Encoder {
    fn set_encoding(&mut self, encoding: IpldCodec) -> Result<&mut Sata, SataError>;
    fn encode (&mut self) -> Result<&mut Sata, SataError>;
    fn encoded(self) -> Result<Vec<u8>, SataError>;
    fn decode (&mut self) -> Result<&mut Sata, SataError>;
    fn decoded(self) -> Result<Vec<u8>, SataError>;
}

pub trait Encryption {
    fn address(&mut self, to: Vec<DIDKey>, from: DIDKey) -> &mut Sata;
    fn encrypt(&mut self) -> Result<&mut Sata, SataError>;
    fn decrypt(&mut self) -> Result<&mut Sata, SataError>;
    fn validate(self) -> Result<(), SataError>;
}

pub trait Feed<T> {
    fn feed(&mut self, data: T) -> Result<&mut Sata, SataError>;
}
