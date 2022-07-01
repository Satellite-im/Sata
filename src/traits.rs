use libipld::IpldCodec;

use crate::Sata;

pub trait Time {
    fn clock_update(&mut self);
    fn get_time(&self) -> i64;
}

pub trait Encoder {
    fn encode(&mut self);
    fn set_encoding(&mut self, encoding: IpldCodec) -> &mut Self;
    fn decode(&mut self) -> &mut Self;
}

pub trait Feed<T> {
    fn feed(&mut self, data: T) -> &mut Sata;
}