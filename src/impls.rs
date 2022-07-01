use chrono::Utc;
use libipld::{IpldCodec, Ipld};

use crate::{traits::{Encoder, Time, Feed}, Sata, Kind};
use libipld::prelude::*;

impl Time for Sata {
    fn clock_update(&mut self) {
        self.updated = Utc::now().timestamp_nanos();
    }
    fn get_time(&self) -> i64 {
        self.updated
    }
}

impl Encoder for Sata {
    fn encode(&mut self) {
        let encoder: IpldCodec = self.encoding;
        self.data = encoder.encode(&Ipld::Bytes(self.data.clone())).unwrap()
    }

    fn decode(&mut self) -> &mut Self {
        let data: Ipld = self.encoding.decode(&self.data).unwrap();

        self.data = match data {
            Ipld::Bytes(data) => data,
            _ => unreachable!(),
        };

        self
    }

    fn set_encoding(&mut self, encoding: IpldCodec) -> &mut Sata {
        self.encoding = encoding;
        self.decode();
        self.encode();
        self
    }
}

impl Feed<Vec<u8>> for Sata {
    fn feed(&mut self, data: Vec<u8>) -> &mut Sata {
        self.data = data;
        self.encode();
        self.clock_update();
        self.kind = Kind::Static;
        self
    }
}