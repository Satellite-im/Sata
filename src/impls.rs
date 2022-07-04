use chrono::Utc;
use libipld::Cid;
use std::fmt::Debug;
use std::fmt::Formatter;
use libipld::{IpldCodec, Ipld};
use libipld::prelude::*;
use did_key::{DIDKey, generate, Ed25519KeyPair};

use crate::State;
use crate::dag_jose::{JWS, JWE, Signature};
use crate::errors::SataError;
use crate::{traits::{Encoder, Time, Feed, Encryption}, Sata, Kind};

/** Standard Implementations **/

impl Default for Sata {
    fn default() -> Self {
        let default_keypair = generate::<Ed25519KeyPair>(None);
        Sata {
            cid: Cid::default(),
            kind: Kind::UnInitalized,
            encoding: IpldCodec::DagJson,
            updated: Utc::now().timestamp_nanos(),
            data: Vec::new(),
            doc: Vec::new(),
            state: State::UnInitalized,
            sender: default_keypair,
            recipients: vec![],
        }
    }
}

impl Debug for Sata {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "Sata {{ cid: {:?}, kind: {:?}, encoding: {:?}, updated: {:?}, data: {:?}, state: {:?} to: [redacted], from: [redacted] }}",
            self.cid, self.kind, self.encoding, self.updated, self.data, self.state)
    }
}

// Constructors

impl From<Vec<u8>> for Sata {
    fn from(data: Vec<u8>) -> Self {
        let sata = Self {
            data,
            ..Default::default()
        };
        sata.cid = Cid::try_from(sata.encoded().unwrap()).unwrap();
        sata
    }
}

impl Feed<Vec<u8>> for Sata {
    fn feed(&mut self, data: Vec<u8>) -> Result<&mut Sata, SataError> {
        self.data = data;
        self.cid = Cid::try_from(self.encoded().unwrap()).unwrap();
        self.clock_update();
        Ok(self)
    }
}

/** Additional Implementations **/
impl Time for Sata {
    fn clock_update(&mut self) {
        self.updated = Utc::now().timestamp_nanos();
    }
    fn get_time(&self) -> i64 {
        self.updated
    }
}

impl Encoder for Sata {
    /// Change the default encoding method
    fn set_encoding(&mut self, encoding: IpldCodec) -> Result<&mut Sata, SataError> {
        if self.state.eq(&State::UnInitalized) {
            return Err(SataError::EncodingSetOutOfOrder);
        }
        self.encoding = encoding;
        Ok(self)
    }

    /// Encode the data in place, this will write over the data field.
    fn encode(&mut self) -> Result<&mut Sata, SataError> {
        if !self.state.eq(&State::Decoded) {
            return Err(SataError::NotDecoded);
        }
        let encoder: IpldCodec = self.encoding;
        self.data = self.encoded()?;
        self.state = State::Encoded;
        Ok(self)
    }

    /// Return the internal data `encoded` with the specified encoder
    fn encoded(self) -> Result<Vec<u8>, SataError> {
        let encoder: IpldCodec = self.encoding;
        match self.state {
            State::UnInitalized => Err(SataError::UnInitalized),
            State::Encoded => Ok(self.data),
            State::Decoded => Ok(encoder.encode(&Ipld::Bytes(self.data.clone())).unwrap()),
            State::Encrypted =>  Err(SataError::CannotEncodeEncrypted),
        }
    }

    /// Decode the data in place, overwriting the data field
    fn decode(&mut self) -> Result<&mut Sata, SataError> {
        if !self.state.eq(&State::Encoded) {
            return Err(SataError::NotEncoded());
        }
        self.data = self.decoded()?;
        Ok(self)
    }

    /// Return the internal data `decoded` with the specified encoder.
    fn decoded(self) -> Result<Vec<u8>, SataError> {
        let encoder: IpldCodec = self.encoding;

        match self.state {
            State::UnInitalized => Err(SataError::UnInitalized),
            State::Encoded => {
                let decoded = match encoder.decode(&self.data) {
                    Ok(Ipld::Bytes(data)) => data,
                    _ => ........
                };
            },
            State::Decoded => Ok(self.data),
            State::Encrypted => Err(SataError::CannotDecodeEncrypted)
        }
    }
}


fn encryption_ready_check(sata: &mut Sata) -> Result<&mut Sata, SataError> {
    match sata.state {
        State::UnInitalized => Err(SataError::UnInitalized),
        State::Encrypted => Err(SataError::AlreadyEncrypted),
        State::Encoded => Ok(sata),
        State::Decoded => Ok(sata),
    }
}

impl Encryption for Sata {
    fn address(&mut self, to: Vec<DIDKey>, from: DIDKey) -> &mut Sata {
        self.sender = from;
        self.recipients = to;
        self
    }
    
    fn encrypt(&mut self) -> Result<&mut Sata, SataError> {
        // We should make sure we're actually ready to encrypt
        let ready_check = encryption_ready_check(self);
        if ready_check.is_err() {
            return ready_check;
        }

        let encoded_data = &self.encoded();
        // Create our new DagJOSE document
        // This is a JSON Web Signature, we will want to still encrypt the data later.
        let mut jws = JWS {
            // We specify that the payload property MUST be a CID, and we set the payload of the encoded JOSE object to Bytes containing the bytes of the CID.
            payload: base64_url::encode(&self.cid.to_bytes()),
            signatures: vec![],
        };

        // Sign the payload using our DIDKey
        jws.signatures.push(Signature {
            header: todo!(),
            protected: todo!(),
            signature: todo!(),
        });

        // JWE which is commonly, JWE is used to encrypt a JWS payload, which is a signed JWT

        let mut jwe: JWE = JWE {
            // The ciphertext must decrypt to a cleartext which is the bytes of a CID.
            ciphertext: self.cid.to_bytes(),
            aad: todo!(),
            iv: todo!(),
            protected: todo!(),
            recipients: todo!(),
            tag: todo!(),
            unprotected: todo!(), 
        };

        unimplemented!()
    }

    // we first encode the data in something standard and track what we used to encode it
    // next we take this encoded data and sign it and create a CID from it

    fn decrypt(&mut self) -> Result<&mut Sata, SataError> {
        unimplemented!()
    }

    fn validate(self) -> Result<(), SataError>{
        unimplemented!()
    }
}
