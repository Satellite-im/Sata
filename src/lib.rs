pub mod ffi;
pub mod error;
pub mod cipher;

pub use libipld;

use chrono::{DateTime, Utc};
use did_key::{DIDKey, Ed25519KeyPair, Fingerprint, Generate, KeyMaterial, ECDH};

use libipld::{
    cid::Version,
    codec::Codec,
    serde::{from_ipld, to_ipld},
    Cid, IpldCodec, multihash::{Code, MultihashDigest},
};

use serde::{Deserialize, Serialize};

use crate::error::Error;

#[derive(Default, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[repr(C)]
pub enum Kind {
    #[default]
    Uninitialized,

    Static,

    Dynamic,

    Reference,

    DeadReference,
}

#[derive(Default, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[repr(C)]
pub enum State {
    #[default]
    Uninitialized,

    Encoded,

    Encrypted
}


#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Sata {
    /// [`Cid`] of the data
    id: Cid,

    /// TBD
    kind: Kind,

    /// TBD
    state: State,

    /// Timestamp of the data
    timestamp: DateTime<Utc>,

    /// Data
    data: Vec<u8>,

    /// [`DIDKey`] of the Sender
    sender: Option<String>,

    /// List of recipients [`DIDKey`]
    recipients: Option<Vec<String>>,
}

impl Default for Sata {
    fn default() -> Self {
        Self {
            id: Default::default(),
            kind: Default::default(),
            state: Default::default(),
            timestamp: Utc::now(),
            data: Default::default(),
            sender: Default::default(),
            recipients: Default::default(),
        }
    }
}

impl Sata {
    pub fn id(&self) -> Cid {
        self.id
    }

    pub fn kind(&self) -> Kind {
        self.kind
    }

    pub fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }

    pub fn data(&self) -> Vec<u8> {
        self.data.clone()
    }

    pub fn sender(&self) -> Option<DIDKey> {
        self.sender
            .clone()
            .and_then(|sender| did_key::resolve(&sender).ok())
    }

    pub fn recipients(&self) -> Option<Vec<DIDKey>> {
        self.recipients.clone().map(|recipients| {
            recipients
                .iter()
                .filter_map(|recipient| did_key::resolve(&recipient).ok())
                .collect::<Vec<_>>()
        })
    }
}

impl Sata {
    pub fn add_recipients(&mut self, recipients: Vec<DIDKey>) -> anyhow::Result<()> {
        if self.kind() != Kind::Uninitialized {
            anyhow::bail!("Cannot add recipient to initialized data")
        }

        match self.state {
            State::Uninitialized => {},
            _ => anyhow::bail!("Cannot add to initialized data")
        };

        self.recipients = Some(
            recipients
                .iter()
                .map(|item| format!("did:key:{}", item.fingerprint()))
                .collect::<Vec<_>>(),
        );

        Ok(())
    }

    pub fn add_recipient(&mut self, recipient: &DIDKey) -> anyhow::Result<()> {
        if self.kind() != Kind::Uninitialized {
            anyhow::bail!("Cannot add recipient to initialized data")
        }
        match self.state {
            State::Uninitialized => {},
            _ => anyhow::bail!("Cannot add to initialized data")
        };
        let fingerprint = format!("did:key:{}", recipient.fingerprint());
        if let Some(list) = self.recipients.as_mut() {
            if list.contains(&fingerprint) {
                anyhow::bail!("Recipient already exist")    
            }
            list.push(fingerprint);
        } else {
            self.recipients = Some(vec![fingerprint])
        }
        Ok(())
    }

    pub fn remove_recipient(&mut self, recipient: &str) -> anyhow::Result<DIDKey> {
        match self.state {
            State::Uninitialized => {},
            _ => anyhow::bail!("Cannot remove from initialized data")
        };
        let list = self.recipients.as_mut().ok_or(Error::Unknown)?;
        let index = list
            .iter()
            .position(|item| item.eq(recipient))
            .ok_or(Error::PositionNotFound)?;
        let item = list.remove(index);
        let key = did_key::resolve(&format!("did:key:{}", item))
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
        Ok(key)
    }
}

impl Sata {
    pub fn encrypt(
        mut self,
        codec: IpldCodec,
        keypair: &DIDKey,
        kind: Kind,
        data: Vec<u8>,
    ) -> anyhow::Result<Self> {

        
        if kind == Kind::Uninitialized {
            anyhow::bail!("Kind cannot uninitialized");
        }

        if keypair.private_key_bytes().is_empty() {
            anyhow::bail!("DIDKey requires secret key");
        }

        

        let ipld = to_ipld(data)?;
        let bytes = codec.encode(&ipld)?;
        let hash = Code::Sha2_256.digest(&bytes);
        let version = if codec == IpldCodec::DagPb {
            Version::V0
        } else {
            Version::V1
        };

        let cid = Cid::new(version, codec.into(), hash)?;

        self.id = cid;
        self.kind = kind;
        self.timestamp = Utc::now();
        self.state = State::Encrypted;

        let mut encrypted_data = vec![];
        let sender_x25519 =
            Ed25519KeyPair::from_secret_key(&keypair.private_key_bytes()).get_x25519();
        if let Some(list) = self.recipients.as_ref() {
            for recipient in list {
                if let Ok(did) = did_key::resolve(recipient) {
                    let recipient_x25519 =
                        Ed25519KeyPair::from_public_key(&did.public_key_bytes()).get_x25519();
                    let shared_key = sender_x25519.key_exchange(&recipient_x25519);
                    let encrypted =
                        match cipher::aes256gcm_encrypt(&shared_key, &bytes) {
                            Ok(data) => data,
                            Err(_e) => {
                                //TODO: Log
                                continue;
                            }
                        };
                    encrypted_data.push(encrypted);
                }
            }
        }
        self.data = serde_json::to_vec(&encrypted_data)?;
        self.sender = Some(format!("did:key:{}", keypair.fingerprint()));
        Ok(self)
    }

    pub fn decrypt(&self, keypair: &DIDKey) -> anyhow::Result<Vec<u8>> {
        if self.data.is_empty() || self.data.len() <= 4 {
            anyhow::bail!("Invalid data provided");
        }

        match self.state {
            State::Encoded => anyhow::bail!("Data is encoded"),
            State::Encrypted => {},
            _ => anyhow::bail!("Unknown data")
        };

        match self.recipients.as_ref() {
            Some(list) => {
                let uri = format!("did:key:{}", keypair.fingerprint());
                if !list.contains(&uri) {
                    anyhow::bail!("DID Key is not a recipient")
                }
            }
            None => anyhow::bail!("Recipients DID Required"),
        };

        let sender_did = match self.sender.as_ref() {
            Some(did_raw) => did_key::resolve(did_raw).map_err(|e| anyhow::anyhow!("{:?}", e))?,
            None => anyhow::bail!("Sender DID Required"),
        };

        let sender_x25519 =
            Ed25519KeyPair::from_public_key(&sender_did.public_key_bytes()).get_x25519();

        let x25519_keypair =
            Ed25519KeyPair::from_secret_key(&keypair.private_key_bytes()).get_x25519();

        let shared_key = x25519_keypair.key_exchange(&sender_x25519);

        let data_list: Vec<Vec<u8>> = serde_json::from_slice(&self.data)?;

        let data = data_list
            .iter()
            .filter_map(|encrypted| {
                cipher::aes256gcm_decrypt(&shared_key, &encrypted).ok()
            })
            .collect::<Vec<_>>()
            .first()
            .cloned()
            .ok_or(Error::PositionNotFound)?;

        let codec = IpldCodec::try_from(self.id.codec())?;
        let hash = Code::Sha2_256.digest(&data);
        
        if hash.ne(self.id.hash()) {
            anyhow::bail!("Hash is invalid")
        }
        
        let data: Vec<u8> = from_ipld(codec.decode(&data)?)?;

        Ok(data)
    }
}

impl Sata {
    pub fn encode(mut self, codec: IpldCodec, kind: Kind, data: Vec<u8>) -> anyhow::Result<Self> {
        if kind == Kind::Uninitialized {
            anyhow::bail!("Kind cannot uninitialized");
        }
        let ipld = to_ipld(data)?;
        let bytes = codec.encode(&ipld)?;
        let hash = Code::Sha2_256.digest(&bytes);
        let version = if codec == IpldCodec::DagPb {
            Version::V0
        } else {
            Version::V1
        };

        let cid = Cid::new(version, codec.into(), hash)?;

        self.id = cid;
        self.kind = kind;
        self.timestamp = Utc::now();
        self.state = State::Encoded;
        self.data = bytes;
        Ok(self)
    }

    pub fn decode(&self) -> anyhow::Result<Vec<u8>> {
        if self.data.is_empty() {
            anyhow::bail!(Error::Unknown);
        }

        match self.state {
            State::Encoded => {},
            State::Encrypted => anyhow::bail!("Data is encrypted"),
            _ => anyhow::bail!("Unknown data")
        };

        let codec = IpldCodec::try_from(self.id.codec())?;
        let hash = Code::Sha2_256.digest(&&self.data);
        
        if hash.ne(self.id.hash()) {
            anyhow::bail!("Hash is invalid")
        }
        let data: Vec<u8> = from_ipld(codec.decode(&self.data)?)?;
        Ok(data)
    }
}