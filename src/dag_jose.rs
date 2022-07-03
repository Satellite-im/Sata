use libipld::Cid;

pub struct Signature {
    header: String,
    protected: Vec<u8>,
    signature: Vec<u8>,
}

pub struct Recipient {
    encrypted_key: Vec<u8>,
    header: String,
}

pub struct JWE {
    aad: Vec<u8>,
    ciphertext: Vec<u8>,
    iv: Vec<u8>,
    protected: Vec<u8>,
    recipients: Vec<Recipient>,
    tag: Vec<u8>,
    unprotected: String,
}

pub struct JWS {
    payload: String,
    pub signatures: Vec<Signature>,
}
