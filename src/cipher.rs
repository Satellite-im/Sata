use aes_gcm::{Nonce, Aes256Gcm, NewAead, aead::Aead, Key};
use digest::Digest;
use sha2::Sha256;

use crate::error::Error;


pub fn aes256gcm_encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    let nonce = generate(12);

    let e_key = match key.len() {
        32 => key.to_vec(),
        _ => sha256_hash(key, Some(nonce.clone())),
    };

    let key = Key::from_slice(&e_key);
    let a_nonce = Nonce::from_slice(&nonce);

    let cipher = Aes256Gcm::new(key);
    let mut edata = cipher
        .encrypt(a_nonce, data)
        .map_err(|_| Error::Unknown)?;

    edata.extend(nonce);

    Ok(edata)
}


pub fn aes256gcm_decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    let (nonce, payload) = extract_data_slice(data, 12);

    let e_key = match key.len() {
        32 => key.to_vec(),
        _ => sha256_hash(key, Some(nonce.to_vec())),
    };

    let key = Key::from_slice(&e_key);
    let nonce = Nonce::from_slice(nonce);

    let cipher = Aes256Gcm::new(key);
    cipher
        .decrypt(nonce, payload)
        .map_err(|_| Error::Unknown)
}

fn extract_data_slice(data: &[u8], size: usize) -> (&[u8], &[u8]) {
    let extracted = &data[data.len() - size..];
    let payload = &data[..data.len() - size];
    (extracted, payload)
}

pub fn sha256_hash(data: &[u8], salt: Option<Vec<u8>>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    if let Some(salt) = salt {
        hasher.update(salt);
    }
    hasher.finalize().to_vec()
}

pub fn generate(limit: usize) -> Vec<u8> {
    let mut buf = vec![0u8; limit];
    getrandom::getrandom(&mut buf).unwrap();
    buf.to_vec()
}