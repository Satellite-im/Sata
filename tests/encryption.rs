#[cfg(test)]
mod tests {
    use did_key::generate;
    use libipld::IpldCodec;
    use sata::{Sata, Kind};

    #[test]
    fn encryption_test_default() -> anyhow::Result<()> {

        let plaintext = b"Hello, Bob!";

        let alice_did = generate::<did_key::Ed25519KeyPair>(None);
        let bob_did = generate::<did_key::Ed25519KeyPair>(None);
    
        let mut data = Sata::default();
        data.add_recipient(&bob_did)?;
        let encrypted_data = data.encrypt(
            IpldCodec::DagCbor,
            &alice_did,
            Kind::Reference,
            plaintext.to_vec(),
        )?;
    
        let extracted_data_by_bob: Vec<u8> = encrypted_data.decrypt(&bob_did)?;
    
        assert_eq!(extracted_data_by_bob, plaintext.to_vec());
        
        Ok(())
    }
}