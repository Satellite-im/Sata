#[cfg(test)]
mod tests {
    use libipld::IpldCodec;
    use sata::{Sata, Kind};

    #[test]
    fn encoding_test_default() -> anyhow::Result<()> {
        let raw_data = b"Blob";
        let data = Sata::default();
        let encoded_data = data.encode(
            IpldCodec::DagCbor,
            Kind::Reference,
            raw_data.to_vec(),
        )?;

        let decoded_data = encoded_data.decode()?;
        assert_eq!(decoded_data, raw_data.to_vec());
        Ok(())
    }
}