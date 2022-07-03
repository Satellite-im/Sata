#[cfg(test)]
mod sata_tests {
    use libipld::IpldCodec;

    use crate::{Sata, traits::Encoder};

    #[test]
    fn it_works() {
        let mut sata = Sata::from(vec![12, 34, 56]);
        println!("{:?}", sata);
    }
}