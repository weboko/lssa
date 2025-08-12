use crate::PrivateKey;

// TODO: Dummy impl. Replace by actual public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey(pub(crate) [u8; 32]);

impl PublicKey {
    pub fn new(key: &PrivateKey) -> Self {
        let value = {
            let secret_key = secp256k1::SecretKey::from_byte_array(key.0).unwrap();
            let public_key =
                secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &secret_key);
            let (x_only, _) = public_key.x_only_public_key();
            x_only.serialize()
        };
        Self(value)
    }
}

#[cfg(test)]
mod tests {
    use crate::{PublicKey, signature::tests::test_vectors};

    #[test]
    fn test_public_key_generation_from_bip340_test_vectors() {
        for (i, test_vector) in test_vectors().iter().enumerate() {
            let Some(private_key) = &test_vector.seckey else {
                continue;
            };
            let public_key = PublicKey::new(private_key);
            let expected_public_key = &test_vector.pubkey;
            assert_eq!(
                &public_key, expected_public_key,
                "Failed test vector at index {i}"
            );
        }
    }
}
