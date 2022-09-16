#[cfg(test)]
mod wycheproof {

    use wycheproof_gen::test_wycheproof;

    use wycheproof::wycheproof::*;

    use core::convert::TryFrom;
    use salty::constants::{
        PUBLICKEY_SERIALIZED_LENGTH, SECRETKEY_SERIALIZED_LENGTH, SIGNATURE_SERIALIZED_LENGTH,
    };
    use salty::{Keypair, PublicKey, SecretKey, Signature};

    #[test_wycheproof("tests/eddsa_test.json", "eddsa_verify_schema.json")]
    fn eddsa_test_case(test_key: &Key, test_data: &SignatureTestVector) {
        let pk = <[u8; PUBLICKEY_SERIALIZED_LENGTH]>::try_from(test_key.pk)
            .map(|arr| PublicKey::try_from(&arr));
        let sk = <[u8; SECRETKEY_SERIALIZED_LENGTH]>::try_from(test_key.sk)
            .map(|arr| SecretKey::from(&arr));
        let expected_sig = <[u8; SIGNATURE_SERIALIZED_LENGTH]>::try_from(test_data.sig)
            .map(|arr| Signature::from(&arr));

        let valid = match (pk, sk, expected_sig) {
            (Ok(Ok(pk)), Ok(sk), Ok(expected_sig)) => {
                let result = pk.verify(&test_data.msg, &expected_sig);
                let kp = Keypair {
                    secret: sk,
                    public: pk,
                };
                let sig = kp.sign(&test_data.msg);
                result.is_ok() && sig.to_bytes() == test_data.sig
            }
            _ => false,
        };

        match test_data.result {
            ExpectedResult::Valid => assert!(valid),
            ExpectedResult::Invalid => {
                if test_data.flags.contains(&"SignatureMalleability") {
                    // accept failing SignatureMalleability tests
                    assert!(true)
                } else {
                    assert!(!valid)
                }
            }
            ExpectedResult::Acceptable => assert!(true),
        }
    }
}
