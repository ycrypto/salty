#[cfg(test)]
mod wycheproof {

    use wycheproof_gen::test_wycheproof;

    use wycheproof::wycheproof::*;

    use core::convert::TryFrom;
    use salty::{PublicKey, Signature};
    use salty::constants::{PUBLICKEY_SERIALIZED_LENGTH, SIGNATURE_SERIALIZED_LENGTH};

    #[test_wycheproof("tests/eddsa_test.json", "eddsa_verify_schema.json")]
    fn eddsa_test_case(test_key: &Key, test_data: &SignatureTestVector) {

        let pk  = <[u8; PUBLICKEY_SERIALIZED_LENGTH]>::try_from(test_key.pk);
        let sig = <[u8; SIGNATURE_SERIALIZED_LENGTH]>::try_from(test_data.sig);
        let valid: bool;

        if pk.is_err() || sig.is_err() {
            valid = false;
        } else {
            let pk  = PublicKey::try_from(&pk.unwrap());
            if pk.is_err() {
                valid = false;
            } else {
                let sig = Signature::from(&sig.unwrap());
                let result = pk.unwrap().verify(&test_data.msg, &sig);
                valid = result.is_ok();
            }
        }

        match test_data.result {
            ExpectedResult::Valid => assert!(valid),
            ExpectedResult::Invalid => {
                if test_data.flags.contains(&"SignatureMalleability") {
                    // accept failing SignatureMalleability tests
                    assert!(true)
                } else {
                    assert!(!valid)
                }
            },
            ExpectedResult::Acceptable => assert!(true),
        }
    }
}
