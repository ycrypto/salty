#[cfg(test)]
mod wycheproof_tests {

    use wycheproof_gen::test_eddsa;

    use wycheproof::eddsa::*;

    use core::convert::TryFrom;
    use salty::{PublicKey, Signature};
    use salty::constants::{PUBLICKEY_SERIALIZED_LENGTH, SIGNATURE_SERIALIZED_LENGTH};

    #[test_eddsa("tests/eddsa_test.json", "eddsa_verify_schema.json")]
    fn eddsa_testcase (tg: &EddsaTestGroup, tc: &SignatureTestVector) {

        let pk  = <[u8; PUBLICKEY_SERIALIZED_LENGTH]>::try_from(tg.key.pk);
        let sig = <[u8; SIGNATURE_SERIALIZED_LENGTH]>::try_from(tc.sig);
        let valid: bool;

        if pk.is_err() || sig.is_err() {
            valid = false;
        } else {
            let pk  = PublicKey::try_from(&pk.unwrap());
            if pk.is_err() {
                valid = false;
            } else {
                let sig = Signature::from(&sig.unwrap());
                let result = pk.unwrap().verify(&tc.msg, &sig);
                valid = result.is_ok();
            }
        }

        match tc.result {
            ExpectedResult::Valid => assert!(valid),
            ExpectedResult::Invalid => {
                if tc.flags.contains(&"SignatureMalleability") {
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
