#[cfg(test)]
mod wycheproof {

    use wycheproof_gen::test_wycheproof;

    use wycheproof::wycheproof::*;

    use core::convert::TryFrom;
    use salty::constants::{PUBLICKEY_SERIALIZED_LENGTH, SECRETKEY_SEED_LENGTH};
    use salty::agreement;

    #[test_wycheproof("tests/x25519_test.json", "xdh_comp_schema.json")]
    fn x25519_test_case(curve: &str, test_data: &XdhTestVector) {

        assert!(curve == "curve25519");

        let private = <[u8; SECRETKEY_SEED_LENGTH]>::try_from(test_data.private);
        let public  = <[u8; PUBLICKEY_SERIALIZED_LENGTH]>::try_from(test_data.public);
        let shared_expected  = <[u8; 32]>::try_from(test_data.shared);
        let valid: bool;

        if private.is_err() || public.is_err() || shared_expected.is_err() {
            valid = false;
        } else {
            let public = agreement::PublicKey::try_from(public.unwrap());
            if public.is_err() {
                valid = false;
            } else {
                let private = agreement::SecretKey::from_seed(&private.unwrap());
                let shared  = private.agree(&public.unwrap());

                valid = shared.to_bytes() == shared_expected.unwrap();
            }
        }

        match test_data.result {
            ExpectedResult::Valid => assert!(valid),
            ExpectedResult::Invalid => assert!(!valid),
            ExpectedResult::Acceptable => assert!(true),
        }
    }
}
