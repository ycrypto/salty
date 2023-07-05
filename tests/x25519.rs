#[cfg(test)]
mod wycheproof {

    use wycheproof_macros::test_wycheproof;
    use wycheproof_types::*;

    use salty::agreement;
    use salty::constants::{PUBLICKEY_SERIALIZED_LENGTH, SECRETKEY_SEED_LENGTH};

    #[test_wycheproof(
        "wycheproof/data/x25519_test.json",
        "wycheproof/data/xdh_comp_schema.json"
    )]
    fn x25519_test_case(curve: &str, test_data: &XdhTestVector) {
        assert!(curve == "curve25519");

        let private = <[u8; SECRETKEY_SEED_LENGTH]>::try_from(test_data.private);
        let public = <[u8; PUBLICKEY_SERIALIZED_LENGTH]>::try_from(test_data.public);
        let shared_expected = <[u8; 32]>::try_from(test_data.shared);
        let valid: bool;

        match (private, public, shared_expected) {
            (Ok(private), Ok(public), Ok(shared_expected)) => {
                let public = agreement::PublicKey::from(public);
                let private = agreement::SecretKey::from_seed(&private);
                let shared = private.agree(&public);

                valid = shared.to_bytes() == shared_expected;
            }
            _ => {
                valid = false;
            }
        }

        match test_data.result {
            ExpectedResult::Valid => assert!(valid),
            ExpectedResult::Invalid => assert!(!valid),
            ExpectedResult::Acceptable => {}
        }
    }
}
