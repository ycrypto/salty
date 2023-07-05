#![no_std]
#![no_main]

extern crate panic_semihosting;
use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprint, hprintln};

use wycheproof_macros::generate_data;

use core::convert::TryFrom;
use salty::constants::{
    PUBLICKEY_SERIALIZED_LENGTH, SECRETKEY_SEED_LENGTH, SIGNATURE_SERIALIZED_LENGTH,
};
use salty::{Keypair, PublicKey, Signature};

use wycheproof_types::*;

const THE_TESTS: WycheproofTest = generate_data!(
    "wycheproof/data/eddsa_test.json",
    "wycheproof/data/eddsa_verify_schema.json"
);

#[entry]
fn main() -> ! {
    hprint!("running tests...\n").ok();

    for testgroup in THE_TESTS.test_groups {
        if let TestGroup::EddsaVerify { key, tests } = testgroup {
            for testcase in tests.iter() {
                run_eddsa_verify(key, testcase);
            }
        }
    }

    for testgroup in THE_TESTS.test_groups {
        if let TestGroup::EddsaVerify { key, tests } = testgroup {
            for testcase in tests.iter() {
                if let ExpectedResult::Valid = testcase.result {
                    test_eddsa_sign(key, testcase);
                }
            }
        }
    }

    hprintln!("done.").ok();

    debug::exit(debug::EXIT_SUCCESS);
    loop {
        continue;
    }
}

fn fail() {
    debug::exit(debug::EXIT_FAILURE);
    loop {
        continue;
    }
}

fn run_eddsa_verify(test_key: &Key, test_data: &SignatureTestVector) {
    hprint!("EddsaVerify test case {:4}: ", test_data.tc_id).ok();

    let pk = <[u8; PUBLICKEY_SERIALIZED_LENGTH]>::try_from(test_key.pk);
    let sig = <[u8; SIGNATURE_SERIALIZED_LENGTH]>::try_from(test_data.sig);

    let valid = match (pk, sig) {
        (Ok(pk), Ok(sig)) => match PublicKey::try_from(&pk) {
            Ok(pk) => {
                let sig = Signature::from(&sig);
                let result = pk.verify(test_data.msg, &sig);
                result.is_ok()
            }
            _ => false,
        },
        _ => false,
    };

    match test_data.result {
        ExpectedResult::Valid => {
            if !valid {
                hprintln!("FAIL (expected VALID, but isn't)").ok();
                fail();
            } else {
                hprintln!("OK (valid input)").ok();
            }
        }
        ExpectedResult::Invalid => {
            if valid {
                if test_data.flags.contains(&"SignatureMalleability") {
                    hprintln!("ALLOW FAIL for SignatureMalleability (expected INVALID, but isn't)")
                        .ok();
                } else {
                    hprintln!("FAIL (expected INVALID, but isn't)").ok();
                    fail();
                }
            } else {
                hprintln!("OK (invalid input)").ok();
            }
        }
        ExpectedResult::Acceptable => {
            hprintln!("ACCEPTABLE in any case").ok();
        }
    }
}

fn test_eddsa_sign(test_key: &Key, test_data: &SignatureTestVector) {
    hprint!("EddsaVerify test sign {:4}: ", test_data.tc_id).ok();

    let sk = <[u8; SECRETKEY_SEED_LENGTH]>::try_from(test_key.sk);
    let sig = <[u8; SIGNATURE_SERIALIZED_LENGTH]>::try_from(test_data.sig);

    let valid = match (sk, sig) {
        (Ok(sk), Ok(sig)) => {
            let sk = Keypair::from(&sk);
            let testsig = sk.sign(test_data.msg);
            let sig = Signature::from(&sig);
            testsig == sig
        }
        _ => false,
    };

    if valid {
        hprintln!("OK").ok();
    } else {
        hprintln!("FAIL signatures do not match").ok();
        fail();
    }
}
