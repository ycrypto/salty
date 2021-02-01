#![no_std]
#![no_main]

extern crate panic_semihosting;
use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprintln, hprint};

use wycheproof_gen::generate_data;

use core::convert::TryFrom;
use salty::{Keypair, PublicKey, Signature};
use salty::constants::{SECRETKEY_SEED_LENGTH, PUBLICKEY_SERIALIZED_LENGTH, SIGNATURE_SERIALIZED_LENGTH};

use wycheproof::wycheproof::*;

const THE_TESTS: WycheproofTest = generate_data!("../tests/eddsa_test.json", "eddsa_verify_schema.json");

#[entry]
fn main () -> ! {

    hprint!("running tests...\n").ok();

    for testgroup in THE_TESTS.test_groups {
        if let TestGroup::EddsaVerify{key, tests} = testgroup {
            for testcase in tests.as_ref() {
                run_eddsa_verify(&key, &testcase);
            }
        }
    }

    for testgroup in THE_TESTS.test_groups {
        if let TestGroup::EddsaVerify{key, tests} = testgroup {
            for testcase in tests.as_ref() {
                match testcase.result {
                    ExpectedResult::Valid => test_eddsa_sign(&key, &testcase),
                    _ => {},
                }
            }
        }
    }

    hprintln!("done.").ok();

    debug::exit(debug::EXIT_SUCCESS);
    loop { continue; }
}

fn fail() {
    debug::exit(debug::EXIT_FAILURE);
    loop { continue; }
}

fn run_eddsa_verify(test_key: &Key, test_data: &SignatureTestVector) {

    hprint!("EddsaVerify test case {:4}: ", test_data.tc_id).ok();

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
        ExpectedResult::Valid => if !valid {
            hprintln!("FAIL (expected VALID, but isn't)").ok();
            fail();
        } else {
            hprintln!("OK (valid input)").ok();
        }
        ExpectedResult::Invalid => if valid {
            if test_data.flags.contains(&"SignatureMalleability") {
                hprintln!("ALLOW FAIL for SignatureMalleability (expected INVALID, but isn't)").ok();
            }
            else
            {
                hprintln!("FAIL (expected INVALID, but isn't)").ok();
                fail();
            }
        } else {
            hprintln!("OK (invalid input)").ok();
        }
        ExpectedResult::Acceptable => {
            hprintln!("ACCEPTABLE in any case").ok();
        },
    }
}

fn test_eddsa_sign(test_key: &Key, test_data: &SignatureTestVector) {

    hprint!("EddsaVerify test sign {:4}: ", test_data.tc_id).ok();

    let sk  = <[u8; SECRETKEY_SEED_LENGTH]>::try_from(test_key.sk);
    let sig = <[u8; SIGNATURE_SERIALIZED_LENGTH]>::try_from(test_data.sig);
    let valid: bool;

    if sk.is_err() || sig.is_err() {
        valid = false;
    } else {
        let sk  = Keypair::from(&sk.unwrap());
        let testsig = sk.sign(&test_data.msg);
        let sig = Signature::from(&sig.unwrap());
        valid = testsig == sig;
    }

    if valid {
        hprintln!("OK").ok();
    } else {
        hprintln!("FAIL signatures do not match").ok();
        fail();
    }
}
