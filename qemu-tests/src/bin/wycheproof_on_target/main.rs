#![no_std]
#![no_main]

extern crate panic_semihosting;
use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprintln, hprint};

use wycheproof_gen::generate_eddsa_data;

use core::convert::TryFrom;
use salty::{Keypair, PublicKey, Signature};
use salty::constants::{SECRETKEY_SEED_LENGTH, PUBLICKEY_SERIALIZED_LENGTH, SIGNATURE_SERIALIZED_LENGTH};

use wycheproof::eddsa::*;

const THE_TESTS: EddsaTest = generate_eddsa_data!("../tests/eddsa_test.json", "eddsa_verify_schema.json");

#[entry]
fn main () -> ! {

    hprint!("running tests...\n").ok();

    for testgroup in THE_TESTS.test_groups {
        for testcase in testgroup.tests {
            run_testcase(&testgroup, &testcase);
        }
    }

    for testgroup in THE_TESTS.test_groups {
        for testcase in testgroup.tests {
            match testcase.result {
                ExpectedResult::Valid => test_sign(&testgroup, &testcase),
                _ => {},
            }
        }
    }

    hprintln!("done.").ok();

    debug::exit(debug::EXIT_SUCCESS);
    loop { continue; }
}

fn run_testcase (tg: &EddsaTestGroup, tc: &SignatureTestVector) {

    hprint!("{} Test case {:4}: ", tg.kind, tc.tc_id).ok();

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
        ExpectedResult::Valid => if !valid {
            hprintln!("FAIL (expected VALID, but isn't)").ok();
        } else {
            hprintln!("OK (valid input)").ok();
        }
        ExpectedResult::Invalid => if valid {
            hprintln!("FAIL (expected INVALID, but isn't)").ok();
        } else {
            hprintln!("OK (invalid input)").ok();
        }
        ExpectedResult::Acceptable => {
            hprintln!("ACCEPTABLE in any case").ok();
        },
    }
}

fn test_sign(tg: &EddsaTestGroup, tc: &SignatureTestVector) {

    hprint!("{} Test sign {:4}: ", tg.kind, tc.tc_id).ok();

    let sk  = <[u8; SECRETKEY_SEED_LENGTH]>::try_from(tg.key.sk);
    let sig = <[u8; SIGNATURE_SERIALIZED_LENGTH]>::try_from(tc.sig);
    let valid: bool;

    if sk.is_err() || sig.is_err() {
        valid = false;
    } else {
        let sk  = Keypair::from(&sk.unwrap());
        let testsig = sk.sign(&tc.msg);
        let sig = Signature::from(&sig.unwrap());
        valid = testsig == sig;
    }

    if valid {
        hprintln!("OK").ok();
    } else {
        hprintln!("FAIL signatures do not match").ok();
    }
}