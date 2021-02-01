#![no_std]
#![no_main]

extern crate panic_semihosting;
use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprintln, hprint};

use wycheproof_gen::generate_data;

use core::convert::TryFrom;
use salty::constants::{SECRETKEY_SEED_LENGTH, PUBLICKEY_SERIALIZED_LENGTH};
use salty::agreement;

use wycheproof::wycheproof::*;

const THE_TESTS: WycheproofTest = generate_data!("../tests/x25519_test.json", "xdh_comp_schema.json");

#[entry]
fn main () -> ! {

    hprint!("running tests...\n").ok();

    for testgroup in THE_TESTS.test_groups {
        if let TestGroup::XdhComp{curve, tests} = testgroup {
            for testcase in tests.as_ref() {
                run_x25519_comp(&curve, &testcase);
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

fn run_x25519_comp(_curve: &str, test_data: &XdhTestVector) {

    hprint!("X25519 test case {:4}: ", test_data.tc_id).ok();

    let private = <[u8; SECRETKEY_SEED_LENGTH]>::try_from(test_data.private);
    let public  = <[u8; PUBLICKEY_SERIALIZED_LENGTH]>::try_from(test_data.public);
    let expect  = <[u8; 32]>::try_from(test_data.shared);
    let valid: bool;

    if private.is_err() || public.is_err() || expect.is_err() {
        valid = false;
    } else {
        let public = agreement::PublicKey::try_from(public.unwrap());
        if public.is_err() {
            valid = false;
        } else {
            let private = agreement::SecretKey::from_seed(&private.unwrap());
            let shared  = private.agree(&public.unwrap());

            valid = shared.to_bytes() == expect.unwrap();
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
            hprintln!("FAIL (expected INVALID, but isn't)").ok();
            fail();
        } else {
            hprintln!("OK (invalid input)").ok();
        }
        ExpectedResult::Acceptable => if valid {
            hprintln!("ACCEPTABLE (valid)").ok();
        } else {
            hprintln!("ACCEPTABLE (invalid)").ok();
        },
    }
}
