#![no_std]
#![no_main]

extern crate panic_semihosting;
use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprint, hprintln};

use wycheproof_macros::generate_data;

use core::convert::TryFrom;
use salty::agreement;
use salty::constants::{PUBLICKEY_SERIALIZED_LENGTH, SECRETKEY_SEED_LENGTH};

use wycheproof_types::*;

const THE_TESTS: WycheproofTest = generate_data!(
    "wycheproof/data/x25519_test.json",
    "wycheproof/data/xdh_comp_schema.json"
);

const EXEMPTED_FAILURES: &[u32] = &[128, 141, 151];

#[entry]
fn main() -> ! {
    hprint!("running tests...\n").ok();

    let mut known_failures: usize = 0;
    for testgroup in THE_TESTS.test_groups {
        if let TestGroup::XdhComp { curve, tests } = testgroup {
            for testcase in tests.iter() {
                known_failures += run_x25519_comparison(curve, testcase) as usize;
            }
        }
    }

    hprintln!(
        "{} test cases failed among the exemption list {:?}",
        known_failures,
        EXEMPTED_FAILURES
    )
    .ok();
    hprintln!("done.").ok();

    debug::exit(debug::EXIT_SUCCESS);
    loop {
        continue;
    }
}

/// returns `true` on exempted failure, does not return for non-exempted failure
fn fail(tc_id: u32) -> bool {
    if !EXEMPTED_FAILURES.iter().any(|&id| id == tc_id) {
        debug::exit(debug::EXIT_FAILURE);
    }
    hprintln!("NOT FAILING due to exemption - do investigate").ok();
    true
}

/// Returns `true` on (exempted) failure, `false` on pass
fn run_x25519_comparison(_curve: &str, test_data: &XdhTestVector) -> bool {
    let tc_id = test_data.tc_id;
    hprint!("X25519 test case {:4}: ", tc_id).ok();

    let private = <[u8; SECRETKEY_SEED_LENGTH]>::try_from(test_data.private);
    let public = <[u8; PUBLICKEY_SERIALIZED_LENGTH]>::try_from(test_data.public);
    let expect = <[u8; 32]>::try_from(test_data.shared);

    let valid = match (private, public, expect) {
        (Ok(private), Ok(public), Ok(expect)) => {
            let public = agreement::PublicKey::from(public);
            let private = agreement::SecretKey::from_seed(&private);
            let shared = private.agree(&public);

            shared.to_bytes() == expect
        }
        _ => false,
    };

    match test_data.result {
        ExpectedResult::Valid => {
            if !valid {
                hprintln!("FAIL (expected VALID, but isn't)").ok();
                return fail(tc_id);
            } else {
                hprintln!("OK (valid input)").ok();
            }
        }
        ExpectedResult::Invalid => {
            if valid {
                hprintln!("FAIL (expected INVALID, but isn't)").ok();
                return fail(tc_id);
            } else {
                hprintln!("OK (invalid input)").ok();
            }
        }
        ExpectedResult::Acceptable => {
            if valid {
                hprintln!("ACCEPTABLE (valid)").ok();
            } else {
                hprintln!("ACCEPTABLE (invalid)").ok();
            }
        }
    }
    false
}
