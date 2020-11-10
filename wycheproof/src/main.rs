#![no_std]
#![no_main]

extern crate panic_semihosting;
//use cortex_m::peripheral::{DWT, Peripherals};
use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprintln, hprint};

use eddsa_tests_gen::generate_testcalls;
use tests_base::ExpectedResult;

use core::convert::TryFrom;
use salty::{PublicKey, Signature, constants::PUBLICKEY_SERIALIZED_LENGTH, constants::SIGNATURE_SERIALIZED_LENGTH};

#[entry]
fn main () -> ! {

    hprint!("running tests...").ok();

    generate_testcalls!();

    hprintln!("\ndone.").ok();

    debug::exit(debug::EXIT_SUCCESS);
    loop { continue; }
}

fn run_testcase (name: &str, pkin: &[u8], msg: &[u8], sigin: &[u8], expect: ExpectedResult) {

    hprint!(".").ok();

    let pk  = <[u8; PUBLICKEY_SERIALIZED_LENGTH]>::try_from(pkin);
    let sig = <[u8; SIGNATURE_SERIALIZED_LENGTH]>::try_from(sigin);
    let valid: bool;

    if pk.is_err() || sig.is_err() {
        valid = false;
    } else {
        let pk  = PublicKey::try_from(&pk.unwrap());
        if pk.is_err() {
            valid = false;
        } else {
            let sig = Signature::from(&sig.unwrap());
            let result = pk.unwrap().verify(&msg, &sig);
            valid = result.is_ok();
        }
    }

    match expect {
        ExpectedResult::Valid => if !valid {
            hprint!("\n{} FAIL (expected VALID, but isn't)", name).ok();
        }
        ExpectedResult::Invalid => if valid {
            hprint!("\n{} FAIL (expected INVALID, but isn't)", name).ok();
        }
        ExpectedResult::Acceptable => {},
    }
}
