#![no_std]
#![no_main]

use cortex_m_semihosting::{debug, hprintln};
extern crate panic_semihosting;
use cortex_m_rt::entry;

#[entry]
fn main() -> ! {

    hprintln!("All tests passed").ok();

    debug::exit(debug::EXIT_SUCCESS);

    loop { continue; }

}
