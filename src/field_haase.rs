// The basic philosophy is to calculate in the
// ring Z/2p, where p = 2**255 - 19 is the Ed25519
// prime, and 2p = 2**256 - 38.
//
// Since Z/2p projects onto Z/p, we only need to
// do the slightly more involved reduction mod p
// when presenting canonical representations.

// little-endian representations
type U64 = [u32; 2];
type U128 = [u32; 4];
type U255 = [u32; 8];  // reduced, 0 <= value < 2*255 - 19
type U256 = [u32; 8];
type U512 = [u32; 16];

#[derive(Clone,Debug,Default)]
pub struct FieldElement(U256);

use core::ops::Add;
impl<'a, 'b> Add<&'b FieldElement> for &'a FieldElement {
    type Output = FieldElement;

    /// Addition of field elements
    fn add(self, other: &'b FieldElement) -> FieldElement {

        let mut out: U256 = Default::default();
        let mut accu: u64 = 0;

        accu = self.0[7] as u64;
        accu += other.0[7] as u64;

        // force `out[7]` to be at most 31 bit,
        // so that an overflow from self[6]+other[6]
        // can be added at the end.
        // if out[7] had the 31st bit set, replace
        // the corresponding value of 2^255 with 19.
        out[7] = (accu as u32) & 0x7fff_ffff;
        // the maximum value of "inner" accu >> 31 is 3,
        // so the maximum value of accu is 3 * 19 = 57 = 0x39 = 0b11_1001
        accu = (((accu >> 31) as u32) * 19) as u64;

        // now we can reduce "on the fly"
        for i in 0..7 {
            accu += self.0[i] as u64;
            accu += other.0[i] as u64;
            out[i] = accu as u32;
            accu >>= 32;
        }

        // out[7] is a 32 bit number, due to our
        // preparations at the start!
        accu += out[7] as u64;
        out[7] = accu as u32;

        FieldElement(out)
    }
}

use core::ops::Sub;
impl<'a, 'b> Sub<&'b FieldElement> for &'a FieldElement {
    type Output = FieldElement;
    fn sub(self, other: &'b FieldElement) -> FieldElement {

        let mut out: U256 = Default::default();
        let mut accu: i64 = 0;

        accu = self.0[7] as i64;
        accu -= other.0[7] as i64;

        // conversely to the approach for `add`, we enforce
        // that bit 31 is set in out[7], so that all the
        // limb-wise subtractions are positive
        out[7] = (accu as u32) | 0x8000_0000;
        // to compensate for setting bit 31, need to subtract
        // "-1" here
        accu = ((((accu >> 31) as u32) - 1) * 19) as i64;

        for i in 0..7 {
            accu += self.0[i] as i64;
            accu -= other.0[i] as i64;

            out[i] = accu as u32;
            accu >>= 32;
        }

        // since out[7] is big enough (by our preparations),
        // accu is actually positive and fits in a u32
        accu += out[7] as i64;
        out[7] = accu as u32;

        FieldElement(out)
    }
}

// The following typedef and extern "C" declaration copied
// from bindgen. Including it here wreaks havoc on byteorders'
// no_std status...
#[cfg(cortex_m4)]
#[allow(non_camel_case_types)]
// pub type fe25519 = [cty::c_uint; 8usize];
pub type fe25519 = [u32; 8usize];
#[cfg(cortex_m4)]
extern "C" {
    pub fn fe25519_mul_asm(pResult: *mut fe25519, pVal1: *const fe25519, pVal2: *const fe25519);
    pub fn fe25519_sqr_asm(pResult: *mut fe25519, pVal1: *const fe25519);
}

#[cfg(cortex_m4)]
use core::ops::Mul;
#[cfg(cortex_m4)]
impl<'a, 'b> Mul<&'b FieldElement> for &'a FieldElement {
    type Output = FieldElement;

    fn mul(self, other: &'b FieldElement) -> FieldElement {
        let mut out: U256 = Default::default();

        unsafe { fe25519_mul_asm(&mut out, &self.0, &other.0); }

        FieldElement(out)
    }
}

#[cfg(cortex_m4)]
fn square(fe: &FieldElement) -> FieldElement {
    let mut out: U256 = Default::default();

    unsafe { fe25519_sqr_asm(&mut out, &fe.0); }

    FieldElement(out)
}

/*
fn multiply_64_64(x: &U64, y: &U64) -> U128 {
    // map to `multiply_64_64` using Karatsuba
    // "faster than textbook multiplication" due
    // to less memory accesses (2 cycles on Cortex-M0)
    //
    // TODO: Bleeee... Let's use Rust's u64 multiply
    // instead. Also, we want M4, no interest in M0
    unimplemented!();
}
fn multiply_128_128(x: &U128, y: &U128) -> U256 {
    // map to `multiply_64_64` using Karatsuba
    unimplemented!();
}

fn multiply_256_256(x: &U256, y: &U256) -> U512 {
    // map to `multiply_128_128` using Karatsuba
    unimplemented!();

    // let x0y0 = multiply_128_128(U128(x.0[..4]), U128(x.0[..4]));
    // let x0y0 = multiply_128_128(U128(x.0[..4]), U128(x.0[..4]));
    let x0y0 = multiply_128_128(x[..4], y[..4]);
    let x1y1 = multiply_128_128(x[4..], y[4..]);
}
*/

fn reduce_partially(value: &U512) -> U256 {
    unimplemented!();
}

pub fn reduce_completely(value: &mut FieldElement) {
    // how many times should we subtract prime p?
    // initial guess: based on bits 31+32
    let guess: u32 = value.0[7] >> 31;

    // guess could be wrong if value in [2**255 - 19, 2**255)
    // add 19 to value to find out!
    //
    // I found it easier to understand replacing p with 10**3 - 17
    // and considering decimal representation. Then the values
    // 983, 984, ... 999 are guessed wrong. Assume value = abcd,
    // then the guess is to subtract ab*983, so: check if
    // v - ab*983 + 17 = v + (ab + 1)*17
    // has thousands or ten-thousands decimals

    let mut accu: u64 = (guess as u64) * 19 + 19;
    for i in 0..7 {
        accu += value.0[i] as u64;
        accu >>= 32;
    }
    accu += value.0[7] as u64;
    let answer: u32 = (accu >> 31) as u32;

    // now reduce
    accu = answer as u64 * 19;
    for i in 0..7 {
        accu += value.0[i] as u64;
        value.0[i] = accu as u32;
        accu >>= 32;
    }

    accu += value.0[7] as u64;
    value.0[7] = (accu as u32) & 0x7fff_ffff;
}

