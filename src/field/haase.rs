use core::ops::{
    Add,
    AddAssign,
    Neg,
    Sub,
    SubAssign,
    Mul,
    MulAssign,
};

use subtle::{
    Choice,
    ConditionallySelectable,
    ConstantTimeEq,
};

use super::FieldImplementation;

pub type Limbs = [u32; 8];

type U256 = [u32; 8];
// reduced, 0 <= value < 2*255 - 19
// type U255 = [u32; 8];

extern "C" {
    pub fn fe25519_add_asm(result: *mut U256, left: *const U256, right: *const U256);
    pub fn fe25519_mul_asm(result: *mut U256, left: *const U256, right: *const U256);
    pub fn fe25519_square_asm(result: *mut U256, value: *const U256);
}

#[derive(Clone,Copy,Debug,Default)]
pub struct FieldElement(pub Limbs);

impl ConditionallySelectable for FieldElement {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut selection = Self::default();
        for i in 0..8 {
            selection.0[i] = u32::conditional_select(&a.0[i], &b.0[i], choice);
        }
        selection
    }

    fn conditional_swap(a: &mut Self, b: &mut Self, choice: Choice) {
        for (ai, bi) in a.0.iter_mut().zip(b.0.iter_mut()) {
            u32::conditional_swap(ai, bi, choice);
        }
    }
}

impl FieldImplementation for FieldElement {
    type Limbs = Limbs;

    const ZERO: Self = Self([0, 0, 0, 0, 0, 0, 0, 0]);

    const ONE: Self = Self([1, 0, 0, 0, 0, 0, 0, 0]);

    const D: Self = Self([
        0x135978a3, 0x75eb4dca,
        0x4141d8ab, 0x00700a4d,
        0x7779e898, 0x8cc74079,
        0x2b6ffe73, 0x52036cee,
    ]);

    const D2: Self = Self([
        0x26b2f159, 0xebd69b94,
        0x8283b156, 0x00e0149a,
        0xeef3d130, 0x198e80f2,
        0x56dffce7, 0x2406d9dc,
    ]);

    const BASEPOINT_X: Self = Self([
        0x8f25d51a, 0xc9562d60,
        0x9525a7b2, 0x692cc760,
        0xfdd6dc5c, 0xc0a4e231,
        0xcd6e53fe, 0x216936d3,
    ]);

    const BASEPOINT_Y: Self = Self([
        0x6666_6658, 0x6666_6666,
        0x6666_6666, 0x6666_6666,
        0x6666_6666, 0x6666_6666,
        0x6666_6666, 0x6666_6666,
    ]);

    const I: Self = Self([
        0x4a0ea0b0, 0xc4ee1b27,
        0xad2fe478, 0x2f431806,
        0x3dfbd7a7, 0x2b4d0099,
        0x4fc1df0b, 0x2b832480,
    ]);

    fn to_bytes(&self) -> [u8; 32] {
        // make our own private copy
        let mut fe = self.clone();
        FieldElement::reduce_completely(&mut fe);
        unsafe { core::mem::transmute(fe.0) }
    }

    fn from_bytes_unchecked(bytes: &[u8; 32]) -> FieldElement {
        let mut limbs: U256 = unsafe { core::mem::transmute(*bytes) };

        // some kind of safety check
        // but: also clears the x-coordinate sign bit
        limbs[7] &= 0x7fff_ffff;

        FieldElement(limbs)
    }

    fn inverse(&self) -> FieldElement {
        // TODO: replace by Haase's version in `fe25519_invert.c`

        let mut inverse = self.clone();

        // exponentiate with 2**255 - 21,
        // which by Fermat's little theorem is the same as inversion
        for i in (0..=253).rev() {
            inverse = inverse.squared();
            if i != 2 && i != 4 {
                inverse = &inverse * &self;
            }
        }

        inverse
    }

    fn squared(&self) -> FieldElement {
        let mut square = U256::default();

        unsafe { fe25519_square_asm(&mut square, &self.0); }
        FieldElement(square)
    }

    fn pow2523(&self) -> FieldElement {
        // TODO: replace by Haase's version in `fe25519_pow2523.c`

        let mut sqrt = self.clone();

        for i in (0..=250).rev() {
            sqrt = sqrt.squared();
            if i != 1 {
                sqrt = &sqrt * &self;
            }
        }

        sqrt
    }
}

impl ConstantTimeEq for FieldElement {
    fn ct_eq(&self, other: &Self) -> Choice {
        let canonical_self = self.to_bytes();
        let canonical_other = other.to_bytes();

        canonical_self.ct_eq(&canonical_other)
    }
}

impl PartialEq for FieldElement {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}


impl<'a, 'b> Add<&'b FieldElement> for &'a FieldElement {
    type Output = FieldElement;

    /// Addition of field elements
    fn add(self, other: &'b FieldElement) -> FieldElement {
        let mut sum = U256::default();
        unsafe { fe25519_add_asm(&mut sum, &self.0, &other.0); }
        FieldElement(sum)
    }
}

impl<'b> AddAssign<&'b FieldElement> for FieldElement {
    fn add_assign(&mut self, other: &'b FieldElement) {
        *self = (self as &FieldElement) + &other;
    }
}

impl<'a> Neg for &'a FieldElement {
    type Output = FieldElement;

    fn neg(self) -> FieldElement {
        let negation = &FieldElement::ZERO - &self;
        negation
    }
}

impl<'a, 'b> Sub<&'b FieldElement> for &'a FieldElement {
    type Output = FieldElement;

    fn sub(self, other: &'b FieldElement) -> FieldElement {
        let mut difference = U256::default();
        let mut accu: i64;

        accu = self.0[7] as i64;
        accu -= other.0[7] as i64;

        // conversely to the approach for `add`, we enforce
        // that bit 31 is set in difference[7], so that all the
        // limb-wise subtractions are positive
        difference[7] = (accu as u32) | 0x8000_0000;
        // to compensate for setting bit 31, need to subtract
        // "-1" here
        accu = ((((accu >> 31) as i32) - 1) * 19) as i64;

        for i in 0..7 {
            accu += self.0[i] as i64;
            accu -= other.0[i] as i64;

            difference[i] = accu as u32;
            accu >>= 32;
        }

        // since difference[7] is big enough (by our preparations),
        // accu is actually positive and fits in a u32
        accu += difference[7] as i64;
        difference[7] = accu as u32;

        FieldElement(difference)
    }
}

impl<'b> SubAssign<&'b FieldElement> for FieldElement {
    fn sub_assign(&mut self, other: &'b FieldElement) {
        *self = (self as &FieldElement) - other;
    }
}

impl<'a, 'b> Mul<&'b FieldElement> for &'a FieldElement {
    type Output = FieldElement;

    fn mul(self, other: &'b FieldElement) -> FieldElement {
        let mut product = U256::default();

        unsafe { fe25519_mul_asm(&mut product, &self.0, &other.0); }

        FieldElement(product)
    }
}

impl<'b> MulAssign<&'b FieldElement> for FieldElement {
    fn mul_assign(&mut self, other: &'b FieldElement) {
        *self = (self as &FieldElement) * other;
    }
}


impl FieldElement {
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

}

#[cfg(test)]
mod tests {

    use crate::field::FieldImplementation;
    use super::FieldElement;
    use subtle::ConstantTimeEq;

    #[test]
    fn test_one_plus_one() {
        let one = FieldElement::ONE;
        let two = &one + &one;

        let expected = FieldElement([
            2, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
        ]);

        // TODO: Implement PartialEq (hopefully in constant time!)
        assert_eq!(two.0, expected.0);
        assert!(bool::from(two.ct_eq(&expected)))

    }

    #[test]
    fn test_one_times_zero() {
        let one = FieldElement::ONE;
        let zero = FieldElement::ZERO;

        let result = &one * &zero;

        // TODO: Implement PartialEq (hopefully in constant time!)
        assert_eq!(result.0, zero.0);
        assert!(bool::from(result.ct_eq(&zero)))

    }

    #[test]
    fn test_two_times_three_is_six() {
        let one = FieldElement::ONE;
        let two = &one + &one;
        let three = &two + &one;

        let two_times_three = &two * &three;
        // no multiplications, just sum up ONEs
        let six = (1..=6).fold(FieldElement::ZERO, |partial_sum, _| &partial_sum + &FieldElement::ONE);

        assert_eq!(two_times_three.to_bytes(), six.to_bytes());
        assert!(bool::from(two_times_three.ct_eq(&six)));

    }

    #[test]
    fn test_negation() {
        let d2 = FieldElement::D2;
        let minus_d2 = -&d2;
        let maybe_zero = &d2 + &minus_d2;

        assert_eq!(FieldElement::ZERO.to_bytes(), maybe_zero.to_bytes());
    }

    #[test]
    fn test_inversion() {
        let d2 = FieldElement::D2;
        let maybe_inverse = d2.inverse();

        let maybe_one = &d2 * &maybe_inverse;
        assert_eq!(maybe_one.to_bytes(), FieldElement::ONE.to_bytes());
        assert!(bool::from(maybe_one.ct_eq(&FieldElement::ONE)));
        assert_eq!(maybe_one, FieldElement::ONE);
    }

    // #[test]
    // fn test_possible_sqrt() {
    //     let d2 = &FieldElement::ONE + &FieldElement::ONE;

    //     let d2_sq = &d2 * &d2; // <-- certainly a square
    //     let maybe_d2 = d2_sq.possible_sqrt();
    //     // assert_eq!(d2, maybe_d2);
    //     let maybe_d2_sq = &maybe_d2 * &maybe_d2;

    //     // assert_eq!(&maybe_d2_sq - &d2_sq , FieldElement::ZERO);

    //     assert_eq!(d2_sq.to_bytes(), maybe_d2_sq.to_bytes());

    //     // let possible_sqrt_d2 = d2.possible_sqrt();
    //     // let maybe_d2 = &possible_sqrt_d2 * &possible_sqrt_d2;

    //     // assert_eq!(d2.to_bytes(), maybe_d2.to_bytes());
    //     // assert!((d2 == maybe_d2) || (d2 == -&maybe_d2));
    // }
}
