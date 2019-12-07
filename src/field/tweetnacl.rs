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

pub type Limbs = [i64; 16];

/// Element of the base field of the elliptic curve
#[derive(Clone,Copy,Debug,Default)]
pub struct FieldElement(pub Limbs);

impl ConditionallySelectable for FieldElement {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut selection = Self::default();
        for i in 0..16 {
            selection.0[i] = i64::conditional_select(&a.0[i], &b.0[i], choice);
        }
        selection
    }

    fn conditional_swap(a: &mut Self, b: &mut Self, choice: Choice) {
        // what TweetNacl originally does
        // let mask: i64 = !(b - 1);
        // TweetNacl translated to Choice language
        // let mask: i64 = !(choice.unwrap_u8() as i64) - 1);
        // `subtle` definition, which is equivalent
        // let mask: i64 = -(choice.unwrap_u8() as i64);
        for (ai, bi) in a.0.iter_mut().zip(b.0.iter_mut()) {
            // let t = mask & (*ai ^ *bi);
            // *ai ^= t;
            // *bi ^= t;
            i64::conditional_swap(ai, bi, choice);
        }
    }
}

impl FieldImplementation for FieldElement {
    type Limbs = Limbs;

    const ZERO: Self = Self([
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
    ]);

    const ONE: Self = Self([
        1, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
    ]);

    const D: Self = Self([
        0x78a3, 0x1359, 0x4dca, 0x75eb,
        0xd8ab, 0x4141, 0x0a4d, 0x0070,
        0xe898, 0x7779, 0x4079, 0x8cc7,
        0xfe73, 0x2b6f, 0x6cee, 0x5203,
    ]);

    const D2: Self = Self([
        0xf159, 0x26b2, 0x9b94, 0xebd6,
        0xb156, 0x8283, 0x149a, 0x00e0,
        0xd130, 0xeef3, 0x80f2, 0x198e,
        0xfce7, 0x56df, 0xd9dc, 0x2406,
    ]);

    const BASEPOINT_X: Self = Self([
        0xd51a, 0x8f25, 0x2d60, 0xc956,
        0xa7b2, 0x9525, 0xc760, 0x692c,
        0xdc5c, 0xfdd6, 0xe231, 0xc0a4,
        0x53fe, 0xcd6e, 0x36d3, 0x2169,
    ]);

    const BASEPOINT_Y: Self = Self([
        0x6658, 0x6666, 0x6666, 0x6666,
        0x6666, 0x6666, 0x6666, 0x6666,
        0x6666, 0x6666, 0x6666, 0x6666,
        0x6666, 0x6666, 0x6666, 0x6666,
    ]);

    const I: Self = Self([
        0xa0b0, 0x4a0e, 0x1b27, 0xc4ee,
        0xe478, 0xad2f, 0x1806, 0x2f43,
        0xd7a7, 0x3dfb, 0x0099, 0x2b4d,
        0xdf0b, 0x4fc1, 0x2480, 0x2b83,
    ]);

    fn to_bytes(&self) -> [u8; 32] {
        // make our own private copy
        let mut fe = self.clone();

        // three times' the charm??
        // TODO: figure out why :)
        fe.carry();
        fe.carry();
        fe.carry();

        // let m_buf: FieldElementBuffer = Default::default();
        // let mut m: FieldElement = FieldElement(m_buf);
        let mut m: Limbs = Default::default();
        for _j in 0..2 {
            m[0] = fe.0[0] - 0xffed;
            for i in 1..15 {
                m[i] = fe.0[i] - 0xffff - ((m[i - 1] >> 16) & 1);
                m[i - 1] &= 0xffff;
            }

            m[15] = fe.0[15] - 0x7fff - ((m[14] >> 16) & 1);
            let b = (m[15] >> 16) & 1;
            m[14] &= 0xffff;
            FieldElement::conditional_swap(&mut fe, &mut FieldElement(m), ((1 - b) as u8).into());
        }

        let mut bytes: [u8; 32] = Default::default();
        for i in 0..16 {
            bytes[2 * i] = fe.0[i] as u8; //& 0xff;
            bytes[2 * i + 1] = (fe.0[i] >> 8) as u8;
        }

        bytes
    }

    fn from_bytes_unchecked(bytes: &[u8; 32]) -> FieldElement {
        let mut limbs = Limbs::default();
        for i in 0..16 {
            limbs[i] = (bytes[2 * i] as i64) + ((bytes[2 * i + 1] as i64) << 8);
        }

        // some kind of safety check
        // but: also clears the x-coordinate sign bit
        limbs[15] &= 0x7fff;

        FieldElement(limbs)
    }

    // sv inv25519(gf o,const gf i)
    // {
    //  // want: o = 1/i in base field
    //   gf c;
    //   int a;
    //   FOR(a,16) c[a]=i[a];
    //   // exponentiate with 2^255 - 21
    //   // same as inversion by Fermat's little theorem
    //   for(a=253;a>=0;a--) {
    //     S(c,c);
    //     if(a!=2&&a!=4) M(c,c,i);
    //   }
    //   FOR(a,16) o[a]=c[a];
    // }
    fn inverse(&self) -> FieldElement {
        // TODO: possibly assert! that fe != 0?

        // make our own private copy
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

    // sv pow2523(gf o,const gf i)
    // // the naming here means "to the power of 2^252 - 3
    // // again by Fermat's little theorem, this is the same
    // // as taking the square root, which is needed for
    // // point decompression
    // {
    //   gf c;
    //   int a;
    //   FOR(a,16) c[a]=i[a];
    //   for(a=250;a>=0;a--) {
    //     S(c,c);
    //     if(a!=1) M(c,c,i);
    //   }
    //   FOR(a,16) o[a]=c[a];
    // }
    /// TODO: figure out why this doesn't pass the test at the end
    fn pow2523(&self) -> FieldElement {

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

    // TODO: TweetNaCl doesn't do any reduction here, why not?
    /// Addition of field elements
    fn add(self, other: &'b FieldElement) -> FieldElement {
        let mut sum = self.clone();
        sum += other;
        sum
    }
}

impl<'b> AddAssign<&'b FieldElement> for FieldElement {
    fn add_assign(&mut self, other: &'b FieldElement) {
        for (x, y) in self.0.iter_mut().zip(other.0.iter()) {
            *x += y;
        }
    }
}

impl<'a> Neg for &'a FieldElement {
    type Output = FieldElement;

    /// Subition of field elements
    fn neg(self) -> FieldElement {
        let mut negation = self.clone();
        for (i, xi) in self.0.iter().enumerate() {
            negation.0[i] = -xi;
        }
        negation
    }
}

impl<'a, 'b> Sub<&'b FieldElement> for &'a FieldElement {
    type Output = FieldElement;

    // TODO: TweetNaCl doesn't do any reduction here, why not?
    /// Subition of field elements
    fn sub(self, other: &'b FieldElement) -> FieldElement {
        let mut difference = self.clone();
        difference -= other;
        difference
    }
}

impl<'b> SubAssign<&'b FieldElement> for FieldElement {
    fn sub_assign(&mut self, other: &'b FieldElement) {
        for (x, y) in self.0.iter_mut().zip(other.0.iter()) {
            *x -= y;
        }
    }
}

impl<'a, 'b> Mul<&'b FieldElement> for &'a FieldElement {
    type Output = FieldElement;

    fn mul(self, other: &'b FieldElement) -> FieldElement {
        // start with so-called "schoolbook multiplication"
        // TODO: nicer way to do this with iterators?
        let mut pre_product: [i64; 31] = Default::default();
        for i in 0..16 {
            for j in 0..16 {
                pre_product[i + j] += self.0[i] * other.0[j];
            }
        }

        // reduce modulo 2**256 - 38
        // (en route to reduction modulo 2**255 - 19)
        for i in 0..15 {
            pre_product[i] += 38 * pre_product[i + 16];
        }

        // ble, would prefer to call pre_product just product,
        // but the two-step initialize then copy doesn't seem
        // to work syntactically.
        // also: really hope the initialization of `product`
        // is optimized away...
        let mut product: Limbs = Default::default();
        product.copy_from_slice(&mut pre_product[..16]);

        let mut fe = FieldElement(product);
        // normalize such that all limbs lie in [0, 2^16)
        // TODO: why twice? why is twice enough?
        fe.carry();
        fe.carry();

        fe
    }
}

impl<'b> MulAssign<&'b FieldElement> for FieldElement {
    fn mul_assign(&mut self, other: &'b FieldElement) {
        let result = (&self as &FieldElement) * other;
        self.0 = result.0;
    }
}


impl FieldElement {
    fn carry(&mut self) {
        // TODO: multiplication calls this twice!!
        // TODO: to_bytes calls this thrice!!!
        //
        // What exactly are the guarantees here?
        // Why don't we do this twice or thrice if it's needed?
        for i in 0..16 {
            // add 2**16
            self.0[i] += 1 << 16;
            // "carry" part, everything over radix 2**16
            let carry = self.0[i] >> 16;

            // a) i < 15: add carry bit, subtract 1 to compensate addition of 2^16
            // --> o[i + 1] += c - 1  // add carry bit, subtract
            // b) i == 15: wraps around to index 0 via 2^256 = 38
            // --> o[0] += 38 * (c - 1)
            self.0[(i + 1) * ((i < 15) as usize)] +=
                carry - 1 + 37 * (carry - 1) * ((i == 15) as i64);
            // get rid of carry bit
            // TODO: why not get rid of it immediately. kinda clearer
            self.0[i] -= carry << 16;
        }
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

    #[test]
    fn test_imaginary() {
        let minus_one = -&FieldElement::ONE;
        let i_squared = &FieldElement::I * &FieldElement::I;

        assert_eq!(minus_one, i_squared);
    }

    #[test]
    fn test_square_roots() {
        let two = &FieldElement::ONE + &FieldElement::ONE;
        // four has Legendre symbol of minus one
        let four = &two * &two;
        let sqrt_minus_four = &four.pow2523() * &four;
        assert_eq!(&sqrt_minus_four * &sqrt_minus_four, -&four);
        let sqrt_four = &FieldElement::I * &sqrt_minus_four;
        assert_eq!(&sqrt_four * &sqrt_four, four);

        let three = &two + &FieldElement::ONE;
        // nine has Legendre symbol of one
        let nine = &three * &three;
        let sqrt_nine = &nine.pow2523() * &nine;
        assert_eq!(&sqrt_nine * &sqrt_nine, nine);
    }

}
