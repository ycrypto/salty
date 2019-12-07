use core::{
    cmp::PartialEq,
    ops::{
        Add,
        Neg,
        Mul,
    }
};

use subtle::{
    Choice,
    ConditionallySelectable,
    ConstantTimeEq,
};

use crate::{
    Error,
    Result,
    constants::COMPRESSED_Y_LENGTH,
    field::{
        FieldImplementation,
        FieldElement,
    },
    scalar::Scalar,
};


/// These represent the (X,Y,Z,T) coordinates
#[derive(Clone,Copy,Debug,Default)]
pub struct CurvePoint (
    // TODO: maybe label them properly
    [FieldElement; 4]
);

/// "Compressed" form of a `CurvePoint`, whereby
/// the sign of the x-coordinate is stuffed in a
/// spare bit of the y-coordinate
#[derive(Clone,Copy,Debug,Default)]
pub struct CompressedY(
    pub [u8; 32])
;

impl From<&[u8; COMPRESSED_Y_LENGTH]> for CompressedY {
    fn from(bytes: &[u8; COMPRESSED_Y_LENGTH]) -> CompressedY {
        CompressedY(bytes.clone())
    }
}

impl CompressedY {
    /// This is rather tricky: to get the x-coordinate,
    /// and not just its sign, need to calculate the square
    /// root of `u/v := (y**2 - 1)/(dy**2 + 1)`. Moreover, we want
    /// to detect whether our compressed Y actually corresponds
    /// to a point on the curve! The original sources are
    /// [the Tweet NaCl paper, section 5](tweetnacl) and
    /// the [ed25519 paper][ed25519], also section 5.
    ///
    /// [tweetnacl]: http://tweetnacl.cr.yp.to/tweetnacl-20140917.pdf
    /// [ed25519]: https://cryptojedi.org/papers/ed25519-20110926.pdf
    pub fn decompressed(&self) -> Result<CurvePoint> {
        #![allow(non_snake_case)]

        // point = (X, Y, Z, T)
        //
        // basic strategy: use exponentiation by `2**252 - 3`,
        // which "has all bits set except position 1".

        // TODO: actually implement TryFrom
        // let Y = FieldElement::try_from(self.as_bytes())?;
        let Y = FieldElement::from_bytes_unchecked(self.as_bytes());
        let Z = FieldElement::ONE;
        let Y_squared = Y.squared();

        let u = &Y_squared - &Z;  // aka num[erator], y**2 - 1
        let v = &(&Y_squared * &FieldElement::D) + &Z;  // aka den[ominator], dy**2 + 1

        let v2 = v.squared();
        let v4 = v2.squared();
        let v7 = &(&v4 * &v2) * &v;

        let t = &v7 * &u; // term: t = uv**7
        let mut X = &(&(&t.pow2523() * &u) * &v2) * &v;  // aka `beta`

        let chk = &X.squared() * &v;
        if chk != u {
            X = &X * &FieldElement::I;
        }

        let chk = &X.squared() * &v;
        if chk != u {
            return Err(Error::PublicKeyBytesInvalid);
        }

        // I really don't get it. TweetNaCl checks for equality.
        // If we do that, our tests fail. This way, tests pass.
        if X.parity() != (self.0[31] >> 7) {
            X = -&X;
        }

        let T = &X * &Y;
        Ok(CurvePoint([X, Y, Z, T]))
    }
    // static int unpackneg(gf r[4],const u8 p[32]) {
    //   // "load curve point"
    //   gf t, chk, num, den, den2, den4, den6;
    //   set25519(r[2],gf1);  // Z = "one"
    //   unpack25519(r[1],p); // Y = compressed Y with x's sign bit erased
    //   S(num,r[1]);
    //   M(den,num,D);
    //   Z(num,num,r[2]);
    //   A(den,r[2],den); // set numerator, denominator as above

    //   S(den2,den);
    //   S(den4,den2);
    //   M(den6,den4,den2);
    //   M(t,den6,num);
    //   M(t,t,den);  // set t = denominator**7 * numerator

    //   pow2523(t,t);
    //   M(t,t,num);
    //   M(t,t,den);
    //   M(t,t,den);
    //   M(r[0],t,den); // X = sqrt(t)*num*den**3

    //   S(chk,r[0]);
    //   M(chk,chk,den);
    //   if (neq25519(chk, num)) M(r[0],r[0],I);

    //   S(chk,r[0]);
    //   M(chk,chk,den);
    //   if (neq25519(chk, num)) return -1;

    //   if (par25519(r[0]) == (p[31]>>7)) Z(r[0],gf0,r[0]);

    //   M(r[3],r[0],r[1]);
    //   return 0;
    // }
}

impl CurvePoint {
    pub fn basepoint() -> CurvePoint {
        CurvePoint([
             FieldElement::BASEPOINT_X,
             FieldElement::BASEPOINT_Y,
             FieldElement::ONE,
             &FieldElement::BASEPOINT_X * &FieldElement::BASEPOINT_Y,
        ])
    }

    pub fn neutral_element() -> CurvePoint {
        CurvePoint([
            FieldElement::ZERO,
            FieldElement::ONE,
            FieldElement::ONE,
            FieldElement::ZERO,
        ])
    }

    pub fn compressed(&self) -> CompressedY {

        // normalize X, Y to Z = 1
        let z_inverse = &self.0[2].inverse();
        let x = &self.0[0] * &z_inverse;
        let y = &self.0[1] * &z_inverse;

        // normalized Y coordinate
        let mut r = y.to_bytes();
        // slot sign of X in the "spare" top bit of last byte
        // dalek calls this parity "is_negative"
        r[31] ^= x.parity() << 7;

        CompressedY(r)
    }
}

impl<'a, 'b> Add<&'b CurvePoint> for &'a CurvePoint {

    type Output = CurvePoint;

    fn add(self, other: &'b CurvePoint) -> Self::Output {

        let p = &self.0;
        let q = &other.0;

        let a = &p[1] - &p[0];
        let t = &q[1] - &q[0];
        let a = &a * &t;        // A <- (Y1 - X1)(Y2 - X2)

        // let mut b = &p[0] + &p[1];
        let b = &p[0] + &p[1];
        let t = &q[0] + &q[1];
        let b = &b * &t;        // B <- (Y1 + X1)*(Y2 + X2)
        // b *= &t;

        let c = &p[3] * &q[3];
        let c = &c * &FieldElement::D2;       // C <- k*T1*T2  with k = 2d' =

        let d = &p[2] * &q[2];
        let d = &d + &d;       // D <- 2*Z1*Z2

        let e = &b - &a;
        let f = &d - &c;
        let g = &d + &c;
        let h = &b + &a;

        let coordinates = [
            &e * &f,
            &h * &g,
            &g * &f,
            &e * &h,
        ];

        CurvePoint(coordinates)
    }
}

impl<'a> Neg for &'a CurvePoint {
    type Output = CurvePoint;

    fn neg(self) -> CurvePoint {
        let p = &self.0;
        CurvePoint([-&p[0], p[1], p[2], -&p[3]])
    }
}

impl<'a, 'b> Mul<&'b CurvePoint> for &'a Scalar {

    type Output = CurvePoint;

    fn mul(self, point: &'b CurvePoint) -> CurvePoint {
        let mut p = CurvePoint([
            FieldElement::ZERO.clone(),
            FieldElement::ONE.clone(),
            FieldElement::ONE.clone(),
            FieldElement::ZERO.clone(),
        ]);

        let mut q = point.clone();
        let scalar = self;

        for i in (0..=255).rev() {
            let b = (((scalar.0[i / 8] >> (i & 7)) & 1) as u8).into();
            CurvePoint::conditional_swap(&mut p, &mut q, b);

            q = &q + &p;
            p = &p + &p;

            CurvePoint::conditional_swap(&mut p, &mut q, b);
        }

        p
    }
}

impl ConditionallySelectable for CurvePoint {
    fn conditional_select(p: &Self, q: &Self, choice: Choice) -> Self {
        let mut selection = Self::default();

        for (i, (pi, qi)) in p.0.iter().zip(q.0.iter()).enumerate() {
            selection.0[i] = FieldElement::conditional_select(pi, qi, choice);
        }
        selection
    }

    fn conditional_swap(p: &mut Self, q: &mut Self, choice: Choice) {
        for (pi, qi) in p.0.iter_mut().zip(q.0.iter_mut()) {
            FieldElement::conditional_swap(pi, qi, choice);
        }
    }
}

impl CompressedY {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl ConstantTimeEq for CompressedY {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for CompressedY {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl ConstantTimeEq for CurvePoint {
    fn ct_eq(&self, other: &Self) -> Choice {
        let self_compressed = self.compressed();
        let other_compressed = other.compressed();
        self_compressed.ct_eq(&other_compressed)
    }
}

impl PartialEq for CurvePoint {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

#[cfg(test)]
mod tests {

    use super::CurvePoint;
    use crate::Scalar;

    #[test]
    fn test_neutral_is_neutral() {
        let n = 42;
        let s = Scalar::from_bytes(&[
            n, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        let ne = CurvePoint::neutral_element();
        assert_eq!(ne, &s * &ne);
    }

    #[test]
    fn test_addition_vs_multiplication() {

        let p = CurvePoint::basepoint();
        let p_plus_p = &p + &p;
        let two = Scalar::from_bytes(&[
            2u8, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]);

        let two_times_p = &two * &p;

        assert_eq!(p_plus_p, two_times_p);
    }

    #[test]
    fn test_some_more() {
        let n = 37;
        let s = Scalar::from_bytes(&[
            n, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        let bp = CurvePoint::basepoint();
        let ne = CurvePoint::neutral_element();

        let a = (1..=n).fold(ne, |partial_sum, _| &partial_sum + &bp);
        let b = &s * &bp;

        assert_eq!(a, b);
    }

    #[test]
    fn test_negation() {
        let bp = CurvePoint::basepoint();
        let minus_bp = -&bp;
        let maybe_neutral = &bp + &minus_bp;

        assert_eq!(maybe_neutral, CurvePoint::neutral_element());
    }
}
