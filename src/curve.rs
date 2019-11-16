use core::{
    cmp::PartialEq,
    ops::{
        Add,
        Mul,
    }
};

use subtle::{
    Choice,
    ConditionallySelectable,
    ConstantTimeEq,
};

use crate::{
    field::{
        FieldImplementation,
        FieldElement,
    },
    scalar::Scalar,
};


/// These represent the (X,Y,T,Z) coordinates
/// TODO: maybe label them properly
#[derive(Clone,Debug,Default)]
pub struct CurvePoint (
    [FieldElement; 4]
);

#[derive(Clone,Debug,Default)]
pub struct CompressedY(
    pub [u8; 32])
;


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
            crate::field::tweetnacl::FieldElement::ZERO,
            crate::field::tweetnacl::FieldElement::ONE,
            crate::field::tweetnacl::FieldElement::ONE,
            crate::field::tweetnacl::FieldElement::ZERO,
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
}
