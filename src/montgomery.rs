//! 99.9% cribbed from curve25519-dalek

use core::ops::{
    // Add,
    // Neg,
    Mul,
    MulAssign,
};

use subtle::Choice;
use subtle::ConditionallySelectable;
use subtle::ConstantTimeEq;
// use zeroize::Zeroize;

use crate::{
    // constants::COMPRESSED_Y_LENGTH,
    edwards::{CompressedY as CompressedEdwardsY, EdwardsPoint},
    field::{FieldElement, FieldImplementation as _},
    scalar::Scalar,
    Error,
    Result,
};

// #[derive(Clone,Copy,Debug,Default)]
/// Holds the \\(u\\)-coordinate of a point on the Montgomery form of
/// Curve25519 or its twist.
#[derive(Clone, Copy, Debug, Default /*,Hash*/)]
pub struct MontgomeryPoint(pub FieldElement);

impl ConstantTimeEq for MontgomeryPoint {
    fn ct_eq(&self, other: &MontgomeryPoint) -> Choice {
        // let self_fe = FieldElement::from_bytes(&self.0);
        // let other_fe = FieldElement::from_bytes(&other.0);

        // self_fe.ct_eq(&other_fe)
        self.0.ct_eq(&other.0)
    }
}

// impl Default for MontgomeryPoint {
//     fn default() -> MontgomeryPoint {
//         MontgomeryPoint([0u8; 32])
//     }
// }

impl PartialEq for MontgomeryPoint {
    fn eq(&self, other: &MontgomeryPoint) -> bool {
        self.ct_eq(other).unwrap_u8() == 1u8
        // self.0 == other.0
    }
}

impl Eq for MontgomeryPoint {}

// impl Zeroize for MontgomeryPoint {
//     fn zeroize(&mut self) {
//         self.0.zeroize();
//     }
// }

impl MontgomeryPoint {
    // /// View this `MontgomeryPoint` as an array of bytes.
    // pub fn as_bytes(&self) -> &[u8; 32] {
    //     &self.0.to_bytes()
    // }

    /// Convert this `MontgomeryPoint` to an array of bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Attempt to convert to an `EdwardsPoint`, using the supplied
    /// choice of sign for the `EdwardsPoint`.
    ///
    /// # Inputs
    ///
    /// * `sign`: a `u8` donating the desired sign of the resulting
    ///   `EdwardsPoint`.  `0` denotes positive and `1` negative.
    ///
    /// # Return
    ///
    /// * `Some(EdwardsPoint)` if `self` is the \\(u\\)-coordinate of a
    /// point on (the Montgomery form of) Curve25519;
    ///
    /// * `None` if `self` is the \\(u\\)-coordinate of a point on the
    /// twist of (the Montgomery form of) Curve25519;
    ///
    pub fn to_edwards(&self, sign: u8) -> Result<EdwardsPoint> {
        // To decompress the Montgomery u coordinate to an
        // `EdwardsPoint`, we apply the birational map to obtain the
        // Edwards y coordinate, then do Edwards decompression.
        //
        // The birational map is y = (u-1)/(u+1).
        //
        // The exceptional points are the zeros of the denominator,
        // i.e., u = -1.
        //
        // But when u = -1, v^2 = u*(u^2+486662*u+1) = 486660.
        //
        // Since this is nonsquare mod p, u = -1 corresponds to a point
        // on the twist, not the curve, so we can reject it early.

        let u = &self.0;
        let one = &FieldElement::ONE;

        if u + one == FieldElement::ZERO {
            return Err(Error::WrongTwist);
        }

        let y = &(u - one) * &(u + one).inverse();

        let mut y_bytes = y.to_bytes();
        y_bytes[31] ^= sign << 7;

        CompressedEdwardsY(y_bytes).decompressed()
    }

    pub fn basepoint() -> Self {
        Self(FieldElement::MONTGOMERY_BASEPOINT_U)
    }
}

/// A `ProjectivePoint` holds a point on the projective line
/// \\( \mathbb P(\mathbb F\_p) \\), which we identify with the Kummer
/// line of the Montgomery curve.
#[derive(Copy, Clone, Debug)]
#[allow(non_snake_case)]
struct ProjectivePoint {
    pub U: FieldElement,
    pub W: FieldElement,
}

// impl Identity for ProjectivePoint {
impl ProjectivePoint {
    fn neutral_element() -> ProjectivePoint {
        ProjectivePoint {
            U: FieldElement::ONE,
            W: FieldElement::ZERO,
        }
    }
}

impl Default for ProjectivePoint {
    fn default() -> ProjectivePoint {
        ProjectivePoint::neutral_element()
    }
}

impl ConditionallySelectable for ProjectivePoint {
    fn conditional_select(
        a: &ProjectivePoint,
        b: &ProjectivePoint,
        choice: Choice,
    ) -> ProjectivePoint {
        ProjectivePoint {
            U: FieldElement::conditional_select(&a.U, &b.U, choice),
            W: FieldElement::conditional_select(&a.W, &b.W, choice),
        }
    }
}

impl ProjectivePoint {
    /// Dehomogenize this point to affine coordinates.
    ///
    /// # Return
    ///
    /// * \\( u = U / W \\) if \\( W \neq 0 \\);
    /// * \\( 0 \\) if \\( W \eq 0 \\);
    pub fn to_affine(&self) -> MontgomeryPoint {
        let u = &self.U * &self.W.inverse();
        MontgomeryPoint(u)
    }
}

/// Perform the double-and-add step of the Montgomery ladder.
///
/// Given projective points
/// \\( (U\_P : W\_P) = u(P) \\),
/// \\( (U\_Q : W\_Q) = u(Q) \\),
/// and the affine difference
/// \\(      u\_{P-Q} = u(P-Q) \\), set
/// $$
///     (U\_P : W\_P) \gets u([2]P)
/// $$
/// and
/// $$
///     (U\_Q : W\_Q) \gets u(P + Q).
/// $$
#[allow(non_snake_case)]
fn differential_add_and_double(
    P: &mut ProjectivePoint,
    Q: &mut ProjectivePoint,
    affine_PmQ: &FieldElement,
) {
    let t0 = &P.U + &P.W;
    let t1 = &P.U - &P.W;
    let t2 = &Q.U + &Q.W;
    let t3 = &Q.U - &Q.W;

    let t4 = t0.squared(); // (U_P + W_P)^2 = U_P^2 + 2 U_P W_P + W_P^2
    let t5 = t1.squared(); // (U_P - W_P)^2 = U_P^2 - 2 U_P W_P + W_P^2

    let t6 = &t4 - &t5; // 4 U_P W_P

    let t7 = &t0 * &t3; // (U_P + W_P) (U_Q - W_Q) = U_P U_Q + W_P U_Q - U_P W_Q - W_P W_Q
    let t8 = &t1 * &t2; // (U_P - W_P) (U_Q + W_Q) = U_P U_Q - W_P U_Q + U_P W_Q - W_P W_Q

    let t9 = &t7 + &t8; // 2 (U_P U_Q - W_P W_Q)
    let t10 = &t7 - &t8; // 2 (W_P U_Q - U_P W_Q)

    let t11 = t9.squared(); // 4 (U_P U_Q - W_P W_Q)^2
    let t12 = t10.squared(); // 4 (W_P U_Q - U_P W_Q)^2

    let t13 = &FieldElement::APLUS2_OVER_FOUR * &t6; // (A + 2) U_P U_Q

    let t14 = &t4 * &t5; // ((U_P + W_P)(U_P - W_P))^2 = (U_P^2 - W_P^2)^2
    let t15 = &t13 + &t5; // (U_P - W_P)^2 + (A + 2) U_P W_P

    let t16 = &t6 * &t15; // 4 (U_P W_P) ((U_P - W_P)^2 + (A + 2) U_P W_P)

    let t17 = affine_PmQ * &t12; // U_D * 4 (W_P U_Q - U_P W_Q)^2
    let t18 = t11; // W_D * 4 (U_P U_Q - W_P W_Q)^2

    P.U = t14; // U_{P'} = (U_P + W_P)^2 (U_P - W_P)^2
    P.W = t16; // W_{P'} = (4 U_P W_P) ((U_P - W_P)^2 + ((A + 2)/4) 4 U_P W_P)
    Q.U = t18; // U_{Q'} = W_D * 4 (U_P U_Q - W_P W_Q)^2
    Q.W = t17; // W_{Q'} = U_D * 4 (W_P U_Q - U_P W_Q)^2
}

/// Multiply this `MontgomeryPoint` by a `Scalar`.
impl<'a, 'b> Mul<&'b Scalar> for &'a MontgomeryPoint {
    type Output = MontgomeryPoint;

    /// Given `self` \\( = u\_0(P) \\), and a `Scalar` \\(n\\), return \\( u\_0([n]P) \\).
    fn mul(self, scalar: &'b Scalar) -> MontgomeryPoint {
        // Algorithm 8 of Costello-Smith 2017
        let affine_u = self.0;
        let mut x0 = ProjectivePoint::neutral_element();
        let mut x1 = ProjectivePoint {
            U: affine_u,
            W: FieldElement::ONE,
        };

        let bits: [i8; 256] = scalar.bits();

        for i in (0..255).rev() {
            let choice: u8 = (bits[i + 1] ^ bits[i]) as u8;
            debug_assert!(choice == 0 || choice == 1);

            ProjectivePoint::conditional_swap(&mut x0, &mut x1, choice.into());
            differential_add_and_double(&mut x0, &mut x1, &affine_u);
        }
        ProjectivePoint::conditional_swap(&mut x0, &mut x1, Choice::from(bits[0] as u8));

        x0.to_affine()
    }

    ///// Given `self` \\( = u\_0(P) \\), and a `Scalar` \\(n\\), return \\( u\_0([n]P) \\).
    //fn mul(self, scalar: &'b Scalar) -> MontgomeryPoint {
    //    // Algorithm 8 of Costello-Smith 2017
    //    let affine_u = self.0;
    //    let mut x0 = ProjectivePoint::neutral_element();
    //    let mut x1 = ProjectivePoint {
    //        U: affine_u,
    //        W: FieldElement::ONE,
    //    };

    //    // TODO(really!!): check if the bits wanted here do actually correspond
    //    // with the construction copy-pasted out of edwards.rs
    //    //
    //    let bits: [i8; 256] = scalar.bits();

    //    for i in (0..255).rev() {
    //        let choice = (((scalar.0[i / 8] >> (i & 7)) & 1) as u8).into();
    //        ProjectivePoint::conditional_swap(&mut x0, &mut x1, choice);
    //        differential_add_and_double(&mut x0, &mut x1, &affine_u);
    //    }
    //    ProjectivePoint::conditional_swap(&mut x0, &mut x1, Choice::from((scalar.0[0] & 1) as u8));

    //    x0.to_affine()
    //}
}

impl<'b> MulAssign<&'b Scalar> for MontgomeryPoint {
    fn mul_assign(&mut self, scalar: &'b Scalar) {
        *self = (self as &MontgomeryPoint) * scalar;
    }
}

impl<'a, 'b> Mul<&'b MontgomeryPoint> for &'a Scalar {
    type Output = MontgomeryPoint;

    fn mul(self, point: &'b MontgomeryPoint) -> MontgomeryPoint {
        point * self
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn to_edwards() {
        let edwards_basepoint = crate::edwards::EdwardsPoint::basepoint();
        let montgomery_basepoint = MontgomeryPoint::basepoint();

        assert_eq!(
            edwards_basepoint,
            montgomery_basepoint.to_edwards(0).unwrap()
        );

        let scalar = Scalar::from(123456);
        assert_eq!(
            &scalar * &edwards_basepoint,
            (&scalar * &montgomery_basepoint).to_edwards(1).unwrap()
        );
    }
}
