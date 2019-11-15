use core::{
    ops::{
        Add,
        Sub,
        Mul,
    }
};

// use subtle::{
//     ConditionallySelectable,
//     Choice,
// };

use crate::field::FieldImplementation;
use crate::scalar::Scalar;

// #[derive(Clone,Debug)]
// pub struct CurvePoint<FieldElement>
// where FieldElement: FieldImplementation {
//     data: [FieldElement; 4]
// }
pub struct CurvePoint<FieldElement> (
    [FieldElement; 4]
);

// impl<'a, 'b, FieldElement> Mul<&'b CurvePoint<FieldElement>> for &'a Scalar
// where
//     FieldElement: FieldImplementation,
//     // for<'u, 'v> &'u CurvePoint<FieldElement>: Add<&'v CurvePoint<FieldElement>, Output = CurvePoint<FieldElement>>,
//     for<'u, 'v> &'u FieldElement: Add<&'v FieldElement, Output=FieldElement>,
//     for<'u, 'v> &'u FieldElement: Sub<&'v FieldElement, Output=FieldElement>,
//     for<'u, 'v> &'u FieldElement: Mul<&'v FieldElement, Output=FieldElement>,
// {
//     type Output = CurvePoint<FieldElement>;

//     fn mul(self, point: &'b CurvePoint<FieldElement>) -> CurvePoint<FieldElement> {
//         let mut p = CurvePoint([
//             FieldElement::ZERO.clone(),
//             FieldElement::ONE.clone(),
//             FieldElement::ONE.clone(),
//             FieldElement::ZERO.clone(),
//         ]);

//         // let mut q = point.clone();
//         // let scalar = self;

//         // for i in (0..=255).rev() {
//         //     let b = ((scalar.0[i / 8] >> (i & 7)) & 1) as i64;
//         //     // CurvePoint::conditional_swap(&mut p, &mut q, b);
//         //     // p.conditional_swap(&mut q, b != 0);
//         //     // q = add(q, p);
//         //     // p = add(p, p);

//         //     // q = &q + &p;
//         //     // p = &p + &p;

//         //     // CurvePoint::conditional_swap(&mut p, &mut q, b);
//         //     // p.conditional_swap(&mut q, b != 0);
//         // }

//         p
//     }
// }

impl<'a, 'b, FieldElement> Mul<&'b Scalar> for &'a CurvePoint<FieldElement>
where
    FieldElement: FieldImplementation,
{
    type Output = CurvePoint<FieldElement>;

    fn mul(self, other: &'b Scalar) -> CurvePoint<FieldElement> {
        let mut p = CurvePoint::<FieldElement>([
            FieldElement::ZERO.clone(),
            FieldElement::ONE.clone(),
            FieldElement::ONE.clone(),
            FieldElement::ZERO.clone(),
        ]);
        p
    }
}

impl<'a, 'b, FieldElement> Add<&'b CurvePoint<FieldElement>> for &'a CurvePoint<FieldElement>
where
    FieldElement: FieldImplementation,
    // TODO: really not possibly to pick this up from FieldImplementation's type??
    for<'u, 'v> &'u FieldElement: Add<&'v FieldElement, Output=FieldElement>,
    for<'u, 'v> &'u FieldElement: Sub<&'v FieldElement, Output=FieldElement>,
    for<'u, 'v> &'u FieldElement: Mul<&'v FieldElement, Output=FieldElement>,
{

    type Output = CurvePoint<FieldElement>;

    fn add(self, other: &'b CurvePoint<FieldElement>) -> Self::Output {

        let p = self.0;
        let q = &other.0;

        let a = &p[1] - &p[0];
        let t = &q[1] - &q[0];
        let a = &a * &t;        // A <- (Y1 - X1)(Y2 - X2)
        // let a = &(&p[1] - &p[0]) * &(&q[1] - &q[0]);

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

#[cfg(test)]
mod tests {

    use crate::field::tweetnacl::FieldElement;
    use super::CurvePoint;
    use crate::Scalar;

    #[test]
    fn test_something() {
        use crate::field::FieldImplementation;
        let p = CurvePoint([
            FieldElement::ZERO.clone(),
            FieldElement::ONE.clone(),
            FieldElement::ONE.clone(),
            FieldElement::ZERO.clone(),
        ]);

        let p1 = &p + &p;
        let two = Scalar::from_bytes(&[
            2u8, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]);

        assert_eq!(p.0[0].0, p1.0[0].0);
        // assert_eq!(p.0[1].0, p1.0[1].0);
        // assert_eq!(p.0[2].0, p1.0[2].0);
        assert_eq!(p.0[3].0, p1.0[3].0);

        // let p2 = &two * &p;
        // let p2 = &p * &two;

        // assert_eq!(p1.0[0].0, p2.0[0].0);
        // assert_eq!(p1.0[1].0, p2.0[1].0);
        // assert_eq!(p1.0[2].0, p2.0[2].0);
        // assert_eq!(p1.0[3].0, p2.0[3].0);
        // let one = FieldElement::ONE;
        // let two = &one + &one;

        // let expected = FieldElement([
        //     2, 0, 0, 0,
        //     0, 0, 0, 0,
        //     0, 0, 0, 0,
        //     0, 0, 0, 0,
        // ]);

        // // TODO: Implement PartialEq (hopefully in constant time!)
        // assert_eq!(two.0, expected.0);

    }
}
