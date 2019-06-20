use crate::field::{FieldElement, D2};
// TODO: use struct with names X,Y,Z,T here?
type CurveCoordinates = [FieldElement; 4];

#[derive(Clone,Debug)]
pub struct CurvePoint(CurveCoordinates);

type PackedPoint = [u8; 32];

// _121665 = {0xDB41,1},
// D = {0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203},
// D2 = {0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406},
// I = {0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83};

// static D2: FieldElement = FieldElement([0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406]);

use core::ops::Add;
impl<'a, 'b> Add<&'b CurvePoint> for &'a CurvePoint {
    type Output = CurvePoint;

    fn add(self, other: &'b CurvePoint) -> CurvePoint {

        let p = &self.0;
        let q = &other.0;

        let a = &p[1] - &p[0];
        let t = &q[1] - &q[0];
        let a = a * &t;        // A <- (Y1 - X1)(Y2 - X2)

        let b = &p[0] + &p[1];
        let t = &q[0] + &q[1];
        let b = b * &t;        // B <- (Y1 + X1)*(Y2 + X2)

        let c = &p[3] * &q[3];
        let c = c * &D2;       // C <- k*T1*T2  with k = 2d' =

        let d = &p[2] * &q[2];
        let d = &d + &d;       // D <- 2*Z1*Z2

        let e = &b - &a;
        let f = &d - &c;
        let g = &d + &c;
        let h = &b + &a;

        let coordinates: CurveCoordinates = [
            &e * &f,
            &h * &g,
            &g * &f,
            &e * &h,
        ];

        CurvePoint(coordinates)
    }
}

pub fn conditional_swap(p: &mut CurvePoint, q: &mut CurvePoint, b: i64) {
    for (pi, qi) in p.0.iter_mut().zip(q.0.iter_mut()) {
        crate::field::conditional_swap(pi, qi, b);
    }
}

// "freeze and store curve point"
pub fn pack_point(p: &CurvePoint) -> PackedPoint {
    let zi = crate::field::invert(&p.0[2]); // inverse of Z-coordinate
    let tx = &p.0[0] * &zi;
    let ty = &p.0[1] * &zi;
    let mut r = crate::field::freeze_to_le_bytes(&ty);
    r[31] ^= crate::field::parity(&tx) << 7;

    r
}

fn scalar_multiple_of_point(scalar: &[u8; 32], q: &CurvePoint) -> CurvePoint {
    let mut p = CurvePoint([
        crate::field::ZERO.clone(),
        crate::field::ONE.clone(),
        crate::field::ONE.clone(),
        crate::field::ZERO.clone(),
    ]);

    let mut q = q.clone();

    for i in (0..=255).rev() {
        let b = ((scalar[i / 8] >> (i & 7)) & 1) as i64;
        conditional_swap(&mut p, &mut q, b);
        // q = add(q, p);
        // p = add(p, p);
        q = &q + &p;
        p = &p + &p;
        conditional_swap(&mut p, &mut q, b);
    }

    p
}

pub fn scalar_multiple_of_base_point(scalar: &[u8; 32]) -> CurvePoint {
    let base = CurvePoint([
         crate::field::X.clone(),
         crate::field::Y.clone(),
         crate::field::ONE.clone(),
         &crate::field::X * &crate::field::Y,
    ]);

    scalar_multiple_of_point(scalar, &base)
}
