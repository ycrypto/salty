// TODO: decide whether to move this to `crate::curve::edwards`

use crate::field::{FieldElement, D2};
// TODO: use struct with names X,Y,Z,T here?
type CurveCoordinates = [FieldElement; 4];

/// Since elliptic curve points are an abelian group,
/// we have a bunch of associated operations :)
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

        // let a = &p[1] - &p[0];
        // let t = &q[1] - &q[0];
        // let a = a * &t;        // A <- (Y1 - X1)(Y2 - X2)
        let a = &(&p[1] - &p[0]) * &(&q[1] - &q[0]);

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
    // "scalar" bytes are interpreted as little-endian integer
    // TODO: use a proper type
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

// TODO: move to `scalar` submodule?
pub static L: [u64; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0x10,
];

// called `modL` in TweetNaCl
pub fn modulo_group_order(x: &mut [i64; 64]) -> [u8; 32] {
    for i in (32..=63).rev() {
        let mut carry: i64 = 0;
        for j in (i - 32)..(i - 12) {
            // x[j] += carry - 16 * x[i] * L[j - (i - 32)];
            // C code doesn't care about u64 vs i64...
            x[j] += carry - 16 * x[i] * L[j - (i - 32)] as i64;
            carry = (x[j] + 128) >> 8;
            x[j] -= carry << 8;
        }
        // x[j] += carry;  // C code uses out-of-scope variable j
        x[i - 12] += carry;
        x[i] = 0;
    }

    let mut carry: i64 = 0;
    for j in 0..32 {
        // x[j] += carry - (x[31] >> 4) * L[j];
        x[j] += carry - (x[31] >> 4) * L[j] as i64;
        carry = x[j] >> 8;
        x[j] &= 0xff;
    }

    for j in 0..32 {
        // x[j] -= carry * L[j];
        x[j] -= carry * L[j] as i64;
    }

    let mut r: [u8; 32] = Default::default();
    for i in 0 ..32 {
        x[i + 1] += x[i] >> 8;
        // r[i] = x[i] & 0xff;
        r[i] = ((x[i] as u64) & 0xff) as u8;
    }

    r

}

// TODO: clean this up obvsly
pub fn modulo_group_order_u8s(x: &[u8; 64]) -> [u8; 32] {
    let mut x64: [i64; 64] = [0; 64];//Default::default();
    for i in 0..64 {
        x64[i] = x[i] as i64;
    }

    modulo_group_order(&mut x64)
}
