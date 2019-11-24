//!
//! the non-optimized arithmetic of the base field
//! of Curve25519, Z/lZ where l = 2^255 - 19
//!
//! this is what we will replace with Haase's assembly code in v0.3.0

// NB: This is no longer used

type FieldElementBuffer = [i64; 16];  // or `FieldElementAsLimbs`?

/// Elements of the base field of the curve
#[derive(Clone,Debug,Default)]
pub struct FieldElement(FieldElementBuffer);

// type CanonicalFieldElement = [u8; 32];

pub static D2: FieldElement = FieldElement([
    0xf159, 0x26b2, 0x9b94, 0xebd6,
    0xb156, 0x8283, 0x149a, 0x00e0,
    0xd130, 0xeef3, 0x80f2, 0x198e,
    0xfce7, 0x56df, 0xd9dc, 0x2406,
]);
/// The additive neutral element of the base field
pub static ZERO: FieldElement = FieldElement([
    0, 0, 0, 0,
    0, 0, 0, 0,
    0, 0, 0, 0,
    0, 0, 0, 0,
]);

/// The additive generator of the base field
pub static ONE: FieldElement = FieldElement([
    1, 0, 0, 0,
    0, 0, 0, 0,
    0, 0, 0, 0,
    0, 0, 0, 0,
]);

pub static X: FieldElement = FieldElement([
    0xd51a, 0x8f25, 0x2d60, 0xc956,
    0xa7b2, 0x9525, 0xc760, 0x692c,
    0xdc5c, 0xfdd6, 0xe231, 0xc0a4,
    0x53fe, 0xcd6e, 0x36d3, 0x2169,
]);

pub static Y: FieldElement = FieldElement([
    0x6658, 0x6666, 0x6666, 0x6666,
    0x6666, 0x6666, 0x6666, 0x6666,
    0x6666, 0x6666, 0x6666, 0x6666,
    0x6666, 0x6666, 0x6666, 0x6666,
]);


// impl Clone for FieldElement {
//     fn clone(&self) -> Self {
//         FieldElement(self.0.clone())
//     }
// }

use core::ops::Add;
/// Aha addition!
impl<'a, 'b> Add<&'b FieldElement> for &'a FieldElement {
    type Output = FieldElement;

    // TODO: TweetNaCl doesn't do any reduction here, why not?
    /// Addition of field elements
    fn add(self, other: &'b FieldElement) -> FieldElement {
        let mut sum: FieldElementBuffer = Default::default();
        for (s, (x, y)) in sum.iter_mut().zip(self.0.iter().zip(other.0.iter())) {
            *s = x + y
        }
        FieldElement(sum)
    }
}

use core::ops::Sub;
impl<'a, 'b> Sub<&'b FieldElement> for &'a FieldElement {
    type Output = FieldElement;

    // TODO: TweetNaCl doesn't do any reduction here, why not?
    /// Subtraction of field elements
    fn sub(self, other: &'b FieldElement) -> FieldElement {
        let mut sum: FieldElementBuffer = Default::default();
        for (s, (x, y)) in sum.iter_mut().zip(self.0.iter().zip(other.0.iter())) {
            *s = x - y
        }
        FieldElement(sum)
    }
}

// impl Sub<FieldElement> for FieldElement {
// }

// impl FieldElement {
//     fn reduce(&mut self) {

//     }
// }

fn reduce(fe: &mut FieldElement) {
    // TODO: multiplication calls this twice
    // What exactly are the guarantees here?
    // Why don't we do this twice if it's needed?
    for i in 0..16 {
        // add 2**16
        fe.0[i] += 1 << 16;
        // "carry" part, everything over radix 2**16
        let carry = fe.0[i] >> 16;

        // a) i < 15: add carry bit, subtract 1 to compensate addition of 2^16
        // --> o[i + 1] += c - 1  // add carry bit, subtract
        // b) i == 15: wraps around to index 0 via 2^256 = 38
        // --> o[0] += 38 * (c - 1)
        fe.0[(i + 1) * ((i < 15) as usize)] +=
            carry - 1 + 37 * (carry - 1) * ((i == 15) as i64);
        // get rid of carry bit
        // TODO: why not get rid of it immediately. kinda clearer
        fe.0[i] -= carry << 16;
    }
}

use core::ops::Mul;
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
        let mut product: FieldElementBuffer = Default::default();
        product.copy_from_slice(&mut pre_product[..16]);

        let mut fe = FieldElement(product);
        // normalize such that all limbs lie in [0, 2^16)
        // TODO: why twice? why is twice enough?
        reduce(&mut fe);
        reduce(&mut fe);

        fe
    }
}

// TODO: one way to avoid this is by using a macro.
// Is there anything nicer?
impl<'a> Mul<&'a FieldElement> for FieldElement {
    type Output = FieldElement;

    fn mul(self, other: &'a FieldElement) -> Self::Output {
        &self * other
    }
}

impl<'a> Mul<FieldElement> for &'a FieldElement {
    type Output = FieldElement;

    fn mul(self, other: FieldElement) -> Self::Output {
        self * &other
    }
}

// non-optimized, but showing off our new multiplication trait \o/
fn square(fe: &FieldElement) -> FieldElement {
    fe * fe
}

// something-something about generics vs function overloading
// fn square(fe: FieldElement) -> FieldElement {
//     fe * fe
// }

/// inversion as field element, building block of `core::ops::Div` trait impl
pub fn invert(fe: &FieldElement) -> FieldElement {
    // TODO: possibly assert! that fe != 0?

    // make our own private copy
    let mut inverse = fe.clone();

    // exponentiate with 2**255 - 21,
    // which by Fermat's little theorem is the same as inversion
    for i in (0..=253).rev() {
        inverse = square(&inverse); // eep...
        if i != 2 && i != 4 {
            inverse = inverse * fe;
        }
    }

    inverse
}

use core::ops::Div;
impl<'a, 'b> Div<&'b FieldElement> for &'a FieldElement {
    type Output = FieldElement;

    fn div(self, other: &'b FieldElement) -> FieldElement {
        self * invert(other)
    }
}

/// constant-time swap of field elements
pub fn conditional_swap(p: &mut FieldElement, q: &mut FieldElement, b: i64) {
    // TODO: change signature to `b: bool`?
    //
    // swap p and q iff b (is true)
    //
    // a) b = 0
    // --> mask = 0, t = 0, p and q remain as they were
    //
    // b) b = 1
    // --> mask = 0xFFFFFFFF, t = p[i]^q[i],
    // so p[i] <- p[i]^p[i]^q[i] = q[i] and similarly
    // q[i] <- p[i], so they swap
    //
    // see test_bit_fiddling below for "verification"

    let mask: i64 = !(b - 1);
    for (pi, qi) in p.0.iter_mut().zip(q.0.iter_mut()) {
        let t = mask & (*pi ^ *qi);
        *pi ^= t;
        *qi ^= t;
    }
}
// fn conditional_move(r: &mut FieldElement, x: &FieldElement, b: u8) {
//     // for (ri, xi) in r.iter_mut().zip(x.iter()) {
//     //     let mask: i32 = b as _;
//     //     *ri ^= mask & (xi ^ *ri);
//     // }
// }

// called `unpack225519` in TweetNaCl
// described as "load integer mod 2**255 - 19 in TweetNaCl paper
pub fn from_le_bytes(bytes: &[u8; 32]) -> FieldElement {
    let mut limbs: FieldElementBuffer = Default::default();
    for i in 0..16 {
        limbs[i] = (bytes[2 * i] as i64) + (bytes[2 * i + 1] as i64) << 8;
    }

    // some kind of safety check
    limbs[15] &= 0x7fff;

    FieldElement(limbs)
}

// called `pack255169` in TweetNaCl
// described as "freeze integer mod 2**255 - 19 and store" in TweetNaCl paper
// TODO: figure out what this actually does and check the transliteration is correct...
pub fn freeze_to_le_bytes(fe: &FieldElement) -> [u8; 32] {
    // make our own private copy
    let mut fe = fe.clone();

    // three times' the charm??
    // TODO: figure out why :)
    reduce(&mut fe);
    reduce(&mut fe);
    reduce(&mut fe);

    // let m_buf: FieldElementBuffer = Default::default();
    // let mut m: FieldElement = FieldElement(m_buf);
    let mut m: FieldElementBuffer = Default::default();
    for _j in 0..2 {
        m[0] = fe.0[0] - 0xffed;
        for i in 1..15 {
            m[i] = fe.0[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }

        m[15] = fe.0[15] - 0x7fff - ((m[14] >> 16) & 1);
        let b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        conditional_swap(&mut fe, &mut FieldElement(m), 1 - b);
    }

    let mut bytes: [u8; 32] = Default::default();
    for i in 0..16 {
        bytes[2 * i] = fe.0[i] as u8; //& 0xff;
        bytes[2 * i + 1] = (fe.0[i] >> 8) as u8;
    }

    bytes
}

/// parity of integer modulo 2**255 - 19
pub fn parity(a: &FieldElement) -> u8 {
    let d = freeze_to_le_bytes(a);
    d[0] & 1
}
