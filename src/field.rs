use core::{
    // cmp::PartialEq,
    fmt::Debug,
    ops::{
        Add,
        AddAssign,
        Neg,
        Sub,
        SubAssign,
        Mul,
        MulAssign,
    },
};

use subtle::{
    ConstantTimeEq,
    ConditionallySelectable,
};

/// Requirements on an implementation of the base field.
///
/// There are *many* ways to implement field arithmetic in
/// the base field of integers modulo 2**255 - 19.
///
/// This trait specifies our requirements, such that end users
/// can experiment with their own ideas.
///
/// This crate, as of now, offers two implementations:
/// - TweetNaCl: a transliteration of the TweetNaCl code to Rust
/// - Haase: a fast implementation in assembly, due to Bjoern Haase
/// - Schoolbook: our own attempt at a fast yet readable implementation
///
/// TODO: Want to implement PartialEq for all implementations of
/// this trait, using `.to_bytes()` and `subtle::ConstantTimeEq`. How?
///
/// TODO: Due to "coherence", we can't (I believe) implement, e.g.
/// PartialEq in constant-time, using subtle::ConstantTimeEq and
/// the required (assumed constant-time) method `.to_bytes()`.
/// Similarly, we can't just required `AddAssign` and implement `Add`
/// ourselves. It would be nice to improve this somehow.
pub trait FieldImplementation
where
    // Self: Sized,
    // Self: Clone,
    Self: Copy,
    // Self: !Copy,  // not sure - curve25519-dalek uses implicit copies, do we want this?

    Self: Debug,
    // Self: Default,  // would want this to return zero I think

    // for<'a, 'b> &'a Self: PartialEq
    Self: ConditionallySelectable,
    for<'b> Self: ConstantTimeEq,

    for<'a, 'b> &'a Self: Add<&'b Self, Output = Self>,
    for<'b> Self: AddAssign<&'b Self>,

    for<'a> &'a Self: Neg<Output = Self>,

    for<'a, 'b> &'a Self: Sub<&'b Self, Output = Self>,
    for<'b> Self: SubAssign<&'b Self>,

    for<'a, 'b> &'a Self: Mul<&'b Self, Output = Self>,
    for<'b> Self: MulAssign<&'b Self>,
    // for<'a> &'a Self: Neg<Output = Self>,
{
    /// Internal representation as limbs
    type Limbs;

    // TODO: maybe have statics outside,
    // and demand functions returning &'static Self instead?
    const ZERO: Self;
    const ONE: Self;
    const D2: Self;
    const BASEPOINT_X: Self;
    const BASEPOINT_Y: Self;

    // /// swap p and q iff b is true, in constant time
    // // TODO: would be great to mark this with an attribute
    // // like #[constant_time], and have this picked up by a testing
    // // harness, that actually tests this!
    // pub fn conditional_swap(p: &mut FieldElement, q: &mut FieldElement, b: bool);

    // fn reduce(&mut self);

    // /// We don't want to introduce Copy on all our types,
    // /// and be indirect about swap, so we do this ourselves
    // fn conditional_swap(&mut self, other: &mut Self, b: bool);

    /// to canonical representation as little-endian bytes
    fn to_bytes(&self) -> [u8; 32];

    /// construct from canonical representation as little-endian bytes
    fn from_bytes_unchecked(bytes: &[u8; 32]) -> Self;

    /// construct from canonical representation as little-endian bytes, with validity check
    fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let unchecked = Self::from_bytes_unchecked(bytes);
        let canonical_representation = unchecked.to_bytes();
        if bool::from(bytes.ct_eq(&canonical_representation)) {
            Some(unchecked)
        } else {
            None
        }
    }

    /// parity of field element, viewed as integer modulo 2**255 - 19
    fn parity(&self) -> u8 {
        let d = self.to_bytes();
        d[0] & 1
    }

    // /// while potentially faster implementation of `&self * &self` may implemented
    // /// by a specific type, we offer a default implementation
    // fn squared(&self) -> Self {
    //     self * self
    // }
}

// impl PartialEq for FieldImplementation {
// }

#[cfg(feature = "tweetnacl")]
pub mod tweetnacl;
#[cfg(feature = "tweetnacl")]
pub use tweetnacl::{Limbs, FieldElement};

