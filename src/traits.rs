use core::ops::{
    Add,
    AddAssign,
    Neg,
};

// pub trait FieldImplementation
// where
//     for<'a, 'b> &'a Self: Add<&'b Self>,
//     for<'a> &'a Self: Neg,
// {
//     type Limbs;

//     // TODO: maybe have statics outside,
//     // and demand functions returning &'static Self instead?
//     const ZERO: Self::Limbs;
//     const ONE: Self::Limbs;
//     const ED25519_BASEPOINT_X: Self::Limbs;
//     const ED25519_BASEPOINT_Y: Self::Limbs;
// }

pub trait FieldImplementation
where
    for<'a, 'b> &'a Self: Add<&'b Self>,
    for<'a, 'b> &'a mut Self: AddAssign<&'b Self>,
    for<'a> &'a Self: Neg<Output = Self>,
{
    type Limbs;

    // TODO: maybe have statics outside,
    // and demand functions returning &'static Self instead?
    const ZERO: Self;
    // const ONE: Self;
    // const ED25519_BASEPOINT_X: Self;
    // const ED25519_BASEPOINT_Y: Self;

    /// swap p and q iff b is true, in constant time
    // TODO: would be great to mark this with an attribute
    // like #[constant_time], and have this picked up by a testing
    // harness, that actually tests this!
    pub fn conditional_swap(p: &mut FieldElement, q: &mut FieldElement, b: bool);

}

type HaaseLimbs = [u8; 32];
struct HaaseFieldElement(pub(crate) HaaseLimbs);
// struct SchoolbookFieldElement(pub(crate) HaaseLimbs);

impl<'a> Neg for &'a HaaseFieldElement {
    type Output = HaaseFieldElement;

    fn neg(self) -> Self::Output {
        // obvsly incorrect return value
        HaaseFieldElement([0u8; 32])
    }

}
// impl FieldImplementation for HaaseFieldElement {
//     const ZERO: Self = [0u8; 32];
// }
// struct FieldElement<Limbs: FieldImplementation>(pub(crate) L);
