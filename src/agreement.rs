//! 99.9% cribbed from x25519-dalek

use crate::{
    constants::SECRETKEY_SEED_LENGTH,
    field::{
        FieldImplementation as _,
        FieldElement,
    },
    montgomery::MontgomeryPoint,
    scalar::Scalar,
};

#[derive(PartialEq, Eq, /*Hash,*/ Copy, Clone, Debug)]
pub struct PublicKey(pub(crate) MontgomeryPoint);

// #[derive(Zeroize)]
// #[zeroize(drop)]
#[derive(Clone/*, Zeroize*/)]
pub struct SecretKey(pub(crate) Scalar);

/// The result of a Diffie-Hellman key exchange.
///
/// Each party computes this using their [`SecretKey`] and their counterparty's [`PublicKey`].
// #[derive(Zeroize)]
// #[zeroize(drop)]
pub struct SharedSecret(pub(crate) MontgomeryPoint);

impl From<[u8; 32]> for PublicKey {
    /// Given a byte array, construct a x25519 `PublicKey`.
    fn from(bytes: [u8; 32]) -> PublicKey {
        PublicKey(MontgomeryPoint(FieldElement::from_bytes(&bytes).unwrap()))
    }
}

impl PublicKey {
    /// Convert this public key to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    // /// View this public key as a byte array.
    // #[inline]
    // pub fn as_bytes(&self) -> &[u8; 32] {
    //     self.0.as_bytes()
    // }
}

impl SecretKey {
    /// Perform a Diffie-Hellman key agreement between `self` and
    /// `their_public` key to produce a `SharedSecret`.
    pub fn agree(&self, their_public: &PublicKey) -> SharedSecret {
        SharedSecret(&self.0 * &their_public.0)
    }

    pub fn from_seed(seed: &[u8; SECRETKEY_SEED_LENGTH]) -> Self {
        Self(clamp_scalar(seed.clone()))
    }

    /// Extract this key's bytes for serialization.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// "Decode" a scalar from a 32-byte array.
///
/// By "decode" here, what is really meant is applying key clamping by twiddling
/// some bits.
///
/// # Returns
///
/// A `Scalar`.
fn clamp_scalar(mut scalar: [u8; 32]) -> Scalar {
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;

    scalar_from_bits(scalar)
}

/// Construct a `Scalar` from the low 255 bits of a 256-bit integer.
///
/// This function is intended for applications like X25519 which
/// require specific bit-patterns when performing scalar
/// multiplication.
pub const fn scalar_from_bits(bytes: [u8; 32]) -> Scalar {
    let mut s = Scalar(bytes);
    // Ensure that s < 2^255 by masking the high bit
    s.0[31] &= 0b0111_1111;

    s
}

#[test]
fn direct_agreement() {
    let seed1: [u8; 32] = [
        0x98, 0xa7, 0x02, 0x22, 0xf0, 0xb8, 0x12, 0x1a,
        0xa9, 0xd3, 0x0f, 0x81, 0x3d, 0x68, 0x3f, 0x80,
        0x9e, 0x46, 0x2b, 0x46, 0x9c, 0x7f, 0xf8, 0x76,
        0x39, 0x49, 0x9b, 0xb9, 0x4e, 0x6d, 0xae, 0x41,
    ];

    let seed2: [u8; 32] = [
        0x31, 0xf8, 0x50, 0x42, 0x46, 0x3c, 0x2a, 0x35,
        0x5a, 0x20, 0x03, 0xd0, 0x62, 0xad, 0xf5, 0xaa,
        0xa1, 0x0b, 0x8c, 0x61, 0xe6, 0x36, 0x06, 0x2a,
        0xaa, 0xd1, 0x1c, 0x2a, 0x26, 0x08, 0x34, 0x06,
    ];

    let sk1 = SecretKey::from_seed(&seed1);
    let sk2 = SecretKey::from_seed(&seed2);

    let pk1 = PublicKey(&sk1.0 * &MontgomeryPoint::basepoint());
    let pk2 = PublicKey(&sk2.0 * &MontgomeryPoint::basepoint());

    let shared1 = sk1.agree(&pk2);
    let shared2 = sk2.agree(&pk1);

    assert_eq!(shared1.0, shared2.0);

}
