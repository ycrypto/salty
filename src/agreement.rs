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

impl SharedSecret {
    #[inline]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
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

    // this is actually redundant, it does `s.0[31] &= 0b0111_1111;`,
    // i.e., set highest bit to zero, enforcing s < 2^255
    // scalar_from_bits(scalar)

    Scalar(scalar)
}

/// Construct a `Scalar` from the low 255 bits of a 256-bit integer.
///
/// This function is intended for applications like X25519 which
/// require specific bit-patterns when performing scalar
/// multiplication.
pub fn make_255_bit(bytes: [u8; 32]) -> FieldElement {
    let mut bytes = bytes;
    // Ensure that s < 2^255 by masking the high bit
    bytes[31] &= 0b0111_1111;

    FieldElement::from_unreduced_bytes(&bytes)
}

/// Implementations:
/// - MUST mask highest bit in input_u
/// - MUST accept non-canonical input_u, reduce modulo base field
///
/// <https://tools.ietf.org/html/rfc7748#section-5>
pub fn x25519(scalar: [u8; 32], input_u: [u8; 32]) -> [u8; 32] {
    let scalar = clamp_scalar(scalar);
    let secret_key = SecretKey(scalar);

    let input_u = make_255_bit(input_u);
    let input_point = MontgomeryPoint(input_u);
    let public_key = PublicKey(input_point);

    let agreed_secret = secret_key.agree(&public_key);
    let raw_agreed_secret = agreed_secret.0.to_bytes();
    raw_agreed_secret
}

#[cfg(test)]
mod tests {
    use core::convert::TryInto;
    use super::*;

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

    fn load_bytes(little_endian_hex_digits: &str) -> [u8; 32] {
        hex::decode(little_endian_hex_digits).unwrap().try_into().unwrap()
    }

    fn rfc_7748_x25519_expected_outputs(
        input_scalar: &str,
        input_u: &str,
        output_u: &str,
    ) {
        let scalar = clamp_scalar(load_bytes(input_scalar));
        let secret_key = SecretKey(scalar);

        // see above x25519 function...
        let input_u = make_255_bit(load_bytes(input_u));
        let input_point = MontgomeryPoint(input_u);
        let public_key = PublicKey(input_point);

        let agreed_secret = secret_key.agree(&public_key);

        let output_u = FieldElement::from_bytes(&load_bytes(output_u)).unwrap();
        let output_point = MontgomeryPoint(output_u);

        assert_eq!(agreed_secret.0, output_point);
    }

    #[test]
    fn rfc_7748_x25519_vector_1() {
        rfc_7748_x25519_expected_outputs(
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
        );
    }

    #[test]
    fn rfc_7748_x25519_vector_2() {
        rfc_7748_x25519_expected_outputs(
            "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
            // this input u coordinate is not "canonical"
            "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
        );
    }

    #[test]
    fn rfc_7748_x25519_iterated() {
        let s = "0900000000000000000000000000000000000000000000000000000000000000";
        let k = load_bytes(s);
        let mut u = load_bytes(s);

        // once
        let mut k = x25519(k, u);
        assert_eq!(hex::encode(k), "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");

        // 1_000 times
        let mut result = [0u8; 32];
        (0..999usize).for_each(|_| {
            result = x25519(k, u);
            u = k;
            k = result;
        });
        assert_eq!(hex::encode(k), "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");

        // #[cfg(feature = "very-long-x25519-test")] {
        //     // 1_000_000 times
        //     (0..999_000usize).for_each(|_| {
        //         result = x25519(k, u);
        //         u = k;
        //         k = result;
        //     });
        //     assert_eq!(hex::encode(k), "7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424");
        // }
    }

}
