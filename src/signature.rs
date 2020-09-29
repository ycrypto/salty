use core::convert::TryFrom;

#[cfg(feature = "cose")]
pub use cosey::Ed25519PublicKey as CosePublicKey;

use crate::{
    Error,
    Result,
    constants::{
        SECRETKEY_SEED_LENGTH,
        SECRETKEY_SCALAR_LENGTH,
        SECRETKEY_NONCE_LENGTH,

        SHA512_LENGTH,
        PUBLICKEY_SERIALIZED_LENGTH,
        SIGNATURE_SERIALIZED_LENGTH,
    },
    curve::{
        CurvePoint,
        CompressedY,
    },
    hash::Sha512,
    scalar::Scalar,
};

/// a secret key, consisting internally of the seed and
/// its expansion into a scalar and a "nonce".
pub struct SecretKey {
    #[allow(dead_code)]
    pub (crate) seed: [u8; SECRETKEY_SEED_LENGTH],
    pub (crate) scalar: Scalar,
    pub /*(crate)*/ nonce: [u8; SECRETKEY_NONCE_LENGTH],
}

/// a public key, consisting internally of both its defining
/// point (the secret scalar times the curve base point)
/// and the compression of that point.
#[derive(Clone,Debug,Default,PartialEq)]
pub struct PublicKey {
    #[allow(dead_code)]
    pub(crate) point: CurvePoint,
    pub compressed: CompressedY,
}

/// pair of secret and corresponding public keys
pub struct Keypair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

/// a signature: pair consisting of a curve point "R" in
/// compressed form and a scalar "s".
#[derive(Debug,Default,PartialEq)]
pub struct Signature {
    pub r: CompressedY,
    pub s: Scalar,
}

// impl core::cmp::PartialEq<Signature> for Signature {
//     fn eq(&self, other: &Self) -> bool {
//         for (l, r) in self.0.iter().zip(other.0.iter()) {
//             if l != r { return false; }
//         }
//         true
//     }
// }

impl Keypair {
    pub fn sign(&self, message: &[u8]) -> Signature {

        // R = rB, with r = H(nonce, M)
        let first_hash = Sha512::new()
            .updated(&self.secret.nonce)
            .updated(message)
            .finalize();

        let r: Scalar = Scalar::from_u512_le(&first_hash);
        #[allow(non_snake_case)]
        let R: CompressedY = (&r * &CurvePoint::basepoint()).compressed();


        // S = r + H(R, A, M)s (mod l), with A = sB the public key
        let second_hash = Sha512::new()
            .updated(&R.0)
            .updated(&self.public.compressed.0)
            .updated(message)
            .finalize();

        let h: Scalar = Scalar::from_u512_le(&second_hash);
        let s = &r.into() + &(&h.into() * &self.secret.scalar);

        Signature { r: R, s }
    }

    pub fn sign_with_context(&self, message: &[u8], context: &[u8])
    -> Signature {
        // By default, the context is an empty string.
        debug_assert!(context.len() <= 255, "The context must not be longer than 255 octets.");

        let first_hash = Sha512::new()
            // Ed25519ph parts
            .updated(b"SigEd25519 no Ed25519 collisions")
            .updated(&[0])
            // context parts
            .updated(&[context.len() as u8])
            .updated(context)
            // usual parts
            .updated(&self.secret.nonce)
            .updated(message)
            .finalize();

        // from here on, same as normal signing
        let r: Scalar = Scalar::from_u512_le(&first_hash);
        #[allow(non_snake_case)]
        let R: CompressedY = (&r * &CurvePoint::basepoint()).compressed();

        let second_hash = Sha512::new()
            // Ed25519ph parts
            .updated(b"SigEd25519 no Ed25519 collisions")
            .updated(&[0])
            // context parts
            .updated(&[context.len() as u8])
            .updated(context)
            // usual parts
            .updated(&R.0)
            .updated(&self.public.compressed.0)
            .updated(message)
            .finalize();

        let h: Scalar = Scalar::from_u512_le(&second_hash);
        let s = &r.into() + &(&h.into() * &self.secret.scalar);

        Signature { r: R, s }
    }

    pub fn sign_prehashed(&self, prehashed_message: &[u8; SHA512_LENGTH], context: Option<&[u8]>)
    -> Signature {
        // By default, the context is an empty string.
        let context: &[u8] = context.unwrap_or(b"");
        debug_assert!(context.len() <= 255, "The context must not be longer than 255 octets.");

        let first_hash = Sha512::new()
            // Ed25519ph parts
            .updated(b"SigEd25519 no Ed25519 collisions")
            .updated(&[1])
            // context parts
            .updated(&[context.len() as u8])
            .updated(context)
            // usual parts
            .updated(&self.secret.nonce)
            .updated(prehashed_message)
            .finalize();

        // from here on, same as normal signing
        let r: Scalar = Scalar::from_u512_le(&first_hash);
        #[allow(non_snake_case)]
        let R: CompressedY = (&r * &CurvePoint::basepoint()).compressed();

        let second_hash = Sha512::new()
            // Ed25519ph parts
            .updated(b"SigEd25519 no Ed25519 collisions")
            .updated(&[1])
            // context parts
            .updated(&[context.len() as u8])
            .updated(context)
            // usual parts
            .updated(&R.0)
            .updated(&self.public.compressed.0)
            .updated(prehashed_message)
            .finalize();

        let h: Scalar = Scalar::from_u512_le(&second_hash);
        let s = &r.into() + &(&h.into() * &self.secret.scalar);

        Signature { r: R, s }
    }
}

impl PublicKey {
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result {
        let hash = Sha512::new()
            .updated(&signature.r.0)
            .updated(&self.compressed.0)
            .updated(message)
            .finalize();

        let k: Scalar = Scalar::from_u512_le(&hash);

        #[allow(non_snake_case)]
        let minus_A = -&self.point;

        #[allow(non_snake_case)]
        let R: CurvePoint = &(&signature.s * &CurvePoint::basepoint()) + &(&k * &minus_A);

        if R.compressed() == signature.r {
            Ok(())
        } else {
            Err(Error::SignatureInvalid)
        }
    }

    pub fn verify_with_context(
        &self,
        message: &[u8],
        signature: &Signature,
        context: &[u8],
    ) -> Result {

        debug_assert!(context.len() <= 255, "The context must not be longer than 255 octets.");

        let hash = Sha512::new()
            // Ed25519ph parts
            .updated(b"SigEd25519 no Ed25519 collisions")
            .updated(&[0])
            // context parts
            .updated(&[context.len() as u8])
            .updated(context)
            // usual parts
            .updated(&signature.r.0)
            .updated(&self.compressed.0)
            .updated(message)
            .finalize();

        let k: Scalar = Scalar::from_u512_le(&hash);

        #[allow(non_snake_case)]
        let minus_A = -&self.point;

        #[allow(non_snake_case)]
        let R: CurvePoint = &(&signature.s * &CurvePoint::basepoint()) + &(&k * &minus_A);

        if R.compressed() == signature.r {
            Ok(())
        } else {
            Err(Error::SignatureInvalid)
        }
    }

    pub fn verify_prehashed(
        &self,
        prehashed_message: &[u8; SHA512_LENGTH],
        signature: &Signature,
        context: Option<&[u8]>,
    ) -> Result {

        // By default, the context is an empty string.
        let context: &[u8] = context.unwrap_or(b"");
        debug_assert!(context.len() <= 255, "The context must not be longer than 255 octets.");

        let hash = Sha512::new()
            // Ed25519ph parts
            .updated(b"SigEd25519 no Ed25519 collisions")
            .updated(&[1])
            // context parts
            .updated(&[context.len() as u8])
            .updated(context)
            // usual parts
            .updated(&signature.r.0)
            .updated(&self.compressed.0)
            .updated(prehashed_message)
            .finalize();

        let k: Scalar = Scalar::from_u512_le(&hash);

        #[allow(non_snake_case)]
        let minus_A = -&self.point;

        #[allow(non_snake_case)]
        let R: CurvePoint = &(&signature.s * &CurvePoint::basepoint()) + &(&k * &minus_A);

        if R.compressed() == signature.r {
            Ok(())
        } else {
            Err(Error::SignatureInvalid)
        }
    }

}

impl PublicKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.compressed.as_bytes()
    }
    pub fn to_bytes(&self) -> [u8; 32] {
        self.compressed.to_bytes()
    }
}

#[cfg(feature = "cose")]
impl Into<CosePublicKey> for PublicKey {
    fn into(self) -> CosePublicKey {
        CosePublicKey {
            x: cosey::Bytes::try_from_slice(&self.as_bytes()[..]).unwrap(),
        }
    }
}

#[cfg(feature = "cose")]
impl TryFrom<&CosePublicKey> for PublicKey {
    type Error = crate::Error;

    fn try_from(cose: &CosePublicKey) -> Result<PublicKey> {
        use core::convert::TryInto;
        let okp: &[u8; 32] = cose.x.as_ref().try_into().unwrap();
        Self::try_from(okp)
    }
}

impl From<&[u8; SECRETKEY_SEED_LENGTH]> for SecretKey {
    fn from(seed: &[u8; SECRETKEY_SEED_LENGTH]) -> SecretKey {

        let hash = Sha512::new()
            .updated(seed)
            .finalize();

        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(&hash[..SECRETKEY_SCALAR_LENGTH]);
        let mut scalar = Scalar(scalar_bytes);
        scalar.0[0] &= 248;
        scalar.0[31] &= 127;
        scalar.0[31] |= 64;

        let mut nonce = [0u8; SECRETKEY_NONCE_LENGTH];
        nonce.copy_from_slice(&hash[SECRETKEY_SCALAR_LENGTH..]);

        SecretKey { seed: seed.clone(), scalar, nonce }
    }
}

impl From<&SecretKey> for PublicKey {
    fn from(secret: &SecretKey) -> PublicKey {

        let point = &secret.scalar * &CurvePoint::basepoint();
        let compressed = point.compressed();

        PublicKey { point, compressed }
    }
}

impl TryFrom<&[u8; PUBLICKEY_SERIALIZED_LENGTH]> for PublicKey {
    type Error = crate::Error;

    fn try_from(bytes: &[u8; PUBLICKEY_SERIALIZED_LENGTH]) -> Result<PublicKey> {
        let compressed = CompressedY(bytes.clone());
        let point = compressed.decompressed()?;
        Ok(PublicKey { compressed, point } )
    }
}

impl From<&[u8; SECRETKEY_SEED_LENGTH]> for Keypair {
    fn from(seed: &[u8; SECRETKEY_SEED_LENGTH]) -> Keypair {
        let secret = SecretKey::from(seed);

        let public = PublicKey::from(&secret);

        Keypair { secret, public }
    }
}

impl From<&[u8; SIGNATURE_SERIALIZED_LENGTH]> for Signature {
    fn from(bytes: &[u8; SIGNATURE_SERIALIZED_LENGTH]) -> Signature {
        let mut r_bytes: [u8; 32] = [0; 32];
        r_bytes.copy_from_slice(&bytes[..32]);
        let r = CompressedY::from(&r_bytes);

        let mut s_bytes: [u8; 32] = [0; 32];
        s_bytes.copy_from_slice(&bytes[32..]);
        let s = Scalar::from(&s_bytes);

        Signature { r, s }
    }

}

impl Signature {
    pub fn to_bytes(&self) -> [u8; SIGNATURE_SERIALIZED_LENGTH] {
        let mut signature_bytes: [u8; SIGNATURE_SERIALIZED_LENGTH] = [0u8; SIGNATURE_SERIALIZED_LENGTH];
        signature_bytes[..32].copy_from_slice(self.r.as_bytes());
        signature_bytes[32..].copy_from_slice(self.s.as_bytes());
        signature_bytes
    }
}


// TODO: to_bytes and from_bytes methods for secretkey, publickey and keypair

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use super::Keypair;
    use crate::hash::Sha512;

    #[test]
    fn test_decompression() {
        #![allow(non_snake_case)]

        // let seed: [u8; 32] = [
        //     0x35, 0xb3, 0x07, 0x76, 0x17, 0x9a, 0x78, 0x58,
        //     0x34, 0xf0, 0x4c, 0x82, 0x88, 0x59, 0x5d, 0xf4,
        //     0xac, 0xa1, 0x0b, 0x33, 0xaa, 0x12, 0x10, 0xad,
        //     0xec, 0x3e, 0x82, 0x47, 0x25, 0x3e, 0x6c, 0x65,
        // ];

        // let mut seed: [u8; 32] = [
        //     0x35, 0xb0, 0x07, 0x76, 0x17, 0x9a, 0x78, 0x50,
        //     0x34, 0xff, 0x4c, 0x82, 0x88, 0x00, 0x5d, 0xf4,
        //     0xac, 0xaf, 0x0b, 0x33, 0xaa, 0x12, 0x10, 0xad,
        //     0xec, 0x30, 0x82, 0x47, 0x25, 0x3e, 0x6c, 0x65,
        // ];
        let mut seed: [u8; 32] = hex!(
            "35b00776179a785034ff4c8288005df4acaf0b33aa1210adec308247253e6c65");

        for i in 0..=255 {
            seed[0] = i;
            let keypair = Keypair::from(&seed);
            let public = keypair.public;

            assert_eq!(public.point.compressed(), public.compressed);
            let possible_point = public.compressed.decompressed();
            assert!(possible_point.is_ok());
            let candidate_point = possible_point.unwrap();
            assert_eq!(candidate_point.compressed(), public.compressed);
            assert_eq!(public.point, candidate_point);
        }
    }

    #[test]
    fn test_signature() {

        #![allow(non_snake_case)]

        let seed: [u8; 32] = [
            0x35, 0xb3, 0x07, 0x76, 0x17, 0x9a, 0x78, 0x58,
            0x34, 0xf0, 0x4c, 0x82, 0x88, 0x59, 0x5d, 0xf4,
            0xac, 0xa1, 0x0b, 0x33, 0xaa, 0x12, 0x10, 0xad,
            0xec, 0x3e, 0x82, 0x47, 0x25, 0x3e, 0x6c, 0x65,
        ];

        let keypair = Keypair::from(&seed);

        let data = "salty!".as_bytes();

        let R_expected = [
            0xec, 0x97, 0x27, 0x40, 0x07, 0xe7, 0x08, 0xc6,
            0xd1, 0xee, 0xd6, 0x01, 0x9f, 0x5d, 0x0f, 0xcb,
            0xe1, 0x8a, 0x67, 0x70, 0x8d, 0x17, 0x92, 0x4b,
            0x95, 0xdb, 0x7e, 0x35, 0xcc, 0xaa, 0x06, 0x3a,
        ];

        let S_expected = [
            0xb8, 0x64, 0x8c, 0x9b, 0xf5, 0x48, 0xb0, 0x09,
            0x90, 0x6f, 0xa1, 0x31, 0x09, 0x0f, 0xfe, 0x85,
            0xa1, 0x7e, 0x89, 0x99, 0xb8, 0xc4, 0x2c, 0x97,
            0x32, 0xf9, 0xa6, 0x44, 0x2a, 0x17, 0xbc, 0x09,
        ];

        let signature = keypair.sign(&data);

        assert_eq!(signature.r.0, R_expected);
        assert_eq!(signature.s.0, S_expected);

        let public_key = keypair.public;
        let verification = public_key.verify(&data, &signature);
        assert!(verification.is_ok());
    }

    #[test]
    fn test_ed25519ph_with_rfc_8032_test_vector() {
        let seed: [u8; 32] = [
            0x83, 0x3f, 0xe6, 0x24, 0x09, 0x23, 0x7b, 0x9d,
            0x62, 0xec, 0x77, 0x58, 0x75, 0x20, 0x91, 0x1e,
            0x9a, 0x75, 0x9c, 0xec, 0x1d, 0x19, 0x75, 0x5b,
            0x7d, 0xa9, 0x01, 0xb9, 0x6d, 0xca, 0x3d, 0x42,
        ];

        let keypair = Keypair::from(&seed);

        let message: [u8; 3] = [0x61, 0x62, 0x63];

        let prehashed_message = Sha512::new().updated(&message).finalize();

        let signature = keypair.sign_prehashed(&prehashed_message, None);

        let expected_r = [
            0x98, 0xa7, 0x02, 0x22, 0xf0, 0xb8, 0x12, 0x1a,
            0xa9, 0xd3, 0x0f, 0x81, 0x3d, 0x68, 0x3f, 0x80,
            0x9e, 0x46, 0x2b, 0x46, 0x9c, 0x7f, 0xf8, 0x76,
            0x39, 0x49, 0x9b, 0xb9, 0x4e, 0x6d, 0xae, 0x41,
        ];

        let expected_s = [
            0x31, 0xf8, 0x50, 0x42, 0x46, 0x3c, 0x2a, 0x35,
            0x5a, 0x20, 0x03, 0xd0, 0x62, 0xad, 0xf5, 0xaa,
            0xa1, 0x0b, 0x8c, 0x61, 0xe6, 0x36, 0x06, 0x2a,
            0xaa, 0xd1, 0x1c, 0x2a, 0x26, 0x08, 0x34, 0x06,
        ];

        assert_eq!(signature.r.0, expected_r);
        assert_eq!(signature.s.0, expected_s);

        let public_key = keypair.public;
        let verification = public_key.verify_prehashed(&prehashed_message, &signature, None);
        assert!(verification.is_ok());
    }

    #[test]
    fn test_reduction_of_s_modulo_ell() {
        // previous transliteration of TweetNaCl's scalar implementation
        // was bugged and didn't reduce S properly, leading to implementations like
        // OpenSSL / libsodium / Python's "cryptography" rejecting ~1% of signatures
        // (whereas SUPERCOP and python-ed25519 are fine with these).
        let seed: &[u8; 32] = b"\\\x8a\x90\x83\x8d\x10U$\xfe\x8d\xf6Z\x9d\xaf\xd9\x9c\xc4\x08S{l\xa3\x1b9\x91\x0bqu5Ut\x15";
        let data: &[u8; 69] = b"\xbf\xab\xc3t2\x95\x8b\x063`\xd3\xadda\xc9\xc4sZ\xe7\xf8\xed\xd4e\x92\xa5\xe0\xf0\x14R\xb2\xe4\xb5\x01\x00\x00\x0b\x0e123456789abcdef0123456789abcdef0";
        let nonreduced_sig: &[u8; 64] = b"E\x13\x8aD\x1f\xb8\xd0\xc5k\x1f\xf7\xe5~u\x998I\x12\x17\x99\xf1X\xe0\xdeV\xf7))p\xea\x93\x9c\xfaV\xef\xeeP\xad\xdf*\x80O\xaaFA\x9d7\xd8L\xc4{\x93\xae\x96\x9e\xf09,\xb7\xf2\x00\xe56\x10";
        // https://colab.research.google.com/drive/1ZDRWkO9o9YVbo6HLl7Weo3G35c4ccIID#scrollTo=ZZqxvbaB8gO4
        let manually_reduced_s: &[u8; 32] = b"\r\x83\xf9\x916J\xcd\xd2\xa9\xb2\xb2\xa3b\xa3X\xc3L\xc4{\x93\xae\x96\x9e\xf09,\xb7\xf2\x00\xe56\x00";

        let keypair = Keypair::from(seed);
        let signature = keypair.sign(data);
        let s = &signature.s;
        assert_eq!(&s.0, manually_reduced_s);
        assert_ne!(&s.0, &nonreduced_sig[32..]);

    }
}

