use crate::{
    constants::{
        SECRETKEY_SEED_LENGTH,
        SECRETKEY_SCALAR_LENGTH,
        SECRETKEY_NONCE_LENGTH,

        // PUBLICKEY_LENGTH,
    },
    curve::{
        CurvePoint,
        CompressedY,
    },
    hash::Hash as Sha512,
    scalar::Scalar,
};

pub struct SecretKey {
    #[allow(dead_code)]
    pub (crate) seed: [u8; SECRETKEY_SEED_LENGTH],
    pub (crate) scalar: Scalar,
    pub (crate) nonce: [u8; SECRETKEY_NONCE_LENGTH],
}

pub struct PublicKey {
    #[allow(dead_code)]
    pub(crate) point: CurvePoint,
    pub(crate) compressed: CompressedY,
}

pub struct Keypair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

pub struct Signature {
    pub r: CompressedY,
    pub s: Scalar,
}

impl Keypair {
    pub fn sign(&self, message: &[u8]) -> Signature {

        // R = rB, with r = H(nonce, M)
        let mut first_hash = Sha512::new();
        first_hash.update(&self.secret.nonce);
        first_hash.update(message);
        let r: Scalar = Scalar::from_u512(&first_hash.finalize());
        #[allow(non_snake_case)]
        let R: CompressedY = (&r * &CurvePoint::basepoint()).compressed();

        // S = r + H(R, A, M)s (mod l), with A = sB the public key
        let mut second_hash = Sha512::new();
        second_hash.update(&R.0);
        second_hash.update(&self.public.compressed.0);
        second_hash.update(message);

        let h: Scalar = Scalar::from_u512(&second_hash.finalize());
        // let s: Scalar = &r + &(&h * &self.secret.scalar);

        // calculate S = r + H(R,A,M) mod \ell, with h = H(R,A,M)
        let mut x: [i64; 64] = [0; 64];
        for i in 0..32 {
            x[i] = r.0[i] as _;
        }
        for i in 0..32 {
            for j in 0..32 {
                x[i + j] += h.0[i] as i64 * self.secret.scalar.0[j] as i64;
            }
        }
        #[allow(non_snake_case)]
        let s = Scalar::modulo_group_order(&mut x);

        Signature { r: R, s }
    }
}

impl From<&[u8; SECRETKEY_SEED_LENGTH]> for SecretKey {
    fn from(seed: &[u8; SECRETKEY_SEED_LENGTH]) -> SecretKey {

        let mut hash: Sha512 = Sha512::new();
        hash.update(seed);
        let digest = hash.finalize();

        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(&digest[..SECRETKEY_SCALAR_LENGTH]);
        let mut scalar = Scalar(scalar_bytes);
        // let mut scalar = Scalar::from_bytes(&digest[..SECRETKEY_SCALAR_LENGTH]);
        scalar.0[0] &= 248;
        scalar.0[31] &= 127;
        scalar.0[31] |= 64;

        let mut nonce = [0u8; SECRETKEY_NONCE_LENGTH];
        nonce.copy_from_slice(&digest[SECRETKEY_SCALAR_LENGTH..]);

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

impl From<&[u8; SECRETKEY_SEED_LENGTH]> for Keypair {
    fn from(seed: &[u8; SECRETKEY_SEED_LENGTH]) -> Keypair {
        let secret = SecretKey::from(seed);

        let public = PublicKey::from(&secret);

        Keypair { secret, public }
    }
}

// TODO: to_bytes and from_bytes methods for secretkey, publickey and keypair

#[cfg(test)]
mod tests {

    use super::Keypair;

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
    }
}

