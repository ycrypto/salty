pub struct SecretKey(
    pub (crate) [u8; SECRET_KEY_LENGTH]
);

pub struct ExpandedSecretKey {
    pub (crate) key: Scalar,
    pub (crate) nonce: [u8; 32],
}

pub struct PublicKey(
    pub(crate) CompressedEdwardsY,
    pub(crate) EdwardsPoint,
}

impl<'a> From<&'a SecretKey> for PublicKey {
    /// Derive this public key from its corresponding `SecretKey`.
    fn from(secret_key: &SecretKey) -> PublicKey {
        let mut h: Sha512 = Sha512::new();
        let mut hash: [u8; 64] = [0u8; 64];
        let mut digest: [u8; 32] = [0u8; 32];

        h.input(secret_key.as_bytes());
        hash.copy_from_slice(h.result().as_slice());

        digest.copy_from_slice(&hash[..32]);

        PublicKey::mangle_scalar_bits_and_multiply_by_basepoint_to_produce_public_key(&mut digest)
    }
}

impl PublicKey {

    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, SignatureError> {
        if bytes.len() != PUBLIC_KEY_LENGTH {
            return Err(SignatureError(InternalError::BytesLengthError {
                name: "PublicKey",
                length: PUBLIC_KEY_LENGTH,
            }));
        }
        let mut bits: [u8; 32] = [0u8; 32];
        bits.copy_from_slice(&bytes[..32]);

        let compressed = CompressedEdwardsY(bits);
        let point = compressed
            .decompress()
            .ok_or(SignatureError(InternalError::PointDecompressionError))?;

        Ok(PublicKey(compressed, point))
    }
}
