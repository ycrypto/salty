pub const SEED_BYTES: usize = 32;
type SeedBuffer = [u8; SEED_BYTES];
#[derive(Clone,Debug,Default)]
pub struct Seed(pub SeedBuffer);

pub const SECRET_SCALAR_BYTES: usize = 32;
type SecretScalarBuffer = [u8; SECRET_SCALAR_BYTES];
#[derive(Clone,Debug,Default)]
pub struct SecretScalar(pub SecretScalarBuffer);

// TODO: better name for this. is there an official one?
// maybe `NonceSalt`?
pub const SECRET_EXTRA_BYTES: usize = 32;
type SecretExtraBuffer = [u8; SECRET_EXTRA_BYTES];
#[derive(Clone,Debug,Default)]
pub struct SecretExtra(pub SecretExtraBuffer);

pub const PUBLIC_KEY_BYTES: usize = 32;
type PublicKeyBuffer = [u8; PUBLIC_KEY_BYTES];
#[derive(Clone,Debug,Default)]
pub struct PublicKey(pub PublicKeyBuffer);

// pub const SECRET_KEY_BYTES: usize = 64;
// type SecretKeyBuffer = [u8; SECRET_KEY_BYTES];
// pub struct SigningSecretKey(pub SecretKeyBuffer);

// Original TweetNaCl sets:
// "secret key" = 32 byte seed,
// the 64 byte SHA-512 hash of which is split into
// - "left" half, the "secret scalar", which defines the public key
// - "right" half, which is used to generate nonces in signatures
// We want to store the seed privately, but keep the three derived
// parts separate

#[derive(Clone,Debug,Default)]
pub struct SecretKey {
    pub seed: Seed,
    pub secret_scalar: SecretScalar,
    pub secret_extra: SecretExtra,
    pub public_key: PublicKey,
}

pub fn generate_key(seed: &Seed) -> SecretKey {
    let seed = seed.0.clone();

    let mut digest: [u8; 64] = [0u8; 64];
    // TODO: get rid of the useless copy,
    // something like `let (mut scalar, extra) = sha512(seed)`
    super::hash::sha512(&mut digest, &seed);

    // Ed25519 keys clamp the secret scalar to ensure two things:
    //   1: integer value is in L/2 .. L, to avoid small-logarithm
    //      non-wraparound
    //   2: low-order 3 bits are zero, so a small-subgroup attack won't learn
    //      any information
    // set the top two bits to 01, and the bottom three to 000

    let mut secret_scalar: SecretScalarBuffer = Default::default();
    secret_scalar.copy_from_slice(&digest[..32]);

    // Curve25519 contains 2-torsion (of order 8), this gets rid of the torsion
    secret_scalar[0] &= 248;
    // TODO: Explanation
    secret_scalar[31] &= 127;
    secret_scalar[31] |= 64;

    let mut secret_extra: SecretExtraBuffer = Default::default();
    secret_extra.copy_from_slice(&digest[32..]);

    let public_point = crate::curve::scalar_multiple_of_base_point(&secret_scalar);
    let public_key = crate::curve::pack_point(&public_point);

    SecretKey {
        seed: Seed(seed),
        secret_scalar: SecretScalar(secret_scalar),
        secret_extra: SecretExtra(secret_extra),
        public_key: PublicKey(public_key),
    }
}
