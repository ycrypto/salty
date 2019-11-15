pub const SEED_BYTES: usize = 32;
pub type SeedBuffer = [u8; SEED_BYTES];
#[derive(Clone,Debug,Default)]
pub struct Seed(pub SeedBuffer);

pub const SECRET_SCALAR_BYTES: usize = 32;
pub type SecretScalarBuffer = [u8; SECRET_SCALAR_BYTES];
#[derive(Clone,Debug,Default)]
pub struct SecretScalar(pub SecretScalarBuffer);

// TODO: better name for this. is there an official one?
// maybe `NonceSalt`?
pub const SECRET_EXTRA_BYTES: usize = 32;
pub type SecretExtraBuffer = [u8; SECRET_EXTRA_BYTES];
#[derive(Clone,Debug,Default)]
pub struct SecretExtra(pub SecretExtraBuffer);

pub const PUBLIC_KEY_BYTES: usize = 32;
pub type PublicKeyBuffer = [u8; PUBLIC_KEY_BYTES];
#[derive(Clone,Debug,Default,PartialEq)]
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
    /// input entropy
    pub seed: Seed,
    /// left half of hash of seed, with some bit-fiddling
    pub secret_scalar: SecretScalar,
    /// right half of hash of seed, for the nonces
    pub secret_extra: SecretExtra,
    /// packed version of secret scalar multiple of base point
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

type Signature = ([u8; 32], [u8; 32]);

pub fn sign(secret_key: &SecretKey, message: &[u8]) -> Signature {

    // UFF! So close...
    // But: by definition, arrays have length known at compile time.
    // Our messages don't.
    //
    // To avoid weird allocations, need to modify sha512 interface instead,
    // so we can hash our concatenated bytes step by step.

    let mut hash = crate::hash::Hash::new();
    hash.update(&secret_key.secret_extra.0);
    hash.update(message);
    let r = crate::curve::modulo_group_order_u8s(&mut hash.finalize());
    #[allow(non_snake_case)]
    let point_R = crate::curve::scalar_multiple_of_base_point(&r);
    #[allow(non_snake_case)]
    let R: [u8; 32]  = crate::curve::pack_point(&point_R);

    let mut hash = crate::hash::Hash::new();
    hash.update(&R);
    hash.update(&secret_key.public_key.0);
    hash.update(message);
    let h = crate::curve::modulo_group_order_u8s(&mut hash.finalize());
    // calculate S = r + H(R,A,M) mod \ell, with h = H(R,A,M)
    let mut x: [i64; 64] = [0; 64];
    for i in 0..32 {
        x[i] = r[i] as _;
    }
    for i in 0..32 {
        for j in 0..32 {
            x[i + j] += h[i] as i64 * secret_key.secret_scalar.0[j] as i64;
        }
    }
    #[allow(non_snake_case)]
    let S: [u8; 32] = crate::curve::modulo_group_order(&mut x);

    (R, S)
}

// ed25519-dalek:
//         let mut h: Sha512 = Sha512::new();
//         let R: CompressedEdwardsY;
//         let r: Scalar;
//         let s: Scalar;
//         let k: Scalar;

//         h.input(&self.nonce);
//         h.input(&message);

//         r = Scalar::from_hash(h);
//         R = (&r * &constants::ED25519_BASEPOINT_TABLE).compress();

//         h = Sha512::new();
//         h.input(R.as_bytes());
//         h.input(public_key.as_bytes());
//         h.input(&message);

//         k = Scalar::from_hash(h);
//         s = &(&k * &self.key) + &r;

//         Signature { R, s }

// pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
//     unimplemented!();
// }
