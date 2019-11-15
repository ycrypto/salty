
// Curve25519 is defined over F_p = Z/pZ,
// and splits as C = N ⋊ C', with N = Z/8Z,
// and C' prime of order l.
//
// Here,
// p = 2**255 - 19, and
// l = 2**252 + 277...493
//

// NB: signatures are "detached"

mod constants {
    pub const KEYPAIR_LENGTH: usize = SECRET_KEY_LENGTH + PUBLIC_KEY_LENGTH;
    pub const PUBLIC_KEY_LENGTH: usize = 32;
    pub const SIGNATURE_LENGTH: usize = 64;

    // the non-expanded secret key, also called seed
    pub const SECRET_KEY_LENGTH: usize = 32;
    // expanded secret key
    const EXPANDED_SECRET_KEY_KEY_LENGTH: usize = 32;
    const EXPANDED_SECRET_KEY_NONCE_LENGTH: usize = 32;
    pub const EXPANDED_SECRET_KEY_LENGTH: usize = EXPANDED_SECRET_KEY_KEY_LENGTH + EXPANDED_SECRET_KEY_NONCE_LENGTH;
};

pub struct ExpandedSecretKey {
    pub (crate) key: Scalar,
    pub (crate) nonce: [u8; 32],
}

pub trait FieldImplementation:
    Add<&'b Self> for &'a Self +

{
    type Limbs;

    // TODO: maybe have statics outside,
    // and demand functions returning &'static Self instead?
    const ZERO: Limbs;
    const ONE: Limbs;
    const ED25519_BASEPOINT_X: Limbs;
    const ED25519_BASEPOINT_Y: Limbs;

    fn add(&'a self, other: &'o other) -> Self;
}

type TweetNaclLimbs = [i64; 16];
pub struct TweetNaclFieldElement (pub (crate) TweetNaclLimbs);

impl FieldImplementation for TweetNaclFieldElement {
    type Limbs = TweetNaclLimbs;

    const ZERO: Limbs = [
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
    ];

    const ONE: Limbs = [
        1, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
    ];

    const ED25519_BASEPOINT_X: Limbs = [
        0xd51a, 0x8f25, 0x2d60, 0xc956,
        0xa7b2, 0x9525, 0xc760, 0x692c,
        0xdc5c, 0xfdd6, 0xe231, 0xc0a4,
        0x53fe, 0xcd6e, 0x36d3, 0x2169,
    ];

    const ED25519_BASEPOINT_Y: Limbs = [
        0x6658, 0x6666, 0x6666, 0x6666,
        0x6666, 0x6666, 0x6666, 0x6666,
        0x6666, 0x6666, 0x6666, 0x6666,
        0x6666, 0x6666, 0x6666, 0x6666,
    ];
    fn add(&self, other: &other) -> Self {
    }
}

type HaaseLimbs = [u32; 8];
pub struct HaaseFieldElement (pub (crate) HaaseLimbs);

impl FieldImplementation for HaaseFieldElement {
    type Limbs = TweetNaclLimbs;

    const ZERO: Limbs = [
        0, 0, 0, 0,
        0, 0, 0, 0,
    ];

    const ONE: Limbs = [
        1, 0, 0, 0,
        0, 0, 0, 0,
    ];


    fn add(&self, other: &other) -> Self {
    }
}

pub struct EdwardsPoint<FieldElement>
where
    FieldElement: FieldImplementation = HaaseFieldImplementation
{
    pub(crate) X: FieldElement,
    pub(crate) Y: FieldElement,
    pub(crate) Z: FieldElement,
    pub(crate) T: FieldElement,
}

// Point (x, y) determined (by sign(x), y)
// First 255 bits represent x, high bits of byte 32 represents sign(y)
// TODO: is this format canonical? seems not
pub struct CompressedEdwardsY(
	pub [u8; 32])
;

/// An `UnpackedScalar` represents an element of the field GF(l), optimized for speed.
#[cfg(feature = "u64_backend")]
// 5 52-bit limbs
pub struct Scalar52(pub [u64; 5]);
#[cfg(feature = "u32_backend")]
// 9 29-bit limbs
pub struct Scalar29(pub [u32; 9]);

// high bit of `bytes[31]` *must* be zero
pub struct Scalar {pub(crate) bytes: [u8; 32],}

impl Scalar {
    // checks that represented little-endian integers is less than ell
    pub fn from_canonical_bytes(bytes: [u8; 32]) -> Option<Scalar>;
    //  256-bit little-endian integer, mod ell
    //  TODO: rename from_u256_as_le_bytes?
    pub fn from_bytes_mod_order(bytes: [u8; 32]) -> Scalar;
    // pub fn from_u256le(bytes: [u8; 32]) -> Scalar;
    //  512-bit little-endian integer, mod ell (e.g. output of SHA3)
    //  TODO: rename from_u512_as_le_bytes?
    pub fn from_bytes_mod_order_wide(bytes: [u8; 64]) -> Scalar;
    // pub fn from_u512le(bytes: [u8; 64]) -> Scalar;
}

pub struct Signature {
    pub (crate) r: CompressedEdwardsY,

    pub (crate) s: Scalar,
}

impl<F: FieldImplementation> CompressedEdwardsY {
    // returns None if input is not y-coordinate of a point
    pub fn decompress(&self) -> Option<EdwardsPoint<F>>;
}

impl<F: FieldImplementation> EdwardsPoint<F> {
    pub fn compress(&self) -> CompressedEdwardsY;
    // returns 8*P
    pub fn mul_by_cofactor(&self) -> Self;
    // contained in torsion subgroup?
    pub fn is_small_order(&self) -> bool {
        self.mul_by_cofactor().is_identity()
    }
    // contained in prime order subgroup?
    pub fn is_torsion_free(&self) -> bool {
        (self * constants::BASEPOINT_ORDER).is_identity()
    }
}

#[cfg(feature = "u64_backend")]
pub struct FieldElement51(pub (crate) [u64; 5]);
#[cfg(feature = "u64_backend")]
pub type FieldElement = backend::serial::u64::field::FieldElement51;

#[cfg(feature = "u32_backend")]
pub struct FieldElement2625(pub (crate) [u32; 10]);
#[cfg(feature = "u32_backend")]
pub type FieldElement = backend::serial::u32::field::FieldElement2625;



pub struct PublicKey(
	pub (crate) CompressedEdwardsY
);

/// This is the main entry point to the Salty signature API.
/// - generate a keypair, by providing a sufficiently entropic seed
///   (we do not ask for a PRNG like ed25519-dalek to avoid the
///   rng_core dependency
/// - generate signatures on messages
/// - verify signatures on messages
// TODO: set default via #[cfg(feature = "haase")] etc.
pub struct Keypair<F, S>
where
    F: FieldImplementation = HaaseFieldElement,
    S: ScalarImplementation = TweetNaclScalar,
{
    pub secret: SecretKey<F>,
    pub public: PublicKey<F>,
}

impl<F: FieldImplementation> Keypair {
    pub fn new(seed: &Seed) -> Keypair;

    pub fn sign(&self, message: &[u8]) -> Signature
        self.secret.expand().sign(&message, &self.public)
    }

    pub fn sign(&self, message: &[u8]) {
        let mut first_hash = Sha512::new();
        // this part needs to be constant-time
        // first_hash.update(&self.secret....);
        // this part does not need to (and cannot!) be constant-time
        // first_hash.update(message);

        // let r: Scalar = Scalar::from_u512le(first_hash.finalize());
        let r: Scalar = first_hash.finalize().into();

        let R: EdwardsPoint<F> = r * Ed25519::BASEPOINT;

        let r: CompressedEdwardsY = R.compress();

        let mut second_hash = Sha512::new();
        // second_hash.update(&R);
        // second_hash.update(self.public_key);
        // second_hash.update(message);
        let h: Scalar = Scalar::from_u512le(second_hash.finalize());

        // let mut hash = crate::hash::Hash::new();
        // hash.update(&R);
        // hash.update(&secret_key.public_key.0);
        // hash.update(message);
        // let h = crate::curve::modulo_group_order_u8s(&mut hash.finalize());
        // // calculate S = r + H(R,A,M) mod \ell, with h = H(R,A,M)
        // let mut x: [i64; 64] = [0; 64];
        // for i in 0..32 {
        //     x[i] = r[i] as _;
        // }
        // for i in 0..32 {
        //     for j in 0..32 {
        //         x[i + j] += h[i] as i64 * secret_key.secret_scalar.0[j] as i64;
        //     }
        // }
        // #[allow(non_snake_case)]
        // let S: [u8; 32] = crate::curve::modulo_group_order(&mut x);

        // (R, S)
    }
    pub fn verify(&self, message: &[u8], signature: &Signature);
}


///////////////////////////////////////////
///////////////////////////////////////////
///////////////////////////////////////////
///////////////////////////////////////////
///////////////////////////////////////////


pub trait FieldImplementation {
    type FieldElement;

    pub fn add(&'s self, other: &'o FieldElement) -> FieldElement;

}

pub struct TweetNaCl;
impl FieldImplementation for TweetNaCl {
    type FieldElement = [u32; 8];
}

pub struct Haase;
impl FieldImplementation for Haase {
    type FieldElement = [u32; 8];
}

pub struct Casper;
impl FieldImplementation for Casper {}


