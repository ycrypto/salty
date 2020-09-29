use core::ops::{
    Add,
    Mul,
};

use crate::constants::SCALAR_LENGTH;

/// 32 octets, interpreted as little-endian 256 bit unsigned integer
pub type U256le = [u8; 32];
/// 64 octets, interpreted as little-endian 512 bit unsigned integer
pub type U512le = [u8; 64];

/// Since the curve is an abelian group, it has a module
/// structure, consisting of these scalars. They are the
/// integers modulo "ell", where "ell" is 2**252 + something something.
#[repr(C)]
#[derive(Debug,Default,PartialEq)]
pub struct Scalar(
    pub [u8; SCALAR_LENGTH]
);

type UnpackedScalar = crate::scalar29::Scalar29;

///// NB: The buffer is assumed to be zero from
///// byte 32 onward - each operation should call
///// `clear_upper_half` to ensure this.
/////
///// Technically, in TweetNaCl, there's an operation
///// (a, b, c) -> a*b + c, which needs only one call
///// to clear upper half, but I think we can live with
///// this slight inefficiency - if scalar ring operations
///// become a bottleneck, there should be bigger improvements
///// achievable by other means.
//pub struct TweetNaclScalar(
//    pub (crate) [i64; 64]
//);

impl From<&[u8; SCALAR_LENGTH]> for Scalar {
    fn from(bytes: &[u8; SCALAR_LENGTH]) -> Scalar {
        Scalar(bytes.clone())
    }
}

// impl From<&[u8; 64]> for TweetNaclScalar {
//     fn from(bytes: &[u8; 64]) -> TweetNaclScalar {
//         let mut x: [i64; 64] = [0; 64];
//         for i in 0..64 {
//             x[i] = bytes[i] as i64;
//         }
//         let mut s = TweetNaclScalar(x);
//         s.clear_upper_half();
//         s
//     }
// }

// impl From<Scalar> for TweetNaclScalar {
//     fn from(scalar: Scalar) -> TweetNaclScalar {
//         let mut x: [i64; 64] = [0; 64];
//         for i in 0..32 {
//             x[i] = scalar.0[i] as i64;
//         }
//         TweetNaclScalar(x)
//     }
// }

// impl From<&Scalar> for TweetNaclScalar {
//     fn from(scalar: &Scalar) -> TweetNaclScalar {
//         let mut x: [i64; 64] = [0; 64];
//         for i in 0..32 {
//             x[i] = scalar.0[i] as i64;
//         }
//         TweetNaclScalar(x)
//     }
// }

// impl TweetNaclScalar {
//     pub(crate) fn clear_upper_half(&mut self) {
//         let x = &mut self.0;
//         #[allow(non_snake_case)]
//         let L = Scalar::L;
//         for i in (32..=63).rev() {
//             let mut carry: i64 = 0;
//             for j in (i - 32)..(i - 12) {
//                 // x[j] += carry - 16 * x[i] * L[j - (i - 32)];
//                 // C code doesn't care about u64 vs i64...
//                 x[j] += carry - 16 * x[i] * L[j - (i - 32)] as i64;
//                 carry = (x[j] + 128) >> 8;
//                 x[j] -= carry << 8;
//             }
//             // x[j] += carry;  // C code uses out-of-scope variable j
//             x[i - 12] += carry;
//             x[i] = 0;
//         }
//     }

//     pub fn reduce_modulo_ell(&mut self) -> Scalar {
//         // probably redundant
//         // self.clear_upper_half();

//         let x = &mut self.0;

//         #[allow(non_snake_case)]
//         let L = Scalar::L;

//         let mut carry: i64 = 0;
//         for j in 0..32 {
//             // x[j] += carry - (x[31] >> 4) * L[j];
//             x[j] += carry - (x[31] >> 4) * L[j] as i64;
//             carry = x[j] >> 8;
//             x[j] &= 0xff;
//         }

//         for j in 0..32 {
//             // x[j] -= carry * L[j];
//             x[j] -= carry * L[j] as i64;
//         }

//         let mut r: [u8; 32] = Default::default();
//         for i in 0 ..32 {
//             x[i + 1] += x[i] >> 8;
//             // r[i] = x[i] & 0xff;
//             r[i] = ((x[i] as u64) & 0xff) as u8;
//         }

//         Scalar(r)

//     }
// }

impl UnpackedScalar {
    /// Pack the limbs of this `UnpackedScalar` into a `Scalar`.
    fn pack(&self) -> Scalar {
        Scalar(self.to_bytes())
    }
}

impl<'a, 'b> Add<&'b Scalar> for &'a Scalar {
    type Output = Scalar;
    #[allow(non_snake_case)]
    fn add(self, _rhs: &'b Scalar) -> Scalar {
        // The UnpackedScalar::add function produces reduced outputs
        // if the inputs are reduced.  However, these inputs may not
        // be reduced -- they might come from Scalar::from_bits.  So
        // after computing the sum, we explicitly reduce it mod l
        // before repacking.
        let sum = UnpackedScalar::add(&self.unpack(), &_rhs.unpack());
        let sum_R = UnpackedScalar::mul_internal(&sum, &crate::scalar29::constants::R);
        let sum_mod_l = UnpackedScalar::montgomery_reduce(&sum_R);
        sum_mod_l.pack()
    }
}

impl<'a, 'b> Mul<&'b Scalar> for &'a Scalar {
    type Output = Scalar;
    fn mul(self, _rhs: &'b Scalar) -> Scalar {
        UnpackedScalar::mul(&self.unpack(), &_rhs.unpack()).pack()
    }
}

// impl<'a, 'b> Add<&'b TweetNaclScalar> for &'a TweetNaclScalar {
//     type Output = TweetNaclScalar;
//     fn add(self, other: &'b TweetNaclScalar) -> TweetNaclScalar {
//         let mut sum: [i64; 64] = [0; 64];
//         for (i, (ai, bi)) in self.0.iter().zip(other.0.iter()).enumerate() {
//             sum[i] = *ai + *bi;
//         }

//         TweetNaclScalar(sum)
//     }
// }

// impl<'a, 'b> Mul<&'b TweetNaclScalar> for &'a TweetNaclScalar {
//     type Output = TweetNaclScalar;
//     fn mul(self, other: &'b TweetNaclScalar) -> TweetNaclScalar {
//         let mut product: [i64; 64] = [0; 64];
//         for (i, ai) in self.0.iter().take(32).enumerate() {
//             for (j, bj) in other.0.iter().take(32).enumerate() {
//                 product[i + j] += *ai * *bj;
//             }
//         }

//         let mut product = TweetNaclScalar(product);
//         product.clear_upper_half();
//         product
//     }
// }

impl Scalar {
    #[allow(non_snake_case)]
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0x10,
    ];

    /// The order of the group, 2**252 + something something
    pub fn ell() -> U256le {
        Scalar::L
    }

    pub fn from_bytes(bytes: &[u8; SCALAR_LENGTH]) -> Self {
        Scalar(bytes.clone())
    }

    pub fn as_bytes(&self) -> &[u8; SCALAR_LENGTH] {
        &self.0
    }

    pub fn to_bytes(&self) -> [u8; SCALAR_LENGTH] {
        self.0
    }

    pub fn from_u256_le(x: &U256le) -> Scalar {
        // TweetNaclScalar::from(&Scalar(*x)).reduce_modulo_ell()
        // Temporarily allow s_unreduced.bytes > 2^255 ...
        let s_unreduced = Scalar(x.clone());

        // Then reduce mod the group order and return the reduced representative.
        let s = s_unreduced.reduce();
        debug_assert_eq!(0u8, s.0[31] >> 7);

        s
    }

    // /// Construct a `Scalar` by reducing a 256-bit little-endian integer
    // /// modulo the group order \\( \ell \\).
    // pub fn from_bytes_mod_order(bytes: [u8; 32]) -> Scalar {
    //     // Temporarily allow s_unreduced.bytes > 2^255 ...
    //     let s_unreduced = Scalar{bytes};

    //     // Then reduce mod the group order and return the reduced representative.
    //     let s = s_unreduced.reduce();
    //     debug_assert_eq!(0u8, s[31] >> 7);

    //     s
    // }

    pub fn from_u512_le(x: &U512le) -> Scalar {
        // TweetNaclScalar::from(x).reduce_modulo_ell()
        UnpackedScalar::from_bytes_wide(x).pack()
    }

    // /// Construct a `Scalar` by reducing a 512-bit little-endian integer
    // /// modulo the group order \\( \ell \\).
    // pub fn from_bytes_mod_order_wide(input: &[u8; 64]) -> Scalar {
    //     UnpackedScalar::from_bytes_wide(input).pack()
    // }


    /// Unpack this `Scalar` to an `UnpackedScalar` for faster arithmetic.
    pub(crate) fn unpack(&self) -> UnpackedScalar {
        UnpackedScalar::from_bytes(&self.0)
    }

    /// Reduce this `Scalar` modulo \\(\ell\\).
    #[allow(non_snake_case)]
    pub fn reduce(&self) -> Scalar {
        let x = self.unpack();
        let xR = UnpackedScalar::mul_internal(&x, &crate::scalar29::constants::R);
        let x_mod_l = UnpackedScalar::montgomery_reduce(&xR);
        x_mod_l.pack()
    }

    /// Check whether this `Scalar` is the canonical representative mod \\(\ell\\).
    ///
    /// This is intended for uses like input validation, where variable-time code is acceptable.
    pub fn is_canonical(&self) -> bool {
        *self == self.reduce()
    }
}
