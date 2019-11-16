#![no_std]
//! Mashup of [TweetNaCl](tweetnacl) with [ed25519-dalek](ed25519-dalek),
//! aimed towards embedded use cases on microcontrollers.
//!
//! Originally, this library was a transliteration of the C implementation of
//! Ed25519 signatures in TweetNaCl to Rust, "with helpful explanations".
//! One reason the current ed25519-dalek library in its current state is not
//! usable for microcontrollers is that it includes ~40kB of pre-computed data
//! to speed things up. Moreover, the implementatons are optimized for PC.
//!
//! Iterating over the not-very-nice API surface of NaCl, we ended up with
//! a close relative of the "[dalek](dalek)" APIs anyway, where things are modeled as,
//! for instance, "compressed y-coordinate of Edwards25519 curve point",
//! instead of raw bytes.
//!
//! The main entry point of the API is either a keypair, or a public key.
//!
//! For keypairs, an external trusted source of entropy is assumed, letting
//! us construct a keypair as:
//!
//! ```ignore
//! let seed: [u8; 32] = <some entropic input>;
//! let keypair: salty::Keypair = salty::Keypair::from(&seed);
//! ```
//!
//! Any byte slice that fits in memory can then be signed (without new
//! entropic input) deterministically via
//!
//! ```ignore
//! let data: &[u8] = <some data>;
//! let signature: salty::Signature = keypair.sign(data);
//! ```
//!
//! Thereafter, the signature can be checked:
//!
//! ```ignore
//! let public_key = &keypair.pubic;
//! assert!(public_key.verify(data, &signature).is_ok());
//! ```
//!
//! Please note that `Ed25519` signatures are *not* init-update-finalize signatures,
//! since two passes over the data are made, sequentially (the output of the first pass
//! is an input to the second pass).
//! For cases where the data to be signed does not fit in memory, as explained in
//! [RFC 8032](rfc-8032) an alternative algorithm `Ed25519ph` ("ph" for prehashed) is
//! defined. This is *not* the same as applying Ed25519 signature to the SHA512 hash of
//! the data; it is is exposed via `Keypair::sign_prehashed` and
//! `PublicKey::verify_prehashed`.
//!
//! Future plans include:
//! - rigorous correctness checks
//! - rigorous checks against timing side-channels, using the DWT cycle count of ARM MCUs
//! - optimize the field operations for Cortex-M4 and above, by using the
//!   implementation provided by Bjoern Haase which is based on the the UMAAL instruction
//!   `(u32, u32, u32, u32) -> u64, (a, b, c, d) -> a*b + c + d`.
//! - add the authenticated encryption part of NaCl
//! - add more lightweight cryptography as alternative
//!
//! Current numbers on an NXP LPC55S69 running at 96Mhz:
//! - signing prehashed message: 52,632,954 cycles
//! - verifying said message: 100,102,158 cycles
//! - code size for this: 19,724 bytes
//! Obviously, this needs to improve :))
//!
//! [tweetnacl]: https://tweetnacl.cr.yp.to/
//! [ed25519-dalek]: https://lib.rs/crates/ed25519-dalek
//! [dalek]: https://dalek.rs/
//! [rfc-8032]: https://tools.ietf.org/html/rfc8032/


/// Extensible error type for all `salty` operations.
///
/// This enum has a hidden member, to prevent exhaustively checking for errors.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Error {
    /// Signature verification failed
    SignatureInvalid,

    #[doc(hidden)]
    _Extensible,
}

/// Result type for all `salty` operations.
pub type Result<T = ()> = core::result::Result<T, Error>;

pub mod constants;

/// Self-contained implementation of SHA512
mod hash;
pub use hash::Sha512;

/// Implementation of underlying curve base field arithmetic
mod field;

mod scalar;
pub use scalar::Scalar;

mod curve;
pub use curve::{CurvePoint, CompressedY};

mod keys;
pub use keys::{SecretKey, PublicKey, Keypair, Signature};


// mod internal;

// mod traits;

// /// The base field Z mod 2^255 - 19
// // #[cfg(feature = "cortex-m4")]
// // pub mod field_haase as field;
// // #[!cfg(feature = "cortex-m4")]
// // pub mod field_tweetnacl as field;
// pub mod field;
// // pub mod field_haase;
// /// The twisted Edwards curve
// pub mod curve;
// /// SHA-512
// pub mod hash;
// /// Ed25519 signatures
// pub mod sign;

// // pub mod field_common;

// #[cfg(test)]
// mod tests;
