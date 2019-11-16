#![no_std]
//! Transliteration of Ed25519 signatures from TweetNaCl to Rust, with helpful explanations.
//!
//! Future plan is to include optimizations of the field operations for Cortex-M4.


pub mod constants;

mod hash;
pub use hash::{
    Digest,
    Hash,
};

mod field;
pub use field::{
    FieldImplementation,
    FieldElement,
};

mod scalar;
pub use scalar::Scalar;

pub mod curve;

// pub mod key;


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
