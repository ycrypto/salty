#![no_std]
//! Transliteration of Ed25519 signatures from TweetNaCl to Rust, with helpful explanations.
//!
//! Future plan is to include optimizations of the field operations for Cortex-M4.

/// The base field Z mod 2^255 - 19
pub mod field;
/// The twisted Edwards curve
pub mod curve;
/// SHA-512
pub mod hash;
/// Ed25519 signatures
pub mod sign;

#[cfg(test)]
mod tests;
