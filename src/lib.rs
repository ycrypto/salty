#![cfg_attr(not(test), no_std)]
/*!
Mashup of [TweetNaCl](https://tweetnacl.cr.yp.to/) with
[ed25519-dalek](https://lib.rs/crates/ed25519-dalek)
aimed towards embedded use cases on microcontrollers.

For more context, see also the [salty book](https://book.salty.rs).

Originally, this library was a transliteration of the C implementation of
Ed25519 signatures in TweetNaCl to Rust, "with helpful explanations".

Iterating over the not-very-nice API surface of NaCl, we ended up with
a close relative of the "[dalek](https://dalek.rs)" APIs, where things are modeled as,
for instance, "compressed y-coordinate of an Edwards25519 curve point",
instead of raw bytes.

One reason the current ed25519-dalek library in its current state is not
ideal for microcontrollers is that it includes ~40kB of pre-computed data
to speed things up. Moreover, its implementations are optimized for PC.

## Usage

The main entry point of the API is either a keypair, or a public key.

For keypairs, an external trusted source of entropy is assumed, letting
us deterministically construct a keypair as:

```
let seed: [u8; 32] = [42; 32]; // 32 actually entropic bytes
let keypair: salty::Keypair = salty::Keypair::from(&seed);
```

Any byte slice of data that fits in memory can then be signed
deterministically via

```
# let seed: [u8; 32] = [42; 32]; // 32 actually entropic bytes
# let keypair: salty::Keypair = salty::Keypair::from(&seed);
let data: &[u8] = &[1, 2, 3]; // some data
let signature: salty::Signature = keypair.sign(data);
```

Thereafter, the signature can be checked:

```
# let seed: [u8; 32] = [42; 32]; // 32 actually entropic bytes
# let keypair: salty::Keypair = salty::Keypair::from(&seed);
# let data: &[u8] = &[1, 2, 3]; // some data
# let signature: salty::Signature = keypair.sign(data);
let public_key: salty::PublicKey = keypair.public;
assert!(public_key.verify(data, &signature).is_ok());
```

For serialization purposes, the entropic seed *is* the private key (32 bytes).
Both public keys and signatures have `to_bytes()` methods, returning 32 and 64
bytes, respectively.

```
# let seed: [u8; 32] = [42; 32]; // 32 actually entropic bytes
# let keypair: salty::Keypair = salty::Keypair::from(&seed);
# let data: &[u8] = &[1, 2, 3]; // some data
# let signature: salty::Signature = keypair.sign(data);
# let public_key = &keypair.public;
let serialized_public_key: [u8; 32] = public_key.to_bytes();
let serialized_signature: [u8; 64] = signature.to_bytes();
```

Conversely, `PublicKey` implements `TryFrom` (verifying the alleged point actually
lies on the curve), and `Signature` implements `From`.

```
# let seed: [u8; 32] = [42; 32]; // 32 actually entropic bytes
# let keypair: salty::Keypair = salty::Keypair::from(&seed);
# let data: &[u8] = &[1, 2, 3]; // some data
# let signature: salty::Signature = keypair.sign(data);
# let public_key = &keypair.public;
# let serialized_public_key: [u8; 32] = public_key.to_bytes();
# let serialized_signature: [u8; 64] = signature.to_bytes();
use core::convert::TryInto;
let deserialized_public_key: salty::PublicKey = (&serialized_public_key).try_into().unwrap();
let deserialized_signature: salty::Signature = (&serialized_signature).into();
assert!(deserialized_public_key.verify(data, &deserialized_signature).is_ok());
```

Please note that `Ed25519` signatures are *not* init-update-finalize signatures,
since two passes over the data are made, sequentially (the output of the first pass
is an input to the second pass).
For cases where the data to be signed does not fit in memory, as explained in
[RFC 8032](https://tools.ietf.org/html/rfc8032/) an alternative algorithm `Ed25519ph` ("ph" for prehashed) is
defined. This is *not* the same as applying Ed25519 signature to the SHA512 hash of
the data; it is is exposed via `Keypair::sign_prehashed` and
`PublicKey::verify_prehashed`. Additionally, there is the option of using "contexts"
for both regular and prehashed signatures.

## Features
The bulk of time generating and verifying signatures is spent with field operations
in the base field of the underlying elliptic curve. This library has two implementations:
The `tweetnacl` implementation is portable but quite slow, and the `haase` implementation,
which makes use of the `UMAAL` assembly instruction, which is only available on
Cortex-M4 and Cortex-M33 microcontrollers. By default, on these targets the fast implementation
is selected, the `tweetnacl` variant can be triggered with the `slow-motion` feature.

This `UMAAL` operation is a mapping `(a, b, c, d) ⟼ a*b + c + d`, where the inputs are `u32`
and the output is a `u64` (there is no overflow). In the future, we hope to offer a third
implementation, which would do "schoolbook multiplication", but using this operation, e.g.
as a compiler intrinsic. The idea is to have a similarly speedy implementation without the
obscurity of the generated assembly code of the `haase` implementation.

Current numbers on an NXP LPC55S69 running at 96Mhz, with "tweetnacl" implementation:
- signing prehashed message: 52,632,954 cycles
- verifying said message: 100,102,158 cycles
- code size for this: 19,724 bytes

Obviously, this needed to improve.

Current numbers on an NXP LPC55S69 running at 96Mhz, with "haase" implementation:
- signing prehashed message: 8,547,161 cycles
- verifying said message: 16,046,465 cycles
- code size: similar

In both cases, we suggest compiling with at least minimal optimization, to get rid
of the zero-cost abstractions.

## Future

Future plans include:
- rigorous correctness checks
- rigorous checks against timing side-channels, using the DWT cycle count of ARM MCUs
- ensure dropped secrets are `zeroize`d
- add the authenticated encryption part of NaCl
- add X25519, i.e., Diffie-Hellman key agreement
- speedy yet understandable field operations using `UMAAL`

*/

// #[cfg(feature = "extern-panic-halt")]
// extern crate panic_halt;

// use hex_literal::hex;

/// Extensible error type for all `salty` operations.
///
/// This enum has a hidden member, to prevent exhaustively checking for errors.
/// It also has a member `NoError` with value zero, for use in the C API.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(C)]
pub enum Error {
    /// Never occurs, simplifies C bindings
    NoError = 0,

    /// Bytes do not correspond to a canonical base field element
    NonCanonicalFieldElement,

    /// Public key bytes invalid
    PublicKeyBytesInvalid,

    /// Signature verification failed
    SignatureInvalid,

    /// Context for prehashed signatures too long
    ContextTooLong,

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
pub use field::{FieldElement, FieldImplementation};

mod scalar29;

mod scalar;
pub use scalar::Scalar;

mod curve;
pub use curve::{CurvePoint, CompressedY};

mod signature;
pub use signature::{SecretKey, PublicKey, Keypair, Signature};
#[cfg(feature = "cose")]
pub use signature::CosePublicKey;
