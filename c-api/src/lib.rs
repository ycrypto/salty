#![no_std]
// This is about `Error` as return type not being FFI-safe
// due to it being non-exhaustive
#![allow(improper_ctypes_definitions)]

extern crate panic_halt;

pub use salty::Error;

use salty::{Keypair, PublicKey, Signature};

// these are skipped instead of converted to defines
// if we `pub use salty::constants::{...}`.
pub const FIELD_ELEMENT_LENGTH: usize = 32;
pub const PUBLICKEY_SERIALIZED_LENGTH: usize = 32;
pub const SECRETKEY_SEED_LENGTH: usize = 32;
pub const SIGNATURE_SERIALIZED_LENGTH: usize = 64;
pub const SHA512_LENGTH: usize = 64;

#[no_mangle]
/// Generates a public key from a secret seed. Use to verify signatures.
/// # Safety
/// These are C-bindings
pub unsafe extern "C" fn salty_public_key(
    seed: &[u8; SECRETKEY_SEED_LENGTH],
    public_key: &mut [u8; PUBLICKEY_SERIALIZED_LENGTH],
) {
    let keypair = Keypair::from(seed);
    public_key.copy_from_slice(keypair.public.compressed.as_bytes());
}

#[no_mangle]
/// Signs the data, based on the keypair generated from the secret seed.
/// # Safety
/// These are C-bindings
pub unsafe extern "C" fn salty_sign(
    seed: &[u8; SECRETKEY_SEED_LENGTH],
    data_ptr: *const u8,
    data_len: usize,
    signature: &mut [u8; SIGNATURE_SERIALIZED_LENGTH],
) {
    let keypair = Keypair::from(seed);
    let data = core::slice::from_raw_parts(data_ptr, data_len);

    signature.copy_from_slice(&keypair.sign(data).to_bytes());
}

#[no_mangle]
/// Signs the data for a given context, based on the keypair generated
/// from the secret seed.
/// # Safety
/// These are C-bindings
pub unsafe extern "C" fn salty_sign_with_context(
    seed: &[u8; SECRETKEY_SEED_LENGTH],
    data_ptr: *const u8,
    data_len: usize,
    context_ptr: *const u8,
    context_len: usize,
    signature: &mut [u8; SIGNATURE_SERIALIZED_LENGTH],
) -> Error {
    if context_len > 255 {
        return Error::ContextTooLong;
    }
    let keypair = Keypair::from(seed);
    let data = core::slice::from_raw_parts(data_ptr, data_len);
    let context = core::slice::from_raw_parts(context_ptr, context_len);

    signature.copy_from_slice(&keypair.sign_with_context(data, context).to_bytes());
    Error::NoError
}

#[no_mangle]
/// Signs the prehashed data, based on the keypair generated from the secret seed.
/// An optional context can also be passed (this is recommended).
/// # Safety
/// These are C-bindings
pub unsafe extern "C" fn salty_sign_prehashed(
    seed: &[u8; SECRETKEY_SEED_LENGTH],
    prehashed_data: &[u8; SHA512_LENGTH],
    context_ptr: *const u8,
    context_len: usize,
    signature: &mut [u8; SIGNATURE_SERIALIZED_LENGTH],
) -> Error {
    if context_len > 255 {
        return Error::ContextTooLong;
    }
    let keypair = Keypair::from(seed);
    let context = core::slice::from_raw_parts(context_ptr, context_len);

    signature.copy_from_slice(
        &keypair
            .sign_prehashed(prehashed_data, Some(context))
            .to_bytes(),
    );

    Error::NoError
}

#[no_mangle]
/// Verify a presumed signature on the given data.
/// # Safety
/// These are C-bindings
pub unsafe extern "C" fn salty_verify(
    public_key: &[u8; PUBLICKEY_SERIALIZED_LENGTH],
    data_ptr: *const u8,
    data_len: usize,
    signature: &[u8; SIGNATURE_SERIALIZED_LENGTH],
) -> Error {
    let maybe_public_key = PublicKey::try_from(public_key);
    if maybe_public_key.is_err() {
        return maybe_public_key.err().unwrap();
    }
    let public_key = maybe_public_key.unwrap();

    let data = core::slice::from_raw_parts(data_ptr, data_len);
    let signature = Signature::from(signature);
    let verification = public_key.verify(data, &signature);

    if verification.is_err() {
        return verification.err().unwrap();
    }
    Error::NoError
}

#[no_mangle]
/// Verify a presumed signature on the given data.
/// # Safety
/// These are C-bindings
pub unsafe extern "C" fn salty_verify_with_context(
    public_key: &[u8; PUBLICKEY_SERIALIZED_LENGTH],
    data_ptr: *const u8,
    data_len: usize,
    signature: &[u8; SIGNATURE_SERIALIZED_LENGTH],
    context_ptr: *const u8,
    context_len: usize,
) -> Error {
    if context_len > 255 {
        return Error::ContextTooLong;
    }
    let maybe_public_key = PublicKey::try_from(public_key);
    if maybe_public_key.is_err() {
        return maybe_public_key.err().unwrap();
    }
    let public_key = maybe_public_key.unwrap();

    let data = core::slice::from_raw_parts(data_ptr, data_len);
    let signature = Signature::from(signature);
    let context = core::slice::from_raw_parts(context_ptr, context_len);
    let verification = public_key.verify_with_context(data, &signature, context);
    if verification.is_err() {
        return verification.err().unwrap();
    }
    Error::NoError
}

#[no_mangle]
/// Verify a presumed signature on the given data.
/// # Safety
/// These are C-bindings
pub unsafe extern "C" fn salty_verify_prehashed(
    public_key: &[u8; PUBLICKEY_SERIALIZED_LENGTH],
    prehashed_data: &[u8; SHA512_LENGTH],
    signature: &[u8; SIGNATURE_SERIALIZED_LENGTH],
    context_ptr: *const u8,
    context_len: usize,
) -> Error {
    if context_len > 255 {
        return Error::ContextTooLong;
    }
    let maybe_public_key = PublicKey::try_from(public_key);
    if maybe_public_key.is_err() {
        return maybe_public_key.err().unwrap();
    }
    let public_key = maybe_public_key.unwrap();
    let signature = Signature::from(signature);
    let context = core::slice::from_raw_parts(context_ptr, context_len);
    let verification = public_key.verify_prehashed(prehashed_data, &signature, Some(context));
    if verification.is_err() {
        return verification.err().unwrap();
    }
    Error::NoError
}

#[no_mangle]
/// Perform X25519 key agreement.
/// # Safety
/// These are C-bindings
pub unsafe extern "C" fn salty_agree(
    scalar: &[u8; SECRETKEY_SEED_LENGTH],
    input_u: &[u8; FIELD_ELEMENT_LENGTH],
    output_u: &mut [u8; FIELD_ELEMENT_LENGTH],
) {
    let shared_secret = salty::agreement::x25519(*scalar, *input_u);
    output_u.copy_from_slice(&shared_secret);
}
