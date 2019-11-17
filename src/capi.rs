use core::convert::TryFrom;

use crate::{
    Error,
    constants::{
        SECRETKEY_SEED_LENGTH,
        PUBLICKEY_SERIALIZED_LENGTH,
        SIGNATURE_SERIALIZED_LENGTH,
        SHA512_LENGTH,
    },
    keys::{
        Keypair,
        // SecretKey,
        PublicKey,
        Signature,
    },
};

// TODO: Define the error codes

// #[no_mangle]
// pub unsafe extern "C" fn precalculate_keypair(
//     seed: &[u8; SECRETKEY_SEED_LENGTH],
//     public_key: &mut [u8; PUBLICKEY_SERIALIZED_LENGTH],
// ) {
//     let keypair = Keypair::from(seed);
//     public_key.copy_from_slice(keypair.public.compressed.as_bytes());
// }

#[no_mangle]
/// Generates a public key from a secret seed. Use to verify signatures.
pub unsafe extern "C" fn salty_public_key(
    seed: &[u8; SECRETKEY_SEED_LENGTH],
    public_key: &mut [u8; PUBLICKEY_SERIALIZED_LENGTH],
) {
    let keypair = Keypair::from(seed);
    public_key.copy_from_slice(keypair.public.compressed.as_bytes());
}

#[no_mangle]
/// Signs the data, based on the keypair generated from the secret seed.
pub unsafe extern "C" fn salty_sign(
    seed: &[u8; SECRETKEY_SEED_LENGTH],
    data_ptr: *const u8,
    data_len: usize,
    signature: &mut [u8; SIGNATURE_SERIALIZED_LENGTH],
) {
    let keypair = Keypair::from(seed);
    let data = core::slice::from_raw_parts(data_ptr, data_len);

    signature.copy_from_slice(
        &keypair.sign(data).to_bytes()
    );
}

#[no_mangle]
/// Signs the prehashed data, based on the keypair generated from the secret seed.
/// An optional context can also be passed (this is recommended).
pub unsafe extern "C" fn salty_sign_prehashed(
    seed: &[u8; SECRETKEY_SEED_LENGTH],
    prehashed_data: &[u8; SHA512_LENGTH],
    context_ptr: *const u8,
    context_len: usize,
    signature: &mut [u8; SIGNATURE_SERIALIZED_LENGTH],
) -> i8 {
    // if context_len > 255 {
    //     return 1;
    // }
    let keypair = Keypair::from(seed);
    let context = core::slice::from_raw_parts(context_ptr, context_len);

    signature.copy_from_slice(
        &keypair.sign_prehashed(prehashed_data, Some(context))
        .to_bytes()
    );

    return 0;
}

#[no_mangle]
/// Verify a presumed signature on the given data.
pub unsafe extern "C" fn salty_verify(
    public_key: &[u8; PUBLICKEY_SERIALIZED_LENGTH],
    data_ptr: *const u8,
    data_len: usize,
    signature: &[u8; SIGNATURE_SERIALIZED_LENGTH],
) -> Error {
    let maybe_public_key = PublicKey::try_from(public_key);
    if maybe_public_key.is_err() {
        return maybe_public_key.err().unwrap()
    }
    let public_key = maybe_public_key.unwrap();
    let data = core::slice::from_raw_parts(data_ptr, data_len);
    let signature = Signature::from(signature);
    let verification = public_key.verify(data, &signature);
    if verification.is_err() {
        return verification.err().unwrap()
    }
    return Error::NoError;
}

#[no_mangle]
/// Verify a presumed signature on the given data.
pub unsafe extern "C" fn salty_verify_prehashed(
    public_key: &[u8; PUBLICKEY_SERIALIZED_LENGTH],
    prehashed_data: &[u8; SHA512_LENGTH],
    signature: &[u8; SIGNATURE_SERIALIZED_LENGTH],
    context_ptr: *const u8,
    context_len: usize,
) -> Error {
    // if context_len > 255 {
    //     return 1;
    // }
    let maybe_public_key = PublicKey::try_from(public_key);
    if maybe_public_key.is_err() {
        return maybe_public_key.err().unwrap()
    }
    let public_key = maybe_public_key.unwrap();
    let signature = Signature::from(signature);
    let context = core::slice::from_raw_parts(context_ptr, context_len);
    let verification = public_key.verify_prehashed(prehashed_data, &signature, Some(context));
    if verification.is_err() {
        return verification.err().unwrap()
    }
    return Error::NoError;
}

