/// the length of a SHA256 digest
pub const SHA256_LENGTH: usize = 64;
/// the length of a SHA512 digest
pub const SHA512_LENGTH: usize = 64;

/// the length of a scalar (module structure on Edwards25519 curve)
pub const SCALAR_LENGTH: usize = 32;

/// the length of the seed part of a secret key (internal)
pub const SECRETKEY_SEED_LENGTH: usize = 32;
/// the length of the scalar part of a secret key (internal)
pub const SECRETKEY_SCALAR_LENGTH: usize = 32;
/// the length of the nonce part of a secret key (internal)
pub const SECRETKEY_NONCE_LENGTH: usize = 32;
/// the length of a compressed point
pub const COMPRESSED_Y_LENGTH: usize = 32;

/// the length of a public key when serialized
pub const PUBLICKEY_SERIALIZED_LENGTH: usize = 32;

/// the length of a secret key when serialized
pub const SECRETKEY_SERIALIZED_LENGTH: usize = 32;

/// the length of a signature when serialized
pub const SIGNATURE_SERIALIZED_LENGTH: usize = 64;

