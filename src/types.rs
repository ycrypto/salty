pub const PUBLIC_KEY_BYTES: usize = 32;
pub const SECRET_KEY_BYTES: usize = 32;
pub const SHA256_BYTES: usize = 64;
pub const SHA512_BYTES: usize = 64;

struct SigningPublicKey(pub [u8; PUBLIC_KEY_BYTES]);
struct SigningSecretKey(pub [u8; SECRET_KEY_BYTES]);

// struct Signature(pub [u8;
// struct SignedMessage {
//     message: &
//     signature:
// }
