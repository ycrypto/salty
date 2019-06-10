trait Signature {
    pub fn generate_keypair(secret_key: &mut SecretKey, public_key: &mut PublicKey) {}
    pub fn sign(message: &[u8], secret_key: &SecretKey) {}
}
