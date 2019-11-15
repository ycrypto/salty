use crate::constants::SCALAR_LENGTH;

pub struct Scalar(
    pub (crate) [u8; SCALAR_LENGTH]
);

impl Scalar {
    pub fn from_bytes(bytes: &[u8; SCALAR_LENGTH]) -> Self {
        Scalar(bytes.clone())
    }
}
