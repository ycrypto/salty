use crate::constants::SCALAR_LENGTH;

pub struct Scalar(
    pub (crate) [u8; SCALAR_LENGTH]
);

impl Scalar {
    #[allow(non_snake_case)]
    const L: [u64; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0x10,
    ];

    pub fn from_bytes(bytes: &[u8; SCALAR_LENGTH]) -> Self {
        Scalar(bytes.clone())
    }

    pub(crate) fn modulo_group_order(x: &mut [i64; 64]) -> Scalar {
        #[allow(non_snake_case)]
        let L = Scalar::L;
        for i in (32..=63).rev() {
            let mut carry: i64 = 0;
            for j in (i - 32)..(i - 12) {
                // x[j] += carry - 16 * x[i] * L[j - (i - 32)];
                // C code doesn't care about u64 vs i64...
                x[j] += carry - 16 * x[i] * L[j - (i - 32)] as i64;
                carry = (x[j] + 128) >> 8;
                x[j] -= carry << 8;
            }
            // x[j] += carry;  // C code uses out-of-scope variable j
            x[i - 12] += carry;
            x[i] = 0;
        }

        let mut carry: i64 = 0;
        for j in 0..32 {
            // x[j] += carry - (x[31] >> 4) * L[j];
            x[j] += carry - (x[31] >> 4) * L[j] as i64;
            carry = x[j] >> 8;
            x[j] &= 0xff;
        }

        for j in 0..32 {
            // x[j] -= carry * L[j];
            x[j] -= carry * L[j] as i64;
        }

        let mut r: [u8; 32] = Default::default();
        for i in 0 ..32 {
            x[i + 1] += x[i] >> 8;
            // r[i] = x[i] & 0xff;
            r[i] = ((x[i] as u64) & 0xff) as u8;
        }

        Scalar(r)

    }

    pub fn from_u512(x: &[u8; 64]) -> Scalar {
        let mut x64: [i64; 64] = [0; 64];//Default::default();
        for i in 0..64 {
            x64[i] = x[i] as i64;
        }

        Scalar::modulo_group_order(&mut x64)
    }

}
