#![no_std]

// pub mod types;
// pub mod implementations;

use byteorder::{BigEndian, ByteOrder, LittleEndian};

pub const PUBLIC_KEY_BYTES: usize = 32;
pub const SECRET_KEY_BYTES: usize = 32;
pub const SHA256_BYTES: usize = 64;
pub const SHA512_BYTES: usize = 64;

struct SigningPublicKey(pub [u8; PUBLIC_KEY_BYTES]);
struct SigningSecretKey(pub [u8; SECRET_KEY_BYTES]);

pub mod hash {
    use byteorder::{BigEndian, ByteOrder};
    use core::num::Wrapping;

    #[allow(non_snake_case)]
    // this is `rotate-right(x, n)` for 64-bit words
    // implicitly, 0 <= n < 64
    fn R(w: Wrapping<u64>, n: usize) -> Wrapping<u64> {
        (w >> n) | (w << (64 - n))
    }
    #[allow(non_snake_case)]
    // this is "choose", input `x` picks the output bit from y or z:
    // if bit `i` of `x` is 1, then output is bit `i` from `y`,
    // else bit `i` from `z`.
    fn Ch(x: Wrapping<u64>, y: Wrapping<u64>, z: Wrapping<u64>) -> Wrapping<u64> {
        (x & y) ^ (!x & z)
    }
    #[allow(non_snake_case)]
    // this is "majority", each bit is the majority of the
    // three input bits of x, y, z at this index
    fn Maj(x: Wrapping<u64>, y: Wrapping<u64>, z: Wrapping<u64>) -> Wrapping<u64> {
        (x & y) ^ (x & z) ^ (y & z)
    }
    #[allow(non_snake_case)]
    fn Sigma0(x: Wrapping<u64>) -> Wrapping<u64> {
        R(x, 28) ^ R(x, 34) ^ R(x, 39)
    }
    #[allow(non_snake_case)]
    fn Sigma1(x: Wrapping<u64>) -> Wrapping<u64> {
        R(x, 14) ^ R(x, 18) ^ R(x, 41)
    }
    fn sigma0(x: Wrapping<u64>) -> Wrapping<u64> {
        R(x, 1) ^ R(x, 8) ^ (x >> 7)
    }
    fn sigma1(x: Wrapping<u64>) -> Wrapping<u64> {
        R(x, 19) ^ R(x, 61) ^ (x >> 6)
    }

    #[rustfmt::skip]
    // fyi, these are the first 64 bits of the fractional parts of
    // the cube roots of the first 80 primes
    static K: [u64; 80] = [
      0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
      0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
      0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
      0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
      0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
      0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
      0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
      0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
      0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
      0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
      0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
      0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
      0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
      0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
      0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
      0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
      0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
      0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
      0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
      0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
    ];

    fn hash_blocks(digest: &mut [u8; 64], msg: &[u8]) -> usize {
        #![allow(non_snake_case)]

        // convert digest (u8-array) into hash parts (u64-words array)
        let mut H: [Wrapping<u64>; 8] = Default::default();//[Wrapping(0); 8];
        for (h, chunk) in H.iter_mut().zip(digest.chunks(8)) {
            *h = Wrapping(BigEndian::read_u64(chunk));
        }

        let unprocessed = msg.len() & 127; // remainder modulo 128
        for block in msg[..msg.len() - unprocessed].chunks(128) {

            // W is the "message schedule", it is updated below
            let mut W: [Wrapping<u64>; 16] = Default::default();//[Wrapping(0); 16];
            for (w, chunk) in W.iter_mut().zip(block.chunks(8)) {
                *w = Wrapping(BigEndian::read_u64(chunk));
            }

            // initialize "working variables" with previous hash
            let mut a = H[0];
            let mut b = H[1];
            let mut c = H[2];
            let mut d = H[3];
            let mut e = H[4];
            let mut f = H[5];
            let mut g = H[6];
            let mut h = H[7];

            // apply 80 rounds
            for t in 0..80 {
                let T1 = h + Sigma1(e) + Ch(e, f, g) + Wrapping(K[t]) + W[t % 16];
                let T2 = Sigma0(a) + Maj(a, b, c);
                h = g;
                g = f;
                f = e;
                e = d + T1;
                d = c;
                c = b;
                b = a;
                a = T1 + T2;

                // update message schedule if necessary
                if t % 16 == 15 {
                    // TODO: need Wprev??
                    // let Wprev = W.clone();
                    // for j in 0..16 {
                    //     W[j] +=      Wprev[(j +  9) % 16]
                    //         + sigma0(Wprev[(j +  1) % 16])
                    //         + sigma1(Wprev[(j + 14) % 16]);
                    // }
                    for j in 0..16 {
                        W[j] +=      W[(j +  9) % 16]
                            + sigma0(W[(j +  1) % 16])
                            + sigma1(W[(j + 14) % 16]);
                    }
                }
            }
            H[0] += a;
            H[1] += b;
            H[2] += c;
            H[3] += d;
            H[4] += e;
            H[5] += f;
            H[6] += g;
            H[7] += h;
        }

        // convert hash parts (u64-words array) back into digest (u8-array)
        for (d, h) in digest.chunks_mut(8).zip(H.iter()) {
            BigEndian::write_u64(d, h.0);
        }

        unprocessed
    }

    #[rustfmt::skip]
    // fyi, these are the first 64 bits of the fractional parts
    // of the square roots of the first 8 primes
    static IV: [u8; 64] = [
      0x6a,0x09,0xe6,0x67,0xf3,0xbc,0xc9,0x08,
      0xbb,0x67,0xae,0x85,0x84,0xca,0xa7,0x3b,
      0x3c,0x6e,0xf3,0x72,0xfe,0x94,0xf8,0x2b,
      0xa5,0x4f,0xf5,0x3a,0x5f,0x1d,0x36,0xf1,
      0x51,0x0e,0x52,0x7f,0xad,0xe6,0x82,0xd1,
      0x9b,0x05,0x68,0x8c,0x2b,0x3e,0x6c,0x1f,
      0x1f,0x83,0xd9,0xab,0xfb,0x41,0xbd,0x6b,
      0x5b,0xe0,0xcd,0x19,0x13,0x7e,0x21,0x79,
    ];

    // generates a 64 bytes hash of the `msg`
    // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
    //
    // steps:
    // - pad message to obtain 128 byte blocks
    // - start with IV
    // - "hash in" each block in turn
    pub fn sha512(digest: &mut [u8; 64], msg: &[u8]) {

        let l = msg.len();
        assert!(l < 2^125);  // u128-encoded length is in bits

        // initialize digest with the initialisation vector
        // let mut h: [u8; 64] = IV.clone();
        digest.copy_from_slice(&IV);

        // hash full (128 bytes) blocks from message
        let unprocessed = hash_blocks(digest, msg);

        // generate padding (can be 1 or 2 blocks of 128 bytes)
        let mut padding: [u8; 256] = [0u8; 256];
        let padding_length = match unprocessed < 112 {
            true => 128,
            false => 256,
        };
        // first: remaining message
        padding[..unprocessed].copy_from_slice(&msg[l - unprocessed..]);
        // then: bit 1 followed by zero bits until...
        padding[unprocessed] = 128;
        // ...message length in bits (NB: l is in bytes)
        padding[padding_length - 9] = (l >> 61) as u8;
        BigEndian::write_u64(&mut padding[padding_length - 8..], (l << 3) as u64);

        let padding = &padding[..padding_length];
        hash_blocks(digest, padding);

        // digest.copy_from_slice(&h);
    }
}

pub mod sign {
    // fn generate_keypair(seed: &[u8; 32], public_key: &mut SigningPublicKey, secret_key: &mut SigningSecretKey) {
    //     // TODO: name `buf` (was: `d`)
    //     let d = hash(secret_key, 32);
    //     d[0] &= 248;
    //     d[31] &= 127;
    //     d[31] |= 64;

    //     public_key.copy_from_slice(secret_key[32..]);
    // }
}

// #[cfg(test)]
mod tests {
    // use super::hash;

    #[test]
    fn test_empty_hash() {
        let mut empty_hash = [0u8; 64];
        super::hash::sha512(&mut empty_hash, &[]);
        #[rustfmt::skip]
        let expected: [u8; 64] = [
            0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd,
            0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
            0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
            0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
            0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
            0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
            0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
            0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e,
        ];
        // println!("{:?}", empty_hash[..8]);
        // println!("{:?}", expected[..8]);
        assert_eq!(empty_hash[..16], expected[..16]);


    }

    #[test]
    fn test_non_empty() {
        let mut digest = [0u8; 64];

        // short example
        super::hash::sha512(&mut digest, &"salty".as_bytes());
        let expected: [u8; 64] = [
            0x34, 0x69, 0x63, 0xb3, 0xd8, 0x46, 0x88, 0x5f,
            0x4a, 0x5c, 0x18, 0x60, 0x51, 0xd0, 0x09, 0x03,
            0x8b, 0x82, 0xc7, 0x48, 0xfb, 0xec, 0xc2, 0x8c,
            0x2c, 0x79, 0x27, 0xc5, 0xf8, 0x80, 0xe2, 0xb3,
            0x60, 0x1b, 0x0e, 0x83, 0x4c, 0xbf, 0xcf, 0xd6,
            0x35, 0x7b, 0xec, 0x8e, 0x01, 0x82, 0xa8, 0xc4,
            0x90, 0x0f, 0xbe, 0xa2, 0x7b, 0x06, 0x0e, 0x5b,
            0xa8, 0xc3, 0x1d, 0x3b, 0xc2, 0xbc, 0xc3, 0x34,
        ];
        assert_eq!(digest[..16], expected[..16]);

        // longer example (>= 122 bytes)
        let example = "saltysaltysaltysaltysaltysaltysaltysaltysaltysaltysaltysaltysaltysaltysaltysaltysaltysaltysaltysaltysaltysaltysaltysaltysalty";
        super::hash::sha512(&mut digest, &example.as_bytes());
        let expected: [u8; 64] = [
            0x57, 0xd3, 0x71, 0x18, 0x15, 0x72, 0x91, 0xbe,
            0x02, 0x6b, 0x72, 0x46, 0x81, 0xb4, 0xcd, 0xb3,
            0xb6, 0xc3, 0x18, 0x78, 0x0e, 0x28, 0x95, 0x85,
            0xb5, 0xed, 0x69, 0x8f, 0x35, 0x4d, 0x54, 0xc9,
            0x1c, 0xfd, 0x6e, 0xd3, 0xfd, 0xf8, 0xb6, 0x0f,
            0x6e, 0x37, 0x41, 0x16, 0x9a, 0x3b, 0xbc, 0xb9,
            0xc1, 0x67, 0x99, 0xf8, 0x45, 0x0c, 0xad, 0x16,
            0x59, 0x18, 0xb9, 0xe9, 0xcb, 0x51, 0x4a, 0x38,
        ];
        assert_eq!(digest[..16], expected[..16]);
    }

}
