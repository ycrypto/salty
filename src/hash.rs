use core::num::Wrapping;

use crate::constants::{
    // SHA256_LENGTH,
    SHA512_LENGTH,
};

pub type Digest = [u8; SHA512_LENGTH];

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
    use core::convert::TryInto;

    // convert digest (u8-array) into hash parts (u64-words array)
    let mut H: [Wrapping<u64>; 8] = Default::default(); //[Wrapping(0); 8];
    for (h, chunk) in H.iter_mut().zip(digest.chunks(8)) {
        // *h = Wrapping(BigEndian::read_u64(chunk));
        *h = Wrapping(u64::from_be_bytes(chunk.try_into().unwrap()));
    }

    let unprocessed = msg.len() & 127; // remainder modulo 128
    for block in msg[..msg.len() - unprocessed].chunks(128) {
        // W is the "message schedule", it is updated below
        // This is like Section 6.1.3 from FIPS 180.
        let mut W: [Wrapping<u64>; 16] = Default::default(); //[Wrapping(0); 16];
        for (w, chunk) in W.iter_mut().zip(block.chunks(8)) {
            *w = Wrapping(u64::from_be_bytes(chunk.try_into().unwrap()));
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
                    W[j] +=
                        W[(j + 9) % 16] + sigma0(W[(j + 1) % 16]) + sigma1(W[(j + 14) % 16]);
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
        // BigEndian::write_u64(d, h.0);
        d.copy_from_slice(&h.0.to_be_bytes());
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
// https://dx.doi.org/10.6028/NIST.FIPS.180-4
//
// steps:
// - pad message to obtain 128 byte blocks
// - start with IV
// - "hash in" each block in turn
#[allow(dead_code)]
pub fn sha512(digest: &mut [u8; 64], msg: &[u8]) {
    let l = msg.len();
    // assert!(l >> 125 == 0);  // u128-encoded length is in bits

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
    #[cfg(target_pointer_width = "64")] {
        padding[padding_length - 9] = (l >> 61) as u8;
    }
    // BigEndian::write_u64(&mut padding[padding_length - 8..], (l << 3) as u64);
    padding[padding_length - 8..].copy_from_slice(&((l << 3) as u64).to_be_bytes());

    let padding = &padding[..padding_length];
    hash_blocks(digest, padding);

    // digest.copy_from_slice(&h);
}


/// self-contained Sha512 hash, following TweetNaCl
pub struct Sha512 {
    digest: Digest,
    buffer: [u8; 128],
    unprocessed: usize,
    data_length: usize,
}

impl Sha512 {
    pub fn new() -> Sha512 {
        let mut digest: Digest = [0; SHA512_LENGTH];
        digest.copy_from_slice(&IV);
        Sha512 {
            digest: digest,
            buffer: [0; 128],
            unprocessed: 0,
            data_length: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.data_length += data.len();

        // if self.unprocessed + data.len() < 128 {
        if self.unprocessed + data.len() & !(0x80 - 1) == 0 {
            self.buffer[self.unprocessed..self.unprocessed + data.len()]
                .copy_from_slice(&data);
            self.unprocessed += data.len();
        } else {
            // fill up buffer
            let filler = 128 - self.unprocessed;
            self.buffer[self.unprocessed..]
                .copy_from_slice(&data[..filler]);
            hash_blocks(&mut self.digest, &self.buffer);

            self.unprocessed = hash_blocks(&mut self.digest, &data[filler..]);
            self.buffer[..self.unprocessed]
                .copy_from_slice(&data[data.len() - self.unprocessed..]);
        }
    }

    pub fn updated(mut self, data: &[u8]) -> Self {
        self.update(data);
        self
    }

    //
    // NOT WORKING
    //
    // pub fn new_update(&mut self, data: &[u8]) {
    //     self.data_length += data.len();

    //     let mut data_ref = data;
    //     if self.unprocessed + data.len() >= 128 {
    //         let filler = 128 - self.unprocessed;
    //         self.buffer[self.unprocessed..]
    //             .copy_from_slice(&data[..filler]);
    //         hash_blocks(&mut self.digest, &self.buffer);
    //         data_ref = &data[filler..];
    //     }
    //     if data_ref.len() >= 128 {
    //         self.unprocessed = hash_blocks(&mut self.digest, &data_ref);
    //     } else {
    //         self.unprocessed = data_ref.len();
    //     }
    //     self.buffer[..self.unprocessed]
    //         .copy_from_slice(&data_ref[data_ref.len() - self.unprocessed..]);
    // }

    pub fn finalize(mut self) -> Digest {
        // generate padding (can be 1 or 2 blocks of 128 bytes)
        let mut padding: [u8; 256] = [0u8; 256];
        let padding_length = match self.unprocessed < 112 {
            true => 128,
            false => 256,
        };
        // first: remaining message
        padding[..self.unprocessed].copy_from_slice(&self.buffer[..self.unprocessed]);
        // then: bit 1 followed by zero bits until...
        padding[self.unprocessed] = 128;
        // ...message length in bits (NB: l is in bytes)

        #[cfg(target_pointer_width = "64")] {
            padding[padding_length - 9] = (self.data_length >> 61) as u8;
        }

        // BigEndian::write_u64(&mut padding[padding_length - 8..], (self.data_length << 3) as u64);
        // padding[padding_length - 8..].copy_from_slice(&((self.data_length << 3) as u64).to_be_bytes());
        padding[padding_length - 8..padding_length].copy_from_slice(&((self.data_length << 3) as u64).to_be_bytes());

        let padding = &padding[..padding_length];
        hash_blocks(&mut self.digest, padding);

        self.digest
    }
}
