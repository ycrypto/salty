// https://github.com/FiloSottile/mostly-harmless/blob/30a2d72/ed25519vectors/ed25519vectors.json

#[cfg(test)]
mod tests {

    extern crate hex;
    extern crate array_tool;

    use std::fs;
    use array_tool::vec::Intersect;
    use core::convert::TryFrom;
    use hex::FromHex;
    use serde::{Deserialize};

    use salty::{PublicKey, Signature};
    use salty::constants::{PUBLICKEY_SERIALIZED_LENGTH, SIGNATURE_SERIALIZED_LENGTH};

    #[derive(Clone, Deserialize, PartialEq, Debug)]
    enum Flag {
        LowOrderA,
        LowOrderComponentA,
        NonCanonicalA,
        LowOrderR,
        LowOrderComponentR,
        NonCanonicalR,
        LowOrderResidue,
    }

    #[derive(Deserialize, Debug)]
    struct TestVector {
        #[serde(rename = "A")]
        a: String,
        #[serde(rename = "R")]
        r: String,
        #[serde(rename = "S")]
        s: String,
        #[serde(rename = "M")]
        msg: String,
        #[serde(rename = "Flags")]
        flags: Option<Vec<Flag>>,
    }

    #[test]
    fn ed25519_test_case() {
        let file = fs::File::open("tests/vectors/ed25519.json")
            .expect("File should open read only");
        let data: Vec<TestVector> = serde_json::from_reader(file)
            .expect("File should be proper JSON");

        for vector in data.iter() {
            // deser PublicKey from hex string for a
            let pk_bytes = <[u8; PUBLICKEY_SERIALIZED_LENGTH]>::from_hex(&vector.a).expect("A should be in hex");
            let pk = PublicKey::try_from(&pk_bytes);

            // deser Signature from hex string for r, s
            const HALF_LENGTH: usize = SIGNATURE_SERIALIZED_LENGTH / 2;
            let r = <[u8; HALF_LENGTH]>::from_hex(&vector.r).expect("R should be in hex");
            let s = <[u8; HALF_LENGTH]>::from_hex(&vector.s).expect("S should be in hex");
            let mut signature_bytes: [u8; SIGNATURE_SERIALIZED_LENGTH] = [0; SIGNATURE_SERIALIZED_LENGTH];
            signature_bytes[..HALF_LENGTH].copy_from_slice(&r);
            signature_bytes[HALF_LENGTH..].copy_from_slice(&s);
            let sig = Signature::try_from(&signature_bytes);

            // https://github.com/golang/go/blob/79b2e14/src/crypto/ed25519/ed25519vectors_test.go#L42
            let expected_to_verify = match &vector.flags {
                None => true,
                // Flag::LowOrderResidue
                //   We use the simplified verification formula that doesn't multiply
                //   by the cofactor, so any low order residue will cause the
                //   signature not to verify.
                //   This is allowed, but not required, by RFC 8032.
                //
                // Flag::NonCanonicalR
                //   Our point decoding allows non-canonical encodings (in violation
                //   of RFC 8032) but R is not decoded: instead, R is recomputed and
                //   compared bytewise against the canonical encoding.
                Some(flags) => flags.intersect(vec![Flag::LowOrderResidue, Flag::NonCanonicalR]).is_empty()
            };

            let result = pk.unwrap().verify(&vector.msg.as_bytes(), &sig.unwrap());
            assert_eq!(result.is_ok(), expected_to_verify);
        }
    }
}
