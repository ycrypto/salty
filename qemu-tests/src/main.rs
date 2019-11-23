#![no_std]
#![no_main]

use core::convert::TryFrom;
extern crate panic_semihosting;
// use cortex_m::peripheral::{DWT, Peripherals};
use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprintln};
use hex_literal::hex;

use salty::{
    FieldElement,
    FieldImplementation,
};

// use subtle::ConstantTimeEq;

// pub fn get_cycle_count() -> u32 {
//     unsafe { (*DWT::ptr()).cyccnt.read() }
// }

fn test_empty_hash() {
    let empty_hash = salty::Sha512::new().updated(&[]).finalize();
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
    assert_eq!(empty_hash[..16], expected[..16]);
}

fn test_arithmetic() {

    let one = FieldElement::ONE;
    let two = &one + &one;
    let three = &two + &one;

    let mut raw_six = FieldElement::default();
    raw_six.0[0] = 6;

    // no multiplications, just sum up ONEs
    let six = (1..=6).fold(FieldElement::ZERO, |partial_sum, _| &partial_sum + &FieldElement::ONE);

    assert_eq!(raw_six.to_bytes(), six.to_bytes());

    let two_times_three = &two * &three;
    assert_eq!(two_times_three.to_bytes(), six.to_bytes());
}

#[allow(dead_code)]
fn test_negation() {
    let d2 = FieldElement::D2;
    let minus_d2 = -&d2;
    let maybe_zero = &d2 + &minus_d2;

    assert_eq!(FieldElement::ZERO.to_bytes(), maybe_zero.to_bytes());
}

#[allow(dead_code)]
fn test_inversion() {
    let d2 = FieldElement::D2;
    let maybe_inverse = d2.inverse();
    let maybe_one = &d2 * &maybe_inverse;

    assert_eq!(maybe_one, FieldElement::ONE);
}

#[allow(dead_code)]
fn test_signature() {
    #![allow(non_snake_case)]

    let seed: [u8; 32] = [
        0x35, 0xb3, 0x07, 0x76, 0x17, 0x9a, 0x78, 0x58,
        0x34, 0xf0, 0x4c, 0x82, 0x88, 0x59, 0x5d, 0xf4,
        0xac, 0xa1, 0x0b, 0x33, 0xaa, 0x12, 0x10, 0xad,
        0xec, 0x3e, 0x82, 0x47, 0x25, 0x3e, 0x6c, 0x65,
    ];

    let keypair = salty::Keypair::from(&seed);

    let data = "salty!".as_bytes();

    let R_expected = [
        0xec, 0x97, 0x27, 0x40, 0x07, 0xe7, 0x08, 0xc6,
        0xd1, 0xee, 0xd6, 0x01, 0x9f, 0x5d, 0x0f, 0xcb,
        0xe1, 0x8a, 0x67, 0x70, 0x8d, 0x17, 0x92, 0x4b,
        0x95, 0xdb, 0x7e, 0x35, 0xcc, 0xaa, 0x06, 0x3a,
    ];

    let S_expected = [
        0xb8, 0x64, 0x8c, 0x9b, 0xf5, 0x48, 0xb0, 0x09,
        0x90, 0x6f, 0xa1, 0x31, 0x09, 0x0f, 0xfe, 0x85,
        0xa1, 0x7e, 0x89, 0x99, 0xb8, 0xc4, 0x2c, 0x97,
        0x32, 0xf9, 0xa6, 0x44, 0x2a, 0x17, 0xbc, 0x09,
    ];

    // sign
    // let before = get_cycle_count();
    let signature = keypair.sign(&data);
    // let after = get_cycle_count();
    // hprintln!("keypair.sign took {} cycles", after - before).ok();

    // check signature is as expected
    assert_eq!(signature.r.to_bytes(), R_expected);
    assert_eq!(signature.s.to_bytes(), S_expected);

    // verify signature
    let public_key = keypair.public;
    let verification = public_key.verify(&data, &signature);
    assert!(verification.is_ok());
}

fn test_ed25519_rfc_8032_test_1() {
    let seed = hex!("
        9d61b19deffd5a60ba844af492ec2cc4
        4449c5697b326919703bac031cae7f60
    ");
    let public_key = hex!("
        d75a980182b10ab7d54bfed3c964073a
        0ee172f3daa62325af021a68f707511a
    ");
    let message: [u8; 0] = [];
    let expected_signature = hex!("
        e5564300c360ac729086e2cc806e828a
        84877f1eb8e5d974d873e06522490155
        5fb8821590a33bacc61e39701cf9b46b
        d25bf5f0595bbe24655141438e7a100b
    ");

    let keypair = salty::Keypair::from(&seed);
    assert_eq!(&keypair.public, &salty::PublicKey::try_from(&public_key).unwrap());
    let signature = keypair.sign(&message);

    assert_eq!(&signature, &salty::Signature::from(&expected_signature));
}

fn test_ed25519_rfc_8032_test_2() {
    let seed = hex!("
        4ccd089b28ff96da9db6c346ec114e0f
        5b8a319f35aba624da8cf6ed4fb8a6fb
    ");
    let public_key = hex!("
        3d4017c3e843895a92b70aa74d1b7ebc
        9c982ccf2ec4968cc0cd55f12af4660c
    ");
    let message: [u8; 1] = [0x72];
    let expected_signature = hex!("
        92a009a9f0d4cab8720e820b5f642540
        a2b27b5416503f8fb3762223ebdb69da
        085ac1e43e15996e458f3613d0f11d8c
        387b2eaeb4302aeeb00d291612bb0c00
    ");

    let keypair = salty::Keypair::from(&seed);
    assert_eq!(&keypair.public, &salty::PublicKey::try_from(&public_key).unwrap());
    let signature = keypair.sign(&message);

    assert_eq!(&signature, &salty::Signature::from(&expected_signature));
}

fn test_ed25519_rfc_8032_test_3() {
    let seed = hex!("
        c5aa8df43f9f837bedb7442f31dcb7b1
        66d38535076f094b85ce3a2e0b4458f7
    ");
    let public_key = hex!("
        fc51cd8e6218a1a38da47ed00230f058
        0816ed13ba3303ac5deb911548908025
    ");
    let message: [u8; 2] = hex!("af82");
    let expected_signature = hex!("
        6291d657deec24024827e69c3abe01a3
        0ce548a284743a445e3680d7db5ac3ac
        18ff9b538d16f290ae67f760984dc659
        4a7c15e9716ed28dc027beceea1ec40a
    ");

    let keypair = salty::Keypair::from(&seed);
    assert_eq!(&keypair.public, &salty::PublicKey::try_from(&public_key).unwrap());
    let signature = keypair.sign(&message);

    assert_eq!(&signature, &salty::Signature::from(&expected_signature));
}

fn test_ed25519_rfc_8032_test_1024() {
    let seed = hex!("
        f5e5767cf153319517630f226876b86c
        8160cc583bc013744c6bf255f5cc0ee5
    ");
    let public_key = hex!("
        278117fc144c72340f67d0f2316e8386
        ceffbf2b2428c9c51fef7c597f1d426e
    ");
    let message: [u8; 1023] = hex!("
        08b8b2b733424243760fe426a4b54908
        632110a66c2f6591eabd3345e3e4eb98
        fa6e264bf09efe12ee50f8f54e9f77b1
        e355f6c50544e23fb1433ddf73be84d8
        79de7c0046dc4996d9e773f4bc9efe57
        38829adb26c81b37c93a1b270b20329d
        658675fc6ea534e0810a4432826bf58c
        941efb65d57a338bbd2e26640f89ffbc
        1a858efcb8550ee3a5e1998bd177e93a
        7363c344fe6b199ee5d02e82d522c4fe
        ba15452f80288a821a579116ec6dad2b
        3b310da903401aa62100ab5d1a36553e

        06203b33890cc9b832f79ef80560ccb9
        a39ce767967ed628c6ad573cb116dbef
        efd75499da96bd68a8a97b928a8bbc10
        3b6621fcde2beca1231d206be6cd9ec7
        aff6f6c94fcd7204ed3455c68c83f4a4
        1da4af2b74ef5c53f1d8ac70bdcb7ed1
        85ce81bd84359d44254d95629e9855a9
        4a7c1958d1f8ada5d0532ed8a5aa3fb2
        d17ba70eb6248e594e1a2297acbbb39d
        502f1a8c6eb6f1ce22b3de1a1f40cc24
        554119a831a9aad6079cad88425de6bd
        e1a9187ebb6092cf67bf2b13fd65f270
        88d78b7e883c8759d2c4f5c65adb7553
        878ad575f9fad878e80a0c9ba63bcbcc
        2732e69485bbc9c90bfbd62481d9089b
        eccf80cfe2df16a2cf65bd92dd597b07
        07e0917af48bbb75fed413d238f5555a
        7a569d80c3414a8d0859dc65a46128ba
        b27af87a71314f318c782b23ebfe808b
        82b0ce26401d2e22f04d83d1255dc51a
        ddd3b75a2b1ae0784504df543af8969b
        e3ea7082ff7fc9888c144da2af58429e
        c96031dbcad3dad9af0dcbaaaf268cb8
        fcffead94f3c7ca495e056a9b47acdb7
        51fb73e666c6c655ade8297297d07ad1
        ba5e43f1bca32301651339e22904cc8c
        42f58c30c04aafdb038dda0847dd988d
        cda6f3bfd15c4b4c4525004aa06eeff8
        ca61783aacec57fb3d1f92b0fe2fd1a8
        5f6724517b65e614ad6808d6f6ee34df
        f7310fdc82aebfd904b01e1dc54b2927
        094b2db68d6f903b68401adebf5a7e08
        d78ff4ef5d63653a65040cf9bfd4aca7
        984a74d37145986780fc0b16ac451649
        de6188a7dbdf191f64b5fc5e2ab47b57
        f7f7276cd419c17a3ca8e1b939ae49e4
        88acba6b965610b5480109c8b17b80e1
        b7b750dfc7598d5d5011fd2dcc5600a3
        2ef5b52a1ecc820e308aa342721aac09
        43bf6686b64b2579376504ccc493d97e
        6aed3fb0f9cd71a43dd497f01f17c0e2
        cb3797aa2a2f256656168e6c496afc5f
        b93246f6b1116398a346f1a641f3b041
        e989f7914f90cc2c7fff357876e506b5
        0d334ba77c225bc307ba537152f3f161
        0e4eafe595f6d9d90d11faa933a15ef1
        369546868a7f3a45a96768d40fd9d034
        12c091c6315cf4fde7cb68606937380d

        b2eaaa707b4c4185c32eddcdd306705e
        4dc1ffc872eeee475a64dfac86aba41c
        0618983f8741c5ef68d3a101e8a3b8ca
        c60c905c15fc910840b94c00a0b9d0
    ");
    let expected_signature = hex!("
        0aab4c900501b3e24d7cdf4663326a3a
        87df5e4843b2cbdb67cbf6e460fec350
        aa5371b1508f9f4528ecea23c436d94b
        5e8fcd4f681e30a6ac00a9704a188a03
    ");

    let keypair = salty::Keypair::from(&seed);
    assert_eq!(&keypair.public, &salty::PublicKey::try_from(&public_key).unwrap());
    let signature = keypair.sign(&message);

    assert_eq!(&signature, &salty::Signature::from(&expected_signature));
}

fn test_ed25519_rfc_8032_sha_abc() {
    let seed = hex!("
        833fe62409237b9d62ec77587520911e
        9a759cec1d19755b7da901b96dca3d42
    ");
    let public_key = hex!("
        ec172b93ad5e563bf4932c70e1245034
        c35467ef2efd4d64ebf819683467e2bf
    ");
    let message: [u8; 64] = hex!("
        ddaf35a193617abacc417349ae204131
        12e6fa4e89a97ea20a9eeee64b55d39a
        2192992a274fc1a836ba3c23a3feebbd
        454d4423643ce80e2a9ac94fa54ca49f
    ");
    let expected_signature = hex!("
        dc2a4459e7369633a52b1bf277839a00
        201009a3efbf3ecb69bea2186c26b589
        09351fc9ac90b3ecfdfbc7c66431e030
        3dca179c138ac17ad9bef1177331a704
    ");

    let keypair = salty::Keypair::from(&seed);
    assert_eq!(&keypair.public, &salty::PublicKey::try_from(&public_key).unwrap());
    let signature = keypair.sign(&message);

    assert_eq!(&signature, &salty::Signature::from(&expected_signature));
}

fn test_ed25519_rfc_8032_ctx_foo_bar() {
    let seed = hex!("
        0305334e381af78f141cb666f6199f57
        bc3495335a256a95bd2a55bf546663f6
    ");
    let keypair = salty::Keypair::from(&seed);

    let public_key = hex!("
        dfc9425e4f968f7f0c29f0259cf5f9ae
        d6851c2bb4ad8bfb860cfee0ab248292
    ");
    assert_eq!(&keypair.public, &salty::PublicKey::try_from(&public_key).unwrap());

    let message: [u8; 16] = hex!("
        f726936d19c800494e3fdaff20b276a8
    ");

    let context_foo: [u8; 3] = hex!("666f6f");
    let expected_signature_foo = hex!("
        55a4cc2f70a54e04288c5f4cd1e45a7b
        b520b36292911876cada7323198dd87a
        8b36950b95130022907a7fb7c4e9b2d5
        f6cca685a587b4b21f4b888e4e7edb0d
    ");
    let signature = keypair.sign_with_context(&message, &context_foo);
    assert_eq!(&signature, &salty::Signature::from(&expected_signature_foo));

    let context_bar: [u8; 3] = hex!("626172");
    let expected_signature_bar = hex!("
        fc60d5872fc46b3aa69f8b5b4351d580
        8f92bcc044606db097abab6dbcb1aee3
        216c48e8b3b66431b5b186d1d28f8ee1
        5a5ca2df6668346291c2043d4eb3e90d
    ");
    let signature = keypair.sign_with_context(&message, &context_bar);
    assert_eq!(&signature, &salty::Signature::from(&expected_signature_bar));
}

fn test_ed25519_rfc_8032_ctx_foo2() {
    let seed = hex!("
        0305334e381af78f141cb666f6199f57
        bc3495335a256a95bd2a55bf546663f6
    ");
    let public_key = hex!("
        dfc9425e4f968f7f0c29f0259cf5f9ae
        d6851c2bb4ad8bfb860cfee0ab248292
    ");
    let message: [u8; 16] = hex!("
		508e9e6882b979fea900f62adceaca35
    ");
    // let prehashed_message = salty::Sha512::new().updated(&message).finalize();
    let context: [u8; 3] = hex!("666f6f");
    let expected_signature = hex!("
		8b70c1cc8310e1de20ac53ce28ae6e72
		07f33c3295e03bb5c0732a1d20dc6490
		8922a8b052cf99b7c4fe107a5abb5b2c
		4085ae75890d02df26269d8945f84b0b
    ");

    let keypair = salty::Keypair::from(&seed);
    assert_eq!(&keypair.public, &salty::PublicKey::try_from(&public_key).unwrap());
    let signature = keypair.sign_with_context(&message, &context);

    assert_eq!(&signature, &salty::Signature::from(&expected_signature));
}

fn test_ed25519_rfc_8032_ctx_foo3() {
    let seed = hex!("
        ab9c2853ce297ddab85c993b3ae14bca
        d39b2c682beabc27d6d4eb20711d6560
    ");
    let public_key = hex!("
        0f1d1274943b91415889152e893d80e9
        3275a1fc0b65fd71b4b0dda10ad7d772
    ");
    let message: [u8; 16] = hex!("
        f726936d19c800494e3fdaff20b276a8
    ");
    // let prehashed_message = salty::Sha512::new().updated(&message).finalize();
    let context: [u8; 3] = hex!("666f6f");
    let expected_signature = hex!("
        21655b5f1aa965996b3f97b3c849eafb
        a922a0a62992f73b3d1b73106a84ad85
        e9b86a7b6005ea868337ff2d20a7f5fb
        d4cd10b0be49a68da2b2e0dc0ad8960f
    ");

    let keypair = salty::Keypair::from(&seed);
    assert_eq!(&keypair.public, &salty::PublicKey::try_from(&public_key).unwrap());
    let signature = keypair.sign_with_context(&message, &context);

    assert_eq!(&signature, &salty::Signature::from(&expected_signature));
}

fn test_ed25519ph_with_rfc_8032_test_vector() {
    let seed: [u8; 32] = [
        0x83, 0x3f, 0xe6, 0x24, 0x09, 0x23, 0x7b, 0x9d,
        0x62, 0xec, 0x77, 0x58, 0x75, 0x20, 0x91, 0x1e,
        0x9a, 0x75, 0x9c, 0xec, 0x1d, 0x19, 0x75, 0x5b,
        0x7d, 0xa9, 0x01, 0xb9, 0x6d, 0xca, 0x3d, 0x42,
    ];

    let keypair = salty::Keypair::from(&seed);

    let message: [u8; 3] = [0x61, 0x62, 0x63];

    let prehashed_message = salty::Sha512::new().updated(&message).finalize();

    let signature = keypair.sign_prehashed(&prehashed_message, None);
    // hprintln!("{:x?}", &signature).ok();

    let expected_r = [
        0x98, 0xa7, 0x02, 0x22, 0xf0, 0xb8, 0x12, 0x1a,
        0xa9, 0xd3, 0x0f, 0x81, 0x3d, 0x68, 0x3f, 0x80,
        0x9e, 0x46, 0x2b, 0x46, 0x9c, 0x7f, 0xf8, 0x76,
        0x39, 0x49, 0x9b, 0xb9, 0x4e, 0x6d, 0xae, 0x41,
    ];

    let expected_s = [
        0x31, 0xf8, 0x50, 0x42, 0x46, 0x3c, 0x2a, 0x35,
        0x5a, 0x20, 0x03, 0xd0, 0x62, 0xad, 0xf5, 0xaa,
        0xa1, 0x0b, 0x8c, 0x61, 0xe6, 0x36, 0x06, 0x2a,
        0xaa, 0xd1, 0x1c, 0x2a, 0x26, 0x08, 0x34, 0x06,
    ];

    assert_eq!(signature.r.0, expected_r);
    assert_eq!(signature.s.0, expected_s);

    let public_key = keypair.public;
    let verification = public_key.verify_prehashed(&prehashed_message, &signature, None);
    assert!(verification.is_ok());
}

fn test_square_roots() {
    let two = &FieldElement::ONE + &FieldElement::ONE;
    // four has Legendre symbol of minus one
    let four = &two * &two;
    let sqrt_minus_four = &four.pow2523() * &four;
    assert_eq!(&sqrt_minus_four * &sqrt_minus_four, -&four);
    let sqrt_four = &FieldElement::I * &sqrt_minus_four;
    assert_eq!(&sqrt_four * &sqrt_four, four);

    let three = &two + &FieldElement::ONE;
    // nine has Legendre symbol of one
    let nine = &three * &three;
    let sqrt_nine = &nine.pow2523() * &nine;
    assert_eq!(&sqrt_nine * &sqrt_nine, nine);
}

#[entry]
fn main() -> ! {

    // let mut peripherals = Peripherals::take().unwrap();
    // peripherals.DWT.enable_cycle_counter();
    // hprintln!("enabled cycle counter").ok();

    test_empty_hash();
    test_arithmetic();
    test_negation();
    test_inversion();
    test_square_roots();
    test_signature();

    test_ed25519_rfc_8032_test_1();
    test_ed25519_rfc_8032_test_2();
    test_ed25519_rfc_8032_test_3();
    test_ed25519_rfc_8032_test_1024();
    test_ed25519_rfc_8032_sha_abc();

    test_ed25519_rfc_8032_ctx_foo_bar();
    test_ed25519_rfc_8032_ctx_foo2();
    test_ed25519_rfc_8032_ctx_foo3();

    test_ed25519ph_with_rfc_8032_test_vector();

    hprintln!("All tests passed, including RFC 8032 test vectors!").ok();

    debug::exit(debug::EXIT_SUCCESS);

    loop { continue; }

}
