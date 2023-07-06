use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use proc_macro2::TokenStream;
use quote::{quote, ToTokens};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExpectedResult {
    Valid,
    Invalid,
    Acceptable,
}

impl ToTokens for ExpectedResult {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let code = match &self {
            ExpectedResult::Valid => quote! { ExpectedResult::Valid },
            ExpectedResult::Invalid => quote! { ExpectedResult::Invalid },
            ExpectedResult::Acceptable => quote! { ExpectedResult::Acceptable },
        };
        code.to_tokens(tokens);
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureTestVector {
    pub tc_id: u32,
    pub comment: String,
    #[serde(with = "hex_serde")]
    pub msg: Vec<u8>,
    #[serde(with = "hex_serde")]
    pub sig: Vec<u8>,
    pub result: ExpectedResult,
    pub flags: Vec<String>,
}

impl ToTokens for SignatureTestVector {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let Self {
            tc_id,
            comment,
            msg,
            sig,
            result,
            flags,
        } = self;

        let code = quote! {
            SignatureTestVector {
                tc_id: #tc_id,
                comment: &#comment,
                msg: &[ #(#msg),* ],
                sig: &[ #(#sig),* ],
                result: &#result,
                flags: &[ #(#flags), *],
            }
        };
        code.to_tokens(tokens);
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct XdhTestVector {
    pub tc_id: u32,
    pub comment: String,
    #[serde(with = "hex_serde")]
    pub public: Vec<u8>,
    #[serde(with = "hex_serde")]
    pub private: Vec<u8>,
    #[serde(with = "hex_serde")]
    pub shared: Vec<u8>,
    pub result: ExpectedResult,
    pub flags: Vec<String>,
}

impl ToTokens for XdhTestVector {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let Self {
            tc_id,
            comment,
            public,
            private,
            shared,
            result,
            flags,
        } = self;

        let code = quote! {
            XdhTestVector {
                tc_id: #tc_id,
                comment: &#comment,
                public: &[ #(#public),* ],
                private: &[ #(#private),* ],
                shared: &[ #(#shared),* ],
                result: &#result,
                flags: &[ #(#flags), *],
            }
        };
        code.to_tokens(tokens);
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Key {
    pub curve: String,
    pub key_size: i32,
    #[serde(with = "hex_serde")]
    pub pk: Vec<u8>,
    #[serde(with = "hex_serde")]
    pub sk: Vec<u8>,
    #[serde(rename = "type")]
    pub kind: String,
}

impl ToTokens for Key {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let Self {
            curve,
            key_size,
            pk,
            sk,
            kind,
        } = self;

        let code = quote! {
            Key {
                curve: &#curve,
                key_size: #key_size,
                pk: &[ #(#pk),* ],
                sk: &[ #(#sk),* ],
                kind: &#kind,
            }
        };
        code.to_tokens(tokens);
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum TestGroup {
    EddsaVerify {
        key: Key,
        tests: Vec<SignatureTestVector>,
    },
    XdhComp {
        curve: String,
        tests: Vec<XdhTestVector>,
    },
}

impl ToTokens for TestGroup {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        match &self {
            TestGroup::EddsaVerify { key, tests } => {
                let code = quote! {
                    TestGroup::EddsaVerify {
                        key: &#key,
                        tests: &[ #(&#tests),* ]
                    }
                };
                code.to_tokens(tokens);
            }

            TestGroup::XdhComp { curve, tests } => {
                let code = quote! {
                    TestGroup::XdhComp {
                        curve: &#curve,
                        tests: &[ #(&#tests),* ]
                    }
                };
                code.to_tokens(tokens);
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WycheproofTest {
    pub algorithm: String,
    pub generator_version: String,
    pub header: Vec<String>,
    pub notes: HashMap<String, String>,
    pub number_of_tests: u32,
    pub schema: String,
    pub test_groups: Vec<TestGroup>,
}

impl ToTokens for WycheproofTest {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let Self {
            algorithm,
            generator_version,
            header,
            notes: _,
            number_of_tests,
            schema,
            test_groups,
        } = self;

        let code = quote! {
            WycheproofTest {
                algorithm: &#algorithm,
                generator_version: &#generator_version,
                header: &[ #(&#header),* ],
                number_of_tests: #number_of_tests,
                schema: &#schema,
                test_groups: &[ #(&#test_groups),* ],
            }
        };
        code.to_tokens(tokens);
    }
}

#[test]
fn read_eddsa_test() {
    let contents = std::fs::read_to_string("data/eddsa_test.json").unwrap();
    let test: WycheproofTest = serde_json::from_str(&contents).unwrap();

    assert_eq!(test.number_of_tests, 145);

    let mut n = 0;
    for g in test.test_groups {
        if let TestGroup::EddsaVerify { key: _, tests } = g {
            for _tc in tests {
                n += 1;
            }
        }
    }

    assert_eq!(n, 145);
}

#[test]
fn read_x25519_test() {
    let contents = std::fs::read_to_string("data/x25519_test.json").unwrap();
    let test: WycheproofTest = serde_json::from_str(&contents).unwrap();

    assert_eq!(test.number_of_tests, 518);

    let mut n = 0;
    for g in test.test_groups {
        if let TestGroup::XdhComp { curve: _, tests } = g {
            for _tc in tests {
                n += 1;
            }
        }
    }

    assert_eq!(n, 518);
}
