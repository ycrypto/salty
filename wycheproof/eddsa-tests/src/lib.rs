use std::collections::HashMap;

use serde::{Serialize, Deserialize};
use hex_serde;

use proc_macro2::TokenStream;
use quote::{quote,ToTokens};

#[derive(Serialize, Deserialize)]
#[serde(rename_all="lowercase")]
pub enum ExpectedResult {
    Valid,
    Invalid,
    Acceptable,
}

impl ToTokens for ExpectedResult {
    fn to_tokens(&self, tokens: &mut TokenStream) {

        let code = match &self {
            ExpectedResult::Valid      => quote!{ ExpectedResult::Valid },
            ExpectedResult::Invalid    => quote!{ ExpectedResult::Invalid },
            ExpectedResult::Acceptable => quote!{ ExpectedResult::Acceptable },
        };
        code.to_tokens(tokens);
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all="camelCase")]
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
        let tc_id = &self.tc_id;
        let comment = &self.comment;
        let msg = &self.msg;
        let sig = &self.sig;
        let result = &self.result;
        let flags = &self.flags;

        let code = quote!{
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
#[serde(rename_all="camelCase")]
pub struct Key {
    pub curve: String,
    pub key_size: i32,
    #[serde(with = "hex_serde")]
    pub pk: Vec<u8>,
    #[serde(with = "hex_serde")]
    pub sk: Vec<u8>,
    #[serde(rename="type")]
    pub kind: String,
}

impl ToTokens for Key {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let curve = &self.curve;
        let key_size = &self.key_size;
        let pk = &self.pk;
        let sk = &self.sk;
        let kind = &self.kind;

        let code = quote!{
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
pub struct EddsaTestGroup {
    #[serde(rename="type")]
    pub kind: String,
    //jwk,
    //key_der,
    //key_pem,
    pub key: Key,
    pub tests: Vec<SignatureTestVector>,
}

impl ToTokens for EddsaTestGroup {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let kind = &self.kind;
        let key = &self.key;
        let tests = &self.tests;

        let code = quote!{
            EddsaTestGroup {
                kind: &#kind,
                key: &#key,
                tests: &[ #(&#tests),* ]
            }
        };
        code.to_tokens(tokens);
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all="camelCase")]
pub struct EddsaTest {
    pub algorithm: String,
    pub generator_version: String,
    pub header: Vec<String>,
    pub notes: HashMap<String, String>,
    pub number_of_tests: u32,
    pub schema: String,
    pub test_groups: Vec<EddsaTestGroup>,
}

impl ToTokens for EddsaTest {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let algorithm = &self.algorithm;
        let generator_version = &self.generator_version;
        let header = &self.header;
        let number_of_tests = &self.number_of_tests;
        let schema = &self.schema;
        let test_groups = &self.test_groups;

        let code = quote!{
            EddsaTest {
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
