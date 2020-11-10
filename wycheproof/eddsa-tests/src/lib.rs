use std::collections::HashMap;

use serde::{Serialize, Deserialize};
use hex_serde;

use tests_base;

#[derive(Serialize, Deserialize)]
#[serde(rename_all="lowercase")]
pub enum ExpectedResult {
    Valid,
    Invalid,
    Acceptable,
}

impl From<ExpectedResult> for tests_base::ExpectedResult {
    fn from(e: ExpectedResult) -> Self {
        match e {
            ExpectedResult::Valid      => tests_base::ExpectedResult::Valid,
            ExpectedResult::Invalid    => tests_base::ExpectedResult::Invalid,
            ExpectedResult::Acceptable => tests_base::ExpectedResult::Acceptable,
        }
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
