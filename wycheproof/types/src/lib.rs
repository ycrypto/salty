#![no_std]

#[allow(dead_code)]
pub enum ExpectedResult {
    Valid,
    Invalid,
    Acceptable,
}

#[allow(dead_code)]
pub struct SignatureTestVector<'a> {
    pub tc_id: u32,
    pub comment: &'a str,
    pub msg: &'a [u8],
    pub sig: &'a [u8],
    pub result: &'a ExpectedResult,
    pub flags: &'a [&'a str],
}

#[allow(dead_code)]
pub struct Key<'a> {
    pub curve: &'a str,
    pub key_size: i32,
    pub pk: &'a [u8],
    pub sk: &'a [u8],
    pub kind: &'a str,
}

#[allow(dead_code)]
pub struct XdhTestVector<'a> {
    pub tc_id: u32,
    pub comment: &'a str,
    pub public: &'a [u8],
    pub private: &'a [u8],
    pub shared: &'a [u8],
    pub result: &'a ExpectedResult,
    pub flags: &'a [&'a str],
}

#[allow(dead_code)]
pub enum TestGroup<'a> {
    EddsaVerify {
        key: &'a Key<'a>,
        tests: &'a [&'a SignatureTestVector<'a>],
    },
    XdhComp {
        curve: &'a str,
        tests: &'a [&'a XdhTestVector<'a>],
    },
}

#[allow(dead_code)]
pub struct WycheproofTest<'a> {
    pub algorithm: &'a str,
    pub generator_version: &'a str,
    pub header: &'a [&'a str],
    pub number_of_tests: u32,
    pub schema: &'a str,
    pub test_groups: &'a [&'a TestGroup<'a>],
}
