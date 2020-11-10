use proc_macro::TokenStream;
use proc_macro2;
use serde_json;
use quote::{quote,format_ident,ToTokens};
use syn;

use tests_base;
use eddsa_tests;

#[proc_macro]
pub fn generate_testcalls(_item: TokenStream) -> TokenStream {

    let contents = std::fs::read_to_string("eddsa_test.json").unwrap();
    let test: eddsa_tests::EddsaTest = serde_json::from_str(&contents).unwrap();

    let mut code = proc_macro2::TokenStream::new();

    for group in test.test_groups {
        for testcase in group.tests {

            let name   = format_ident!("tc{:03}", testcase.tc_id);
            let pk     = &group.key.pk;
            let sig    = &testcase.sig;
            let msg    = &testcase.msg;
            let expect: tests_base::ExpectedResult = testcase.result.into();
            let expect = syn::parse_str::<syn::Expr>(match expect {
                tests_base::ExpectedResult::Valid      => "tests_base::ExpectedResult::Valid",
                tests_base::ExpectedResult::Invalid    => "tests_base::ExpectedResult::Invalid",
                tests_base::ExpectedResult::Acceptable => "tests_base::ExpectedResult::Acceptable",
            }).unwrap();

            let call = quote! {
                run_testcase(stringify!(#name), &[#(#pk),*], &[#(#msg),*], &[#(#sig),*], #expect);
            };

            call.to_tokens(&mut code);
        }
    }

    code.into()
}
