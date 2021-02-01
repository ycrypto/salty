use proc_macro::TokenStream;
use serde_json;
use quote::{quote, ToTokens};
use syn::{parse_macro_input, Token, LitStr, ItemFn};
use syn::parse::{Parse, ParseStream, Result};

use wycheproof_tests;

struct TestDataArgs {
    fname: LitStr,
    schema: LitStr,
}

impl Parse for TestDataArgs {
    fn parse(input: ParseStream) -> Result<Self> {
        let fname: LitStr = input.parse()?;
        input.parse::<Token![,]>()?;
        let schema: LitStr = input.parse()?;
        Ok(TestDataArgs{
            fname,
            schema
        })
    }
}

#[proc_macro]
pub fn generate_data(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as TestDataArgs);

    let testdata = std::fs::read_to_string(input.fname.value()).unwrap();
    let test: wycheproof_tests::WycheproofTest = serde_json::from_str(&testdata).unwrap();

    if test.schema != input.schema.value() {
        panic!("JSON schemas do not match!");
    }

    let code = quote!{
        #test
    };
    code.into()
}

#[proc_macro_attribute]
pub fn test_wycheproof(args: TokenStream, func: TokenStream) -> TokenStream {
    let TestDataArgs { fname, schema } = parse_macro_input!(args as TestDataArgs);

    let testdata = std::fs::read_to_string(fname.value()).unwrap();
    let testdata: wycheproof_tests::WycheproofTest = serde_json::from_str(&testdata).unwrap();

    if testdata.schema != schema.value() {
        panic!("JSON schemas do not match!");
    }

    let mut func_copy: proc_macro2::TokenStream = func.clone().into();
    let func_ast: ItemFn = syn::parse(func)
        .expect("failed to parse function");
    let func_ident = func_ast.sig.ident;

    for testgroup in &testdata.test_groups {
        match testgroup {
            wycheproof_tests::TestGroup::EddsaVerify{key, tests} => {
                for testcase in tests {
                    let test_name = format!("{}_{}", func_ident.to_string(), testcase.tc_id);
                    let test_ident = proc_macro2::Ident::new(&test_name, proc_macro2::Span::call_site());
                    let item = quote! {
                        #[test]
                        fn # test_ident () {
                            # func_ident ( & # key, & # testcase);
                        }
                    };

                    item.to_tokens(&mut func_copy);
                }
            },

            wycheproof_tests::TestGroup::XdhComp{curve, tests} => {
                for testcase in tests {
                    let test_name = format!("{}_{}", func_ident.to_string(), testcase.tc_id);
                    let test_ident = proc_macro2::Ident::new(&test_name, proc_macro2::Span::call_site());
                    let item = quote! {
                        #[test]
                        fn # test_ident () {
                            # func_ident ( & # curve, & # testcase);
                        }
                    };

                    item.to_tokens(&mut func_copy);
                }
            },
        }
    }

    func_copy.into()
}
