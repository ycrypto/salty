use proc_macro::TokenStream;
use quote::{quote, ToTokens};
use syn::parse::{Parse, ParseStream, Result};
use syn::{parse_macro_input, ItemFn, LitStr, Token};

struct TestDataArgs {
    fname: String,
    schema: String,
}

impl Parse for TestDataArgs {
    fn parse(input: ParseStream) -> Result<Self> {
        let fname: LitStr = input.parse()?;
        input.parse::<Token![,]>()?;
        let schema: LitStr = input.parse()?;
        Ok(TestDataArgs {
            fname: fname.value(),
            schema: schema.value(),
        })
    }
}

#[proc_macro]
pub fn generate_data(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as TestDataArgs);

    let testdata = std::fs::read_to_string(&input.fname).unwrap();
    let test: wycheproof::WycheproofTest = serde_json::from_str(&testdata).unwrap();

    if !input.schema.ends_with(&test.schema) {
        dbg!(&test.schema);
        dbg!(&input.schema);
        panic!("JSON schemas do not match!");
    }

    let code = quote! {
        #test
    };
    code.into()
}

#[proc_macro_attribute]
pub fn test_wycheproof(args: TokenStream, func: TokenStream) -> TokenStream {
    let TestDataArgs { fname, schema } = parse_macro_input!(args as TestDataArgs);

    let testdata = std::fs::read_to_string(&fname).unwrap();
    let testdata: wycheproof::WycheproofTest = serde_json::from_str(&testdata).unwrap();

    if !schema.ends_with(&testdata.schema) {
        panic!("JSON schemas do not match!");
    }

    let mut func_copy: proc_macro2::TokenStream = func.clone().into();
    let func_ast: ItemFn = syn::parse(func).expect("failed to parse function");
    let func_ident = func_ast.sig.ident;

    for testgroup in &testdata.test_groups {
        match testgroup {
            wycheproof::TestGroup::EddsaVerify { key, tests } => {
                for testcase in tests {
                    let test_name = format!("{}_{}", func_ident, testcase.tc_id);
                    let test_ident =
                        proc_macro2::Ident::new(&test_name, proc_macro2::Span::call_site());
                    let item = quote! {
                        #[test]
                        fn # test_ident () {
                            # func_ident ( & # key, & # testcase);
                        }
                    };

                    item.to_tokens(&mut func_copy);
                }
            }

            wycheproof::TestGroup::XdhComp { curve, tests } => {
                for testcase in tests {
                    let test_name = format!("{}_{}", func_ident, testcase.tc_id);
                    let test_ident =
                        proc_macro2::Ident::new(&test_name, proc_macro2::Span::call_site());
                    let item = quote! {
                        #[test]
                        fn # test_ident () {
                            # func_ident ( & # curve, & # testcase);
                        }
                    };

                    item.to_tokens(&mut func_copy);
                }
            }
        }
    }

    func_copy.into()
}
