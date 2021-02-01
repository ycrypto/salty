use std::fs;

use wycheproof_tests::{WycheproofTest,TestGroup};

mod test {
    use super::*;

    #[test]
    fn read_eddsa_test() {
        let contents = fs::read_to_string("tests/eddsa_test.json").unwrap();
        let test: WycheproofTest = serde_json::from_str(&contents).unwrap();

        assert_eq!(test.number_of_tests, 145);

        let mut n = 0;
        for g in test.test_groups {
            if let TestGroup::EddsaVerify{key:_, tests} = g {
                for _tc in tests {
                    n += 1;
                }
            }
        }

        assert_eq!(n, 145);
    }

    #[test]
    fn read_x25519_test() {
        let contents = fs::read_to_string("tests/x25519_test.json").unwrap();
        let test: WycheproofTest = serde_json::from_str(&contents).unwrap();

        assert_eq!(test.number_of_tests, 518);

        let mut n = 0;
        for g in test.test_groups {
            if let TestGroup::XdhComp{curve: _, tests} = g {
                for _tc in tests {
                    n += 1;
                }
            }
        }

        assert_eq!(n, 518);
    }
}
