use std::fs;

use eddsa_tests::EddsaTest;

mod test {
    use super::*;

    #[test]
    fn read_json() {
        let contents = fs::read_to_string("../eddsa_test.json").unwrap();
        let test: EddsaTest = serde_json::from_str(&contents).unwrap();

        assert_eq!(test.number_of_tests, 145);

        let mut n = 0;
        for g in test.test_groups {
            for _tc in g.tests {
                n += 1;
            }
        }

        assert_eq!(n, 145);
    }
}
