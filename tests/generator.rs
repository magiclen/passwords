use passwords::PasswordGenerator;
use regex::Regex;

const PASSWORD_COUNT: usize = 5000;

#[test]
fn random() {
    {
        let pg = PasswordGenerator::new();

        {
            let result_1 = pg.generate_one().unwrap();
            let result_2 = pg.generate_one().unwrap();

            assert_ne!(result_1, result_2);
        }

        {
            let results = pg.generate(2).unwrap();

            assert_eq!(2, results.len());
            assert_ne!(results[0], results[1]);
        }
    }

    {
        let pg = PasswordGenerator::new().strict(true);

        {
            let result_1 = pg.generate_one().unwrap();
            let result_2 = pg.generate_one().unwrap();

            assert_ne!(result_1, result_2);
        }

        {
            let results = pg.generate(2).unwrap();

            assert_eq!(2, results.len());
            assert_ne!(results[0], results[1]);
        }
    }
}

#[test]
fn multiply_generate() {
    {
        let pg = PasswordGenerator::new();

        let results = pg.generate(PASSWORD_COUNT).unwrap();

        assert_eq!(PASSWORD_COUNT, results.len());
    }

    {
        let pg = PasswordGenerator::new().strict(true);

        let results = pg.generate(PASSWORD_COUNT).unwrap();

        assert_eq!(PASSWORD_COUNT, results.len());
    }
}

#[test]
fn length() {
    {
        let pg = PasswordGenerator::new();

        let re = Regex::new(r"^.{8}$").unwrap();

        let results = pg.generate(PASSWORD_COUNT).unwrap();

        for result in results {
            assert!(re.is_match(&result));
        }
    }

    {
        let pg = PasswordGenerator::new().length(10);

        let re = Regex::new(r"^.{10}$").unwrap();

        let results = pg.generate(PASSWORD_COUNT).unwrap();

        for result in results {
            assert!(re.is_match(&result));
        }
    }
}

#[test]
fn only_numbers() {
    let pg = PasswordGenerator::new().lowercase_letters(false);

    let re = Regex::new(r"^[0-9]{8}$").unwrap();

    let results = pg.generate(PASSWORD_COUNT).unwrap();

    for result in results {
        assert!(re.is_match(&result));
    }
}

#[test]
fn only_numbers_exclude_similar() {
    let pg = PasswordGenerator::new().lowercase_letters(false).exclude_similar_characters(true);

    let re = Regex::new(r"^[2-9]{8}$").unwrap();

    let results = pg.generate(PASSWORD_COUNT).unwrap();

    for result in results {
        assert!(re.is_match(&result));
    }
}

#[test]
fn only_lowercase_letters() {
    let pg = PasswordGenerator::new().numbers(false);

    let re = Regex::new(r"^[a-z]{8}$").unwrap();

    let results = pg.generate(PASSWORD_COUNT).unwrap();

    for result in results {
        assert!(re.is_match(&result));
    }
}

#[test]
fn only_lowercase_letters_exclude_similar() {
    let pg = PasswordGenerator::new().numbers(false).exclude_similar_characters(true);

    let re = Regex::new(r"^[a-hj-km-np-z]{8}$").unwrap();

    let results = pg.generate(PASSWORD_COUNT).unwrap();

    for result in results {
        assert!(re.is_match(&result));
    }
}

#[test]
fn only_uppercase_letters() {
    let pg =
        PasswordGenerator::new().lowercase_letters(false).numbers(false).uppercase_letters(true);

    let re = Regex::new(r"^[A-Z]{8}$").unwrap();

    let results = pg.generate(PASSWORD_COUNT).unwrap();

    for result in results {
        assert!(re.is_match(&result));
    }
}

#[test]
fn only_uppercase_letters_exclude_similar() {
    let pg = PasswordGenerator::new()
        .lowercase_letters(false)
        .numbers(false)
        .uppercase_letters(true)
        .exclude_similar_characters(true);

    let re = Regex::new(r"^[A-HJ-NP-Z]{8}$").unwrap();

    let results = pg.generate(PASSWORD_COUNT).unwrap();

    for result in results {
        assert!(re.is_match(&result));
    }
}

#[test]
fn only_symbols() {
    let pg = PasswordGenerator::new().lowercase_letters(false).numbers(false).symbols(true);

    let re = Regex::new(r##"^[!"#$%&'()*+,-./:;<=>?@\[\\\]^_`{|}~]{8}$"##).unwrap();

    let results = pg.generate(PASSWORD_COUNT).unwrap();

    for result in results {
        assert!(re.is_match(&result));
    }
}

#[test]
fn only_symbols_exclude_similar() {
    let pg = PasswordGenerator::new()
        .lowercase_letters(false)
        .numbers(false)
        .symbols(true)
        .exclude_similar_characters(true);

    let re = Regex::new(r"^[!#$%&()*+,-./:;<=>?@\[\\\]^_{}~]{8}$").unwrap();

    let results = pg.generate(PASSWORD_COUNT).unwrap();

    for result in results {
        assert!(re.is_match(&result));
    }
}

#[test]
fn only_spaces() {
    let pg = PasswordGenerator::new().lowercase_letters(false).numbers(false).spaces(true);

    let re = Regex::new(r##"^[ ]{8}$"##).unwrap();

    let results = pg.generate(PASSWORD_COUNT).unwrap();

    for result in results {
        assert!(re.is_match(&result));
    }
}

#[test]
fn numbers_and_lowercase_letters() {
    {
        let pg = PasswordGenerator::new();

        let re = Regex::new(r"^[0-9a-z]{8}$").unwrap();

        let results = pg.generate(PASSWORD_COUNT).unwrap();

        for result in results {
            assert!(re.is_match(&result));
        }
    }

    {
        let pg = PasswordGenerator::new().strict(true);

        let re = Regex::new(r"^[0-9a-z]{8}$").unwrap();
        let re_n = Regex::new(r"[0-9]+").unwrap();
        let re_l = Regex::new(r"[a-z]+").unwrap();

        let results = pg.generate(PASSWORD_COUNT).unwrap();

        for result in results {
            assert!(re.is_match(&result));
            assert!(re_n.is_match(&result));
            assert!(re_l.is_match(&result));
        }
    }
}

#[test]
fn numbers_and_lowercase_letters_exclude_similar() {
    {
        let pg = PasswordGenerator::new().exclude_similar_characters(true);

        let re = Regex::new(r"^[2-9a-hj-km-np-z]{8}$").unwrap();

        let results = pg.generate(PASSWORD_COUNT).unwrap();

        for result in results {
            assert!(re.is_match(&result));
        }
    }

    {
        let pg = PasswordGenerator::new().strict(true).exclude_similar_characters(true);

        let re = Regex::new(r"^[2-9a-hj-km-np-z]{8}$").unwrap();
        let re_n = Regex::new(r"[2-9]+").unwrap();
        let re_l = Regex::new(r"[a-hj-km-np-z]+").unwrap();

        let results = pg.generate(PASSWORD_COUNT).unwrap();

        for result in results {
            assert!(re.is_match(&result));
            assert!(re_n.is_match(&result));
            assert!(re_l.is_match(&result));
        }
    }
}

#[test]
fn numbers_and_letters() {
    {
        let pg = PasswordGenerator::new().uppercase_letters(true);

        let re = Regex::new(r"^[0-9a-zA-Z]{8}$").unwrap();

        let results = pg.generate(PASSWORD_COUNT).unwrap();

        for result in results {
            assert!(re.is_match(&result));
        }
    }

    {
        let pg = PasswordGenerator::new().uppercase_letters(true).strict(true);

        let re = Regex::new(r"^[0-9a-zA-Z]{8}$").unwrap();
        let re_n = Regex::new(r"[0-9]+").unwrap();
        let re_l = Regex::new(r"[a-z]+").unwrap();
        let re_u = Regex::new(r"[A-Z]+").unwrap();

        let results = pg.generate(PASSWORD_COUNT).unwrap();

        for result in results {
            assert!(re.is_match(&result));
            assert!(re_n.is_match(&result));
            assert!(re_l.is_match(&result));
            assert!(re_u.is_match(&result));
        }
    }
}

#[test]
fn numbers_and_letters_exclude_similar() {
    {
        let pg = PasswordGenerator::new().uppercase_letters(true).exclude_similar_characters(true);

        let re = Regex::new(r"^[2-9a-hj-km-np-zA-HJ-NP-Z]{8}$").unwrap();

        let results = pg.generate(PASSWORD_COUNT).unwrap();

        for result in results {
            assert!(re.is_match(&result));
        }
    }

    {
        let pg = PasswordGenerator::new()
            .uppercase_letters(true)
            .strict(true)
            .exclude_similar_characters(true);

        let re = Regex::new(r"^[2-9a-hj-km-np-zA-HJ-NP-Z]{8}$").unwrap();
        let re_n = Regex::new(r"[2-9]+").unwrap();
        let re_l = Regex::new(r"[a-hj-km-np-z]+").unwrap();
        let re_u = Regex::new(r"[A-HJ-NP-Z]+").unwrap();

        let results = pg.generate(PASSWORD_COUNT).unwrap();

        for result in results {
            assert!(re.is_match(&result));
            assert!(re_n.is_match(&result));
            assert!(re_l.is_match(&result));
            assert!(re_u.is_match(&result));
        }
    }
}

#[test]
fn numbers_letters_symbols() {
    {
        let pg = PasswordGenerator::new().uppercase_letters(true).symbols(true);

        let re = Regex::new(r##"^[0-9a-zA-Z!"#$%&'()*+,-./:;<=>?@\[\\\]^_`{|}~]{8}$"##).unwrap();

        let results = pg.generate(PASSWORD_COUNT).unwrap();

        for result in results {
            assert!(re.is_match(&result));
        }
    }

    {
        let pg = PasswordGenerator::new().uppercase_letters(true).symbols(true).strict(true);

        let re = Regex::new(r##"^[0-9a-zA-Z!"#$%&'()*+,-./:;<=>?@\[\\\]^_`{|}~]{8}$"##).unwrap();
        let re_n = Regex::new(r"[0-9]+").unwrap();
        let re_l = Regex::new(r"[a-z]+").unwrap();
        let re_u = Regex::new(r"[A-Z]+").unwrap();
        let re_s = Regex::new(r##"[!"#$%&'()*+,-./:;<=>?@\[\\\]^_`{|}~]+"##).unwrap();

        let results = pg.generate(PASSWORD_COUNT).unwrap();

        for result in results {
            assert!(re.is_match(&result));
            assert!(re_n.is_match(&result));
            assert!(re_l.is_match(&result));
            assert!(re_u.is_match(&result));
            assert!(re_s.is_match(&result));
        }
    }
}

#[test]
fn numbers_letters_symbols_exclude_similar() {
    {
        let pg = PasswordGenerator::new()
            .uppercase_letters(true)
            .symbols(true)
            .exclude_similar_characters(true);

        let re =
            Regex::new(r"^[2-9a-hj-km-np-zA-HJ-NP-Z!#$%&()*+,-./:;<=>?@\[\\\]^_{}~]{8}$").unwrap();

        let results = pg.generate(PASSWORD_COUNT).unwrap();

        for result in results {
            assert!(re.is_match(&result));
        }
    }

    {
        let pg = PasswordGenerator::new()
            .uppercase_letters(true)
            .symbols(true)
            .strict(true)
            .exclude_similar_characters(true);

        let re =
            Regex::new(r"^[2-9a-hj-km-np-zA-HJ-NP-Z!#$%&()*+,-./:;<=>?@\[\\\]^_{}~]{8}$").unwrap();
        let re_n = Regex::new(r"[2-9]+").unwrap();
        let re_l = Regex::new(r"[a-hj-km-np-z]+").unwrap();
        let re_u = Regex::new(r"[A-HJ-NP-Z]+").unwrap();
        let re_s = Regex::new(r"[!#$%&()*+,-./:;<=>?@\[\\\]^_{}~]+").unwrap();

        let results = pg.generate(PASSWORD_COUNT).unwrap();

        for result in results {
            assert!(re.is_match(&result));
            assert!(re_n.is_match(&result));
            assert!(re_l.is_match(&result));
            assert!(re_u.is_match(&result));
            assert!(re_s.is_match(&result));
        }
    }
}

#[test]
fn visible_ascii() {
    {
        let pg = PasswordGenerator::new().uppercase_letters(true).symbols(true).spaces(true);

        let re = Regex::new(r##"^[0-9a-zA-Z!"#$%&'()*+,-./:;<=>?@\[\\\]^_`{|}~ ]{8}$"##).unwrap();

        let results = pg.generate(PASSWORD_COUNT).unwrap();

        for result in results {
            assert!(re.is_match(&result));
        }
    }

    {
        let pg = PasswordGenerator::new()
            .uppercase_letters(true)
            .symbols(true)
            .spaces(true)
            .strict(true);

        let re = Regex::new(r##"^[0-9a-zA-Z!"#$%&'()*+,-./:;<=>?@\[\\\]^_`{|}~ ]{8}$"##).unwrap();
        let re_n = Regex::new(r"[0-9]+").unwrap();
        let re_l = Regex::new(r"[a-z]+").unwrap();
        let re_u = Regex::new(r"[A-Z]+").unwrap();
        let re_s = Regex::new(r##"[!"#$%&'()*+,-./:;<=>?@\[\\\]^_`{|}~]+"##).unwrap();

        let results = pg.generate(PASSWORD_COUNT).unwrap();

        for result in results {
            assert!(re.is_match(&result));
            assert!(re_n.is_match(&result));
            assert!(re_l.is_match(&result));
            assert!(re_u.is_match(&result));
            assert!(re_s.is_match(&result));
            assert!(result.contains(' '));
        }
    }
}

#[test]
fn visible_ascii_exclude_similar() {
    {
        let pg = PasswordGenerator::new()
            .uppercase_letters(true)
            .symbols(true)
            .spaces(true)
            .exclude_similar_characters(true);

        let re =
            Regex::new(r"^[2-9a-hj-km-np-zA-HJ-NP-Z!#$%&()*+,-./:;<=>?@\[\\\]^_{}~ ]{8}$").unwrap();

        let results = pg.generate(PASSWORD_COUNT).unwrap();

        for result in results {
            assert!(re.is_match(&result));
        }
    }

    {
        let pg = PasswordGenerator::new()
            .uppercase_letters(true)
            .symbols(true)
            .spaces(true)
            .strict(true)
            .exclude_similar_characters(true);

        let re =
            Regex::new(r"^[2-9a-hj-km-np-zA-HJ-NP-Z!#$%&()*+,-./:;<=>?@\[\\\]^_{}~ ]{8}$").unwrap();
        let re_n = Regex::new(r"[2-9]+").unwrap();
        let re_l = Regex::new(r"[a-hj-km-np-z]+").unwrap();
        let re_u = Regex::new(r"[A-HJ-NP-Z]+").unwrap();
        let re_s = Regex::new(r"[!#$%&()*+,-./:;<=>?@\[\\\]^_{}~]+").unwrap();

        let results = pg.generate(PASSWORD_COUNT).unwrap();

        for result in results {
            assert!(re.is_match(&result));
            assert!(re_n.is_match(&result));
            assert!(re_l.is_match(&result));
            assert!(re_u.is_match(&result));
            assert!(re_s.is_match(&result));
            assert!(result.contains(' '));
        }
    }
}

#[test]
fn iter() {
    let mut pgi = PasswordGenerator::new().try_iter().unwrap();

    let re = Regex::new(r"^.{8}$").unwrap();

    for _ in 0..PASSWORD_COUNT {
        let result = pgi.next().unwrap();

        assert!(re.is_match(&result));
    }
}

#[test]
#[should_panic(expected = "The length of passwords is too short.")]
fn length_too_short() {
    PasswordGenerator::new().length(2).uppercase_letters(true).strict(true).try_iter().unwrap();
}

#[test]
#[should_panic(expected = "The length of passwords cannot be 0.")]
fn length_zero() {
    PasswordGenerator::new().length(0).try_iter().unwrap();
}

#[test]
#[should_panic(expected = "You need to enable at least one kind of characters.")]
fn no_characters() {
    PasswordGenerator::new().numbers(false).lowercase_letters(false).try_iter().unwrap();
}
