extern crate passwords;
extern crate regex;

use regex::Regex;

use passwords::PasswordGenerator;

const PASSWORD_COUNT: usize = 5000;

#[test]
fn generate_password_lv1() {
    let pg = PasswordGenerator {
        length: 8,
        numbers: true,
        lowercase_letters: false,
        uppercase_letters: false,
        symbols: false,
        strict: false,
    };

    let re = Regex::new(r"^[1-9]{8}$").unwrap();

    for _ in 0..PASSWORD_COUNT {
        let result = pg.generate_one().unwrap();

        assert!(re.is_match(&result));
    }
}

#[test]
fn generate_password_lv2() {
    let pg = PasswordGenerator {
        length: 8,
        numbers: true,
        lowercase_letters: true,
        uppercase_letters: false,
        symbols: false,
        strict: false,
    };

    let re = Regex::new(r"^[1-9a-hj-km-np-z]{8}$").unwrap();

    let results = pg.generate(PASSWORD_COUNT).unwrap();

    for result in results {
        assert!(re.is_match(&result));
    }
}

#[test]
fn generate_password_lv3() {
    let pg = PasswordGenerator {
        length: 8,
        numbers: true,
        lowercase_letters: true,
        uppercase_letters: true,
        symbols: false,
        strict: false,
    };

    let re = Regex::new(r"^[1-9a-hj-km-np-zA-HJ-KM-NP-Z]{8}$").unwrap();

    let results = pg.generate(PASSWORD_COUNT).unwrap();

    for result in results {
        assert!(re.is_match(&result));
    }
}

#[test]
fn generate_password_lv4() {
    let pg = PasswordGenerator {
        length: 8,
        numbers: true,
        lowercase_letters: true,
        uppercase_letters: true,
        symbols: true,
        strict: false,
    };

    let re = Regex::new("^[1-9a-hj-km-np-zA-HJ-KM-NP-Z!@#$%^&*()+_\\-=}{\\[\\]:;\"/?.><,~]{8}$")
        .unwrap();

    let results = pg.generate(PASSWORD_COUNT).unwrap();

    for result in results {
        assert!(re.is_match(&result));
    }
}

#[test]
fn generate_password_lv5() {
    let pg = PasswordGenerator {
        length: 8,
        numbers: true,
        lowercase_letters: true,
        uppercase_letters: false,
        symbols: false,
        strict: true,
    };

    let re = Regex::new(r"^[1-9a-hj-km-np-z]{8}$").unwrap();
    let re_n = Regex::new(r"[1-9]+").unwrap();
    let re_l = Regex::new(r"[a-hj-km-np-z]+").unwrap();

    let results = pg.generate(PASSWORD_COUNT).unwrap();

    for result in results {
        assert!(re.is_match(&result));
        assert!(re_n.is_match(&result));
        assert!(re_l.is_match(&result));
    }
}

#[test]
fn generate_password_lv6() {
    let pg = PasswordGenerator {
        length: 8,
        numbers: true,
        lowercase_letters: true,
        uppercase_letters: true,
        symbols: false,
        strict: true,
    };

    let re = Regex::new(r"^[1-9a-hj-km-np-zA-HJ-KM-NP-Z]{8}$").unwrap();
    let re_n = Regex::new(r"[1-9]+").unwrap();
    let re_l = Regex::new(r"[a-hj-km-np-z]+").unwrap();
    let re_u = Regex::new(r"[A-HJ-KM-NP-Z]+").unwrap();

    let results = pg.generate(PASSWORD_COUNT).unwrap();

    for result in results {
        assert!(re.is_match(&result));
        assert!(re_n.is_match(&result));
        assert!(re_l.is_match(&result));
        assert!(re_u.is_match(&result));
    }
}

#[test]
fn generate_password_lv7() {
    let pg = PasswordGenerator {
        length: 8,
        numbers: true,
        lowercase_letters: true,
        uppercase_letters: true,
        symbols: true,
        strict: true,
    };

    let re = Regex::new("^[1-9a-hj-km-np-zA-HJ-KM-NP-Z!@#$%^&*()+_\\-=}{\\[\\]:;\"/?.><,~]{8}$")
        .unwrap();
    let re_n = Regex::new(r"[1-9]+").unwrap();
    let re_l = Regex::new(r"[a-hj-km-np-z]+").unwrap();
    let re_u = Regex::new(r"[A-HJ-KM-NP-Z]+").unwrap();
    let re_s = Regex::new("[!@#$%^&*()+_\\-=}{\\[\\]:;\"/?.><,~]+").unwrap();

    let results = pg.generate(PASSWORD_COUNT).unwrap();

    for result in results {
        assert!(re.is_match(&result));
        assert!(re_n.is_match(&result));
        assert!(re_l.is_match(&result));
        assert!(re_u.is_match(&result));
        assert!(re_s.is_match(&result));
    }
}
