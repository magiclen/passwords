#![cfg(feature = "crypto")]

const BCRYPT_BODY: &str = "06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe";

#[test]
fn null_terminated_byte() {
    let password = passwords::hasher::get_password_with_null_terminated_byte("password");

    assert_eq!(b"password\0", password.as_ref());
}

#[test]
fn bcrypt_identify_true() {
    let salt = passwords::hasher::gen_salt();

    let password = passwords::hasher::get_password_with_null_terminated_byte("password");

    let hashed = passwords::hasher::bcrypt(10, &salt, &password).unwrap();

    assert!(unsafe { passwords::hasher::identify_bcrypt(10, &salt, &password, &hashed) });

    let hashed_format = passwords::hasher::bcrypt_format(10, &salt, &password).unwrap();

    assert!(unsafe { passwords::hasher::identify_bcrypt_format(&password, hashed_format) });
}

#[test]
#[should_panic(expected = "assertion failed")]
fn bcrypt_identify_false() {
    let salt = passwords::hasher::gen_salt();

    let password = passwords::hasher::get_password_with_null_terminated_byte("password");

    let hashed = passwords::hasher::bcrypt(10, &salt, &password).unwrap();

    assert!(unsafe { passwords::hasher::identify_bcrypt(10, &salt, "password", &hashed) });
}

#[test]
fn bcrypt_identify_format_prefixes() {
    for prefix in ["$2$", "$2a$", "$2b$", "$2x$", "$2y$"] {
        let hashed_format = format!("{prefix}{BCRYPT_BODY}");

        assert!(unsafe { passwords::hasher::identify_bcrypt_format(b"a\0", hashed_format) });
    }
}

#[test]
fn bcrypt_identify_non_ascii_vectors() {
    // This vector is from https://github.com/openwall/crypt_blowfish/blob/master/wrapper.c.
    let body = "05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq";

    for prefix in ["$2a$", "$2b$", "$2y$"] {
        let hashed_format = format!("{prefix}{body}");

        assert!(unsafe { passwords::hasher::identify_bcrypt_format(b"\xA3\0", hashed_format) });
    }
}

#[test]
fn bcrypt_identify_short_hash() {
    assert!(!unsafe { passwords::hasher::identify_bcrypt(6, &[0u8; 16], b"a\0", &[0u8; 22]) });
}

#[test]
fn bcrypt_identify_invalid_format() {
    for hashed_format in [
        format!("$2z${BCRYPT_BODY}"),
        format!("$2b!{BCRYPT_BODY}"),
        format!("$2b$06!{}", &BCRYPT_BODY[3..]),
        format!("$2b$+6${}", &BCRYPT_BODY[3..]),
        format!("AAAé{}", &BCRYPT_BODY[1..]),
    ] {
        assert!(!unsafe { passwords::hasher::identify_bcrypt_format(b"a\0", hashed_format) });
    }
}
