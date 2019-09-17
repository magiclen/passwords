#![cfg(feature = "crypto")]

extern crate passwords;

#[test]
fn bcrypt_identify_true() {
    let salt = passwords::hasher::gen_salt();

    let hashed = passwords::hasher::bcrypt(10, &salt, "password").unwrap();

    assert!(passwords::hasher::identify_bcrypt(10, &salt, "password", &hashed).unwrap());
}

#[test]
#[should_panic(expected = "assertion failed")]
fn bcrypt_identify_false() {
    let salt = passwords::hasher::gen_salt();

    let hashed = passwords::hasher::bcrypt(10, &salt, "password").unwrap();

    assert!(passwords::hasher::identify_bcrypt(10, &salt, "password2", &hashed).unwrap());
}
