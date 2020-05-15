#![cfg(feature = "crypto")]

extern crate passwords;

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
