#![cfg(feature = "crypto")]

extern crate crypto;
extern crate rand;

use self::rand::Rng;

use self::crypto::md5::Md5;
use self::crypto::digest::Digest;

/// Generate a random 16-byte salt.
///
/// ```
/// extern crate passwords;
///
/// let salt = passwords::gen_salt();
///
/// println!("{:?}", salt);
/// ```
pub fn gen_salt() -> [u8; 16] {
    let mut result = [0u8; 16];

    for i in 0..16 {
        result[i] = rand::thread_rng().gen();
    }

    result
}

/// Use bcrypt to hash a password whose length is not bigger than 72 bytes to 24 bytes data. If the salt is not 16 bytes, it will be MD5 hashed first.
///
/// ```
/// extern crate passwords;
///
/// let hashed = passwords::bcrypt(10, "salt", "password").unwrap();
///
/// println!("{:?}", hashed);
/// ```
pub fn bcrypt<T: ?Sized + AsRef<[u8]>, K: ?Sized + AsRef<[u8]>>(cost: u8, salt: &K, password: &T) -> Result<[u8; 24], &'static str> {
    let mut result = [0u8; 24];

    if cost >= 32 {
        return Err("Cost needs to be smaller than 32.");
    }

    let password = password.as_ref();

    let password_len = password.len();

    if password_len == 0 {
        return Err("The password is empty.");
    }

    if password_len > 72 {
        return Err("The length of the password should not be bigger than 72.");
    }

    let salt = salt.as_ref();

    if salt.len() != 16 {
        let mut new_salt = [0u8; 16];

        let mut md5 = Md5::new();

        md5.input(salt);

        md5.result(&mut new_salt);

        crypto::bcrypt::bcrypt(cost as u32, &new_salt, password, &mut result);
    } else {
        crypto::bcrypt::bcrypt(cost as u32, salt, password, &mut result);
    }


    Ok(result)
}

/// Identify a plain text password by using the bcrypt-hashed data we've stored before.
///
/// ```
/// extern crate passwords;
///
/// let hashed = passwords::bcrypt(10, "salt", "password").unwrap();
///
/// assert!(passwords::identify_bcrypt(10, "salt", "password", &hashed).unwrap());
/// ```
pub fn identify_bcrypt<T: ?Sized + AsRef<[u8]>, K: ?Sized + AsRef<[u8]>>(cost: u8, salt: &K, password: &T, hashed: &[u8; 24]) -> Result<bool, &'static str> {
    let p = bcrypt(cost, salt, password)?;

    Ok(hashed.eq(&p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bcrypt_identify_true() {
        let salt = gen_salt();

        let hashed = bcrypt(10, &salt, "password").unwrap();

        assert!(identify_bcrypt(10, &salt, "password", &hashed).unwrap());
    }

    #[test]
    #[should_panic(expected = "assertion failed")]
    fn test_bcrypt_identify_false() {
        let salt = gen_salt();

        let hashed = bcrypt(10, &salt, "password").unwrap();

        assert!(identify_bcrypt(10, &salt, "password2", &hashed).unwrap());
    }
}
