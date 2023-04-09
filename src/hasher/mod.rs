#![cfg(feature = "crypto")]

use std::borrow::Cow;

use base64::{engine::DecodePaddingMode, Engine};
use rand::RngCore;

/// Generate a random 16-byte salt.
#[inline]
pub fn gen_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];

    rand::thread_rng().fill_bytes(&mut salt);

    salt
}

/// Check the password and make it terminated with a null byte, `0u8`.
pub fn get_password_with_null_terminated_byte<T: ?Sized + AsRef<[u8]>>(password: &T) -> Cow<[u8]> {
    let password = password.as_ref();

    let password_len = password.len();

    if password_len > 0 {
        let mut i = 0;

        while i < password_len && password[i] > 0 {
            i += 1;
        }

        if i == password_len - 1 {
            Cow::from(password)
        } else {
            let mut new_password = Vec::with_capacity(i + 1);

            new_password.extend_from_slice(&password[..i]);

            new_password.push(0);

            Cow::from(new_password)
        }
    } else {
        Cow::from(password)
    }
}

/// Use bcrypt to hash a password (the null-terminated byte will not be added automatically) whose length is not bigger than 72 bytes to 24 bytes data. If the salt is not 16 bytes, it will be MD5 hashed first.
#[inline]
pub fn bcrypt<T: ?Sized + AsRef<[u8]>, K: ?Sized + AsRef<[u8]>>(
    cost: u8,
    salt: &K,
    password: &T,
) -> Result<[u8; 24], &'static str> {
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

    let hash = if salt.len() != 16 {
        let new_salt = *md5::compute(salt);

        bcrypt::bcrypt(cost as u32, new_salt, password)
    } else {
        let mut salt_fixed = [0u8; 16];
        salt_fixed.copy_from_slice(salt);

        bcrypt::bcrypt(cost as u32, salt_fixed, password)
    };

    Ok(hash)
}

/// Identify a password (the null-terminated byte will not be added automatically) by using the bcrypt-hashed data we've stored before.
///
/// Use this function carefully because it assumes its input parameters are always correct.
///
/// Typically, the unidentified password should be hashed on the client-side instead of using this function on the server-side.
#[allow(clippy::missing_safety_doc)]
#[inline]
pub unsafe fn identify_bcrypt<T: ?Sized + AsRef<[u8]>, K: ?Sized + AsRef<[u8]>>(
    cost: u8,
    salt: &K,
    password: &T,
    hashed: &[u8],
) -> bool {
    match bcrypt(cost, salt, password) {
        Ok(hash) => hashed[..23].eq(&hash[..23]),
        Err(_) => false,
    }
}

/// Use bcrypt to hash a password (the null-terminated byte will not be added automatically) whose length is not bigger than 72 bytes to 24 bytes data. The result will be in Modular Crypt Format. If the salt is not 16 bytes, it will be MD5 hashed first.
pub fn bcrypt_format<T: ?Sized + AsRef<[u8]>, K: ?Sized + AsRef<[u8]>>(
    cost: u8,
    salt: &K,
    password: &T,
) -> Result<String, &'static str> {
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

    let base64_bcrypt = base64::engine::general_purpose::GeneralPurpose::new(
        &base64::alphabet::BCRYPT,
        base64::engine::general_purpose::GeneralPurposeConfig::new().with_encode_padding(false),
    );

    let (hash, salt) = if salt.len() != 16 {
        let new_salt = *md5::compute(salt);

        let hash = bcrypt::bcrypt(cost as u32, new_salt, password);
        let salt = base64_bcrypt.encode(new_salt);

        (hash, salt)
    } else {
        let mut salt_fixed = [0u8; 16];
        salt_fixed.copy_from_slice(salt);

        let hash = bcrypt::bcrypt(cost as u32, salt_fixed, password);
        let salt = base64_bcrypt.encode(salt);

        (hash, salt)
    };

    let hash = base64_bcrypt.encode(&hash[..23]);

    Ok(format!("$2b${:02}${}{}", cost, salt, hash))
}

/// Identify a password (the null-terminated byte will not be added automatically) by using the bcrypt-hashed data in Modular Crypt Format we've stored before.
///
/// Use this function carefully because it assumes its input parameters are always correct.
///
/// Typically, the unidentified password should be hashed on the client-side instead of using this function on the server-side.
#[allow(clippy::missing_safety_doc)]
pub unsafe fn identify_bcrypt_format<T: ?Sized + AsRef<[u8]>, S: AsRef<str>>(
    password: &T,
    hashed_format: S,
) -> bool {
    let hashed_format = hashed_format.as_ref();
    let hashed_format_len = hashed_format.len();

    let cost_index = if hashed_format_len == 59 {
        // $2$
        3
    } else if hashed_format_len == 60 {
        // $2a$, $2b$, ...
        4
    } else {
        return false;
    };

    let cost = match hashed_format[cost_index..cost_index + 2].parse::<u8>() {
        Ok(cost) => cost,
        Err(_) => return false,
    };

    let base64_bcrypt = base64::engine::general_purpose::GeneralPurpose::new(
        &base64::alphabet::BCRYPT,
        base64::engine::general_purpose::GeneralPurposeConfig::new()
            .with_decode_padding_mode(DecodePaddingMode::RequireNone),
    );

    let salt = match base64_bcrypt.decode(&hashed_format[cost_index + 3..cost_index + 25]) {
        Ok(salt) => salt,
        Err(_) => return false,
    };

    let hashed = match base64_bcrypt.decode(&hashed_format[cost_index + 25..]) {
        Ok(hashed) => hashed,
        Err(_) => return false,
    };

    identify_bcrypt(cost, &salt, password, &hashed)
}
