extern crate random_pick;

static NUMBERS: [&'static str; 9] = ["1", "2", "3", "4", "5", "6", "7", "8", "9"];
static LOWERCASE_LETTERS: [&'static str; 23] = ["a", "b", "c", "d", "e", "f", "g", "h", "j", "k", "m", "n", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"];
static UPPERCASE_LETTERS: [&'static str; 23] = ["A", "B", "C", "D", "E", "F", "G", "H", "J", "K", "M", "N", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"];
static SYMBOLS: [&'static str; 28] = ["!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "+", "_", "-", "=", "}", "{", "[", "]", ":", ";", "\"", "/", "?", ".", ">", "<", ",", "~"];

/// This struct can help you generate passwords.
#[derive(Debug, Clone, PartialEq)]
pub struct PasswordGenerator {
    /// The length of the generated passwords.
    pub length: usize,
    /// Passwords are allowed to, or must if the strict is true, contain a number or numbers.
    /// Numbers are `123456789`. (0 is excluded)
    pub numbers: bool,
    /// Passwords are allowed to, or must if the strict is true, contain a lowercase letter or lowercase letters.
    /// Lowercase letters are `abcdefghjkmnpqrstuvwxyz`. (i, l, o are excluded)
    pub lowercase_letters: bool,
    /// Passwords are allowed to, or must if the strict is true, contain an uppercase letter or uppercase letters.
    /// Uppercase letters are `ABCDEFGHJKMNPQRSTUVWXYZ`. (I, L, O are excluded)
    pub uppercase_letters: bool,
    /// Passwords are allowed to, or must if the strict is true, contain a symbol or symbols.
    /// Symbols are `!@#$%^&*()+_-=}{[]:;"/?.><,~`.
    pub symbols: bool,
    /// Whether the password rules are strict.
    pub strict: bool,
}

impl PasswordGenerator {
    /// Generate random passwords.
    pub fn generate(&self, count: usize) -> Result<Vec<String>, &'static str> {
        if self.length == 0 {
            return Err("A password's length cannot be 0.");
        }

        let mut pool: Vec<&[&'static str]> = Vec::new();

        let mut sections_count = 0;

        let mut target_mask: u8 = 0;

        if self.numbers {
            pool.push(&NUMBERS);
            sections_count += 1;
            target_mask |= 0b00000001;
        }

        if self.lowercase_letters {
            pool.push(&LOWERCASE_LETTERS);
            sections_count += 1;
            target_mask |= 0b00000010;
        }

        if self.uppercase_letters {
            pool.push(&UPPERCASE_LETTERS);
            sections_count += 1;
            target_mask |= 0b00000100;
        }

        if self.symbols {
            pool.push(&SYMBOLS);
            sections_count += 1;
            target_mask |= 0b00001000;
        }

        if !self.numbers && !self.lowercase_letters && !self.uppercase_letters && !self.symbols {
            return Err("You need to enable at least one kind of characters.");
        }

        if self.strict && self.length < sections_count {
            return Err("The length of passwords is too short.");
        }
        if self.strict {
            if self.length < sections_count {
                return Err("The length of passwords is too short.");
            }

            let mut result = Vec::with_capacity(count);

            while result.len() < count {
                let c = count - result.len();

                let random = random_pick::pick_multiple_from_multiple_slices(&pool, &[1], c * self.length);

                for i in (0..c).step_by(self.length) {
                    let start = i * self.length;

                    let mut password = String::with_capacity(self.length);
                    let mut mask: u8 = 0;
                    let mut m = false;

                    for &s in &random[start..start + self.length] {
                        password.push_str(s);

                        if !m {
                            if NUMBERS.contains(s) {
                                mask |= 0b00000001;
                            } else if LOWERCASE_LETTERS.contains(s) {
                                mask |= 0b00000010;
                            } else if UPPERCASE_LETTERS.contains(s) {
                                mask |= 0b00000100;
                            } else if SYMBOLS.contains(s) {
                                mask |= 0b00001000;
                            } else {
                                continue;
                            }
                            m = mask == target_mask;
                        }
                    }

                    if !m {
                        if mask != target_mask {
                            continue;
                        }
                    }

                    result.push(password);
                }
            }

            Ok(result)
        } else {
            let random = random_pick::pick_multiple_from_multiple_slices(&pool, &[1], count * self.length);

            let mut result = Vec::with_capacity(count);

            for i in (0..count).step_by(self.length) {
                let start = i * self.length;

                let mut password = String::with_capacity(self.length);
                for &s in &random[start..start + self.length] {
                    password.push_str(s);
                }

                result.push(password);
            }

            Ok(result)
        }
    }

    /// Generate a random password.
    pub fn generate_one(&self) -> Result<String, &'static str> {
        Ok(self.generate(1)?.remove(0))
    }
}


#[cfg(test)]
mod tests {
    extern crate regex;

    use super::*;

    const PASSWORD_COUNT: usize = 5000;

    #[test]
    fn test_generate_password_lv1() {
        let pg = PasswordGenerator {
            length: 8,
            numbers: true,
            lowercase_letters: false,
            uppercase_letters: false,
            symbols: false,
            strict: false,
        };

        let re = regex::Regex::new(r"^[1-9]{8}$").unwrap();

        for _ in 0..PASSWORD_COUNT {
            let result = pg.generate_one().unwrap();

            assert!(re.is_match(&result));
        }
    }

    #[test]
    fn test_generate_password_lv2() {
        let pg = PasswordGenerator {
            length: 8,
            numbers: true,
            lowercase_letters: true,
            uppercase_letters: false,
            symbols: false,
            strict: false,
        };

        let re = regex::Regex::new(r"^[1-9a-hj-km-np-z]{8}$").unwrap();

        let results = pg.generate(PASSWORD_COUNT).unwrap();

        for result in results {
            assert!(re.is_match(&result));
        }
    }

    #[test]
    fn test_generate_password_lv3() {
        let pg = PasswordGenerator {
            length: 8,
            numbers: true,
            lowercase_letters: true,
            uppercase_letters: true,
            symbols: false,
            strict: false,
        };

        let re = regex::Regex::new(r"^[1-9a-hj-km-np-zA-HJ-KM-NP-Z]{8}$").unwrap();

        let results = pg.generate(PASSWORD_COUNT).unwrap();

        for result in results {
            assert!(re.is_match(&result));
        }
    }

    #[test]
    fn test_generate_password_lv4() {
        let pg = PasswordGenerator {
            length: 8,
            numbers: true,
            lowercase_letters: true,
            uppercase_letters: true,
            symbols: true,
            strict: false,
        };

        let re = regex::Regex::new("^[1-9a-hj-km-np-zA-HJ-KM-NP-Z!@#$%^&*()+_\\-=}{\\[\\]:;\"/?.><,~]{8}$").unwrap();

        let results = pg.generate(PASSWORD_COUNT).unwrap();

        for result in results {
            assert!(re.is_match(&result));
        }
    }

    #[test]
    fn test_generate_password_lv5() {
        let pg = PasswordGenerator {
            length: 8,
            numbers: true,
            lowercase_letters: true,
            uppercase_letters: false,
            symbols: false,
            strict: true,
        };

        let re = regex::Regex::new(r"^[1-9a-hj-km-np-z]{8}$").unwrap();
        let re_n = regex::Regex::new(r"[1-9]+").unwrap();
        let re_l = regex::Regex::new(r"[a-hj-km-np-z]+").unwrap();

        let results = pg.generate(PASSWORD_COUNT).unwrap();

        for result in results {
            assert!(re.is_match(&result));
            assert!(re_n.is_match(&result));
            assert!(re_l.is_match(&result));
        }
    }

    #[test]
    fn test_generate_password_lv6() {
        let pg = PasswordGenerator {
            length: 8,
            numbers: true,
            lowercase_letters: true,
            uppercase_letters: true,
            symbols: false,
            strict: true,
        };

        let re = regex::Regex::new(r"^[1-9a-hj-km-np-zA-HJ-KM-NP-Z]{8}$").unwrap();
        let re_n = regex::Regex::new(r"[1-9]+").unwrap();
        let re_l = regex::Regex::new(r"[a-hj-km-np-z]+").unwrap();
        let re_u = regex::Regex::new(r"[A-HJ-KM-NP-Z]+").unwrap();

        let results = pg.generate(PASSWORD_COUNT).unwrap();

        for result in results {
            assert!(re.is_match(&result));
            assert!(re_n.is_match(&result));
            assert!(re_l.is_match(&result));
            assert!(re_u.is_match(&result));
        }
    }

    #[test]
    fn test_generate_password_lv7() {
        let pg = PasswordGenerator {
            length: 8,
            numbers: true,
            lowercase_letters: true,
            uppercase_letters: true,
            symbols: true,
            strict: true,
        };

        let re = regex::Regex::new("^[1-9a-hj-km-np-zA-HJ-KM-NP-Z!@#$%^&*()+_\\-=}{\\[\\]:;\"/?.><,~]{8}$").unwrap();
        let re_n = regex::Regex::new(r"[1-9]+").unwrap();
        let re_l = regex::Regex::new(r"[a-hj-km-np-z]+").unwrap();
        let re_u = regex::Regex::new(r"[A-HJ-KM-NP-Z]+").unwrap();
        let re_s = regex::Regex::new("[!@#$%^&*()+_\\-=}{\\[\\]:;\"/?.><,~]+").unwrap();

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
