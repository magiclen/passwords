extern crate random_pick;

static NUMBERS: [char; 9] = ['1', '2', '3', '4', '5', '6', '7', '8', '9'];
static LOWERCASE_LETTERS: [char; 23] = [
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'j', 'k', 'm', 'n', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z',
];
static UPPERCASE_LETTERS: [char; 23] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
    'W', 'X', 'Y', 'Z',
];
static SYMBOLS: [char; 28] = [
    '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '+', '_', '-', '=', '}', '{', '[', ']', ':',
    ';', '"', '/', '?', '.', '>', '<', ',', '~',
];

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

        let mut pool: Vec<&[char]> = Vec::new();

        let mut sections_count = 0;

        let mut target_mask: u8 = 0;

        if self.numbers {
            pool.push(&NUMBERS);
            sections_count += 1;
            target_mask |= 0b0000_0001;
        }

        if self.lowercase_letters {
            pool.push(&LOWERCASE_LETTERS);
            sections_count += 1;
            target_mask |= 0b0000_0010;
        }

        if self.uppercase_letters {
            pool.push(&UPPERCASE_LETTERS);
            sections_count += 1;
            target_mask |= 0b0000_0100;
        }

        if self.symbols {
            pool.push(&SYMBOLS);
            sections_count += 1;
            target_mask |= 0b0000_1000;
        }

        if !self.numbers && !self.lowercase_letters && !self.uppercase_letters && !self.symbols {
            return Err("You need to enable at least one kind of characters.");
        }

        if self.strict {
            if self.length < sections_count {
                return Err("The length of passwords is too short.");
            }

            let mut result = Vec::with_capacity(count);

            while result.len() < count {
                let c = count - result.len();

                let random =
                    random_pick::pick_multiple_from_multiple_slices(&pool, &[1], c * self.length);

                for i in (0..c).step_by(self.length) {
                    let start = i * self.length;

                    let mut password = String::with_capacity(self.length);
                    let mut mask: u8 = 0;
                    let mut m = false;

                    for &c in random[start..start + self.length].iter() {
                        password.push(*c);

                        if !m {
                            if NUMBERS.contains(c) {
                                mask |= 0b0000_0001;
                            } else if LOWERCASE_LETTERS.contains(c) {
                                mask |= 0b0000_0010;
                            } else if UPPERCASE_LETTERS.contains(c) {
                                mask |= 0b0000_0100;
                            } else if SYMBOLS.contains(c) {
                                mask |= 0b0000_1000;
                            } else {
                                continue;
                            }
                            m = mask == target_mask;
                        }
                    }

                    if !m && mask != target_mask {
                        continue;
                    }

                    result.push(password);
                }
            }

            Ok(result)
        } else {
            let random =
                random_pick::pick_multiple_from_multiple_slices(&pool, &[1], count * self.length);

            let mut result = Vec::with_capacity(count);

            for i in (0..count).step_by(self.length) {
                let start = i * self.length;

                let mut password = String::with_capacity(self.length);
                for &&c in random[start..start + self.length].iter() {
                    password.push(c);
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
