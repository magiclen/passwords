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
    /// Numbers are `123456789`.
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
    pub fn generate(&self, count: usize) -> Result<Vec<String>, &'static str> {
        if self.length == 0 {
            return Err("A password's length cannot be 0.");
        }

        let mut pool: Vec<&[&'static str]> = Vec::new();

        let mut sections_count = 0;

        if self.numbers {
            pool.push(&NUMBERS);
            sections_count += 1;
        }

        if self.lowercase_letters {
            pool.push(&LOWERCASE_LETTERS);
            sections_count += 1;
        }

        if self.uppercase_letters {
            pool.push(&UPPERCASE_LETTERS);
            sections_count += 1;
        }

        if self.symbols {
            pool.push(&SYMBOLS);
            sections_count += 1;
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

            return Err("Not support yet");
        } else {
            let mut random = random_pick::pick_multiple_from_multiple_slices(&pool, &[1], count * self.length);

            for i in (0..count).step_by(self.length) {

            }
        }

        let mut result: Vec<String> = Vec::new();

        for _ in 0..count {
            let mut password = String::with_capacity(self.length);

            if self.strict {
                return Err("Not support yet");
            } else {}
        }

        Ok(result)
    }

    pub fn generate_one(&self) -> Result<String, &'static str> {
        Ok(self.generate(1)?.remove(0))
    }
}