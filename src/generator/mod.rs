static NUMBERS: [char; 10] = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'];
static NUMBERS_EXCLUDE_SIMILAR: [char; 8] = ['2', '3', '4', '5', '6', '7', '8', '9'];

static LOWERCASE_LETTERS: [char; 26] = [
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
    't', 'u', 'v', 'w', 'x', 'y', 'z',
];
static LOWERCASE_LETTERS_EXCLUDE_SIMILAR: [char; 23] = [
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'j', 'k', 'm', 'n', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z',
];

static UPPERCASE_LETTERS: [char; 26] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
];
static UPPERCASE_LETTERS_EXCLUDE_SIMILAR: [char; 24] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U',
    'V', 'W', 'X', 'Y', 'Z',
];

static SYMBOLS: [char; 32] = [
    '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/', ':', ';', '<', '=',
    '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|', '}', '~',
];
static SYMBOLS_EXCLUDE_SIMILAR: [char; 28] = [
    '!', '#', '$', '%', '&', '(', ')', '*', '+', ',', '-', '.', '/', ':', ';', '<', '=', '>', '?',
    '@', '[', '\\', ']', '^', '_', '{', '}', '~',
];

static SPACE: [char; 1] = [' '];

/// This struct can help you continually generate passwords.
#[derive(Debug, Clone, PartialEq)]
pub struct PasswordGeneratorIter {
    pool: Vec<&'static [char]>,
    length: usize,
    target_mask: u8,
    strict: bool,
}

impl PasswordGeneratorIter {
    /// Generate random passwords.
    pub fn generate(&self, count: usize) -> Vec<String> {
        debug_assert_ne!(0, self.target_mask);

        let mut result = Vec::with_capacity(count);

        let random =
            random_pick::pick_multiple_from_multiple_slices(&self.pool, &[1], count * self.length);

        if self.strict {
            let mut i = 0;

            while i < count {
                let start = i * self.length;

                let mut password = String::with_capacity(self.length);

                let handle = |random: &[&char], start: usize, end: usize, password: &mut String| {
                    let mut mask: u8 = 0;
                    let mut m = false;

                    for &c in random[start..end].iter() {
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
                            } else if ' '.eq(c) {
                                mask |= 0b0001_0000;
                            } else {
                                continue;
                            }
                            m = mask == self.target_mask;
                        }
                    }

                    m
                };

                if !handle(&random, start, start + self.length, &mut password) {
                    loop {
                        let random = random_pick::pick_multiple_from_multiple_slices(
                            &self.pool,
                            &[1],
                            self.length,
                        );

                        password.clear();

                        if handle(&random, 0, self.length, &mut password) {
                            break;
                        }
                    }
                }

                result.push(password);

                i += 1;
            }
        } else {
            for i in 0..count {
                let start = i * self.length;
                let mut password = String::with_capacity(self.length);

                for &c in random[start..start + self.length].iter() {
                    password.push(*c);
                }

                result.push(password);
            }
        }

        result
    }

    /// Generate a random password.
    #[inline]
    pub fn generate_one(&self) -> String {
        self.generate(1).remove(0)
    }
}

impl Iterator for PasswordGeneratorIter {
    type Item = String;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        Some(self.generate_one())
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (usize::max_value(), None)
    }

    #[inline]
    fn count(self) -> usize
    where
        Self: Sized, {
        usize::max_value()
    }

    #[inline]
    fn last(self) -> Option<Self::Item>
    where
        Self: Sized, {
        Some(self.generate_one())
    }

    #[inline]
    fn nth(&mut self, mut _n: usize) -> Option<Self::Item> {
        Some(self.generate_one())
    }
}

/// This struct can help you generate passwords.
#[derive(Debug, Clone, PartialEq)]
pub struct PasswordGenerator {
    /// The length of the generated passwords.
    ///
    /// Default: `8`
    pub length: usize,
    /// Passwords are allowed to, or must if the strict is true, contain a number or numbers.
    ///
    /// Default: `true`
    pub numbers: bool,
    /// Passwords are allowed to, or must if the strict is true, contain a lowercase letter or lowercase letters.
    ///
    /// Default: `true`
    pub lowercase_letters: bool,
    /// Passwords are allowed to, or must if the strict is true, contain an uppercase letter or uppercase letters.
    ///
    /// Default: `false`
    pub uppercase_letters: bool,
    /// Passwords are allowed to, or must if the strict is true, contain a symbol or symbols.
    ///
    /// Default: `false`
    pub symbols: bool,
    /// Passwords are allowed to, or must if the strict is true, contain a space or spaces.
    ///
    /// Default: `false`
    pub spaces: bool,
    /// Whether to exclude similar characters, ``iI1loO0"'`|``.
    ///
    /// Default: `false`
    pub exclude_similar_characters: bool,
    /// Whether the password rules are strict.
    ///
    /// Default: `false`
    pub strict: bool,
}

impl PasswordGenerator {
    /// Create a `PasswordGenerator` instance.
    ///
    /// ```rust,ignore
    /// PasswordGenerator {
    ///     length: 8,
    ///     numbers: true,
    ///     lowercase_letters: true,
    ///     uppercase_letters: false,
    ///     symbols: false,
    ///     spaces: false,
    ///     exclude_similar_characters: false,
    ///     strict: false,
    /// }
    /// ```
    pub const fn new() -> PasswordGenerator {
        PasswordGenerator {
            length: 8,
            numbers: true,
            lowercase_letters: true,
            uppercase_letters: false,
            symbols: false,
            spaces: false,
            exclude_similar_characters: false,
            strict: false,
        }
    }

    /// The length of the generated passwords.
    pub const fn length(mut self, length: usize) -> PasswordGenerator {
        self.length = length;

        self
    }

    /// Passwords are allowed to, or must if the strict is true, contain a number or numbers.
    pub const fn numbers(mut self, numbers: bool) -> PasswordGenerator {
        self.numbers = numbers;

        self
    }

    /// Passwords are allowed to, or must if the strict is true, contain a lowercase letter or lowercase letters.
    pub const fn lowercase_letters(mut self, lowercase_letters: bool) -> PasswordGenerator {
        self.lowercase_letters = lowercase_letters;

        self
    }

    /// Passwords are allowed to, or must if the strict is true, contain an uppercase letter or uppercase letters.
    pub const fn uppercase_letters(mut self, uppercase_letters: bool) -> PasswordGenerator {
        self.uppercase_letters = uppercase_letters;

        self
    }

    /// Passwords are allowed to, or must if the strict is true, contain a symbol or symbols.
    pub const fn symbols(mut self, symbols: bool) -> PasswordGenerator {
        self.symbols = symbols;

        self
    }

    /// Passwords are allowed to, or must if the strict is true, contain a space or spaces.
    pub const fn spaces(mut self, space: bool) -> PasswordGenerator {
        self.spaces = space;

        self
    }

    /// Whether to exclude similar characters? The excluded similar characters set is ``iI1loO0"'`|``.
    pub const fn exclude_similar_characters(
        mut self,
        exclude_similar_characters: bool,
    ) -> PasswordGenerator {
        self.exclude_similar_characters = exclude_similar_characters;

        self
    }

    /// Whether the password rules are strict.
    pub const fn strict(mut self, strict: bool) -> PasswordGenerator {
        self.strict = strict;

        self
    }
}

impl PasswordGenerator {
    /// Generate random passwords.
    #[inline]
    pub fn generate(&self, count: usize) -> Result<Vec<String>, &'static str> {
        let iter = self.try_iter()?;

        Ok(iter.generate(count))
    }

    /// Generate a random password.
    #[inline]
    pub fn generate_one(&self) -> Result<String, &'static str> {
        let iter = self.try_iter()?;

        Ok(iter.generate_one())
    }

    /// Try to create an iterator for the purpose of reusing.
    pub fn try_iter(&self) -> Result<PasswordGeneratorIter, &'static str> {
        if self.length == 0 {
            return Err("The length of passwords cannot be 0.");
        }

        let mut pool: Vec<&[char]> = Vec::new();

        let mut sections_count = 0;

        let mut target_mask: u8 = 0;

        if self.numbers {
            if self.exclude_similar_characters {
                pool.push(&NUMBERS_EXCLUDE_SIMILAR);
            } else {
                pool.push(&NUMBERS);
            }

            sections_count += 1;
            target_mask |= 0b0000_0001;
        }

        if self.lowercase_letters {
            if self.exclude_similar_characters {
                pool.push(&LOWERCASE_LETTERS_EXCLUDE_SIMILAR);
            } else {
                pool.push(&LOWERCASE_LETTERS);
            }

            sections_count += 1;
            target_mask |= 0b0000_0010;
        }

        if self.uppercase_letters {
            if self.exclude_similar_characters {
                pool.push(&UPPERCASE_LETTERS_EXCLUDE_SIMILAR);
            } else {
                pool.push(&UPPERCASE_LETTERS);
            }

            sections_count += 1;
            target_mask |= 0b0000_0100;
        }

        if self.symbols {
            if self.exclude_similar_characters {
                pool.push(&SYMBOLS_EXCLUDE_SIMILAR);
            } else {
                pool.push(&SYMBOLS);
            }

            sections_count += 1;
            target_mask |= 0b0000_1000;
        }

        if self.spaces {
            pool.push(&SPACE);

            sections_count += 1;
            target_mask |= 0b0001_0000;
        }

        if !self.numbers
            && !self.lowercase_letters
            && !self.uppercase_letters
            && !self.symbols
            && !self.spaces
        {
            Err("You need to enable at least one kind of characters.")
        } else if self.strict && self.length < sections_count {
            Err("The length of passwords is too short.")
        } else {
            Ok(PasswordGeneratorIter {
                pool,
                length: self.length,
                target_mask,
                strict: self.strict,
            })
        }
    }
}

impl Default for PasswordGenerator {
    #[inline]
    fn default() -> PasswordGenerator {
        PasswordGenerator::new()
    }
}
