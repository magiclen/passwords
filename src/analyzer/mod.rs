use std::collections::HashMap;

#[cfg(feature = "common-password")]
#[derive(Debug, Clone, PartialEq)]
/// The struct of an analysis.
pub struct AnalyzedPassword {
    password: String,
    length: usize,
    spaces_count: usize,
    numbers_count: usize,
    lowercase_letters_count: usize,
    uppercase_letters_count: usize,
    symbols_count: usize,
    other_characters_count: usize,
    consecutive_count: usize,
    non_consecutive_count: usize,
    progressive_count: usize,
    is_common: bool,
}

#[cfg(not(feature = "common-password"))]
#[derive(Debug, Clone, PartialEq)]
/// The struct of an analysis.
pub struct AnalyzedPassword {
    password: String,
    length: usize,
    spaces_count: usize,
    numbers_count: usize,
    lowercase_letters_count: usize,
    uppercase_letters_count: usize,
    symbols_count: usize,
    other_characters_count: usize,
    consecutive_count: usize,
    non_consecutive_count: usize,
    progressive_count: usize,
}

impl AnalyzedPassword {
    pub fn password(&self) -> &str {
        &self.password
    }

    pub fn length(&self) -> usize {
        self.length
    }

    pub fn spaces_count(&self) -> usize {
        self.spaces_count
    }

    pub fn numbers_count(&self) -> usize {
        self.numbers_count
    }

    pub fn lowercase_letters_count(&self) -> usize {
        self.lowercase_letters_count
    }

    pub fn uppercase_letters_count(&self) -> usize {
        self.uppercase_letters_count
    }

    pub fn symbols_count(&self) -> usize {
        self.symbols_count
    }

    pub fn other_characters_count(&self) -> usize {
        self.other_characters_count
    }

    pub fn consecutive_count(&self) -> usize {
        self.consecutive_count
    }

    pub fn non_consecutive_count(&self) -> usize {
        self.non_consecutive_count
    }

    pub fn progressive_count(&self) -> usize {
        self.progressive_count
    }

    pub fn into_password(self) -> String {
        self.password
    }

    #[cfg(feature = "common-password")]
    pub fn is_common(&self) -> bool {
        self.is_common
    }
}

#[cfg(feature = "common-password")]
macro_rules! gen_analyzed_password {
    (
        $password:ident,
        $length:ident,
        $spaces_count:ident,
        $numbers_count:ident,
        $lowercase_letters_count:ident,
        $uppercase_letters_count:ident,
        $symbols_count:ident,
        $other_characters_count:ident,
        $consecutive_count:ident,
        $non_consecutive_count:ident,
        $progressive_count:ident,
        $is_common:ident
    ) => {{
        let $is_common = is_common_password(&$password);
        AnalyzedPassword {
            $password,
            $length,
            $spaces_count,
            $numbers_count,
            $lowercase_letters_count,
            $uppercase_letters_count,
            $symbols_count,
            $other_characters_count,
            $consecutive_count,
            $non_consecutive_count,
            $progressive_count,
            $is_common,
        }
    }};
}

#[cfg(not(feature = "common-password"))]
macro_rules! gen_analyzed_password {
    (
        $password:ident,
        $length:ident,
        $spaces_count:ident,
        $numbers_count:ident,
        $lowercase_letters_count:ident,
        $uppercase_letters_count:ident,
        $symbols_count:ident,
        $other_characters_count:ident,
        $consecutive_count:ident,
        $non_consecutive_count:ident,
        $progressive_count:ident,
        $is_common:ident
    ) => {{
        AnalyzedPassword {
            $password,
            $length,
            $spaces_count,
            $numbers_count,
            $lowercase_letters_count,
            $uppercase_letters_count,
            $symbols_count,
            $other_characters_count,
            $consecutive_count,
            $non_consecutive_count,
            $progressive_count,
        }
    }};
}

#[cfg(not(debug_assertions))]
#[cfg(feature = "common-password")]
static COMMON_PASSWORDS: [&'static str; 422054] =
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/data/common-passwords.json"));

#[cfg(debug_assertions)]
#[cfg(feature = "common-password")]
static COMMON_PASSWORDS: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/data/common-passwords.json"));

#[cfg(debug_assertions)]
#[cfg(feature = "common-password")]
/// Whether the input password is common or not. A common password means it is dangerous.
pub fn is_common_password<S: AsRef<str>>(password: S) -> bool {
    let target = format!("\"{}\"", password.as_ref());

    COMMON_PASSWORDS.contains(&target.as_str())
}

#[cfg(not(debug_assertions))]
#[cfg(feature = "common-password")]
/// Whether the input password is common or not. A common password means it is dangerous.
pub fn is_common_password<S: AsRef<str>>(password: S) -> bool {
    COMMON_PASSWORDS.binary_search(&password.as_ref()).is_ok()
}

/// Analyze a password.
pub fn analyze<S: AsRef<str>>(password: S) -> AnalyzedPassword {
    let password = password.as_ref();
    let password_chars = password.chars();

    let mut spaces_count = 0usize;
    let mut numbers_count = 0usize;
    let mut lowercase_letters_count = 0usize;
    let mut uppercase_letters_count = 0usize;
    let mut symbols_count = 0usize;
    let mut other_characters_count = 0usize;
    let mut consecutive_count = 0usize;
    let mut non_consecutive_count = 0usize;
    let mut progressive_count = 0usize;

    let mut last_char_code: u32 = <u32>::max_value();
    let mut last_step: i32 = <i32>::max_value();
    let mut last_step_consecutive = false;
    let mut last_step_repeat = false;
    let mut last_char_code_consecutive = false;

    let mut count_map: HashMap<char, usize> = HashMap::new();

    let mut password = String::with_capacity(password.len());

    let mut length = 0;

    for c in password_chars {
        let char_code = c as u32;

        if char_code <= 0x1F || char_code == 0x7F {
            continue;
        }

        password.push(c);

        length += 1;

        let count = count_map.entry(c).or_insert(0);
        *count += 1;

        if last_char_code == char_code {
            if last_char_code_consecutive {
                consecutive_count += 1;
            } else {
                consecutive_count += 2;
                last_char_code_consecutive = true;
            }
            last_step_consecutive = false;
        } else {
            last_char_code_consecutive = false;
            let step = last_char_code as i32 - char_code as i32;
            last_char_code = char_code;
            if last_step == step {
                if last_step_consecutive {
                    progressive_count += 1;
                } else {
                    last_step_consecutive = true;
                    if last_step_repeat {
                        progressive_count += 2;
                    } else {
                        progressive_count += 3;
                    }
                    last_step_repeat = true;
                }
            } else {
                last_step = step;
                if last_step_consecutive {
                    last_step_consecutive = false;
                } else {
                    last_step_repeat = false;
                }
            }
        }
        if char_code >= 48 && char_code <= 57 {
            numbers_count += 1;
        } else if char_code >= 65 && char_code <= 90 {
            uppercase_letters_count += 1;
        } else if char_code >= 97 && char_code <= 122 {
            lowercase_letters_count += 1;
        } else if char_code == 32 {
            spaces_count += 1;
        } else if char_code >= 33 && char_code <= 47
            || char_code >= 58 && char_code <= 64
            || char_code >= 91 && char_code <= 96
            || char_code >= 123 && char_code <= 126
        {
            symbols_count += 1;
        } else {
            other_characters_count += 1;
        }
    }

    for (_, &a) in count_map.iter() {
        if a > 1 {
            non_consecutive_count += a;
        }
    }

    non_consecutive_count -= consecutive_count;

    gen_analyzed_password!(
        password,
        length,
        spaces_count,
        numbers_count,
        lowercase_letters_count,
        uppercase_letters_count,
        symbols_count,
        other_characters_count,
        consecutive_count,
        non_consecutive_count,
        progressive_count,
        is_common
    )
}
