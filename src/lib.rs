/*!
# Passwords
This crate provides useful tools to generate multiple readable passwords, as well as analyze and score them.

## Generator

`PasswordGenerator` can be used for generating passwords which consist optional numbers, lowercase letters, uppercase letters, symbols and spaces.

```rust
extern crate passwords;

use passwords::PasswordGenerator;

let pg = PasswordGenerator {
       length: 8,
       numbers: true,
       lowercase_letters: true,
       uppercase_letters: true,
       symbols: true,
       spaces: true,
       exclude_similar_characters: false,
       strict: true,
   };

println!("{}", pg.generate_one().unwrap());
println!("{:?}", pg.generate(5).unwrap());
```

It also has a fluent interface.

```rust
extern crate passwords;

use passwords::PasswordGenerator;

let pg = PasswordGenerator::new().length(8).numbers(true).lowercase_letters(true).uppercase_letters(true).symbols(true).spaces(true).exclude_similar_characters(true).strict(true);

println!("{}", pg.generate_one().unwrap());
println!("{:?}", pg.generate(5).unwrap());
```

The `generate` method has been optimized for multiple generation. Don't reuse the `generate_one` method to generate multiple passwords. If the count of passwords can't be determined, use the `try_iter` method to create a `PasswordGeneratorIter` instance which implements the `Iterator` trait and can re-generate passwords more efficiently.

```rust
extern crate passwords;

use passwords::PasswordGenerator;

let pgi = PasswordGenerator::new().try_iter().unwrap();

println!("{}", pgi.generate_one());
println!("{:?}", pgi.generate(5));
```

```rust
extern crate passwords;

use passwords::PasswordGenerator;

let mut pgi = PasswordGenerator::new().try_iter().unwrap();

println!("{}", pgi.next().unwrap());
println!("{}", pgi.next().unwrap());
```

## Hasher

To enable hashing functions, you need to enable the **crypto** feature.

```toml
[dependencies.passwords]
version = "*"
features = ["crypto"]
```

Then, `bcrypt`, `identify_bcrypt`, `bcrypt_format`, `identify_bcrypt_format`, `get_password_with_null_terminated_byte` and `gen_salt` functions in the `hasher` module are available.

```rust,ignore
extern crate passwords;

let salt = passwords::gen_salt();
let hashed = passwords::bcrypt(10, &salt, "password\0").unwrap();
assert!(passwords::identify_bcrypt(10, &salt, "password\0", &hashed).unwrap());
```

## Analyzer

The `analyze` function in the `analyzer` module can be used to create a `AnalyzedPassword` instance which contains some information about the input password.

Typically, we don't want our readable password to contain control characters like BS, LF, CR, etc.
Before the analyzer analyzes a password, it filters the password in order to remove its control characters. And after analyzing, the analyzer will return the filtered password.
Therefore, you can use this analyzer as a password guard before you store the input password (or generally hash it first and then store) to your database.

```rust
extern crate passwords;

use passwords::analyzer;

let password = "ZYX[$BCkQB中文}%A_3456]  H(\rg";

let analyzed = analyzer::analyze(password);

assert_eq!("ZYX[$BCkQB中文}%A_3456]  H(g", analyzed.password()); // "\r" was filtered
assert_eq!(26, analyzed.length()); // Characters' length, instead of that of UTF-8 bytes
assert_eq!(2, analyzed.spaces_count()); // Two spaces between "]" and "H"
assert_eq!(4, analyzed.numbers_count()); // Numbers are "3456"
assert_eq!(2, analyzed.lowercase_letters_count()); // Lowercase letters are "k" and "g"
assert_eq!(9, analyzed.uppercase_letters_count()); // Uppercase letters are "ZYX", "BC", "QB", "A" and "H"
assert_eq!(7, analyzed.symbols_count()); // Symbols are "[$", "}%", "_", "]" and "("
assert_eq!(2, analyzed.other_characters_count()); // Other characters are "中文". These characters are usually not included on the rainbow table.
assert_eq!(2, analyzed.consecutive_count()); // Consecutive repeated characters are "  " (two spaces)
assert_eq!(2, analyzed.non_consecutive_count()); // Non-consecutive repeated characters are "B" (appears twice)
assert_eq!(7, analyzed.progressive_count()); // Progressive characters are "ZYX" and "3456". "BC" is not counted, because its length is only 2, not three or more.
```

You can also check whether a password is too simple and dangerous to use, by looking up a *common passwords table*.
If you want to do that, you need to enable the **common-password** feature.

```toml
[dependencies.passwords]
version = "*"
features = ["common-password"]
```
Then, the `is_common_password` function in `analyzer` module and the `is_common` method of a `AnalyzedPassword` instance are available.

You should notice that after you enable the **common-password** feature, the time for compiling increases dramatically, because the *common passwords table* will be compiled into the executable binary file as a hardcode array.


## Scorer

After analyzing a password, you can use the `score` function in the `scorer` module to score it.

```rust
extern crate passwords;

use passwords::analyzer;
use passwords::scorer;

assert_eq!(62f64, scorer::score(&analyzer::analyze("kq4zpz13")));
assert_eq!(100f64, scorer::score(&analyzer::analyze("ZYX[$BCkQB中文}%A_3456]  H(\rg")));

if cfg!(feature = "common-password") {
    assert_eq!(11.2f64, scorer::score(&analyzer::analyze("feelings"))); // "feelings" is common, so the score is punitively the original divided by 5
} else {
    assert_eq!(56f64, scorer::score(&analyzer::analyze("feelings")));
}
```

A password whose score is,

* 0 ~ 20 is very dangerous (may be cracked within few seconds)
* 20 ~ 40 is dangerous
* 40 ~ 60 is very weak
* 60 ~ 80 is weak
* 80 ~ 90 is good
* 90 ~ 95 is strong
* 95 ~ 99 is very strong
* 99 ~ 100 is invulnerable
*/

/// Analyze passwords.
pub mod analyzer;
mod generator;
#[cfg(feature = "crypto")]
/// Hash passwords.
pub mod hasher;
/// Score passwords.
pub mod scorer;

pub use analyzer::AnalyzedPassword;
pub use generator::PasswordGenerator;
