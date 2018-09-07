Passwords
====================

[![Build Status](https://travis-ci.org/magiclen/passwords.svg?branch=master)](https://travis-ci.org/magiclen/passwords)
[![Build status](https://ci.appveyor.com/api/projects/status/do7d8pu833tdk4tm/branch/master?svg=true)](https://ci.appveyor.com/project/magiclen/passwords/branch/master)

This crate provides useful tools to generate multiple readable passwords, as well as analyze and score them.

## Generator

`PasswordGenerator` can be used for generating passwords which consist optional numbers, lowercase letters, uppercase letters and symbols.

```rust
extern crate passwords;

use passwords::PasswordGenerator;

let pg = PasswordGenerator {
       length: 8,
       numbers: true,
       lowercase_letters: true,
       uppercase_letters: true,
       symbols: true,
       strict: true,
   };

println!("{}", pg.generate_one().unwrap());
println!("{:?}", pg.generate(5).unwrap());
```

## Hasher

To enable hashing functions, you need to enable the **crypto** feature.

```toml
[dependencies.passwords]
version = "*"
features = ["crypto"]
```

Then, `bcrypt`, `identify_bcrypt` and `gen_salt` functions in the `hasher` module are available.

```rust
extern crate passwords;
use passwords::hasher;

let salt = hasher::gen_salt();
let hashed = hasher::bcrypt(10, &salt, "password").unwrap();
assert!(hasher::identify_bcrypt(10, &salt, "password", &hashed).unwrap());
```

## Analyzer

The `analyze` function is `analyzer` module can be used to create a `AnalyzedPassword` instance which contains some information about the input password.

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

You should notice that after you enable the **common-password** feature, the time for compiling increases dramatically, because the *common passwords table* will be compiled into the executable binary file.

## TODO

* Scorer

## Crates.io

https://crates.io/crates/passwords

## Documentation

https://docs.rs/passwords

## License

[MIT](LICENSE)