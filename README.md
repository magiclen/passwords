Passwords
====================

[![Build Status](https://travis-ci.org/magiclen/passwords.svg?branch=master)](https://travis-ci.org/magiclen/passwords)
[![Build status](https://ci.appveyor.com/api/projects/status/do7d8pu833tdk4tm/branch/master?svg=true)](https://ci.appveyor.com/project/magiclen/passwords/branch/master)

This crate provides useful tools to generate multiple readable passwords, as well as analyze and score them.

## Generating Passwords

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

## Hashing

To enable hashing functions, you need to enable the **crypto** feature.

```toml
[dependencies.passwords]
version = "*"
features = ["crypto"]
```

Then, `bcrypt`, `identify_bcrypt` and `gen_salt` functions are available.

```rust
extern crate passwords;

let salt = passwords::gen_salt();
let hashed = passwords::bcrypt(10, &salt, "password").unwrap();
assert!(passwords::identify_bcrypt(10, &salt, "password", &hashed).unwrap());
```

## TODO

* Analyzer
* Scorer

## Crates.io

https://crates.io/crates/passwords

## Documentation

https://docs.rs/passwords

## License

[MIT](LICENSE)