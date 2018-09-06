//! # Passwords
//! This crate provides useful tools to generate multiple readable passwords, as well as analyze and score them.
//!
//! ## Generating Passwords
//!
//! `PasswordGenerator` can be used for generating passwords which consist optional numbers, lowercase letters, uppercase letters and symbols.
//!
//! ```
//! extern crate passwords;
//!
//! use passwords::PasswordGenerator;
//!
//! let pg = PasswordGenerator {
//!        length: 8,
//!        numbers: true,
//!        lowercase_letters: true,
//!        uppercase_letters: true,
//!        symbols: true,
//!        strict: true,
//!    };
//!
//! println!("{}", pg.generate_one().unwrap());
//! println!("{:?}", pg.generate(5).unwrap());
//! ```

mod generator;

pub use generator::PasswordGenerator;