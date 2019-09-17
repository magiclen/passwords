extern crate passwords;

#[test]
fn analyze() {
    let password = "ZYX[$BCkQB中文}%A_3456]  H(\rg";

    let analyzed = passwords::analyzer::analyze(password);

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
}

#[cfg(feature = "common-password")]
#[test]
fn analyze_common() {
    let password = "abc123";

    let analyzed = passwords::analyzer::analyze(password);

    assert!(analyzed.is_common());
}

#[cfg(feature = "common-password")]
#[test]
fn is_common_password_1() {
    assert!(passwords::analyzer::is_common_password("12345678"));
}

#[cfg(feature = "common-password")]
#[test]
fn is_common_password_2() {
    assert!(!passwords::analyzer::is_common_password("5jhx>_\"g-T"));
}
