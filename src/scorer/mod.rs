use ::AnalyzedPassword;

#[cfg(feature = "common-password")]
#[inline]
fn is_common(analyzed_password: &AnalyzedPassword) -> bool {
    analyzed_password.is_common()
}

#[cfg(not(feature = "common-password"))]
#[inline]
fn is_common(_: &AnalyzedPassword) -> bool {
    false
}

/// Score a password by using its analysis.
/// * 0 ~ 20 is very dangerous (may be cracked within few seconds)
/// * 20 ~ 40 is dangerous
/// * 40 ~ 60 is very weak
/// * 60 ~ 80 is weak
/// * 80 ~ 90 is good
/// * 90 ~ 95 is strong
/// * 95 ~ 99 is very strong
/// * 99 ~ 100 is invulnerable
pub fn score(analyzed_password: &AnalyzedPassword) -> f64 {
    let max_score = match analyzed_password.length() - analyzed_password.other_characters_count() {
        0 => 0f64,
        1 => 2f64,
        2 => 5f64,
        3 => 9f64,
        4 => 16f64,
        5 => 25f64,
        6 => 40f64,
        7 => 58f64,
        8 => 80f64,
        9 => 88f64,
        10 => 95f64,
        11 => 100f64,
        _ => {
            (100 + analyzed_password.length() - 11) as f64
        }
    };

    let mut score = max_score;

    if score > 0f64 {
        if analyzed_password.spaces_count() >= 1 {
            score += analyzed_password.spaces_count() as f64;
        }

        if analyzed_password.numbers_count() == 0 {
            score -= max_score * 0.05;
        }

        if analyzed_password.lowercase_letters_count() == 0 {
            score -= max_score * 0.1;
        }
        if analyzed_password.uppercase_letters_count() == 0 {
            score -= max_score * 0.1;
        }
        if analyzed_password.spaces_count() == 0 {
            score -= max_score * 0.1;
        }
        if analyzed_password.lowercase_letters_count() >= 1 && analyzed_password.uppercase_letters_count() >= 1 {
            score += 1f64;
        }
        if analyzed_password.symbols_count() >= 1 {
            score += 1f64;
        }

        score -= max_score * (analyzed_password.consecutive_count() as f64 / analyzed_password.length() as f64 / 5f64);

        score -= max_score * (analyzed_password.progressive_count() as f64 / analyzed_password.length() as f64 / 5f64);

        score -= max_score * (analyzed_password.non_consecutive_count() as f64 / analyzed_password.length() as f64 / 10f64);
    }

    if score < 0f64 {
        score = 0f64;
    } else if score > max_score {
        score = max_score;
    }

    score += analyzed_password.other_characters_count() as f64 * 20f64;

    if score > 100f64 {
        score = 100f64;
    }

    if is_common(analyzed_password) {
        score /= 5f64;
    }

    score
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_password() {
        let password = "kq4zpz13";

        let analyzed = ::analyzer::analyze(password);

        assert_eq!(62f64, score(&analyzed));
    }

    #[test]
    fn strong_password() {
        let password = "ZYX[$BCkQB中文}%A_3456]  H(\rg";

        let analyzed = ::analyzer::analyze(password);

        assert_eq!(100f64, score(&analyzed));
    }

    #[test]
    fn common_password() {
        let password = "abc123";

        let analyzed = ::analyzer::analyze(password);

        if cfg!(feature = "common-password") {
            assert_eq!(4.8f64, score(&analyzed)); // "abc123" is common, so the score is punitively the original divided by 5
        } else {
            assert_eq!(24f64, score(&analyzed));
        }
    }
}
