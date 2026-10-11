//! Path, label, and prefix rules.

use crate::limits::{LABEL_MAX, PATH_MAX};

/// Whether `c` is a control character as the path rules define it: C0, `U+007F`, or C1.
fn is_control(c: char) -> bool {
    let u = c as u32;
    u < 0x20 || (0x7f..=0x9f).contains(&u)
}

/// The structural path rules: at most 1,024 bytes, `/`-separated, no empty, `.`, or `..`
/// segment, no leading or trailing `/`, and no control characters. NFC is never checked here;
/// clients normalise on entry, not on decode.
pub fn is_valid_path(p: &str) -> bool {
    if p.is_empty() || p.len() > PATH_MAX || p.chars().any(is_control) {
        return false;
    }
    p.split('/')
        .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

/// Device label: 1 to 32 characters from `[a-z0-9-]`.
pub fn is_valid_label(l: &str) -> bool {
    !l.is_empty()
        && l.len() <= LABEL_MAX
        && l.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Bucket prefix: 1 to 64 characters from `[A-Za-z0-9._/-]`, ending in `/`.
pub fn is_valid_prefix(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 64
        && p.ends_with('/')
        && p.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._/-".contains(&b))
}

/// Normalise a path to NFC, as clients do when a user enters or imports one.
pub fn normalise_path(p: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    p.nfc().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_rules() {
        assert!(is_valid_path("Email/example.com"));
        assert!(is_valid_path("Wörk/ünïcode"));
        for bad in [
            "", "/a", "a/", "a//b", "a/./b", "a/../b", "..", "a\u{7}b", "a\u{7f}b", "a\u{85}b",
        ] {
            assert!(!is_valid_path(bad), "{bad:?}");
        }
        assert!(is_valid_path(&"a".repeat(1024)));
        assert!(!is_valid_path(&"a".repeat(1025)));
    }

    #[test]
    fn label_and_prefix_rules() {
        assert!(is_valid_label("pixel-7"));
        assert!(!is_valid_label("Pixel"));
        assert!(!is_valid_label(""));
        assert!(!is_valid_label(&"a".repeat(33)));
        assert!(is_valid_prefix("vlt/"));
        assert!(!is_valid_prefix("vlt"));
        assert!(!is_valid_prefix("v:t/"));
    }
}
