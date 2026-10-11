//! The entry text format: password line, field section, and notes. Content is stored verbatim;
//! parsing only drives display, search, TOTP, and import mapping.

use zeroize::Zeroizing;

/// One `key: value` field. Values may be secrets, so they are zeroized.
#[derive(Clone)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct Field {
    /// Key, compared case-insensitively.
    pub key: String,
    /// Value.
    pub value: Zeroizing<String>,
}

/// A parsed entry.
#[derive(Clone)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct ParsedEntry {
    /// Line 1. May be empty.
    pub password: Zeroizing<String>,
    /// Fields in order; keys may repeat.
    pub fields: Vec<Field>,
    /// `otpauth://` URI lines in the field section, in order.
    pub otpauth: Vec<Zeroizing<String>>,
    /// The notes, verbatim, or `None` when there are none.
    pub notes: Option<Zeroizing<String>>,
}

impl ParsedEntry {
    /// The first value of `key`, case-insensitively.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|f| f.key.eq_ignore_ascii_case(key))
            .map(|f| f.value.as_str())
    }
}

fn strip_cr(l: &str) -> &str {
    l.strip_suffix('\r').unwrap_or(l)
}

/// Parse entry content. Content that is not UTF-8 has no fields and yields `None`.
pub fn parse_entry_text(content: &[u8]) -> Option<ParsedEntry> {
    let text = core::str::from_utf8(content).ok()?;
    let raw: Vec<&str> = text.split('\n').collect();
    let lines: Vec<&str> = raw.iter().map(|l| strip_cr(l)).collect();
    let password = Zeroizing::new(lines[0].to_owned());
    let mut fields = Vec::new();
    let mut otpauth = Vec::new();
    let n = lines.len();
    let mut i = 1;
    while i < n {
        let l = lines[i];
        if l.starts_with("otpauth://") {
            otpauth.push(Zeroizing::new(l.to_owned()));
            i += 1;
            continue;
        }
        let Some(colon) = l.find(':') else { break };
        let key = &l[..colon];
        if key.is_empty() || key.starts_with(char::is_whitespace) {
            break;
        }
        let rest = &l[colon + 1..];
        let value = if rest.is_empty() {
            ""
        } else if let Some(v) = rest.strip_prefix(' ') {
            v
        } else {
            break;
        };
        i += 1;
        if value == "|" && i < n && lines[i].starts_with("  ") {
            let mut block: Vec<&str> = Vec::new();
            while i < n && lines[i].starts_with("  ") {
                block.push(&lines[i][2..]);
                i += 1;
            }
            fields.push(Field {
                key: key.to_owned(),
                value: Zeroizing::new(block.join("\n")),
            });
        } else {
            fields.push(Field {
                key: key.to_owned(),
                value: Zeroizing::new(value.to_owned()),
            });
        }
    }
    if i < n && lines[i].is_empty() {
        i += 1;
    }
    let notes = if i < n {
        raw[i..].join("\n")
    } else {
        String::new()
    };
    let notes = (!notes.is_empty()).then(|| Zeroizing::new(notes));
    Some(ParsedEntry {
        password,
        fields,
        otpauth,
        notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn never_panics(b in proptest::collection::vec(any::<u8>(), 0..400)) {
            let _ = parse_entry_text(&b);
        }
    }
}
