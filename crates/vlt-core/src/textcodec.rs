//! Crockford base32 and strict unpadded base64url.

use crate::error::{IntegrityKind as K, Result, integrity};

const CROCK: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Crockford base32, most significant bit first, no padding. Trailing bits that do not fill a
/// character are zero-filled on the right.
pub(crate) fn crock(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len() * 8 / 5 + 1);
    let mut acc = 0u32;
    let mut n = 0;
    for &x in b {
        acc = (acc << 8) | x as u32;
        n += 8;
        while n >= 5 {
            n -= 5;
            out.push(CROCK[((acc >> n) & 31) as usize] as char);
        }
        acc &= (1 << n) - 1;
    }
    if n > 0 {
        out.push(CROCK[((acc << (5 - n)) & 31) as usize] as char);
    }
    out
}

/// Tolerant Crockford decode of exactly `nbytes`: case-insensitive, ignores `-` and spaces, maps
/// `O` to `0` and `I` and `L` to `1`. Returns `None` on any other character or a wrong length.
pub(crate) fn crock_decode(s: &str, nbytes: usize) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(nbytes);
    let mut acc = 0u32;
    let mut n = 0;
    let mut chars = 0usize;
    for c in s.chars() {
        let c = match c.to_ascii_uppercase() {
            '-' | ' ' => continue,
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        };
        let v = CROCK.iter().position(|&x| x as char == c)? as u32;
        chars += 1;
        acc = (acc << 5) | v;
        n += 5;
        if n >= 8 {
            n -= 8;
            out.push((acc >> n) as u8);
            acc &= (1 << n) - 1;
        }
    }
    (out.len() == nbytes && chars == (nbytes * 8).div_ceil(5)).then_some(out)
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Unpadded base64url.
#[cfg(test)]
pub(crate) fn b64url(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len().div_ceil(3) * 4);
    b64url_into(&mut out, b);
    out
}

/// Append unpadded base64url to `out`, which the caller sizes so that nothing reallocates.
pub(crate) fn b64url_into(out: &mut String, b: &[u8]) {
    for chunk in b.chunks(3) {
        let v = chunk
            .iter()
            .enumerate()
            .fold(0u32, |a, (i, &x)| a | (x as u32) << (16 - 8 * i));
        for i in 0..chunk.len() + 1 {
            out.push(B64[((v >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
}

/// Strict unpadded base64url: alphabet only, no padding, and unused trailing bits zero.
pub(crate) fn b64url_decode(s: &str) -> Result<Vec<u8>> {
    let bytes = s.as_bytes();
    if bytes.len() % 4 == 1 {
        return integrity(K::Base64);
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut v = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            let Some(d) = B64.iter().position(|&x| x == c) else {
                return integrity(K::Base64);
            };
            v |= (d as u32) << (18 - 6 * i);
        }
        let nbytes = chunk.len() - 1;
        let unused = match chunk.len() {
            2 => v & 0xffff,
            3 => v & 0xff,
            _ => 0,
        };
        if unused != 0 {
            return integrity(K::Base64);
        }
        for i in 0..nbytes {
            out.push((v >> (16 - 8 * i)) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn b64_round_trip(b in proptest::collection::vec(any::<u8>(), 0..300)) {
            prop_assert_eq!(b64url_decode(&b64url(&b)).unwrap(), b);
        }

        #[test]
        fn crock_round_trip(b in proptest::collection::vec(any::<u8>(), 0..40)) {
            prop_assert_eq!(crock_decode(&crock(&b), b.len()).unwrap(), b);
        }
    }

    #[test]
    fn b64_rejects_noncanonical() {
        assert!(b64url_decode("AB").is_err());
        assert!(b64url_decode("AA").is_ok());
        assert!(b64url_decode("AAA=").is_err());
        assert!(b64url_decode("A").is_err());
    }
}
