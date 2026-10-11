//! The secret key's text form: `VLT1-` and eight groups of four Crockford base32 characters.

use crate::error::{Error, Result};
use crate::prim::sha256;
use crate::secret::{SecretKey, SecretString};
use crate::textcodec::{crock, crock_decode};
use zeroize::Zeroizing;

/// The 4-byte check value of a secret key, also stored as an encrypted export's `sk_check`.
pub fn check_value(sk: &SecretKey) -> [u8; 4] {
    let h = sha256(&[b"vlt/v1/secret-key-check", sk.expose()]);
    [h[0], h[1], h[2], h[3]]
}

/// Encode as `VLT1-XXXX-...-XXXX`.
pub fn encode(sk: &SecretKey) -> SecretString {
    let mut b = Zeroizing::new([0u8; 20]);
    b[..16].copy_from_slice(sk.expose());
    b[16..].copy_from_slice(&check_value(sk));
    let enc = Zeroizing::new(crock(b.as_ref()));
    let mut out = Zeroizing::new(String::with_capacity(44));
    out.push_str("VLT1");
    for g in enc.as_bytes().chunks(4) {
        out.push('-');
        out.push_str(core::str::from_utf8(g).expect("ASCII"));
    }
    out
}

/// The secret key ending: the last group of the text form, which derives from the check value
/// alone and identifies a kit without revealing the key.
pub fn ending_of_check(check: &[u8; 4]) -> String {
    let v = u32::from_be_bytes(*check) & 0xfffff;
    let alphabet = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    (0..4)
        .rev()
        .map(|i| alphabet[((v >> (5 * i)) & 31) as usize] as char)
        .collect()
}

/// Decode, tolerating case, `-`, spaces, `O` for `0`, and `I` or `L` for `1`. A wrong check value
/// is reported as a typo before any key derivation.
pub fn decode(text: &str) -> Result<SecretKey> {
    let t = text.trim();
    let rest = t
        .get(..5)
        .filter(|p| p.eq_ignore_ascii_case("VLT1-"))
        .map(|_| &t[5..])
        .ok_or(Error::SecretKeyTypo)?;
    let b = Zeroizing::new(crock_decode(rest, 20).ok_or(Error::SecretKeyTypo)?);
    let sk = SecretKey::from_bytes(b[..16].try_into().expect("16 bytes"));
    // The check value only catches typos and is printed on the kit, so this need not be constant
    // time.
    if check_value(&sk) != b[16..20] {
        return Err(Error::SecretKeyTypo);
    }
    Ok(sk)
}
