//! Thin wrappers over the RustCrypto primitives the spec names.

use crate::error::{IntegrityKind as K, Result, integrity};
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// SHA-256 over the concatenation of `parts`.
pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut d = Sha256::new();
    for p in parts {
        d.update(p);
    }
    d.finalize().into()
}

/// HKDF-SHA256 with a 32-byte output.
pub(crate) fn hkdf32(ikm: &[u8], salt: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = Zeroizing::new([0u8; 32]);
    // A 32-byte output is always within HKDF's limit.
    hk.expand(info, okm.as_mut()).expect("32-byte HKDF output");
    okm
}

/// HMAC-SHA256.
pub(crate) fn hmac(key: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key size");
    m.update(msg);
    m.finalize().into_bytes().into()
}

/// Constant-time HMAC-SHA256 check.
pub(crate) fn hmac_verify(key: &[u8; 32], msg: &[u8], tag: &[u8]) -> Result<()> {
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key size");
    m.update(msg);
    m.verify_slice(tag).or(integrity(K::Mac))
}

/// XChaCha20-Poly1305 seal: ciphertext followed by the 16-byte tag.
pub(crate) fn seal(key: &[u8; 32], nonce: &[u8; 24], pt: &[u8], ad: &[u8]) -> Vec<u8> {
    let c = XChaCha20Poly1305::new(&(*key).into());
    c.encrypt(&(*nonce).into(), Payload { msg: pt, aad: ad })
        .expect("XChaCha20-Poly1305 encryption of in-memory data cannot fail")
}

/// XChaCha20-Poly1305 open.
pub(crate) fn open(
    key: &[u8; 32],
    nonce: &[u8; 24],
    ct: &[u8],
    ad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let c = XChaCha20Poly1305::new(&(*key).into());
    c.decrypt(&(*nonce).into(), Payload { msg: ct, aad: ad })
        .map(Zeroizing::new)
        .or(integrity(K::Aead))
}
