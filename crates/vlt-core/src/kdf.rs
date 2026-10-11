//! Argon2id parameters, the 29-byte KDF block, password normalisation, and the account unlock key.

use crate::codec::{Reader, Writer};
use crate::error::{Error, InputKind, IntegrityKind as K, Result, input, integrity};
use crate::prim::hkdf32;
use crate::secret::{Auk, SecretKey};
use argon2::{Algorithm, Argon2, Params, Version};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

/// Argon2id parameters and salt, as stored in a KDF block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory, KiB.
    pub m_kib: u32,
    /// Iterations.
    pub t: u32,
    /// Lanes.
    pub p: u32,
    /// Salt, fresh on every password change.
    pub salt: [u8; 16],
}

/// The floor: 64 MiB, t = 3, p = 1.
pub const FLOOR: (u32, u32, u32) = (65536, 3, 1);
/// The ceiling: 1 GiB, t = 10, p = 4.
pub const CEILING: (u32, u32, u32) = (1_048_576, 10, 4);
/// The test set: 64 KiB, t = 1, p = 1. Only test builds accept it, and only with `test_kdf` set.
pub const TEST: (u32, u32, u32) = (64, 1, 1);
/// Length of an encoded KDF block.
pub const KDF_BLOCK_LEN: usize = 29;

/// Whether this build accepts the test parameter set. True only in this crate's own tests.
pub(crate) const TEST_KDF_ALLOWED: bool = cfg!(test);

impl KdfParams {
    /// Encode the 29-byte block: `alg = 1`, `m_kib`, `t`, `p`, `kdf_salt`.
    pub fn to_block(&self) -> [u8; KDF_BLOCK_LEN] {
        let mut w = Writer::new();
        w.u8(1)
            .u32(self.m_kib)
            .u32(self.t)
            .u32(self.p)
            .bytes(&self.salt);
        w.into_vec().try_into().expect("29 bytes")
    }

    pub(crate) fn decode(r: &mut Reader<'_>) -> Result<KdfParams> {
        if r.u8()? != 1 {
            return integrity(K::KdfParams);
        }
        Ok(KdfParams {
            m_kib: r.u32()?,
            t: r.u32()?,
            p: r.u32()?,
            salt: r.array()?,
        })
    }

    /// Check the parameters against the floor, the ceiling, and the test set. `test_kdf` is the
    /// object's flag.
    pub(crate) fn check(&self, test_kdf: bool, allow_test: bool) -> Result<()> {
        let mtp = (self.m_kib, self.t, self.p);
        if test_kdf {
            if !allow_test {
                return integrity(K::TestKdfInRelease);
            }
            return if mtp == TEST {
                Ok(())
            } else {
                integrity(K::KdfParams)
            };
        }
        let ok = (FLOOR.0..=CEILING.0).contains(&mtp.0)
            && (FLOOR.1..=CEILING.1).contains(&mtp.1)
            && (FLOOR.2..=CEILING.2).contains(&mtp.2);
        if ok { Ok(()) } else { integrity(K::KdfParams) }
    }
}

/// The master password normalised to NFKC, as UTF-8.
pub fn nfkc(password: &str) -> Zeroizing<String> {
    // NFKC expands a UTF-8 string by at most a factor of 11 (U+FDFA); reserving that much means
    // the buffer never reallocates and leaves no unzeroized copy behind.
    let mut out = Zeroizing::new(String::with_capacity(password.len() * 11 + 4));
    out.extend(password.nfkc());
    out
}

/// The rules for setting a master password: at least 12 Unicode scalar values after NFKC, and no
/// code point unassigned in this client's Unicode tables. Never applied at unlock.
pub fn validate_new_password(password: &str) -> Result<()> {
    let n = nfkc(password);
    if n.chars().count() < 12 {
        return input(InputKind::PasswordTooShort);
    }
    if !password
        .chars()
        .all(unicode_normalization::char::is_public_assigned)
    {
        return input(InputKind::PasswordUnassigned);
    }
    Ok(())
}

/// `pw_key = Argon2id(NFKC(password), salt, m, t, p)`, 32 bytes. Parameters are checked first.
pub(crate) fn pw_key(
    password: &str,
    params: &KdfParams,
    test_kdf: bool,
) -> Result<Zeroizing<[u8; 32]>> {
    params.check(test_kdf, TEST_KDF_ALLOWED)?;
    argon2id(password, params)
}

fn argon2id(password: &str, params: &KdfParams) -> Result<Zeroizing<[u8; 32]>> {
    let p = Params::new(params.m_kib, params.t, params.p, Some(32))
        .map_err(|_| Error::Integrity(K::KdfParams))?;
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = Zeroizing::new([0u8; 32]);
    a.hash_password_into(nfkc(password).as_bytes(), &params.salt, out.as_mut())
        .map_err(|_| Error::Integrity(K::KdfParams))?;
    Ok(out)
}

/// `AUK = HKDF(pw_key || sk, salt = vault_id, info = "vlt/v1/auk")`.
pub(crate) fn auk_from_pw_key(pw_key: &[u8; 32], sk: &SecretKey, vault_id: &[u8; 16]) -> Auk {
    let mut ikm = Zeroizing::new([0u8; 48]);
    ikm[..32].copy_from_slice(pw_key);
    ikm[32..].copy_from_slice(sk.expose());
    Auk::from_zeroizing(hkdf32(ikm.as_ref(), vault_id, b"vlt/v1/auk"))
}

/// Derive the account unlock key from the master password and secret key.
pub fn derive_auk(
    password: &str,
    sk: &SecretKey,
    params: &KdfParams,
    test_kdf: bool,
    vault_id: &[u8; 16],
) -> Result<Auk> {
    let pk = pw_key(password, params, test_kdf)?;
    Ok(auk_from_pw_key(&pk, sk, vault_id))
}

/// Argon2id for the test-set vector check, bypassing the parameter policy.
#[cfg(test)]
pub(crate) fn argon2id_unchecked(password: &str, params: &KdfParams) -> Zeroizing<[u8; 32]> {
    argon2id(password, params).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(m: u32, t: u32, pp: u32) -> KdfParams {
        KdfParams {
            m_kib: m,
            t,
            p: pp,
            salt: [0; 16],
        }
    }

    #[test]
    fn bounds() {
        assert!(p(65536, 3, 1).check(false, false).is_ok());
        assert!(p(1_048_576, 10, 4).check(false, false).is_ok());
        assert!(p(65535, 3, 1).check(false, false).is_err());
        assert!(p(65536, 2, 1).check(false, false).is_err());
        assert!(p(65536, 3, 0).check(false, false).is_err());
        assert!(p(1_048_577, 3, 1).check(false, false).is_err());
        assert!(p(65536, 11, 1).check(false, false).is_err());
        assert!(p(65536, 3, 5).check(false, false).is_err());
        assert_eq!(
            p(64, 1, 1).check(true, false),
            Err(Error::Integrity(K::TestKdfInRelease))
        );
        assert!(p(64, 1, 1).check(true, true).is_ok());
        assert!(p(65536, 3, 1).check(true, true).is_err());
        assert!(p(64, 1, 1).check(false, true).is_err());
    }

    #[test]
    fn new_password_rules() {
        assert!(validate_new_password("correct horse").is_ok());
        assert_eq!(
            validate_new_password("short"),
            Err(Error::InvalidInput(InputKind::PasswordTooShort))
        );
        assert_eq!(
            validate_new_password("twelve chars\u{e0000}x"),
            Err(Error::InvalidInput(InputKind::PasswordUnassigned))
        );
    }
}
