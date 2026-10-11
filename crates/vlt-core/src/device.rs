//! The device secret bundle and the password-sealed device file (`VLTD`).

use crate::FORMAT_VERSION;
use crate::codec::{Reader, Writer};
use crate::error::{Error, IntegrityKind as K, Result, integrity};
use crate::ext::{ExtCtx, ExtList};
use crate::kdf::{KdfParams, TEST_KDF_ALLOWED, pw_key};
use crate::prim::{hkdf32, open, seal};
use crate::rng::{draw, os};
use crate::secret::{DeviceSecrets, LocalWrapKey, SecretString};
use rand_core::TryCryptoRng;
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"VLTD";
const FLAG_TEST_KDF: u16 = 1;
/// Length of the device file's cleartext prefix, which is also its associated data.
pub const DEVICE_FILE_PREFIX_LEN: usize = 77;
/// Largest device file accepted or written. A guard on allocation; real files are under 1 KiB.
pub const DEVICE_FILE_MAX: usize = 64 * 1024;

/// A device's secrets: its ID, private keys, and S3 access key. The OS keyring and the Android
/// Keystore hold its encoding directly; the device file seals it under the master password.
pub struct Bundle {
    /// Device ID.
    pub device_id: [u8; 16],
    /// Private keys.
    pub secrets: DeviceSecrets,
    /// S3 access key ID; empty for a local vault.
    pub access_key_id: SecretString,
    /// S3 secret access key; empty for a local vault.
    pub secret_access_key: SecretString,
    /// Extension list.
    pub ext: ExtList,
}

impl Bundle {
    /// Encode the bundle. The output is secret.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.ext
            .check(ExtCtx::Other)
            .map_err(|_| Error::InvalidInput(crate::error::InputKind::Ext))?;
        let mut w = Writer::new();
        w.bytes(&self.device_id)
            .bytes(&self.secrets.x25519_sk)
            .bytes(&self.secrets.kem_seed);
        w.str16(self.access_key_id.as_bytes())?;
        w.str16(self.secret_access_key.as_bytes())?;
        self.ext.encode(&mut w)?;
        Ok(w.into_secret())
    }

    /// Decode a bundle strictly.
    pub fn decode(bytes: &[u8]) -> Result<Bundle> {
        let mut r = Reader::new(bytes);
        let device_id = r.array()?;
        let x25519_sk = r.take(32)?;
        let kem_seed = r.take(64)?;
        let access_key_id = Zeroizing::new(r.str16()?.to_owned());
        let secret_access_key = Zeroizing::new(r.str16()?.to_owned());
        let ext = ExtList::decode(&mut r, ExtCtx::Other)?;
        r.finish()?;
        Ok(Bundle {
            device_id,
            secrets: DeviceSecrets::from_slices(x25519_sk, kem_seed),
            access_key_id,
            secret_access_key,
            ext,
        })
    }
}

fn local_wrap_key(pw_key: &[u8; 32], vault_id: &[u8; 16]) -> LocalWrapKey {
    LocalWrapKey::from_zeroizing(hkdf32(pw_key, vault_id, b"vlt/v1/local-wrap"))
}

fn prefix(vault_id: &[u8; 16], kdf: &KdfParams, test_kdf: bool, nonce: &[u8; 24]) -> Vec<u8> {
    let mut w = Writer::new();
    w.bytes(MAGIC)
        .u16(FORMAT_VERSION)
        .u16(if test_kdf { FLAG_TEST_KDF } else { 0 });
    w.bytes(vault_id).bytes(&kdf.to_block()).bytes(nonce);
    w.into_vec()
}

pub(crate) fn seal_with_key(
    key: &LocalWrapKey,
    vault_id: &[u8; 16],
    kdf: &KdfParams,
    test_kdf: bool,
    nonce: &[u8; 24],
    bundle: &Bundle,
) -> Result<Vec<u8>> {
    let ad = prefix(vault_id, kdf, test_kdf, nonce);
    let mut out = ad.clone();
    out.extend(seal(key.expose(), nonce, &bundle.encode()?, &ad));
    if out.len() > DEVICE_FILE_MAX {
        return Err(Error::InvalidInput(crate::error::InputKind::TooLarge));
    }
    Ok(out)
}

/// Seal a bundle into a device file. Draw order: salt (16), nonce (24).
#[allow(clippy::too_many_arguments)]
pub(crate) fn seal_device_file_with<R: TryCryptoRng + ?Sized>(
    rng: &mut R,
    password: &str,
    vault_id: &[u8; 16],
    m_kib: u32,
    t: u32,
    p: u32,
    test_kdf: bool,
    bundle: &Bundle,
) -> Result<Vec<u8>> {
    let kdf = KdfParams {
        m_kib,
        t,
        p,
        salt: draw(rng)?,
    };
    let nonce = draw(rng)?;
    let key = local_wrap_key(&*pw_key(password, &kdf, test_kdf)?, vault_id);
    seal_with_key(&key, vault_id, &kdf, test_kdf, &nonce, bundle)
}

/// Seal a bundle into a device file under the master password.
pub fn seal_device_file(
    password: &str,
    vault_id: &[u8; 16],
    m_kib: u32,
    t: u32,
    p: u32,
    test_kdf: bool,
    bundle: &Bundle,
) -> Result<Vec<u8>> {
    seal_device_file_with(&mut os(), password, vault_id, m_kib, t, p, test_kdf, bundle)
}

/// The cleartext fields of a device file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceFileInfo {
    /// Vault ID.
    pub vault_id: [u8; 16],
    /// KDF parameters.
    pub kdf: KdfParams,
    /// Whether the test KDF flag is set.
    pub test_kdf: bool,
}

fn parse(bytes: &[u8]) -> Result<(DeviceFileInfo, [u8; 24])> {
    if bytes.len() < DEVICE_FILE_PREFIX_LEN || bytes.len() > DEVICE_FILE_MAX {
        return integrity(K::SizeLimit);
    }
    let mut r = Reader::new(&bytes[..DEVICE_FILE_PREFIX_LEN]);
    if &r.array::<4>()? != MAGIC {
        return integrity(K::BadMagic);
    }
    let v = r.u16()?;
    if v != FORMAT_VERSION {
        return Err(Error::UnsupportedFormatVersion(v));
    }
    let flags = r.u16()?;
    if flags & !FLAG_TEST_KDF != 0 {
        return integrity(K::UnknownFlags);
    }
    let test_kdf = flags & FLAG_TEST_KDF != 0;
    let vault_id = r.array()?;
    let kdf = KdfParams::decode(&mut r)?;
    kdf.check(test_kdf, TEST_KDF_ALLOWED)?;
    Ok((
        DeviceFileInfo {
            vault_id,
            kdf,
            test_kdf,
        },
        r.array()?,
    ))
}

/// Read a device file's cleartext fields.
pub fn device_file_info(bytes: &[u8]) -> Result<DeviceFileInfo> {
    parse(bytes).map(|(i, _)| i)
}

pub(crate) fn open_with_key(bytes: &[u8], key: &LocalWrapKey) -> Result<Bundle> {
    let (_, nonce) = parse(bytes)?;
    let pt = open(
        key.expose(),
        &nonce,
        &bytes[DEVICE_FILE_PREFIX_LEN..],
        &bytes[..DEVICE_FILE_PREFIX_LEN],
    )?;
    Bundle::decode(&pt)
}

/// Open a device file with the master password.
pub fn open_device_file(bytes: &[u8], password: &str) -> Result<Bundle> {
    let (info, _) = parse(bytes)?;
    let key = local_wrap_key(
        &*pw_key(password, &info.kdf, info.test_kdf)?,
        &info.vault_id,
    );
    open_with_key(bytes, &key).map_err(|e| match e {
        Error::Integrity(K::Aead) => Error::WrongPasswordOrUnknownDevice,
        e => e,
    })
}

#[cfg(test)]
pub(crate) fn lk_for_test(pw_key: &[u8; 32], vault_id: &[u8; 16]) -> LocalWrapKey {
    local_wrap_key(pw_key, vault_id)
}
