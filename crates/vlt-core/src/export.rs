//! The encrypted export (`VLTX`): one self-contained file that opens with the master password and,
//! by default, the secret key.

use crate::FORMAT_VERSION;
use crate::codec::{Reader, Writer};
use crate::error::{Error, InputKind, IntegrityKind as K, Result, input, integrity};
use crate::ext::{ExtCtx, ExtList};
use crate::kdf::{KdfParams, TEST_KDF_ALLOWED, pw_key};
use crate::limits::{CONTENT_MAX, COUNTER_CAP};
use crate::path::is_valid_path;
use crate::prim::{hkdf32, open, seal};
use crate::rng::{draw, os};
use crate::secret::{ExportKey, SecretBytes, SecretKey};
use crate::secret_key_text::check_value;
use core::fmt;
use rand_core::TryCryptoRng;
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"VLTX";
const FLAG_TEST_KDF: u16 = 1;
const FLAG_PASSWORD_ONLY: u16 = 2;
/// Length of the export's cleartext prefix, which is also its associated data.
pub const EXPORT_PREFIX_LEN: usize = 81;

/// One revision in an export.
#[derive(Clone)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct ExportRevision {
    /// Revision number.
    pub revision: u64,
    /// Writer's wall clock.
    pub created_unix: i64,
    /// Writer device.
    pub device_id: [u8; 16],
    /// Entry text.
    pub content: SecretBytes,
}

/// One entry or tombstone in an export, with its revisions newest first.
#[derive(Clone)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct ExportRecord {
    /// Path.
    pub path: String,
    /// Revisions, strictly descending.
    pub revisions: Vec<ExportRevision>,
}

/// The export payload.
#[derive(Clone, Default)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct ExportPayload {
    /// When the export was written.
    pub created_unix: i64,
    /// Live entries, sorted by path, unique.
    pub entries: Vec<ExportRecord>,
    /// Tombstones, sorted by path.
    pub tombstones: Vec<ExportRecord>,
    /// Extension list.
    pub ext: ExtList,
}

impl fmt::Debug for ExportPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExportPayload")
            .field("entries", &self.entries.len())
            .field("tombstones", &self.tombstones.len())
            .finish_non_exhaustive()
    }
}

impl ExportPayload {
    fn check(&self) -> Result<()> {
        if self
            .entries
            .windows(2)
            .any(|w| w[0].path.as_bytes() >= w[1].path.as_bytes())
            || self
                .tombstones
                .windows(2)
                .any(|w| w[0].path.as_bytes() > w[1].path.as_bytes())
        {
            return input(InputKind::Order);
        }
        for rec in self.entries.iter().chain(&self.tombstones) {
            if !is_valid_path(&rec.path) {
                return input(InputKind::Path);
            }
            if rec
                .revisions
                .windows(2)
                .any(|w| w[0].revision <= w[1].revision)
            {
                return input(InputKind::Order);
            }
            for r in &rec.revisions {
                if r.revision == 0 || r.revision > COUNTER_CAP {
                    return input(InputKind::CounterCap);
                }
                if r.content.len() > CONTENT_MAX {
                    return input(InputKind::TooLarge);
                }
            }
        }
        self.ext
            .check(ExtCtx::Other)
            .map_err(|_| Error::InvalidInput(InputKind::Ext))
    }

    fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.check()?;
        let mut w = Writer::new();
        w.i64(self.created_unix);
        for list in [&self.entries, &self.tombstones] {
            w.u32(list.len() as u32);
            for rec in list.iter() {
                w.str16(rec.path.as_bytes())?;
                w.u32(rec.revisions.len() as u32);
                for r in &rec.revisions {
                    w.u64(r.revision).i64(r.created_unix).bytes(&r.device_id);
                    w.bytes32(&r.content)?;
                }
            }
        }
        self.ext.encode(&mut w)?;
        Ok(w.into_secret())
    }

    fn decode(plain: &[u8]) -> Result<ExportPayload> {
        let mut r = Reader::new(plain);
        let created_unix = r.i64()?;
        let mut lists = [Vec::new(), Vec::new()];
        for list in &mut lists {
            let n = r.u32()? as usize;
            for _ in 0..n {
                let path = r.str16()?;
                if !is_valid_path(path) {
                    return integrity(K::PathRule);
                }
                let path = path.to_owned();
                let rc = r.u32()? as usize;
                let mut revisions = Vec::with_capacity(rc.min(r.remaining() / 40));
                for _ in 0..rc {
                    revisions.push(ExportRevision {
                        revision: r.counter()?,
                        created_unix: r.i64()?,
                        device_id: r.array()?,
                        content: Zeroizing::new(r.bytes32(CONTENT_MAX)?.to_vec()),
                    });
                }
                list.push(ExportRecord { path, revisions });
            }
        }
        let ext = ExtList::decode(&mut r, ExtCtx::Other)?;
        r.finish()?;
        let [entries, tombstones] = lists;
        let p = ExportPayload {
            created_unix,
            entries,
            tombstones,
            ext,
        };
        p.check().map_err(|e| match e {
            Error::InvalidInput(InputKind::CounterCap) => Error::Integrity(K::CounterCap),
            _ => Error::Integrity(K::Order),
        })?;
        Ok(p)
    }
}

pub(crate) fn export_key(
    pw_key: &[u8; 32],
    sk: Option<&SecretKey>,
    vault_id: &[u8; 16],
) -> ExportKey {
    match sk {
        Some(sk) => {
            let mut ikm = Zeroizing::new([0u8; 48]);
            ikm[..32].copy_from_slice(pw_key);
            ikm[32..].copy_from_slice(sk.expose());
            ExportKey::from_zeroizing(hkdf32(ikm.as_ref(), vault_id, b"vlt/v1/export"))
        }
        None => ExportKey::from_zeroizing(hkdf32(pw_key, vault_id, b"vlt/v1/export-password-only")),
    }
}

/// The cleartext fields of an export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportInfo {
    /// Source vault.
    pub vault_id: [u8; 16],
    /// KDF parameters.
    pub kdf: KdfParams,
    /// Whether the test KDF flag is set.
    pub test_kdf: bool,
    /// Whether the export opens with the password alone.
    pub password_only: bool,
    /// The secret key's check value, or zeros for a password-only export.
    pub sk_check: [u8; 4],
}

fn parse(bytes: &[u8]) -> Result<(ExportInfo, [u8; 24])> {
    if bytes.len() < EXPORT_PREFIX_LEN {
        return integrity(K::Truncated);
    }
    let mut r = Reader::new(&bytes[..EXPORT_PREFIX_LEN]);
    if &r.array::<4>()? != MAGIC {
        return integrity(K::BadMagic);
    }
    let v = r.u16()?;
    if v != FORMAT_VERSION {
        return Err(Error::UnsupportedFormatVersion(v));
    }
    let flags = r.u16()?;
    if flags & !(FLAG_TEST_KDF | FLAG_PASSWORD_ONLY) != 0 {
        return integrity(K::UnknownFlags);
    }
    let test_kdf = flags & FLAG_TEST_KDF != 0;
    let password_only = flags & FLAG_PASSWORD_ONLY != 0;
    let vault_id = r.array()?;
    let kdf = KdfParams::decode(&mut r)?;
    kdf.check(test_kdf, TEST_KDF_ALLOWED)?;
    let sk_check = r.array()?;
    if password_only && sk_check != [0; 4] {
        return integrity(K::SkCheck);
    }
    Ok((
        ExportInfo {
            vault_id,
            kdf,
            test_kdf,
            password_only,
            sk_check,
        },
        r.array()?,
    ))
}

impl ExportInfo {
    /// Whether `sk` is the secret key this export needs. Import calls this before any key
    /// derivation and, on a mismatch, names the secret key ending the file needs. The check value
    /// is not secret, so an ordinary comparison is fine.
    pub fn sk_matches(&self, sk: &SecretKey) -> bool {
        self.password_only || check_value(sk) == self.sk_check
    }

    /// The secret key ending this export needs, or `None` for a password-only export.
    pub fn needed_ending(&self) -> Option<String> {
        (!self.password_only).then(|| crate::secret_key_text::ending_of_check(&self.sk_check))
    }
}

/// Read an export's cleartext fields, including the `sk_check` that names the kit it needs.
pub fn export_info(bytes: &[u8]) -> Result<ExportInfo> {
    parse(bytes).map(|(i, _)| i)
}

pub(crate) fn seal_with_key(
    key: &ExportKey,
    info: &ExportInfo,
    nonce: &[u8; 24],
    payload: &ExportPayload,
) -> Result<Vec<u8>> {
    let mut flags = 0;
    if info.test_kdf {
        flags |= FLAG_TEST_KDF;
    }
    if info.password_only {
        flags |= FLAG_PASSWORD_ONLY;
    }
    let mut w = Writer::new();
    w.bytes(MAGIC)
        .u16(FORMAT_VERSION)
        .u16(flags)
        .bytes(&info.vault_id);
    w.bytes(&info.kdf.to_block())
        .bytes(&info.sk_check)
        .bytes(nonce);
    let ad = w.into_vec();
    let mut out = ad.clone();
    out.extend(seal(key.expose(), nonce, &payload.encode()?, &ad));
    Ok(out)
}

/// Seal an export. `sk` is `None` for a password-only export. Draw order: salt (16), nonce (24).
#[allow(clippy::too_many_arguments)]
pub(crate) fn seal_export_with<R: TryCryptoRng + ?Sized>(
    rng: &mut R,
    password: &str,
    sk: Option<&SecretKey>,
    vault_id: &[u8; 16],
    m_kib: u32,
    t: u32,
    p: u32,
    test_kdf: bool,
    payload: &ExportPayload,
) -> Result<Vec<u8>> {
    let kdf = KdfParams {
        m_kib,
        t,
        p,
        salt: draw(rng)?,
    };
    let nonce = draw(rng)?;
    let key = export_key(&*pw_key(password, &kdf, test_kdf)?, sk, vault_id);
    let info = ExportInfo {
        vault_id: *vault_id,
        kdf,
        test_kdf,
        password_only: sk.is_none(),
        sk_check: sk.map(check_value).unwrap_or([0; 4]),
    };
    seal_with_key(&key, &info, &nonce, payload)
}

/// Seal an encrypted export.
#[allow(clippy::too_many_arguments)]
pub fn seal_export(
    password: &str,
    sk: Option<&SecretKey>,
    vault_id: &[u8; 16],
    m_kib: u32,
    t: u32,
    p: u32,
    test_kdf: bool,
    payload: &ExportPayload,
) -> Result<Vec<u8>> {
    seal_export_with(
        &mut os(),
        password,
        sk,
        vault_id,
        m_kib,
        t,
        p,
        test_kdf,
        payload,
    )
}

pub(crate) fn open_with_key(bytes: &[u8], key: &ExportKey) -> Result<ExportPayload> {
    let (_, nonce) = parse(bytes)?;
    let pt = open(
        key.expose(),
        &nonce,
        &bytes[EXPORT_PREFIX_LEN..],
        &bytes[..EXPORT_PREFIX_LEN],
    )?;
    ExportPayload::decode(&pt)
}

/// Open an export. `sk` is ignored for a password-only export.
pub fn open_export(bytes: &[u8], password: &str, sk: Option<&SecretKey>) -> Result<ExportPayload> {
    let (info, _) = parse(bytes)?;
    let sk = if info.password_only {
        None
    } else {
        Some(sk.ok_or(Error::SecretKeyTypo)?)
    };
    let key = export_key(
        &*pw_key(password, &info.kdf, info.test_kdf)?,
        sk,
        &info.vault_id,
    );
    open_with_key(bytes, &key).map_err(|e| match e {
        Error::Integrity(K::Aead) => Error::WrongPasswordOrUnknownDevice,
        e => e,
    })
}
