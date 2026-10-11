//! Entry objects: one immutable, padded, sealed revision of one entry.

use crate::FORMAT_VERSION;
use crate::codec::{Reader, Writer, check_padding, padded_plain_len};
use crate::error::{Error, InputKind, IntegrityKind as K, Result, input, integrity};
use crate::ext::{ExtCtx, ExtList};
use crate::header::VaultKeys;
use crate::limits::{CONTENT_MAX, COUNTER_CAP, ENTRY_BLOCK, ENTRY_OBJECT_MAX};
use crate::prim::{open, seal};
use crate::rng::{draw, os};
use crate::secret::{EntryKey, SecretBytes};
use core::fmt;
use rand_core::TryCryptoRng;
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"VLTE";
/// Length of the cleartext prefix, which is also the associated data.
pub const PREFIX_LEN: usize = 68;

/// An entry revision's plaintext.
#[derive(Clone)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct EntryPlain {
    /// 1 for a new entry, the parent's revision plus one for an edit.
    pub revision: u64,
    /// The previous revision's object ID, or zeros.
    pub parent_object_id: [u8; 16],
    /// SHA-256 of the previous revision's whole object, or zeros.
    pub parent_sha256: [u8; 32],
    /// Device that wrote this revision.
    pub device_id: [u8; 16],
    /// Writer's wall clock, seconds; display only.
    pub created_unix: i64,
    /// Entry text, at most 1 MiB.
    pub content: SecretBytes,
    /// Extension list.
    pub ext: ExtList,
}

impl fmt::Debug for EntryPlain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntryPlain")
            .field("revision", &self.revision)
            .field("content", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// The cleartext prefix of an entry object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryPrefix {
    /// Vault ID of the lineage whose key sealed the object.
    pub vault_id: [u8; 16],
    /// Epoch whose `K_entry` sealed the object.
    pub epoch: u32,
    /// Object ID; equals the object key's hex.
    pub object_id: [u8; 16],
}

impl EntryPlain {
    fn check(&self) -> Result<()> {
        if self.revision == 0 || self.revision > COUNTER_CAP {
            return input(InputKind::CounterCap);
        }
        if !parent_rule(self) {
            return input(InputKind::ParentRule);
        }
        if self.content.len() > CONTENT_MAX {
            return input(InputKind::TooLarge);
        }
        self.ext
            .check(ExtCtx::Other)
            .map_err(|_| Error::InvalidInput(InputKind::Ext))
    }
}

fn parent_rule(p: &EntryPlain) -> bool {
    let id_zero = p.parent_object_id == [0; 16];
    let sha_zero = p.parent_sha256 == [0; 32];
    if p.revision == 1 {
        id_zero && sha_zero
    } else {
        !id_zero && !sha_zero
    }
}

fn parse_prefix(bytes: &[u8]) -> Result<(EntryPrefix, [u8; 24])> {
    if bytes.len() > ENTRY_OBJECT_MAX {
        return integrity(K::SizeLimit);
    }
    // Magic and version come before the size rule, so a newer format reports "upgrade" rather
    // than tampering.
    let mut r = Reader::new(bytes);
    if &r.array::<4>()? != MAGIC {
        return integrity(K::BadMagic);
    }
    let v = r.u16()?;
    if v != FORMAT_VERSION {
        return Err(Error::UnsupportedFormatVersion(v));
    }
    if bytes.len() < ENTRY_BLOCK || !bytes.len().is_multiple_of(ENTRY_BLOCK) {
        return integrity(K::PaddedSize);
    }
    if r.u16()? != 0 {
        return integrity(K::UnknownFlags);
    }
    let prefix = EntryPrefix {
        vault_id: r.array()?,
        epoch: r.u32()?,
        object_id: r.array()?,
    };
    Ok((prefix, r.array()?))
}

/// Read an entry object's cleartext prefix without opening it.
pub fn entry_prefix(bytes: &[u8]) -> Result<EntryPrefix> {
    parse_prefix(bytes).map(|(p, _)| p)
}

pub(crate) fn open_with_key(bytes: &[u8], key: &EntryKey) -> Result<(EntryPrefix, EntryPlain)> {
    let (prefix, nonce) = parse_prefix(bytes)?;
    let plain = open(
        key.expose(),
        &nonce,
        &bytes[PREFIX_LEN..],
        &bytes[..PREFIX_LEN],
    )?;
    Ok((prefix, decode_plain(&plain)?))
}

fn decode_plain(plain: &[u8]) -> Result<EntryPlain> {
    let mut r = Reader::new(plain);
    let revision = r.counter()?;
    let parent_object_id = r.array()?;
    let parent_sha256 = r.array()?;
    let device_id = r.array()?;
    let created_unix = r.i64()?;
    let content = Zeroizing::new(r.bytes32(CONTENT_MAX)?.to_vec());
    let ext = ExtList::decode(&mut r, ExtCtx::Other)?;
    let body = r.pos();
    check_padding(PREFIX_LEN, body, r.rest(), ENTRY_BLOCK)?;
    let p = EntryPlain {
        revision,
        parent_object_id,
        parent_sha256,
        device_id,
        created_unix,
        content,
        ext,
    };
    if revision == 0 || !parent_rule(&p) {
        return integrity(K::ParentRule);
    }
    Ok(p)
}

/// Open an entry object fetched from `expected_object_id`'s key. Its SHA-256 must equal
/// `expected_sha256`, the index's `head_sha256` or a child's `parent_sha256`, which is checked
/// before any key is chosen, so an overwritten object is rejected even if it carries a valid
/// ciphertext under an old or legacy key. The key is chosen by the object's own
/// `(vault_id, epoch)`: the current lineage or a legacy lineage of `keys`.
pub fn open_entry(
    keys: &VaultKeys,
    expected_object_id: &[u8; 16],
    expected_sha256: &[u8; 32],
    bytes: &[u8],
) -> Result<(EntryPrefix, EntryPlain)> {
    if &crate::prim::sha256(&[bytes]) != expected_sha256 {
        return integrity(K::ShaMismatch);
    }
    let prefix = entry_prefix(bytes)?;
    if &prefix.object_id != expected_object_id {
        return integrity(K::ObjectIdMismatch);
    }
    let key = keys.entry_key_for(&prefix.vault_id, prefix.epoch)?;
    open_with_key(bytes, &key)
}

pub(crate) fn seal_with_key(
    key: &EntryKey,
    prefix: &EntryPrefix,
    plain: &EntryPlain,
    nonce: &[u8; 24],
) -> Result<Vec<u8>> {
    plain.check()?;
    let mut w = Writer::new();
    w.bytes(MAGIC)
        .u16(FORMAT_VERSION)
        .u16(0)
        .bytes(&prefix.vault_id)
        .u32(prefix.epoch);
    w.bytes(&prefix.object_id).bytes(nonce);
    let ad = w.into_vec();
    let mut p = Writer::new();
    p.u64(plain.revision)
        .bytes(&plain.parent_object_id)
        .bytes(&plain.parent_sha256);
    p.bytes(&plain.device_id).i64(plain.created_unix);
    p.bytes32(&plain.content)?;
    plain.ext.encode(&mut p)?;
    let len = padded_plain_len(PREFIX_LEN, p.len(), ENTRY_BLOCK);
    p.zeros(len - p.len());
    let body = p.into_secret();
    let mut out = ad.clone();
    out.extend(seal(key.expose(), nonce, &body, &ad));
    if out.len() > ENTRY_OBJECT_MAX {
        return input(InputKind::TooLarge);
    }
    Ok(out)
}

/// Seal a new entry object under the current epoch. Draw order: nonce (24).
pub(crate) fn seal_entry_with<R: TryCryptoRng + ?Sized>(
    rng: &mut R,
    keys: &VaultKeys,
    object_id: &[u8; 16],
    plain: &EntryPlain,
) -> Result<Vec<u8>> {
    let prefix = EntryPrefix {
        vault_id: keys.vault_id(),
        epoch: keys.epoch(),
        object_id: *object_id,
    };
    seal_with_key(&keys.current_entry_key(), &prefix, plain, &draw(rng)?)
}

/// Seal a new entry object under the current epoch.
pub fn seal_entry(keys: &VaultKeys, object_id: &[u8; 16], plain: &EntryPlain) -> Result<Vec<u8>> {
    seal_entry_with(&mut os(), keys, object_id, plain)
}
