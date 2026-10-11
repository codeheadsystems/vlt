//! The index object: every path's head, the tombstones, and the applied table.

use crate::FORMAT_VERSION;
use crate::codec::{Reader, Writer, check_padding, padded_plain_len};
use crate::entry::{EntryPlain, EntryPrefix, open_entry};
use crate::error::{Error, InputKind, IntegrityKind as K, Result, input, integrity};
use crate::ext::{ExtCtx, ExtList};
use crate::header::VaultKeys;
use crate::limits::{COUNTER_CAP, INDEX_BLOCK, INDEX_MAX, PATH_MAX};
use crate::path::is_valid_path;
use crate::prim::{open, seal, sha256};
use crate::rng::{draw, os};
use crate::secret::IndexKey;
use core::fmt;
use rand_core::TryCryptoRng;
use std::collections::HashSet;

const MAGIC: &[u8; 4] = b"VLTI";
/// Length of the cleartext prefix, which is also the associated data.
pub const PREFIX_LEN: usize = 68;

/// One live path.
#[derive(Clone, PartialEq, Eq)]
pub struct IndexEntry {
    /// Path.
    pub path: String,
    /// Object ID of the head revision.
    pub head_object_id: [u8; 16],
    /// SHA-256 of the whole head entry object.
    pub head_sha256: [u8; 32],
    /// Revision of the head.
    pub revision: u64,
    /// Writer of the head revision.
    pub device_id: [u8; 16],
    /// Extension list.
    pub ext: ExtList,
}

/// One removed path.
#[derive(Clone, PartialEq, Eq)]
pub struct Tombstone {
    /// Path.
    pub path: String,
    /// Object ID of the last head.
    pub head_object_id: [u8; 16],
    /// SHA-256 of that object.
    pub head_sha256: [u8; 32],
    /// Its revision.
    pub revision: u64,
    /// Its writer.
    pub device_id: [u8; 16],
    /// `index_seq` of the index that removed it.
    pub removed_index_seq: u64,
    /// Extension list.
    pub ext: ExtList,
}

/// The highest published `op_seq` of one device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Applied {
    /// Device ID.
    pub device_id: [u8; 16],
    /// Highest `op_seq` published.
    pub last_op_seq: u64,
}

/// The index plaintext.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct IndexPlain {
    /// The device that wrote this index.
    pub writer_device_id: [u8; 16],
    /// Live paths, sorted by path bytes.
    pub entries: Vec<IndexEntry>,
    /// Tombstones, sorted by path bytes then `removed_index_seq`.
    pub tombstones: Vec<Tombstone>,
    /// Applied table, sorted by device ID.
    pub applied: Vec<Applied>,
    /// Extension list.
    pub ext: ExtList,
}

impl fmt::Debug for IndexPlain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IndexPlain")
            .field("entries", &self.entries.len())
            .field("tombstones", &self.tombstones.len())
            .finish_non_exhaustive()
    }
}

/// The cleartext prefix of an index object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexPrefix {
    /// Vault ID.
    pub vault_id: [u8; 16],
    /// Epoch whose `K_index` sealed the object.
    pub epoch: u32,
    /// Index sequence number.
    pub index_seq: u64,
    /// `header_seq` of the header current when this index was written.
    pub header_seq: u64,
}

fn parse_prefix(bytes: &[u8]) -> Result<(IndexPrefix, [u8; 24])> {
    if bytes.len() > INDEX_MAX {
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
    if bytes.len() < INDEX_BLOCK || !bytes.len().is_multiple_of(INDEX_BLOCK) {
        return integrity(K::PaddedSize);
    }
    if r.u16()? != 0 {
        return integrity(K::UnknownFlags);
    }
    let prefix = IndexPrefix {
        vault_id: r.array()?,
        epoch: r.u32()?,
        index_seq: r.counter()?,
        header_seq: r.counter()?,
    };
    Ok((prefix, r.array()?))
}

/// Read an index object's cleartext prefix without opening it.
pub fn index_prefix(bytes: &[u8]) -> Result<IndexPrefix> {
    parse_prefix(bytes).map(|(p, _)| p)
}

fn path(r: &mut Reader<'_>) -> Result<String> {
    let p = r.str16()?;
    if p.len() > PATH_MAX || !is_valid_path(p) {
        return integrity(K::PathRule);
    }
    Ok(p.to_owned())
}

fn decode_plain(plain: &[u8]) -> Result<IndexPlain> {
    let mut r = Reader::new(plain);
    let writer_device_id = r.array()?;
    let n = r.u32()? as usize;
    let mut entries: Vec<IndexEntry> = Vec::with_capacity(n.min(plain.len() / 60));
    for _ in 0..n {
        let path = path(&mut r)?;
        let head_object_id = r.array()?;
        let head_sha256 = r.array()?;
        let revision = r.counter()?;
        let device_id = r.array()?;
        let ext = ExtList::decode(
            &mut r,
            ExtCtx::IndexEntry {
                path: &path,
                revision,
            },
        )?;
        entries.push(IndexEntry {
            path,
            head_object_id,
            head_sha256,
            revision,
            device_id,
            ext,
        });
    }
    let n = r.u32()? as usize;
    let mut tombstones = Vec::with_capacity(n.min(plain.len() / 60));
    for _ in 0..n {
        let path = path(&mut r)?;
        let head_object_id = r.array()?;
        let head_sha256 = r.array()?;
        let revision = r.counter()?;
        let device_id = r.array()?;
        let removed_index_seq = r.counter()?;
        let ext = ExtList::decode(&mut r, ExtCtx::Tombstone { revision })?;
        tombstones.push(Tombstone {
            path,
            head_object_id,
            head_sha256,
            revision,
            device_id,
            removed_index_seq,
            ext,
        });
    }
    let n = r.u16()? as usize;
    let mut applied = Vec::with_capacity(n);
    for _ in 0..n {
        applied.push(Applied {
            device_id: r.array()?,
            last_op_seq: r.counter()?,
        });
    }
    let ext = ExtList::decode(&mut r, ExtCtx::Other)?;
    let body = r.pos();
    check_padding(PREFIX_LEN, body, r.rest(), INDEX_BLOCK)?;
    let p = IndexPlain {
        writer_device_id,
        entries,
        tombstones,
        applied,
        ext,
    };
    p.check_order().map_err(|e| match e {
        Error::InvalidInput(InputKind::Duplicate) => Error::Integrity(K::Duplicate),
        Error::InvalidInput(InputKind::CounterCap) => Error::Integrity(K::CounterCap),
        Error::InvalidInput(InputKind::Path) => Error::Integrity(K::PathRule),
        Error::InvalidInput(InputKind::Ext) => Error::Integrity(K::ExtValue),
        _ => Error::Integrity(K::Order),
    })?;
    Ok(p)
}

impl IndexPlain {
    /// The ordering, uniqueness, and value rules, shared by the decoder and the encoder.
    fn check_order(&self) -> Result<()> {
        for w in self.entries.windows(2) {
            match w[0].path.as_bytes().cmp(w[1].path.as_bytes()) {
                core::cmp::Ordering::Less => {}
                core::cmp::Ordering::Equal => return input(InputKind::Duplicate),
                core::cmp::Ordering::Greater => return input(InputKind::Order),
            }
        }
        let mut heads = HashSet::with_capacity(self.entries.len());
        for e in &self.entries {
            if !heads.insert(e.head_object_id) {
                return input(InputKind::Duplicate);
            }
            if e.revision == 0 || e.revision > COUNTER_CAP {
                return input(InputKind::CounterCap);
            }
            if !is_valid_path(&e.path) {
                return input(InputKind::Path);
            }
            e.ext
                .check(ExtCtx::IndexEntry {
                    path: &e.path,
                    revision: e.revision,
                })
                .map_err(|_| Error::InvalidInput(InputKind::Ext))?;
        }
        for w in self.tombstones.windows(2) {
            let a = (w[0].path.as_bytes(), w[0].removed_index_seq);
            let b = (w[1].path.as_bytes(), w[1].removed_index_seq);
            if a >= b {
                return input(if a == b {
                    InputKind::Duplicate
                } else {
                    InputKind::Order
                });
            }
        }
        for t in &self.tombstones {
            if t.revision == 0 || t.revision > COUNTER_CAP || t.removed_index_seq > COUNTER_CAP {
                return input(InputKind::CounterCap);
            }
            if !is_valid_path(&t.path) {
                return input(InputKind::Path);
            }
            t.ext
                .check(ExtCtx::Tombstone {
                    revision: t.revision,
                })
                .map_err(|_| Error::InvalidInput(InputKind::Ext))?;
        }
        if self
            .applied
            .windows(2)
            .any(|w| w[0].device_id >= w[1].device_id)
        {
            return input(InputKind::Order);
        }
        if self.applied.iter().any(|a| a.last_op_seq > COUNTER_CAP) {
            return input(InputKind::CounterCap);
        }
        self.ext
            .check(ExtCtx::Other)
            .map_err(|_| Error::InvalidInput(InputKind::Ext))
    }
}

pub(crate) fn open_with_key(bytes: &[u8], key: &IndexKey) -> Result<(IndexPrefix, IndexPlain)> {
    let (prefix, nonce) = parse_prefix(bytes)?;
    let plain = open(
        key.expose(),
        &nonce,
        &bytes[PREFIX_LEN..],
        &bytes[..PREFIX_LEN],
    )?;
    Ok((prefix, decode_plain(&plain)?))
}

/// Open an index. It must belong to the keys' vault, and its epoch must be the header's, or the
/// committed rotation epoch with a SHA-256 equal to the rotation commitment.
pub fn open_index(keys: &VaultKeys, bytes: &[u8]) -> Result<(IndexPrefix, IndexPlain)> {
    let prefix = index_prefix(bytes)?;
    if prefix.vault_id != keys.vault_id() {
        return integrity(K::VaultIdMismatch);
    }
    if prefix.epoch != keys.epoch() && sha256(&[bytes]) != keys.rotation().from_index_sha256 {
        return integrity(K::IndexEpoch);
    }
    let key = keys.index_key_for(prefix.epoch)?;
    open_with_key(bytes, &key)
}

pub(crate) fn seal_with_key(
    key: &IndexKey,
    prefix: &IndexPrefix,
    plain: &IndexPlain,
    nonce: &[u8; 24],
) -> Result<Vec<u8>> {
    if prefix.index_seq > COUNTER_CAP || prefix.header_seq > COUNTER_CAP {
        return input(InputKind::CounterCap);
    }
    plain.check_order()?;
    let mut w = Writer::new();
    w.bytes(MAGIC)
        .u16(FORMAT_VERSION)
        .u16(0)
        .bytes(&prefix.vault_id)
        .u32(prefix.epoch);
    w.u64(prefix.index_seq).u64(prefix.header_seq).bytes(nonce);
    let ad = w.into_vec();
    let mut p = Writer::new();
    p.bytes(&plain.writer_device_id)
        .u32(plain.entries.len() as u32);
    for e in &plain.entries {
        p.str16(e.path.as_bytes())?;
        p.bytes(&e.head_object_id)
            .bytes(&e.head_sha256)
            .u64(e.revision)
            .bytes(&e.device_id);
        e.ext.encode(&mut p)?;
    }
    p.u32(plain.tombstones.len() as u32);
    for t in &plain.tombstones {
        p.str16(t.path.as_bytes())?;
        p.bytes(&t.head_object_id)
            .bytes(&t.head_sha256)
            .u64(t.revision)
            .bytes(&t.device_id);
        p.u64(t.removed_index_seq);
        t.ext.encode(&mut p)?;
    }
    p.u16(
        u16::try_from(plain.applied.len()).map_err(|_| Error::InvalidInput(InputKind::TooLarge))?,
    );
    for a in &plain.applied {
        p.bytes(&a.device_id).u64(a.last_op_seq);
    }
    plain.ext.encode(&mut p)?;
    let len = padded_plain_len(PREFIX_LEN, p.len(), INDEX_BLOCK);
    p.zeros(len - p.len());
    let body = p.into_secret();
    let mut out = ad.clone();
    out.extend(seal(key.expose(), nonce, &body, &ad));
    if out.len() > INDEX_MAX {
        return input(InputKind::TooLarge);
    }
    Ok(out)
}

/// Seal an index under the current epoch. Draw order: nonce (24).
pub(crate) fn seal_index_with<R: TryCryptoRng + ?Sized>(
    rng: &mut R,
    keys: &VaultKeys,
    index_seq: u64,
    header_seq: u64,
    plain: &IndexPlain,
) -> Result<Vec<u8>> {
    let prefix = IndexPrefix {
        vault_id: keys.vault_id(),
        epoch: keys.epoch(),
        index_seq,
        header_seq,
    };
    seal_with_key(&keys.current_index_key(), &prefix, plain, &draw(rng)?)
}

/// Seal an index under the current epoch.
pub fn seal_index(
    keys: &VaultKeys,
    index_seq: u64,
    header_seq: u64,
    plain: &IndexPlain,
) -> Result<Vec<u8>> {
    seal_index_with(&mut os(), keys, index_seq, header_seq, plain)
}

/// Open the head entry object an index entry points at, checking its hash, object ID, revision,
/// and writer against the index.
pub fn open_head(
    keys: &VaultKeys,
    head: &IndexEntry,
    entry_object: &[u8],
) -> Result<(EntryPrefix, EntryPlain)> {
    let (prefix, plain) = open_entry(keys, &head.head_object_id, &head.head_sha256, entry_object)?;
    if plain.revision != head.revision || plain.device_id != head.device_id {
        return integrity(K::HeadMismatch);
    }
    Ok((prefix, plain))
}

/// Open the parent of `child` while walking history, checking its hash, object ID, and that its
/// revision is exactly one less.
pub fn open_parent(
    keys: &VaultKeys,
    child: &EntryPlain,
    parent_object: &[u8],
) -> Result<(EntryPrefix, EntryPlain)> {
    if child.revision <= 1 {
        return integrity(K::ParentRule);
    }
    let (prefix, plain) = open_entry(
        keys,
        &child.parent_object_id,
        &child.parent_sha256,
        parent_object,
    )?;
    if plain.revision + 1 != child.revision {
        return integrity(K::ParentRule);
    }
    Ok((prefix, plain))
}
