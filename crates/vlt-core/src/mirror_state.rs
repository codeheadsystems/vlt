//! The mirror's `state` file: pins, etags, the write queue, writer-check records, notices, and
//! per-object bookkeeping, sealed with `K_mirror`.
//!
//! The envelope is the spec's: `"VLTS"`, `u16 1`, `u16 0`, `b16 vault_id`, `u32 epoch`, `b24 nonce`,
//! then `AEAD(K_mirror, nonce, serialised state, bytes 0..52)`. The plaintext serialisation is
//! internal to vlt and lives here so that every client built on `vlt-core` shares it. It is a
//! version number and a list of tagged sections; a section this build does not know is kept
//! byte for byte, so a later build can add sections without a new layout.

use crate::codec::{Reader, Writer};
use crate::error::{Error, IntegrityKind as K, Result, integrity};
use crate::header::VaultKeys;
use crate::limits::{COUNTER_CAP, PATH_MAX};
use crate::notice::{Notice, ObjectKind};
use crate::ops::{MoveOp, Op, PutOp, RemoveOp};
use crate::path::is_valid_path;
use crate::pins::{HeaderPin, IndexPin, OwnRecord, OwnRecords};
use crate::prim::{open, seal};
use crate::rng::{draw, os};
use core::fmt;
use rand_core::TryCryptoRng;

const MAGIC: &[u8; 4] = b"VLTS";
/// Length of the cleartext prefix, which is also the associated data.
pub const PREFIX_LEN: usize = 52;
/// The largest `state` file a client opens.
pub const STATE_MAX: usize = 64 * 1024 * 1024;
/// Notices kept; older ones are dropped first.
pub const NOTICES_MAX: usize = 256;
/// Version of the plaintext serialisation.
const PLAIN_VERSION: u16 = 1;

/// Which objects the mirror keeps, the spec's `mirror.history`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryMode {
    /// Every object reachable from a head or tombstone down to its history floor.
    Full,
    /// Heads, tombstone heads, and objects the user has displayed.
    Heads,
}

/// Bookkeeping for one entry object the mirror holds or has given up on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectMeta {
    /// Object ID.
    pub object_id: [u8; 16],
    /// Parent object ID, zeros for revision 1.
    pub parent: [u8; 16],
    /// The parent's SHA-256 as this object records it, zeros for revision 1.
    pub parent_sha256: [u8; 32],
    /// Revision.
    pub revision: u64,
    /// When this device published the object, or 0.
    pub published_unix: i64,
    /// When the object was last displayed to the user, or 0.
    pub displayed_unix: i64,
    /// Since when the current index no longer reaches the object, or 0 while it does.
    pub unreachable_since: i64,
    /// The backend answered `404` for it: purged. Its file is gone and it is not fetched again.
    pub purged: bool,
    /// Written by this device and not yet known to be in the backend. A `404` for it says nothing
    /// about a purge, so retention never checks it.
    pub local_only: bool,
    /// While unreachable, the backend confirmed that the object still exists, so it is not purged
    /// and is not checked again until it becomes reachable and then unreachable once more.
    pub gone_checked: bool,
}

/// A notice with when it was raised and whether `vlt status` has shown it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredNotice {
    /// The notice.
    pub notice: Notice,
    /// When it was raised.
    pub unix: i64,
    /// Whether it has been shown.
    pub read: bool,
}

/// The last failure of a background publish, kept until a publish succeeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishFailure {
    /// The CLI exit code it maps to.
    pub exit_code: u8,
    /// A message without entry content, paths, or key material.
    pub message: String,
    /// When it happened.
    pub unix: i64,
}

/// The decoded `state`.
#[derive(Clone, PartialEq, Eq)]
pub struct MirrorState {
    /// This device.
    pub device_id: [u8; 16],
    /// The next `op_seq` to hand out.
    pub next_op_seq: u64,
    /// Header pin; also identifies the mirrored `header` file by its SHA-256.
    pub header_pin: HeaderPin,
    /// Index pin; also identifies the mirrored `index` file. `None` before the first index.
    pub index_pin: Option<IndexPin>,
    /// The backend's etag for the mirrored header.
    pub header_etag: Option<String>,
    /// The backend's etag for the mirrored index.
    pub index_etag: Option<String>,
    /// The write queue, in queue order.
    pub queue: Vec<Op>,
    /// Writer-check records.
    pub own: OwnRecords,
    /// Notices, oldest first.
    pub notices: Vec<StoredNotice>,
    /// Per-object bookkeeping, sorted by object ID.
    pub objects: Vec<ObjectMeta>,
    /// When the last sync succeeded.
    pub last_sync_unix: Option<i64>,
    /// The last background publish failure.
    pub last_publish_error: Option<PublishFailure>,
    /// Whether the bucket's index is an unmatched rotation index.
    pub rotation_pending: bool,
    /// `mirror.history`.
    pub history: HistoryMode,
    /// Sections this build does not know, by tag, kept verbatim.
    pub other: Vec<(u16, Vec<u8>)>,
}

// The queue holds paths, so the state formats as counts only.
impl fmt::Debug for MirrorState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MirrorState")
            .field("next_op_seq", &self.next_op_seq)
            .field("queue", &self.queue.len())
            .field("objects", &self.objects.len())
            .finish_non_exhaustive()
    }
}

impl MirrorState {
    /// A fresh state for a mirror built from an accepted header.
    pub fn new(device_id: [u8; 16], header_pin: HeaderPin, history: HistoryMode) -> MirrorState {
        let headers_from = header_pin.header_seq.saturating_add(1);
        MirrorState {
            device_id,
            next_op_seq: 1,
            header_pin,
            index_pin: None,
            header_etag: None,
            index_etag: None,
            queue: Vec::new(),
            own: OwnRecords::starting_at(headers_from, 0),
            notices: Vec::new(),
            objects: Vec::new(),
            last_sync_unix: None,
            last_publish_error: None,
            rotation_pending: false,
            history,
            other: Vec::new(),
        }
    }

    /// Add a notice, dropping the oldest beyond the limit.
    pub fn push_notice(&mut self, notice: Notice, now: i64) {
        self.notices.push(StoredNotice {
            notice,
            unix: now,
            read: false,
        });
        if self.notices.len() > NOTICES_MAX {
            let excess = self.notices.len() - NOTICES_MAX;
            self.notices.drain(..excess);
        }
    }

    /// Adopt an accepted index's applied value for this device, as the spec's "Index operations
    /// and merge" requires on every accepted index. A value at or past the next `op_seq`, or one
    /// that covers a queued `put` this device has not uploaded (which its own publish cannot have
    /// produced), raises the counter and renumbers the queue above it. Otherwise the operations at
    /// or below it were applied by an earlier publish whose response was lost and leave the queue.
    pub fn adopt_applied(
        &mut self,
        applied: u64,
        index_writer: [u8; 16],
        now: i64,
    ) -> crate::error::Result<Option<Notice>> {
        let unuploaded = self
            .queue
            .iter()
            .any(|op| matches!(op, Op::Put(p) if p.op_seq <= applied && !p.uploaded));
        if unuploaded {
            self.next_op_seq = self.next_op_seq.min(applied);
        }
        let notice = crate::ops::raise_op_seq(
            &mut self.next_op_seq,
            &mut self.queue,
            applied,
            index_writer,
        )?;
        let mut published = Vec::new();
        self.queue.retain(|op| {
            let done = op.op_seq() <= applied;
            if done && let Op::Put(p) = op {
                published.push(p.object_id);
            }
            !done
        });
        for id in published {
            if let Ok(i) = self.objects.binary_search_by(|o| o.object_id.cmp(&id)) {
                self.objects[i].published_unix = now;
                self.objects[i].local_only = false;
            }
        }
        Ok(notice)
    }

    /// The bookkeeping record for an object.
    pub fn object(&self, id: &[u8; 16]) -> Option<&ObjectMeta> {
        self.objects
            .binary_search_by(|o| o.object_id.cmp(id))
            .ok()
            .map(|i| &self.objects[i])
    }

    /// The bookkeeping record for an object, created if absent.
    pub fn object_mut(
        &mut self,
        id: &[u8; 16],
        parent: [u8; 16],
        parent_sha256: [u8; 32],
        revision: u64,
    ) -> &mut ObjectMeta {
        let i = match self.objects.binary_search_by(|o| o.object_id.cmp(id)) {
            Ok(i) => i,
            Err(i) => {
                self.objects.insert(
                    i,
                    ObjectMeta {
                        object_id: *id,
                        parent,
                        parent_sha256,
                        revision,
                        published_unix: 0,
                        displayed_unix: 0,
                        unreachable_since: 0,
                        purged: false,
                        local_only: false,
                        gone_checked: false,
                    },
                );
                i
            }
        };
        &mut self.objects[i]
    }
}

mod tag {
    pub(super) const CORE: u16 = 1;
    pub(super) const HEADER_PIN: u16 = 2;
    pub(super) const INDEX_PIN: u16 = 3;
    pub(super) const QUEUE: u16 = 4;
    pub(super) const OWN: u16 = 5;
    pub(super) const NOTICES: u16 = 6;
    pub(super) const OBJECTS: u16 = 7;
    pub(super) const PUBLISH_ERROR: u16 = 8;
}

fn opt_str(w: &mut Writer, s: &Option<String>) -> Result<()> {
    match s {
        None => {
            w.u8(0);
        }
        Some(s) => {
            w.u8(1);
            w.str16(s.as_bytes())?;
        }
    }
    Ok(())
}

fn read_opt_str(r: &mut Reader<'_>) -> Result<Option<String>> {
    match r.u8()? {
        0 => Ok(None),
        1 => Ok(Some(r.str16()?.to_owned())),
        _ => integrity(K::MirrorMismatch),
    }
}

fn path(w: &mut Writer, p: &str) -> Result<()> {
    w.str16(p.as_bytes())?;
    Ok(())
}

fn read_path(r: &mut Reader<'_>) -> Result<String> {
    let p = r.str16()?;
    if p.len() > PATH_MAX || !is_valid_path(p) {
        return integrity(K::PathRule);
    }
    Ok(p.to_owned())
}

fn kind_byte(k: ObjectKind) -> u8 {
    match k {
        ObjectKind::Header => 0,
        ObjectKind::Index => 1,
    }
}

fn read_kind(r: &mut Reader<'_>) -> Result<ObjectKind> {
    match r.u8()? {
        0 => Ok(ObjectKind::Header),
        1 => Ok(ObjectKind::Index),
        _ => integrity(K::MirrorMismatch),
    }
}

fn encode_notice(w: &mut Writer, n: &Notice) {
    match n {
        Notice::VaultKeyChanged { writer, epoch } => {
            w.u8(1).bytes(writer).u32(*epoch);
        }
        Notice::CounterJump {
            kind,
            writer,
            from,
            to,
        } => {
            w.u8(2)
                .u8(kind_byte(*kind))
                .bytes(writer)
                .u64(*from)
                .u64(*to);
        }
        Notice::UnenrolledWriter { kind, writer } => {
            w.u8(3).u8(kind_byte(*kind)).bytes(writer);
        }
        Notice::OwnWriteUnverified { kind, seq } => {
            w.u8(4).u8(kind_byte(*kind)).u64(*seq);
        }
        Notice::OpSeqRaised {
            writer,
            next_op_seq,
        } => {
            w.u8(5).bytes(writer).u64(*next_op_seq);
        }
    }
}

fn decode_notice(r: &mut Reader<'_>) -> Result<Notice> {
    Ok(match r.u8()? {
        1 => Notice::VaultKeyChanged {
            writer: r.array()?,
            epoch: r.u32()?,
        },
        2 => Notice::CounterJump {
            kind: read_kind(r)?,
            writer: r.array()?,
            from: r.u64()?,
            to: r.u64()?,
        },
        3 => Notice::UnenrolledWriter {
            kind: read_kind(r)?,
            writer: r.array()?,
        },
        4 => Notice::OwnWriteUnverified {
            kind: read_kind(r)?,
            seq: r.u64()?,
        },
        5 => Notice::OpSeqRaised {
            writer: r.array()?,
            next_op_seq: r.u64()?,
        },
        _ => return integrity(K::MirrorMismatch),
    })
}

fn encode_op(w: &mut Writer, op: &Op) -> Result<()> {
    match op {
        Op::Put(p) => {
            w.u8(1).u64(p.op_seq);
            path(w, &p.path)?;
            w.bytes(&p.object_id)
                .bytes(&p.object_sha256)
                .u64(p.revision)
                .bytes(&p.parent_object_id)
                .bytes(&p.device_id)
                .bytes(&p.entry_vault_id)
                .u32(p.entry_epoch)
                .u8(p.uploaded as u8);
        }
        Op::Remove(rm) => {
            w.u8(2).u64(rm.op_seq);
            path(w, &rm.path)?;
            w.bytes(&rm.expected_head);
        }
        Op::Move(m) => {
            w.u8(3).u64(m.op_seq);
            path(w, &m.from)?;
            path(w, &m.to)?;
            w.bytes(&m.expected_head);
        }
    }
    Ok(())
}

fn decode_op(r: &mut Reader<'_>) -> Result<Op> {
    Ok(match r.u8()? {
        1 => Op::Put(PutOp {
            op_seq: r.counter()?,
            path: read_path(r)?,
            object_id: r.array()?,
            object_sha256: r.array()?,
            revision: r.counter()?,
            parent_object_id: r.array()?,
            device_id: r.array()?,
            entry_vault_id: r.array()?,
            entry_epoch: r.u32()?,
            uploaded: match r.u8()? {
                0 => false,
                1 => true,
                _ => return integrity(K::MirrorMismatch),
            },
        }),
        2 => Op::Remove(RemoveOp {
            op_seq: r.counter()?,
            path: read_path(r)?,
            expected_head: r.array()?,
        }),
        3 => Op::Move(MoveOp {
            op_seq: r.counter()?,
            from: read_path(r)?,
            to: read_path(r)?,
            expected_head: r.array()?,
        }),
        _ => return integrity(K::MirrorMismatch),
    })
}

fn records(w: &mut Writer, list: &[OwnRecord]) {
    w.u32(list.len() as u32);
    for r in list {
        w.u64(r.seq).bytes(&r.sha256).i64(r.unix);
    }
}

fn read_records(r: &mut Reader<'_>) -> Result<Vec<OwnRecord>> {
    let n = r.u32()? as usize;
    let mut v = Vec::with_capacity(n.min(r.remaining() / 48));
    for _ in 0..n {
        v.push(OwnRecord {
            seq: r.counter()?,
            sha256: r.array()?,
            unix: r.i64()?,
        });
    }
    Ok(v)
}

/// Serialise a state. The buffers are zeroizing because the queue holds paths.
pub(crate) fn encode(s: &MirrorState) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let mut sections: Vec<(u16, zeroize::Zeroizing<Vec<u8>>)> = Vec::new();
    let mut w = Writer::new();
    w.bytes(&s.device_id).u64(s.next_op_seq);
    w.i64(s.last_sync_unix.unwrap_or(0))
        .u8(s.last_sync_unix.is_some() as u8);
    w.u8(s.rotation_pending as u8);
    w.u8(match s.history {
        HistoryMode::Full => 0,
        HistoryMode::Heads => 1,
    });
    opt_str(&mut w, &s.header_etag)?;
    opt_str(&mut w, &s.index_etag)?;
    sections.push((tag::CORE, w.into_secret()));

    let mut w = Writer::new();
    let p = &s.header_pin;
    w.bytes(&p.vault_id).u32(p.epoch).bytes(&p.fingerprint);
    w.u64(p.header_seq)
        .bytes(&p.header_sha256)
        .bytes(&p.legacy_sha256);
    w.u16(p.devices.len() as u16);
    for d in &p.devices {
        w.bytes(d);
    }
    sections.push((tag::HEADER_PIN, w.into_secret()));

    if let Some(p) = &s.index_pin {
        let mut w = Writer::new();
        w.u64(p.index_seq).bytes(&p.index_sha256).u32(p.index_epoch);
        sections.push((tag::INDEX_PIN, w.into_secret()));
    }

    let mut w = Writer::new();
    w.u32(s.queue.len() as u32);
    for op in &s.queue {
        encode_op(&mut w, op)?;
    }
    sections.push((tag::QUEUE, w.into_secret()));

    let mut w = Writer::new();
    w.u64(s.own.headers_from).u64(s.own.indexes_from);
    records(&mut w, &s.own.headers);
    records(&mut w, &s.own.indexes);
    sections.push((tag::OWN, w.into_secret()));

    let mut w = Writer::new();
    w.u32(s.notices.len() as u32);
    for n in &s.notices {
        w.i64(n.unix).u8(n.read as u8);
        encode_notice(&mut w, &n.notice);
    }
    sections.push((tag::NOTICES, w.into_secret()));

    let mut w = Writer::with_capacity(s.objects.len() * 99 + 4);
    w.u32(s.objects.len() as u32);
    for o in &s.objects {
        w.bytes(&o.object_id)
            .bytes(&o.parent)
            .bytes(&o.parent_sha256)
            .u64(o.revision);
        w.i64(o.published_unix)
            .i64(o.displayed_unix)
            .i64(o.unreachable_since)
            .u8(o.purged as u8)
            .u8(o.local_only as u8)
            .u8(o.gone_checked as u8);
    }
    sections.push((tag::OBJECTS, w.into_secret()));

    if let Some(e) = &s.last_publish_error {
        let mut w = Writer::new();
        w.u8(e.exit_code).i64(e.unix);
        w.str16(e.message.as_bytes())?;
        sections.push((tag::PUBLISH_ERROR, w.into_secret()));
    }
    for (t, v) in &s.other {
        sections.push((*t, zeroize::Zeroizing::new(v.clone())));
    }
    sections.sort_by_key(|(t, _)| *t);
    if sections.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err(Error::InvalidInput(crate::error::InputKind::Duplicate));
    }
    let total: usize = sections.iter().map(|(_, v)| v.len() + 6).sum();
    let mut out = Writer::with_capacity(total + 4);
    out.u16(PLAIN_VERSION).u16(sections.len() as u16);
    for (t, v) in &sections {
        out.u16(*t);
        out.bytes32(v)?;
    }
    Ok(out.into_secret())
}

fn flag(r: &mut Reader<'_>) -> Result<bool> {
    match r.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => integrity(K::MirrorMismatch),
    }
}

/// Parse a serialised state.
pub(crate) fn decode(plain: &[u8]) -> Result<MirrorState> {
    let mut r = Reader::new(plain);
    if r.u16()? != PLAIN_VERSION {
        return integrity(K::MirrorMismatch);
    }
    let n = r.u16()? as usize;
    let mut core = None;
    let mut header_pin = None;
    let mut index_pin = None;
    let mut queue = Vec::new();
    let mut own = OwnRecords::default();
    let mut notices = Vec::new();
    let mut objects = Vec::new();
    let mut last_publish_error = None;
    let mut other = Vec::new();
    let mut prev: Option<u16> = None;
    for _ in 0..n {
        let t = r.u16()?;
        if prev.is_some_and(|p| p >= t) {
            return integrity(K::Order);
        }
        prev = Some(t);
        let body = r.bytes32(STATE_MAX)?;
        let mut s = Reader::new(body);
        match t {
            tag::CORE => {
                let device_id: [u8; 16] = s.array()?;
                let next_op_seq = s.u64()?;
                if next_op_seq == 0 || next_op_seq > COUNTER_CAP + 1 {
                    return integrity(K::CounterCap);
                }
                let sync = s.i64()?;
                let has_sync = flag(&mut s)?;
                let rotation_pending = flag(&mut s)?;
                let history = match s.u8()? {
                    0 => HistoryMode::Full,
                    1 => HistoryMode::Heads,
                    _ => return integrity(K::MirrorMismatch),
                };
                let header_etag = read_opt_str(&mut s)?;
                let index_etag = read_opt_str(&mut s)?;
                core = Some((
                    device_id,
                    next_op_seq,
                    has_sync.then_some(sync),
                    rotation_pending,
                    history,
                    header_etag,
                    index_etag,
                ));
            }
            tag::HEADER_PIN => {
                let vault_id = s.array()?;
                let epoch = s.u32()?;
                let fingerprint = s.array()?;
                let header_seq = s.counter()?;
                let header_sha256 = s.array()?;
                let legacy_sha256 = s.array()?;
                let dc = s.u16()? as usize;
                let mut devices = Vec::with_capacity(dc.min(crate::limits::DEVICES_MAX));
                for _ in 0..dc {
                    devices.push(s.array()?);
                }
                header_pin = Some(HeaderPin {
                    vault_id,
                    epoch,
                    fingerprint,
                    header_seq,
                    header_sha256,
                    legacy_sha256,
                    devices,
                });
            }
            tag::INDEX_PIN => {
                index_pin = Some(IndexPin {
                    index_seq: s.counter()?,
                    index_sha256: s.array()?,
                    index_epoch: s.u32()?,
                });
            }
            tag::QUEUE => {
                let c = s.u32()? as usize;
                queue.reserve(c.min(s.remaining() / 30));
                for _ in 0..c {
                    queue.push(decode_op(&mut s)?);
                }
            }
            tag::OWN => {
                own.headers_from = s.u64()?;
                own.indexes_from = s.u64()?;
                own.headers = read_records(&mut s)?;
                own.indexes = read_records(&mut s)?;
            }
            tag::NOTICES => {
                let c = s.u32()? as usize;
                for _ in 0..c.min(NOTICES_MAX) {
                    let unix = s.i64()?;
                    let read = flag(&mut s)?;
                    notices.push(StoredNotice {
                        unix,
                        read,
                        notice: decode_notice(&mut s)?,
                    });
                }
                if c > NOTICES_MAX {
                    return integrity(K::SizeLimit);
                }
            }
            tag::OBJECTS => {
                let c = s.u32()? as usize;
                objects.reserve(c.min(s.remaining() / 99));
                for _ in 0..c {
                    let o = ObjectMeta {
                        object_id: s.array()?,
                        parent: s.array()?,
                        parent_sha256: s.array()?,
                        revision: s.counter()?,
                        published_unix: s.i64()?,
                        displayed_unix: s.i64()?,
                        unreachable_since: s.i64()?,
                        purged: flag(&mut s)?,
                        local_only: flag(&mut s)?,
                        gone_checked: flag(&mut s)?,
                    };
                    objects.push(o);
                }
                if objects
                    .windows(2)
                    .any(|w: &[ObjectMeta]| w[0].object_id >= w[1].object_id)
                {
                    return integrity(K::Order);
                }
            }
            tag::PUBLISH_ERROR => {
                let exit_code = s.u8()?;
                let unix = s.i64()?;
                let message = s.str16()?.to_owned();
                last_publish_error = Some(PublishFailure {
                    exit_code,
                    message,
                    unix,
                });
            }
            _ => {
                other.push((t, s.rest().to_vec()));
            }
        }
        s.finish()?;
    }
    r.finish()?;
    let (Some(core), Some(header_pin)) = (core, header_pin) else {
        return integrity(K::MirrorMismatch);
    };
    let (
        device_id,
        next_op_seq,
        last_sync_unix,
        rotation_pending,
        history,
        header_etag,
        index_etag,
    ) = core;
    Ok(MirrorState {
        device_id,
        next_op_seq,
        header_pin,
        index_pin,
        header_etag,
        index_etag,
        queue,
        own,
        notices,
        objects,
        last_sync_unix,
        last_publish_error,
        rotation_pending,
        history,
        other,
    })
}

fn prefix(vault_id: &[u8; 16], epoch: u32, nonce: &[u8; 24]) -> Vec<u8> {
    let mut w = Writer::with_capacity(PREFIX_LEN);
    w.bytes(MAGIC)
        .u16(1)
        .u16(0)
        .bytes(vault_id)
        .u32(epoch)
        .bytes(nonce);
    w.into_vec()
}

/// Seal a state under the current epoch's `K_mirror`. Draw order: nonce (24).
pub(crate) fn seal_state_with<R: TryCryptoRng + ?Sized>(
    rng: &mut R,
    keys: &VaultKeys,
    state: &MirrorState,
) -> Result<Vec<u8>> {
    if state.header_pin.vault_id != keys.vault_id() {
        return Err(Error::InvalidInput(crate::error::InputKind::VaultConfig));
    }
    let plain = encode(state)?;
    let nonce = draw(rng)?;
    let ad = prefix(&keys.vault_id(), keys.epoch(), &nonce);
    let key = keys.mirror_key();
    let mut out = ad.clone();
    out.extend(seal(key.expose(), &nonce, &plain, &ad));
    Ok(out)
}

/// Seal a state under the current epoch's `K_mirror`.
pub fn seal_state(keys: &VaultKeys, state: &MirrorState) -> Result<Vec<u8>> {
    seal_state_with(&mut os(), keys, state)
}

/// Open a state. It must belong to the keys' vault and be sealed under the current epoch or an
/// earlier one of the same lineage; the second value is that epoch, so the caller knows to reseal
/// a state from before a rotation at its next write.
pub fn open_state(keys: &VaultKeys, bytes: &[u8]) -> Result<(MirrorState, u32)> {
    if bytes.len() > STATE_MAX {
        return integrity(K::SizeLimit);
    }
    let mut r = Reader::new(bytes);
    if &r.array::<4>()? != MAGIC {
        return integrity(K::BadMagic);
    }
    let v = r.u16()?;
    if v != 1 {
        return Err(Error::UnsupportedFormatVersion(v));
    }
    if r.u16()? != 0 {
        return integrity(K::UnknownFlags);
    }
    let vault_id: [u8; 16] = r.array()?;
    let epoch = r.u32()?;
    let nonce: [u8; 24] = r.array()?;
    if vault_id != keys.vault_id() {
        return integrity(K::VaultIdMismatch);
    }
    let key = keys
        .mirror_key_for(epoch)
        .ok_or(Error::Integrity(K::UnknownLineage))?;
    let plain = open(
        key.expose(),
        &nonce,
        &bytes[PREFIX_LEN..],
        &bytes[..PREFIX_LEN],
    )?;
    let state = decode(&plain)?;
    if state.header_pin.vault_id != vault_id {
        return integrity(K::VaultIdMismatch);
    }
    Ok((state, epoch))
}
