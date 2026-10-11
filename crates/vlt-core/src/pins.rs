//! Header and index pins, rollback and fork detection, and writer checks.
//!
//! A device pins the last header and index it accepted and checks every later one against the
//! pins, as the spec's "Header authentication and pinning", "Writer checks", and "Rollback
//! detection" sections define. The checks here are pure: they take the pins and the candidate and
//! return the notices to report or an integrity error. Updating the pins is the caller's job once
//! a candidate is accepted.

use crate::error::{IntegrityKind as K, Result, integrity};
use crate::header::{HeaderInfo, VaultKeys};
use crate::index::IndexPrefix;
use crate::notice::{Notice, ObjectKind};

/// The most an epoch may advance past the pinned one in one accepted header.
pub const MAX_EPOCH_ADVANCE: u32 = 16;
/// A counter advance beyond this is reported as an implausible jump.
pub const COUNTER_JUMP: u64 = 1 << 32;
/// Own-write records are kept at least this long.
pub const OWN_RECORD_DAYS: i64 = 400;
/// Own-write records are kept at least this many per kind.
pub const OWN_RECORD_COUNT: usize = 4096;

/// The header pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderPin {
    /// Vault ID; never changes within a lineage.
    pub vault_id: [u8; 16],
    /// Pinned epoch.
    pub epoch: u32,
    /// Fingerprint of the pinned epoch's vault key.
    pub fingerprint: [u8; 32],
    /// Pinned `header_seq`; 0 before the first accepted header (a pin set from an invite).
    pub header_seq: u64,
    /// SHA-256 of the pinned header; zeros before the first accepted header.
    pub header_sha256: [u8; 32],
    /// The legacy pin.
    pub legacy_sha256: [u8; 32],
    /// Device IDs enrolled in the pinned header, for the unenrolled-writer check.
    pub devices: Vec<[u8; 16]>,
}

impl HeaderPin {
    /// The pin an accepted header sets.
    pub fn from_header(info: &HeaderInfo) -> HeaderPin {
        HeaderPin {
            vault_id: info.vault_id,
            epoch: info.epoch,
            fingerprint: info.fingerprint,
            header_seq: info.header_seq,
            header_sha256: info.header_sha256,
            legacy_sha256: info.legacy_sha256,
            devices: info.devices.iter().map(|d| d.record.device_id).collect(),
        }
    }
}

/// The index pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexPin {
    /// Pinned `index_seq`.
    pub index_seq: u64,
    /// SHA-256 of the pinned index object.
    pub index_sha256: [u8; 32],
    /// Epoch of the pinned index.
    pub index_epoch: u32,
}

/// One record of a header or index this device published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnRecord {
    /// Its `header_seq` or `index_seq`.
    pub seq: u64,
    /// SHA-256 of the whole object.
    pub sha256: [u8; 32],
    /// When it was recorded, seconds.
    pub unix: i64,
}

/// The records behind the writer check, per kind, with the sequence number from which they are
/// complete. An object below that number that names this device may predate the records.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OwnRecords {
    /// Headers this device published.
    pub headers: Vec<OwnRecord>,
    /// Indexes this device published.
    pub indexes: Vec<OwnRecord>,
    /// Headers below this `header_seq` are not covered.
    pub headers_from: u64,
    /// Indexes below this `index_seq` are not covered.
    pub indexes_from: u64,
}

impl OwnRecords {
    /// Records that cover objects from the given sequence numbers on, with none recorded yet.
    pub fn starting_at(headers_from: u64, indexes_from: u64) -> OwnRecords {
        OwnRecords {
            headers: Vec::new(),
            indexes: Vec::new(),
            headers_from,
            indexes_from,
        }
    }

    fn list(&self, kind: ObjectKind) -> (&Vec<OwnRecord>, u64) {
        match kind {
            ObjectKind::Header => (&self.headers, self.headers_from),
            ObjectKind::Index => (&self.indexes, self.indexes_from),
        }
    }

    /// Record an object about to be published. Recording comes before the write, so that a
    /// crash after a successful write cannot leave the device accusing itself.
    pub fn record(&mut self, kind: ObjectKind, seq: u64, sha256: [u8; 32], now: i64) {
        let list = match kind {
            ObjectKind::Header => &mut self.headers,
            ObjectKind::Index => &mut self.indexes,
        };
        if !list.iter().any(|r| r.sha256 == sha256) {
            list.push(OwnRecord {
                seq,
                sha256,
                unix: now,
            });
        }
    }

    /// Check an object that names this device as writer.
    pub fn check(&self, kind: ObjectKind, seq: u64, sha256: &[u8; 32]) -> Result<Option<Notice>> {
        let (list, from) = self.list(kind);
        if list.iter().any(|r| &r.sha256 == sha256) {
            return Ok(None);
        }
        if seq < from {
            return Ok(Some(Notice::OwnWriteUnverified { kind, seq }));
        }
        integrity(K::ForgedWriter)
    }

    /// Drop records older than 400 days beyond the newest 4,096 of each kind, raising the
    /// coverage start past every dropped record.
    pub fn prune(&mut self, now: i64) {
        fn prune_one(list: &mut Vec<OwnRecord>, from: &mut u64, now: i64) {
            if list.len() <= OWN_RECORD_COUNT {
                return;
            }
            list.sort_by_key(|r| r.seq);
            let cutoff = now.saturating_sub(OWN_RECORD_DAYS * 86_400);
            let excess = list.len() - OWN_RECORD_COUNT;
            // Among the oldest `excess` records, drop those past the age limit. Records are in
            // `seq` order, which is publication order, so the dropped ones form a prefix.
            let drop = list[..excess]
                .iter()
                .take_while(|r| r.unix < cutoff)
                .count();
            if drop > 0 {
                let max_dropped = list[drop - 1].seq;
                list.drain(..drop);
                *from = (*from).max(max_dropped.saturating_add(1));
            }
        }
        prune_one(&mut self.headers, &mut self.headers_from, now);
        prune_one(&mut self.indexes, &mut self.indexes_from, now);
    }
}

/// Check an unlocked header against the pin and this device's records. `keys` must come from
/// unlocking the same header as `info`. Returns the notices to report; the caller then sets the
/// pin with [`HeaderPin::from_header`].
pub fn check_header(
    pin: &HeaderPin,
    info: &HeaderInfo,
    keys: &VaultKeys,
    own: &OwnRecords,
    device_id: &[u8; 16],
) -> Result<Vec<Notice>> {
    if info.vault_id != pin.vault_id {
        return integrity(K::VaultIdMismatch);
    }
    if info.epoch < pin.epoch {
        return integrity(K::HeaderRollback);
    }
    if info.epoch - pin.epoch > MAX_EPOCH_ADVANCE {
        return integrity(K::EpochJump);
    }
    let pinned_fp = if info.epoch == pin.epoch {
        Some(info.fingerprint)
    } else {
        keys.fingerprint_of(pin.epoch)
    };
    if pinned_fp != Some(pin.fingerprint) {
        return integrity(K::PinFingerprint);
    }
    if info.header_seq < pin.header_seq {
        return integrity(K::HeaderRollback);
    }
    if info.header_seq == pin.header_seq {
        if info.header_sha256 != pin.header_sha256 {
            return integrity(K::HeaderFork);
        }
        return Ok(Vec::new());
    }
    if info.legacy_sha256 != pin.legacy_sha256 {
        return integrity(K::Legacy);
    }
    let writer = info.writer_device_id;
    let mut notices = Vec::new();
    if &writer == device_id
        && let Some(n) = own.check(ObjectKind::Header, info.header_seq, &info.header_sha256)?
    {
        notices.push(n);
    }
    if info.epoch != pin.epoch {
        notices.push(Notice::VaultKeyChanged {
            writer,
            epoch: info.epoch,
        });
    }
    if pin.header_seq != 0 && info.header_seq - pin.header_seq > COUNTER_JUMP {
        notices.push(Notice::CounterJump {
            kind: ObjectKind::Header,
            writer,
            from: pin.header_seq,
            to: info.header_seq,
        });
    }
    if pin.header_seq != 0 && !pin.devices.contains(&writer) {
        notices.push(Notice::UnenrolledWriter {
            kind: ObjectKind::Header,
            writer,
        });
    }
    Ok(notices)
}

/// The verdict on an index's cleartext prefix, before it is opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexVerdict {
    /// The index names a newer header; fetch and accept the header, then check again.
    NeedHeader,
    /// The pinned index itself.
    Unchanged,
    /// An epoch-`e` index under an epoch-`e + 1` header that does not match the rotation
    /// commitment: a status, not an error. Serve reads from the mirror and keep writes queued.
    RotationPending,
    /// A newer index that may be opened.
    Accept,
}

/// Check an index's prefix and SHA-256 against the current header and the index pin. An
/// accepted index is then opened with [`crate::index::open_index`] and its writer checked with
/// [`check_index_writer`].
pub fn check_index(
    pin: Option<&IndexPin>,
    header: &HeaderInfo,
    prefix: &IndexPrefix,
    sha256: &[u8; 32],
) -> Result<IndexVerdict> {
    if prefix.vault_id != header.vault_id {
        return integrity(K::VaultIdMismatch);
    }
    if prefix.header_seq > header.header_seq {
        return Ok(IndexVerdict::NeedHeader);
    }
    let mut unchanged = false;
    if let Some(pin) = pin {
        if prefix.epoch < pin.index_epoch {
            return integrity(K::IndexEpoch);
        }
        if prefix.index_seq < pin.index_seq {
            return integrity(K::IndexRollback);
        }
        if prefix.index_seq == pin.index_seq {
            if sha256 != &pin.index_sha256 {
                return integrity(K::IndexFork);
            }
            unchanged = true;
        }
    }
    // The epoch rule applies to the pinned index too, because the header may have moved on.
    let rot = &header.rotation;
    let epoch_ok = prefix.epoch == header.epoch
        || (rot.from_epoch != 0
            && prefix.epoch == rot.from_epoch
            && rot.from_epoch.checked_add(1) == Some(header.epoch)
            && sha256 == &rot.from_index_sha256);
    if !epoch_ok {
        if rot.from_epoch != 0
            && prefix.epoch == rot.from_epoch
            && rot.from_epoch.checked_add(1) == Some(header.epoch)
        {
            return Ok(IndexVerdict::RotationPending);
        }
        return integrity(K::IndexEpoch);
    }
    Ok(if unchanged {
        IndexVerdict::Unchanged
    } else {
        IndexVerdict::Accept
    })
}

/// Writer checks and counter notices for an accepted, opened index.
pub fn check_index_writer(
    pin: Option<&IndexPin>,
    header: &HeaderInfo,
    prefix: &IndexPrefix,
    sha256: &[u8; 32],
    writer: &[u8; 16],
    own: &OwnRecords,
    device_id: &[u8; 16],
) -> Result<Vec<Notice>> {
    let mut notices = Vec::new();
    if writer == device_id
        && let Some(n) = own.check(ObjectKind::Index, prefix.index_seq, sha256)?
    {
        notices.push(n);
    }
    if let Some(pin) = pin
        && prefix.index_seq - pin.index_seq > COUNTER_JUMP
    {
        notices.push(Notice::CounterJump {
            kind: ObjectKind::Index,
            writer: *writer,
            from: pin.index_seq,
            to: prefix.index_seq,
        });
    }
    if !header.devices.iter().any(|d| &d.record.device_id == writer) {
        notices.push(Notice::UnenrolledWriter {
            kind: ObjectKind::Index,
            writer: *writer,
        });
    }
    Ok(notices)
}

impl IndexPin {
    /// The pin an accepted index sets.
    pub fn from_index(prefix: &IndexPrefix, sha256: [u8; 32]) -> IndexPin {
        IndexPin {
            index_seq: prefix.index_seq,
            index_sha256: sha256,
            index_epoch: prefix.epoch,
        }
    }
}
