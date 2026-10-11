//! Index operations and the `op_seq` counter, from the spec's "Index operations and merge".
//!
//! A device never merges two index states. It queues each change as an [`Op`] and replays the
//! queue on top of the latest remote index when it publishes (see [`crate::merge`]).

use crate::error::{IntegrityKind as K, Result, integrity};
use crate::limits::COUNTER_CAP;
use crate::notice::Notice;
use core::fmt;

/// A new head for a path: a new entry (zero parent), an edit, a copy, or a restore.
#[derive(Clone, PartialEq, Eq)]
pub struct PutOp {
    /// Operation sequence number.
    pub op_seq: u64,
    /// Path the user wrote to.
    pub path: String,
    /// The new revision's object ID.
    pub object_id: [u8; 16],
    /// SHA-256 of the new revision's whole object.
    pub object_sha256: [u8; 32],
    /// The new revision number.
    pub revision: u64,
    /// The previous head, or zeros for a new entry.
    pub parent_object_id: [u8; 16],
    /// The writing device.
    pub device_id: [u8; 16],
    /// Vault ID of the lineage the object was sealed under. Not part of the spec's operation;
    /// it lets publishing decide on a re-seal without decrypting.
    pub entry_vault_id: [u8; 16],
    /// Epoch the object was sealed under.
    pub entry_epoch: u32,
    /// Whether the object is known to be in the backend, so a retried publish skips its `PUT`.
    pub uploaded: bool,
}

impl PutOp {
    /// Whether this is a new entry rather than an edit.
    pub fn is_new(&self) -> bool {
        self.parent_object_id == [0; 16]
    }
}

/// Remove the entry whose head is `expected_head`.
#[derive(Clone, PartialEq, Eq)]
pub struct RemoveOp {
    /// Operation sequence number.
    pub op_seq: u64,
    /// Path the user removed.
    pub path: String,
    /// Head the user saw.
    pub expected_head: [u8; 16],
}

/// Rename the entry whose head is `expected_head` from `from` to `to`.
#[derive(Clone, PartialEq, Eq)]
pub struct MoveOp {
    /// Operation sequence number.
    pub op_seq: u64,
    /// Source path.
    pub from: String,
    /// Destination path.
    pub to: String,
    /// Head the user saw.
    pub expected_head: [u8; 16],
}

/// One queued operation.
#[derive(Clone, PartialEq, Eq)]
pub enum Op {
    /// `put`.
    Put(PutOp),
    /// `remove`.
    Remove(RemoveOp),
    /// `move`.
    Move(MoveOp),
}

impl Op {
    /// The operation's sequence number.
    pub fn op_seq(&self) -> u64 {
        match self {
            Op::Put(p) => p.op_seq,
            Op::Remove(r) => r.op_seq,
            Op::Move(m) => m.op_seq,
        }
    }

    fn set_op_seq(&mut self, v: u64) {
        match self {
            Op::Put(p) => p.op_seq = v,
            Op::Remove(r) => r.op_seq = v,
            Op::Move(m) => m.op_seq = v,
        }
    }
}

// Paths are entry metadata, so operations format without them.
impl fmt::Debug for Op {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, seq) = match self {
            Op::Put(p) => ("Put", p.op_seq),
            Op::Remove(r) => ("Remove", r.op_seq),
            Op::Move(m) => ("Move", m.op_seq),
        };
        f.debug_struct(kind)
            .field("op_seq", &seq)
            .finish_non_exhaustive()
    }
}

/// Raise this device's next `op_seq` past an index's applied value for it, renumbering the queue
/// above it in order, as the spec requires whenever `applied[device_id]` is at least the next
/// `op_seq`. Returns the notice to report, or `None` when nothing changed. A value at the cap
/// leaves no room and is an integrity error that names `vlt repair --rekey`.
pub fn raise_op_seq(
    next_op_seq: &mut u64,
    queue: &mut [Op],
    applied: u64,
    index_writer: [u8; 16],
) -> Result<Option<Notice>> {
    if applied < *next_op_seq {
        return Ok(None);
    }
    let needed = applied
        .checked_add(1)
        .and_then(|first| first.checked_add(queue.len() as u64))
        .filter(|next| *next - 1 <= COUNTER_CAP && applied < COUNTER_CAP);
    let Some(next) = needed else {
        return integrity(K::CounterCap);
    };
    for (i, op) in queue.iter_mut().enumerate() {
        op.set_op_seq(applied + 1 + i as u64);
    }
    *next_op_seq = next;
    Ok(Some(Notice::OpSeqRaised {
        writer: index_writer,
        next_op_seq: next,
    }))
}

/// Take the next `op_seq`, failing at the cap.
pub fn take_op_seq(next_op_seq: &mut u64) -> Result<u64> {
    let v = *next_op_seq;
    if v == 0 || v > COUNTER_CAP {
        return integrity(K::CounterCap);
    }
    *next_op_seq = v + 1;
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rm(seq: u64) -> Op {
        Op::Remove(RemoveOp {
            op_seq: seq,
            path: "a".into(),
            expected_head: [1; 16],
        })
    }

    #[test]
    fn raise_renumbers_in_order() {
        let mut next = 3;
        let mut q = vec![rm(1), rm(2)];
        assert_eq!(raise_op_seq(&mut next, &mut q, 2, [9; 16]).unwrap(), None);
        let n = raise_op_seq(&mut next, &mut q, 3, [9; 16]).unwrap();
        assert_eq!(
            n,
            Some(Notice::OpSeqRaised {
                writer: [9; 16],
                next_op_seq: 6
            })
        );
        assert_eq!(q.iter().map(Op::op_seq).collect::<Vec<_>>(), vec![4, 5]);
        assert_eq!(next, 6);
    }

    #[test]
    fn raise_at_cap_is_integrity() {
        let mut next = 1;
        let mut q = vec![];
        assert_eq!(
            raise_op_seq(&mut next, &mut q, COUNTER_CAP, [0; 16]),
            Err(crate::Error::Integrity(K::CounterCap))
        );
        let mut q = vec![rm(1), rm(2)];
        assert_eq!(
            raise_op_seq(&mut next, &mut q, COUNTER_CAP - 1, [0; 16]),
            Err(crate::Error::Integrity(K::CounterCap))
        );
        let mut q = vec![];
        raise_op_seq(&mut next, &mut q, COUNTER_CAP - 1, [0; 16]).unwrap();
        assert_eq!(next, COUNTER_CAP);
        assert_eq!(take_op_seq(&mut next), Ok(COUNTER_CAP));
        assert!(take_op_seq(&mut next).is_err());
    }
}
