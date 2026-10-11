//! Replay of queued operations on a remote index, from the spec's "Index operations and merge".
//!
//! [`replay`] is pure and restartable. Where a rule needs to know whether one revision descends
//! from another, it asks a [`ChainView`]; an object the view does not hold yet comes back as
//! [`ReplayOutcome::Need`], the caller fetches and verifies it, and calls [`replay`] again with the
//! same inputs. The same function gives the optimistic local view that reads use, with a view that
//! answers [`Lookup::Unavailable`] for anything not in the mirror.

use crate::error::Result;
use crate::ext::{CONFLICT_OF, ExtList};
use crate::index::{Applied, IndexEntry, IndexPlain, Tombstone};
use crate::limits::PATH_MAX;
use crate::ops::{MoveOp, Op, PutOp, RemoveOp};
use core::cmp::Ordering;
use core::fmt;

/// The longest descent walk replay attempts. A longer one is treated as a walk that cannot
/// complete, which the replay rules resolve as a concurrent edit, so a forged revision gap cannot
/// make a device fetch without bound.
pub const MAX_WALK: u64 = 10_000;

/// What a [`ChainView`] knows about one object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lookup {
    /// A verified object: its parent's object ID and its own revision.
    Known {
        /// Parent object ID, zeros for revision 1.
        parent: [u8; 16],
        /// The object's revision.
        revision: u64,
    },
    /// Not held yet; the caller can fetch it.
    Missing,
    /// Not obtainable now, for example offline.
    Unavailable,
}

/// The chain links replay may consult.
pub trait ChainView {
    /// What is known about `object_id`.
    fn lookup(&self, object_id: &[u8; 16]) -> Lookup;
}

/// A view that knows nothing and can fetch nothing: every descent walk is a concurrent edit.
pub struct NoChain;

impl ChainView for NoChain {
    fn lookup(&self, _: &[u8; 16]) -> Lookup {
        Lookup::Unavailable
    }
}

/// Inputs to replay besides the index and the queue.
pub struct ReplayCtx<'a> {
    /// This device, the writer of the new index.
    pub device_id: [u8; 16],
    /// Labels of the devices enrolled in the current header, for conflict paths.
    pub labels: &'a [([u8; 16], String)],
    /// `index_seq` the new index will carry, recorded in new tombstones.
    pub new_index_seq: u64,
}

/// One event of a replay that the sync report lists. Paths are entry metadata: the report is for
/// the user's own terminal, never for logs.
#[derive(Clone, PartialEq, Eq)]
pub enum ReportItem {
    /// Two revisions met at `path`; the older moved to `copy_path`.
    Conflict {
        /// The contested path, kept by the newer revision.
        path: String,
        /// Where the older revision now lives.
        copy_path: String,
        /// Writer of the revision that moved.
        copy_device: [u8; 16],
    },
    /// An edit of a removed entry put it back.
    EditWonOverDelete {
        /// The removed path.
        path: String,
        /// Where the edit now lives: `path`, or a conflict path if `path` was taken.
        at: String,
    },
    /// An edit whose previous head is nowhere in the index was inserted.
    InsertedWithoutTarget {
        /// The path of the edit.
        path: String,
        /// Where it now lives.
        at: String,
    },
    /// A removal whose entry was edited since; the edit wins.
    RemoveDropped {
        /// The path removed.
        path: String,
    },
    /// A move whose entry could not be found, or whose source now holds another entry.
    MoveDropped {
        /// Source path.
        from: String,
        /// Destination path.
        to: String,
    },
    /// A move whose destination was taken.
    MovedToConflictPath {
        /// The requested destination.
        to: String,
        /// Where the entry now lives.
        at: String,
    },
}

impl fmt::Debug for ReportItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            ReportItem::Conflict { .. } => "Conflict",
            ReportItem::EditWonOverDelete { .. } => "EditWonOverDelete",
            ReportItem::InsertedWithoutTarget { .. } => "InsertedWithoutTarget",
            ReportItem::RemoveDropped { .. } => "RemoveDropped",
            ReportItem::MoveDropped { .. } => "MoveDropped",
            ReportItem::MovedToConflictPath { .. } => "MovedToConflictPath",
        };
        f.write_str(kind)
    }
}

/// A finished replay.
pub struct ReplayResult {
    /// The new index plaintext, with this device as writer and the applied table advanced.
    pub index: IndexPlain,
    /// Events to report.
    pub report: Vec<ReportItem>,
    /// The highest `op_seq` processed, including dropped operations; `None` if every operation
    /// was already applied.
    pub last_processed: Option<u64>,
    /// How many queued operations were left for a further publish. Two removals of one path in
    /// one publish would need two tombstones with the same path and `removed_index_seq`, which
    /// the index cannot hold, so replay stops before the second one.
    pub deferred: usize,
}

/// The outcome of one replay attempt.
pub enum ReplayOutcome {
    /// Replay finished.
    Done(ReplayResult),
    /// Fetch and verify this object, then replay again.
    Need([u8; 16]),
}

/// The spec's revision order: `(revision, device_id, object_id)`.
pub fn revision_order(a: (u64, &[u8; 16], &[u8; 16]), b: (u64, &[u8; 16], &[u8; 16])) -> Ordering {
    a.cmp(&b)
}

fn entry_order(e: &IndexEntry) -> (u64, &[u8; 16], &[u8; 16]) {
    (e.revision, &e.device_id, &e.head_object_id)
}

/// The label used in a conflict path for `device`: its label if enrolled, otherwise the first 8
/// hex characters of its ID.
pub fn conflict_label(labels: &[([u8; 16], String)], device: &[u8; 16]) -> String {
    labels
        .iter()
        .find(|(d, _)| d == device)
        .map(|(_, l)| l.clone())
        .unwrap_or_else(|| hex8(device))
}

fn hex8(id: &[u8; 16]) -> String {
    id[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// The conflict path for `path`, as the spec's "Replay rules" define it: `<path>.conflict-<label>`,
/// then `-2`, `-3`, and so on while taken, with the last segment truncated to fit 1,024 bytes, and
/// `<h>.conflict-<label>` at the top level when even a one-character last segment does not fit.
pub fn conflict_path(
    path: &str,
    label: &str,
    loser_object_id: &[u8; 16],
    taken: impl Fn(&str) -> bool,
) -> String {
    let (parent, last) = match path.rfind('/') {
        Some(i) => (&path[..=i], &path[i + 1..]),
        None => ("", path),
    };
    let mut n: u64 = 1;
    loop {
        let suffix = if n == 1 {
            format!(".conflict-{label}")
        } else {
            format!(".conflict-{label}-{n}")
        };
        let room = PATH_MAX.saturating_sub(parent.len() + suffix.len());
        let candidate = if last.len() <= room {
            format!("{parent}{last}{suffix}")
        } else {
            let mut cut = room;
            while cut > 0 && !last.is_char_boundary(cut) {
                cut -= 1;
            }
            if cut > 0 {
                format!("{parent}{}{suffix}", &last[..cut])
            } else {
                // The parent segments leave no room: the copy goes to the top level.
                format!("{}{suffix}", hex8(loser_object_id))
            }
        };
        if !taken(&candidate) {
            return candidate;
        }
        n += 1;
    }
}

/// The extension items a new head keeps from the record it continues: the items a changed record
/// keeps, without a history floor above its revision or a conflict-of naming its own path.
fn carried_ext(ext: &ExtList, path: &str, revision: u64) -> ExtList {
    let mut e = ext.for_changed_record();
    if e.history_floor().is_some_and(|f| f > revision) {
        e.remove(crate::ext::HISTORY_FLOOR);
    }
    if e.conflict_of().is_some_and(|o| o == path) {
        e.remove(CONFLICT_OF);
    }
    e
}

enum Walk {
    Yes,
    No,
    Need([u8; 16]),
    Unavailable,
}

/// Whether the revision `head` (at `head_rev`) descends from `ancestor` (at `ancestor_rev`): walk
/// the chain back from `head` while its revision is greater than the ancestor's.
fn descends(
    view: &dyn ChainView,
    head: &[u8; 16],
    head_rev: u64,
    ancestor: &[u8; 16],
    ancestor_rev: u64,
) -> Walk {
    if head_rev <= ancestor_rev {
        return Walk::No;
    }
    if head_rev - ancestor_rev > MAX_WALK {
        return Walk::Unavailable;
    }
    let mut cur = *head;
    let mut rev = head_rev;
    while rev > ancestor_rev {
        match view.lookup(&cur) {
            Lookup::Known { parent, revision } => {
                if revision != rev {
                    return Walk::No;
                }
                cur = parent;
                rev -= 1;
            }
            Lookup::Missing => return Walk::Need(cur),
            Lookup::Unavailable => return Walk::Unavailable,
        }
    }
    if &cur == ancestor {
        Walk::Yes
    } else {
        Walk::No
    }
}

struct State<'a> {
    idx: IndexPlain,
    report: Vec<ReportItem>,
    ctx: &'a ReplayCtx<'a>,
}

impl State<'_> {
    fn find_path(&self, p: &str) -> core::result::Result<usize, usize> {
        self.idx
            .entries
            .binary_search_by(|e| e.path.as_bytes().cmp(p.as_bytes()))
    }

    fn find_head(&self, id: &[u8; 16]) -> Option<usize> {
        self.idx
            .entries
            .iter()
            .position(|e| &e.head_object_id == id)
    }

    fn is_taken(&self, p: &str) -> bool {
        self.find_path(p).is_ok()
    }

    fn insert(&mut self, e: IndexEntry) {
        match self.find_path(&e.path) {
            Ok(_) => unreachable!("insert at a taken path"),
            Err(i) => self.idx.entries.insert(i, e),
        }
    }

    fn label(&self, device: &[u8; 16]) -> String {
        conflict_label(self.ctx.labels, device)
    }

    /// Mark `e` as a conflict copy of `original` and give it a free conflict path.
    fn to_conflict_copy(
        &self,
        mut e: IndexEntry,
        original: &str,
        label_device: &[u8; 16],
    ) -> IndexEntry {
        let label = self.label(label_device);
        let path = conflict_path(original, &label, &e.head_object_id, |p| self.is_taken(p));
        e.ext = e.ext.for_changed_record();
        let keep = e
            .ext
            .conflict_of()
            .is_some_and(|o| o != path && crate::path::is_valid_path(o));
        if !keep {
            e.ext.set(CONFLICT_OF, original.as_bytes().to_vec());
        }
        e.path = path;
        e
    }

    /// Two revisions meet at the path of entry `i`: the newer keeps it, the older becomes a
    /// conflict copy labelled with its own writer. With `same_record`, the incoming revision is a
    /// concurrent edit of the record at the path, and if it wins it keeps that record's extension
    /// items where they remain valid for it.
    fn conflict_at(&mut self, i: usize, incoming: IndexEntry, same_record: bool) {
        let path = self.idx.entries[i].path.clone();
        if entry_order(&incoming) > entry_order(&self.idx.entries[i]) {
            let loser = self.idx.entries.remove(i);
            let loser_dev = loser.device_id;
            let mut winner = incoming;
            winner.path = path.clone();
            if same_record {
                winner.ext = carried_ext(&loser.ext, &winner.path, winner.revision);
            }
            self.insert(winner);
            let copy = self.to_conflict_copy(loser, &path, &loser_dev);
            self.report.push(ReportItem::Conflict {
                path,
                copy_path: copy.path.clone(),
                copy_device: loser_dev,
            });
            self.insert(copy);
        } else {
            let dev = incoming.device_id;
            let copy = self.to_conflict_copy(incoming, &path, &dev);
            self.report.push(ReportItem::Conflict {
                path,
                copy_path: copy.path.clone(),
                copy_device: dev,
            });
            self.insert(copy);
        }
    }

    fn new_entry(p: &PutOp, ext: ExtList) -> IndexEntry {
        IndexEntry {
            path: p.path.clone(),
            head_object_id: p.object_id,
            head_sha256: p.object_sha256,
            revision: p.revision,
            device_id: p.device_id,
            ext,
        }
    }

    /// Insert `e` at its path, or as a conflict copy of that path labelled with its writer if the
    /// path is taken. Returns where it went.
    fn insert_or_copy(&mut self, e: IndexEntry) -> String {
        if self.is_taken(&e.path) {
            let original = e.path.clone();
            let dev = e.device_id;
            let copy = self.to_conflict_copy(e, &original, &dev);
            let at = copy.path.clone();
            self.insert(copy);
            at
        } else {
            let at = e.path.clone();
            self.insert(e);
            at
        }
    }

    fn put(&mut self, p: &PutOp, view: &dyn ChainView) -> Option<[u8; 16]> {
        if p.is_new() {
            let e = Self::new_entry(p, ExtList::new());
            match self.find_path(&p.path) {
                Ok(i) => self.conflict_at(i, e, false),
                Err(_) => self.insert(e),
            }
            return None;
        }
        // Edit: the target is the entry whose head is the parent, wherever it now lives.
        if let Some(i) = self.find_head(&p.parent_object_id) {
            let t = &mut self.idx.entries[i];
            t.head_object_id = p.object_id;
            t.head_sha256 = p.object_sha256;
            t.revision = p.revision;
            t.device_id = p.device_id;
            t.ext = t.ext.for_changed_record();
            return None;
        }
        if let Some(t) = self
            .idx
            .tombstones
            .iter()
            .find(|t| t.head_object_id == p.parent_object_id)
        {
            let e = Self::new_entry(p, t.ext.for_changed_record());
            let at = self.insert_or_copy(e);
            self.report.push(ReportItem::EditWonOverDelete {
                path: p.path.clone(),
                at,
            });
            return None;
        }
        if let Ok(i) = self.find_path(&p.path) {
            let h = &self.idx.entries[i];
            let walk = descends(
                view,
                &h.head_object_id,
                h.revision,
                &p.parent_object_id,
                p.revision.saturating_sub(1),
            );
            match walk {
                Walk::Need(id) => return Some(id),
                Walk::Yes | Walk::Unavailable => {
                    self.conflict_at(i, Self::new_entry(p, ExtList::new()), true);
                    return None;
                }
                Walk::No => {}
            }
        }
        let at = self.insert_or_copy(Self::new_entry(p, ExtList::new()));
        self.report.push(ReportItem::InsertedWithoutTarget {
            path: p.path.clone(),
            at,
        });
        None
    }

    /// Returns `false` when the removal must wait for a later publish.
    fn remove(&mut self, r: &RemoveOp) -> bool {
        let Some(i) = self.find_head(&r.expected_head) else {
            self.report.push(ReportItem::RemoveDropped {
                path: r.path.clone(),
            });
            return true;
        };
        let seq = self.ctx.new_index_seq;
        let path = self.idx.entries[i].path.clone();
        let pos = self.idx.tombstones.binary_search_by(|t| {
            (t.path.as_bytes(), t.removed_index_seq).cmp(&(path.as_bytes(), seq))
        });
        let Err(pos) = pos else {
            return false;
        };
        let e = self.idx.entries.remove(i);
        let mut ext = e.ext.for_changed_record();
        ext.remove(CONFLICT_OF);
        self.idx.tombstones.insert(
            pos,
            Tombstone {
                path: e.path,
                head_object_id: e.head_object_id,
                head_sha256: e.head_sha256,
                revision: e.revision,
                device_id: e.device_id,
                removed_index_seq: seq,
                ext,
            },
        );
        true
    }

    fn move_entry(&mut self, i: usize, m: &MoveOp) {
        if self.idx.entries[i].path == m.to {
            return;
        }
        let mut e = self.idx.entries.remove(i);
        if self.is_taken(&m.to) {
            let dev = self.ctx.device_id;
            let copy = self.to_conflict_copy(e, &m.to, &dev);
            self.report.push(ReportItem::MovedToConflictPath {
                to: m.to.clone(),
                at: copy.path.clone(),
            });
            self.insert(copy);
        } else {
            e.ext = e.ext.for_changed_record();
            if e.ext.conflict_of() == Some(m.to.as_str()) {
                e.ext.remove(CONFLICT_OF);
            }
            e.path = m.to.clone();
            self.insert(e);
        }
    }

    fn mv(&mut self, m: &MoveOp, view: &dyn ChainView) -> Option<[u8; 16]> {
        if let Some(i) = self.find_head(&m.expected_head) {
            self.move_entry(i, m);
            return None;
        }
        let dropped = ReportItem::MoveDropped {
            from: m.from.clone(),
            to: m.to.clone(),
        };
        let Ok(i) = self.find_path(&m.from) else {
            self.report.push(dropped);
            return None;
        };
        let h = &self.idx.entries[i];
        // The expected head's revision is unknown to the operation; the walk finds it.
        match descends_unknown_rev(view, &h.head_object_id, h.revision, &m.expected_head) {
            Walk::Need(id) => Some(id),
            Walk::Yes => {
                self.move_entry(i, m);
                None
            }
            Walk::No | Walk::Unavailable => {
                self.report.push(dropped);
                None
            }
        }
    }
}

/// Like [`descends`], for an ancestor whose revision is not known: walk back from `head` until the
/// ancestor or revision 1, within [`MAX_WALK`] steps.
fn descends_unknown_rev(
    view: &dyn ChainView,
    head: &[u8; 16],
    head_rev: u64,
    ancestor: &[u8; 16],
) -> Walk {
    let mut cur = *head;
    let mut rev = head_rev;
    let mut steps = 0;
    loop {
        if steps > 0 && &cur == ancestor {
            return Walk::Yes;
        }
        if rev <= 1 || cur == [0; 16] {
            return Walk::No;
        }
        if steps >= MAX_WALK {
            return Walk::Unavailable;
        }
        match view.lookup(&cur) {
            Lookup::Known { parent, revision } => {
                if revision != rev {
                    return Walk::No;
                }
                cur = parent;
                rev -= 1;
                steps += 1;
            }
            Lookup::Missing => return Walk::Need(cur),
            Lookup::Unavailable => return Walk::Unavailable,
        }
    }
}

/// Replay `ops` in queue order on `remote`.
///
/// Operations at or below the remote applied value for this device are skipped, as is a `put`
/// whose object is already a head or tombstone head (a publish whose response was lost). The
/// result's applied table records the highest `op_seq` processed, dropped operations included.
pub fn replay(
    remote: &IndexPlain,
    ops: &[Op],
    ctx: &ReplayCtx<'_>,
    view: &dyn ChainView,
) -> Result<ReplayOutcome> {
    let applied = remote
        .applied
        .iter()
        .find(|a| a.device_id == ctx.device_id)
        .map_or(0, |a| a.last_op_seq);
    let mut st = State {
        idx: remote.clone(),
        report: Vec::new(),
        ctx,
    };
    let mut last = None;
    let mut deferred = 0;
    for (n, op) in ops.iter().enumerate() {
        if op.op_seq() <= applied {
            continue;
        }
        let need = match op {
            Op::Put(p) => {
                let present = st.find_head(&p.object_id).is_some()
                    || st
                        .idx
                        .tombstones
                        .iter()
                        .any(|t| t.head_object_id == p.object_id);
                if present { None } else { st.put(p, view) }
            }
            Op::Remove(r) => {
                if !st.remove(r) {
                    deferred = ops.len() - n;
                    break;
                }
                None
            }
            Op::Move(m) => st.mv(m, view),
        };
        if let Some(id) = need {
            return Ok(ReplayOutcome::Need(id));
        }
        last = Some(op.op_seq());
    }
    let mut idx = st.idx;
    idx.writer_device_id = ctx.device_id;
    if let Some(v) = last {
        match idx
            .applied
            .binary_search_by(|a| a.device_id.cmp(&ctx.device_id))
        {
            Ok(i) => idx.applied[i].last_op_seq = idx.applied[i].last_op_seq.max(v),
            Err(i) => idx.applied.insert(
                i,
                Applied {
                    device_id: ctx.device_id,
                    last_op_seq: v,
                },
            ),
        }
    }
    Ok(ReplayOutcome::Done(ReplayResult {
        index: idx,
        report: st.report,
        last_processed: last,
        deferred,
    }))
}
