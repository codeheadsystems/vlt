//! Replay tests: one per row of the spec's replay rules table, the conflict path rules, extension
//! handling, skips and restarts, and properties over random indexes and queues.

use crate::ext::{CONFLICT_OF, ExtList, HISTORY_FLOOR};
use crate::index::{self, Applied, IndexEntry, IndexPlain, IndexPrefix, Tombstone};
use crate::merge::{
    ChainView, Lookup, MAX_WALK, NoChain, ReplayCtx, ReplayOutcome, ReplayResult, ReportItem,
    conflict_label, conflict_path, replay, revision_order,
};
use crate::ops::{MoveOp, Op, PutOp, RemoveOp};
use crate::path::is_valid_path;
use crate::secret::IndexKey;
use core::cell::{Cell, RefCell};
use core::cmp::Ordering;
use proptest::collection::vec;
use proptest::prelude::*;
use std::collections::{BTreeSet, HashMap, HashSet};

/// This device, enrolled as `laptop`.
const ME: [u8; 16] = [0xaa; 16];
/// Another enrolled device, `phone`. Lower than `ME`, so `ME` wins revision ties.
const OTHER: [u8; 16] = [0x11; 16];
/// A device no longer enrolled; its label is `01234567`.
const GONE: [u8; 16] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
const ZERO: [u8; 16] = [0; 16];
/// `index_seq` of the index the replay builds.
const SEQ: u64 = 10;
/// An unknown copy-safe extension type.
const CS: u16 = 0x4100;
/// An unknown extension type without the copy-safe bit.
const NCS: u16 = 0x0100;

// ---- builders --------------------------------------------------------------------------------

fn oid(n: u8) -> [u8; 16] {
    let mut a = [0; 16];
    a[0] = 0x0b;
    a[1] = n;
    a
}

/// Object ID of revision `rev` in a test chain tagged `tag`.
fn cid(tag: u8, rev: u64) -> [u8; 16] {
    let mut a = [0; 16];
    a[0] = tag;
    a[2..10].copy_from_slice(&rev.to_be_bytes());
    a
}

fn ext(items: Vec<(u16, Vec<u8>)>) -> ExtList {
    let mut e = ExtList::new();
    for (ty, v) in items {
        e.set(ty, v);
    }
    e
}

fn floor(n: u64) -> (u16, Vec<u8>) {
    (HISTORY_FLOOR, n.to_be_bytes().to_vec())
}

fn cof(p: &str) -> (u16, Vec<u8>) {
    (CONFLICT_OF, p.as_bytes().to_vec())
}

fn items(e: &ExtList) -> Vec<(u16, Vec<u8>)> {
    e.items.iter().map(|i| (i.ty, i.value.clone())).collect()
}

fn ent(path: &str, head: [u8; 16], revision: u64, device: [u8; 16]) -> IndexEntry {
    ent_x(path, head, revision, device, vec![])
}

fn ent_x(
    path: &str,
    head: [u8; 16],
    revision: u64,
    device: [u8; 16],
    x: Vec<(u16, Vec<u8>)>,
) -> IndexEntry {
    IndexEntry {
        path: path.into(),
        head_object_id: head,
        head_sha256: [head[1]; 32],
        revision,
        device_id: device,
        ext: ext(x),
    }
}

fn tomb(path: &str, head: [u8; 16], revision: u64, seq: u64, x: Vec<(u16, Vec<u8>)>) -> Tombstone {
    Tombstone {
        path: path.into(),
        head_object_id: head,
        head_sha256: [head[1]; 32],
        revision,
        device_id: OTHER,
        removed_index_seq: seq,
        ext: ext(x),
    }
}

fn idx(
    mut entries: Vec<IndexEntry>,
    mut tombstones: Vec<Tombstone>,
    applied: Vec<([u8; 16], u64)>,
) -> IndexPlain {
    entries.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    tombstones.sort_by(|a, b| {
        (a.path.as_bytes(), a.removed_index_seq).cmp(&(b.path.as_bytes(), b.removed_index_seq))
    });
    let mut applied: Vec<Applied> = applied
        .into_iter()
        .map(|(device_id, last_op_seq)| Applied {
            device_id,
            last_op_seq,
        })
        .collect();
    applied.sort_by_key(|a| a.device_id);
    IndexPlain {
        writer_device_id: OTHER,
        entries,
        tombstones,
        applied,
        ext: ExtList::new(),
    }
}

fn put(
    seq: u64,
    path: &str,
    object: [u8; 16],
    revision: u64,
    parent: [u8; 16],
    device: [u8; 16],
) -> Op {
    Op::Put(PutOp {
        op_seq: seq,
        path: path.into(),
        object_id: object,
        object_sha256: [object[1]; 32],
        revision,
        parent_object_id: parent,
        device_id: device,
        entry_vault_id: [5; 16],
        entry_epoch: 1,
        uploaded: true,
    })
}

fn rm(seq: u64, path: &str, head: [u8; 16]) -> Op {
    Op::Remove(RemoveOp {
        op_seq: seq,
        path: path.into(),
        expected_head: head,
    })
}

fn mv(seq: u64, from: &str, to: &str, head: [u8; 16]) -> Op {
    Op::Move(MoveOp {
        op_seq: seq,
        from: from.into(),
        to: to.into(),
        expected_head: head,
    })
}

/// A [`ChainView`] backed by a map, answering `fallback` for anything not in it and counting
/// lookups.
struct Chain {
    links: RefCell<HashMap<[u8; 16], Lookup>>,
    fallback: Lookup,
    calls: Cell<usize>,
}

impl Chain {
    fn new(fallback: Lookup) -> Self {
        Chain {
            links: RefCell::new(HashMap::new()),
            fallback,
            calls: Cell::new(0),
        }
    }

    fn with(links: HashMap<[u8; 16], Lookup>, fallback: Lookup) -> Self {
        Chain {
            links: RefCell::new(links),
            fallback,
            calls: Cell::new(0),
        }
    }

    fn link(self, id: [u8; 16], parent: [u8; 16], revision: u64) -> Self {
        self.feed(id, Lookup::Known { parent, revision });
        self
    }

    /// The chain `tag` from revision `top` down to revision 1.
    fn chain(mut self, tag: u8, top: u64) -> Self {
        for r in 1..=top {
            let parent = if r == 1 { ZERO } else { cid(tag, r - 1) };
            self = self.link(cid(tag, r), parent, r);
        }
        self
    }

    fn feed(&self, id: [u8; 16], l: Lookup) {
        self.links.borrow_mut().insert(id, l);
    }
}

impl ChainView for Chain {
    fn lookup(&self, id: &[u8; 16]) -> Lookup {
        self.calls.set(self.calls.get() + 1);
        *self.links.borrow().get(id).unwrap_or(&self.fallback)
    }
}

fn labels() -> Vec<([u8; 16], String)> {
    vec![(ME, "laptop".into()), (OTHER, "phone".into())]
}

fn attempt(remote: &IndexPlain, ops: &[Op], view: &dyn ChainView, seq: u64) -> ReplayOutcome {
    let l = labels();
    let ctx = ReplayCtx {
        device_id: ME,
        labels: &l,
        new_index_seq: seq,
    };
    replay(remote, ops, &ctx, view).expect("replay")
}

fn done(o: ReplayOutcome) -> ReplayResult {
    match o {
        ReplayOutcome::Done(r) => r,
        ReplayOutcome::Need(id) => panic!("unexpected Need({})", hex::encode(id)),
    }
}

fn sealed(p: &IndexPlain) -> crate::Result<IndexPlain> {
    let k = IndexKey::from_bytes([7; 32]);
    let pfx = IndexPrefix {
        vault_id: [3; 16],
        epoch: 1,
        index_seq: SEQ,
        header_seq: 1,
    };
    let obj = index::seal_with_key(&k, &pfx, p, &[0; 24])?;
    Ok(index::open_with_key(&obj, &k)?.1)
}

/// Replay to completion and check what every published index must satisfy.
fn run(remote: &IndexPlain, ops: &[Op], view: &dyn ChainView) -> ReplayResult {
    let r = done(attempt(remote, ops, view, SEQ));
    assert_eq!(r.index.writer_device_id, ME);
    let back = sealed(&r.index).expect("the result seals");
    assert!(back == r.index, "the result reopens unchanged");
    r
}

type Head = (String, [u8; 16], u64, [u8; 16]);

fn heads(p: &IndexPlain) -> Vec<Head> {
    p.entries
        .iter()
        .map(|e| (e.path.clone(), e.head_object_id, e.revision, e.device_id))
        .collect()
}

fn h(path: &str, head: [u8; 16], revision: u64, device: [u8; 16]) -> Head {
    (path.into(), head, revision, device)
}

fn tombs(p: &IndexPlain) -> Vec<(String, [u8; 16], u64, u64)> {
    p.tombstones
        .iter()
        .map(|t| {
            (
                t.path.clone(),
                t.head_object_id,
                t.revision,
                t.removed_index_seq,
            )
        })
        .collect()
}

fn get<'a>(p: &'a IndexPlain, path: &str) -> &'a IndexEntry {
    p.entries
        .iter()
        .find(|e| e.path == path)
        .unwrap_or_else(|| panic!("no entry at {path}"))
}

fn applied(p: &IndexPlain, device: [u8; 16]) -> Option<u64> {
    p.applied
        .iter()
        .find(|a| a.device_id == device)
        .map(|a| a.last_op_seq)
}

fn show(r: &ReportItem) -> String {
    match r {
        ReportItem::Conflict {
            path,
            copy_path,
            copy_device,
        } => format!(
            "Conflict {path} -> {copy_path} by {}",
            hex::encode(copy_device)
        ),
        ReportItem::EditWonOverDelete { path, at } => format!("EditWonOverDelete {path} at {at}"),
        ReportItem::InsertedWithoutTarget { path, at } => {
            format!("InsertedWithoutTarget {path} at {at}")
        }
        ReportItem::RemoveDropped { path } => format!("RemoveDropped {path}"),
        ReportItem::MoveDropped { from, to } => format!("MoveDropped {from} -> {to}"),
        ReportItem::MovedToConflictPath { to, at } => format!("MovedToConflictPath {to} at {at}"),
    }
}

fn assert_report(got: &[ReportItem], want: &[ReportItem]) {
    let g: Vec<String> = got.iter().map(show).collect();
    let w: Vec<String> = want.iter().map(show).collect();
    assert_eq!(g, w);
}

fn conflict(path: &str, copy_path: &str, copy_device: [u8; 16]) -> ReportItem {
    ReportItem::Conflict {
        path: path.into(),
        copy_path: copy_path.into(),
        copy_device,
    }
}

/// The remote index with only the writer changed, which is what replay produces when nothing
/// applies.
fn rewritten(remote: &IndexPlain) -> IndexPlain {
    let mut p = remote.clone();
    p.writer_device_id = ME;
    p
}

// ---- replay rules table, one test per row ----------------------------------------------------

#[test]
fn put_new_at_free_path_inserts() {
    let remote = idx(vec![ent("b", oid(1), 2, OTHER)], vec![], vec![]);
    let r = run(&remote, &[put(1, "a", oid(2), 1, ZERO, ME)], &NoChain);
    assert_eq!(
        heads(&r.index),
        vec![h("a", oid(2), 1, ME), h("b", oid(1), 2, OTHER)]
    );
    assert!(get(&r.index, "a").ext.items.is_empty());
    assert_report(&r.report, &[]);
    assert_eq!(r.last_processed, Some(1));
    assert_eq!(r.deferred, 0);
    assert_eq!(applied(&r.index, ME), Some(1));
}

#[test]
fn put_new_at_taken_path_conflicts_and_older_incoming_moves() {
    let remote = idx(vec![ent("a", oid(1), 3, OTHER)], vec![], vec![]);
    let r = run(&remote, &[put(1, "a", oid(2), 1, ZERO, ME)], &NoChain);
    assert_eq!(
        heads(&r.index),
        vec![
            h("a", oid(1), 3, OTHER),
            h("a.conflict-laptop", oid(2), 1, ME)
        ]
    );
    assert_eq!(
        items(&get(&r.index, "a.conflict-laptop").ext),
        vec![cof("a")]
    );
    assert_report(&r.report, &[conflict("a", "a.conflict-laptop", ME)]);
    assert_eq!(r.last_processed, Some(1));
    assert_eq!(applied(&r.index, ME), Some(1));
}

#[test]
fn put_new_at_taken_path_conflicts_and_older_remote_moves() {
    let remote = idx(
        vec![ent_x(
            "a",
            oid(1),
            1,
            OTHER,
            vec![(CS, vec![1]), (NCS, vec![2])],
        )],
        vec![],
        vec![],
    );
    // Revisions tie at 1; ME's device ID is greater, so the incoming revision is newer.
    let r = run(&remote, &[put(1, "a", oid(2), 1, ZERO, ME)], &NoChain);
    assert_eq!(
        heads(&r.index),
        vec![
            h("a", oid(2), 1, ME),
            h("a.conflict-phone", oid(1), 1, OTHER)
        ]
    );
    // The new entry is a different record and takes nothing from the one it displaced.
    assert!(get(&r.index, "a").ext.items.is_empty());
    // The loser is a changed record: copy-safe kept, non-copy-safe dropped, conflict-of added.
    assert_eq!(
        items(&get(&r.index, "a.conflict-phone").ext),
        vec![cof("a"), (CS, vec![1])]
    );
    assert_eq!(get(&r.index, "a.conflict-phone").head_sha256, [1; 32]);
    assert_report(&r.report, &[conflict("a", "a.conflict-phone", OTHER)]);
    assert_eq!(r.last_processed, Some(1));
    assert_eq!(applied(&r.index, ME), Some(1));
}

#[test]
fn put_edit_with_target_at_op_path_replaces_head() {
    let remote = idx(
        vec![
            ent_x(
                "a",
                oid(1),
                2,
                OTHER,
                vec![floor(2), (CS, vec![1]), (NCS, vec![2])],
            ),
            ent_x("b", oid(9), 1, OTHER, vec![(NCS, vec![3])]),
        ],
        vec![],
        vec![],
    );
    let r = run(&remote, &[put(1, "a", oid(2), 3, oid(1), ME)], &NoChain);
    assert_eq!(
        heads(&r.index),
        vec![h("a", oid(2), 3, ME), h("b", oid(9), 1, OTHER)]
    );
    assert_eq!(get(&r.index, "a").head_sha256, [2; 32]);
    assert_eq!(
        items(&get(&r.index, "a").ext),
        vec![floor(2), (CS, vec![1])]
    );
    // A record carried over unchanged keeps every item byte for byte.
    assert_eq!(items(&get(&r.index, "b").ext), vec![(NCS, vec![3])]);
    assert_report(&r.report, &[]);
    assert_eq!(r.last_processed, Some(1));
    assert_eq!(applied(&r.index, ME), Some(1));
}

#[test]
fn put_edit_with_target_elsewhere_replaces_head_at_target_path() {
    let remote = idx(vec![ent("moved", oid(1), 2, OTHER)], vec![], vec![]);
    let r = run(&remote, &[put(1, "a", oid(2), 3, oid(1), ME)], &NoChain);
    assert_eq!(heads(&r.index), vec![h("moved", oid(2), 3, ME)]);
    assert_report(&r.report, &[]);
    assert_eq!(r.last_processed, Some(1));
    assert_eq!(applied(&r.index, ME), Some(1));
}

#[test]
fn put_edit_of_tombstoned_head_wins_over_delete() {
    let remote = idx(
        vec![],
        vec![tomb("a", oid(1), 4, 3, vec![floor(3)])],
        vec![],
    );
    let r = run(&remote, &[put(1, "a", oid(2), 5, oid(1), ME)], &NoChain);
    assert_eq!(heads(&r.index), vec![h("a", oid(2), 5, ME)]);
    assert_eq!(items(&get(&r.index, "a").ext), vec![floor(3)]);
    // The tombstone stays as history.
    assert_eq!(tombs(&r.index), vec![("a".into(), oid(1), 4, 3)]);
    assert_report(
        &r.report,
        &[ReportItem::EditWonOverDelete {
            path: "a".into(),
            at: "a".into(),
        }],
    );
    assert_eq!(r.last_processed, Some(1));
    assert_eq!(applied(&r.index, ME), Some(1));
}

#[test]
fn put_edit_of_tombstoned_head_at_taken_path_goes_to_conflict_path() {
    let remote = idx(
        vec![ent("a", oid(3), 1, OTHER)],
        vec![tomb("a", oid(1), 4, 3, vec![floor(3)])],
        vec![],
    );
    let r = run(&remote, &[put(1, "a", oid(2), 5, oid(1), ME)], &NoChain);
    assert_eq!(
        heads(&r.index),
        vec![
            h("a", oid(3), 1, OTHER),
            h("a.conflict-laptop", oid(2), 5, ME)
        ]
    );
    assert_eq!(
        items(&get(&r.index, "a.conflict-laptop").ext),
        vec![cof("a"), floor(3)]
    );
    assert_eq!(tombs(&r.index), vec![("a".into(), oid(1), 4, 3)]);
    assert_report(
        &r.report,
        &[ReportItem::EditWonOverDelete {
            path: "a".into(),
            at: "a.conflict-laptop".into(),
        }],
    );
    assert_eq!(r.last_processed, Some(1));
    assert_eq!(applied(&r.index, ME), Some(1));
}

#[test]
fn put_edit_with_descendant_at_path_is_a_concurrent_edit_remote_newer() {
    // Remote head is revision 3 of chain 0xc1; the edit continues revision 1 of the same chain.
    let remote = idx(vec![ent("a", cid(0xc1, 3), 3, OTHER)], vec![], vec![]);
    let view = Chain::new(Lookup::Missing).chain(0xc1, 3);
    let r = run(&remote, &[put(1, "a", oid(2), 2, cid(0xc1, 1), ME)], &view);
    assert_eq!(
        heads(&r.index),
        vec![
            h("a", cid(0xc1, 3), 3, OTHER),
            h("a.conflict-laptop", oid(2), 2, ME)
        ]
    );
    assert_eq!(
        items(&get(&r.index, "a.conflict-laptop").ext),
        vec![cof("a")]
    );
    assert_report(&r.report, &[conflict("a", "a.conflict-laptop", ME)]);
    assert_eq!(r.last_processed, Some(1));
    assert_eq!(applied(&r.index, ME), Some(1));
}

#[test]
fn put_edit_with_descendant_at_path_is_a_concurrent_edit_incoming_newer() {
    let remote = idx(
        vec![ent_x(
            "a",
            cid(0xc1, 2),
            2,
            OTHER,
            vec![floor(2), (CS, vec![1]), (NCS, vec![2])],
        )],
        vec![],
        vec![],
    );
    let view = Chain::new(Lookup::Missing).chain(0xc1, 2);
    // Both are revision 2; ME's device ID breaks the tie.
    let r = run(&remote, &[put(1, "a", oid(2), 2, cid(0xc1, 1), ME)], &view);
    assert_eq!(
        heads(&r.index),
        vec![
            h("a", oid(2), 2, ME),
            h("a.conflict-phone", cid(0xc1, 2), 2, OTHER)
        ]
    );
    // The winner is a new head of the same record and keeps its items where valid; a floor equal
    // to its revision is valid.
    assert_eq!(
        items(&get(&r.index, "a").ext),
        vec![floor(2), (CS, vec![1])]
    );
    assert_eq!(
        items(&get(&r.index, "a.conflict-phone").ext),
        vec![cof("a"), floor(2), (CS, vec![1])]
    );
    assert_report(&r.report, &[conflict("a", "a.conflict-phone", OTHER)]);
    assert_eq!(r.last_processed, Some(1));
    assert_eq!(applied(&r.index, ME), Some(1));
}

#[test]
fn put_edit_without_target_at_free_path_inserts_and_reports() {
    let remote = idx(vec![ent("b", oid(9), 1, OTHER)], vec![], vec![]);
    let view = Chain::new(Lookup::Missing);
    let r = run(&remote, &[put(1, "a", oid(2), 3, oid(1), ME)], &view);
    assert_eq!(view.calls.get(), 0, "no walk without a head at the path");
    assert_eq!(
        heads(&r.index),
        vec![h("a", oid(2), 3, ME), h("b", oid(9), 1, OTHER)]
    );
    assert!(get(&r.index, "a").ext.items.is_empty());
    assert_report(
        &r.report,
        &[ReportItem::InsertedWithoutTarget {
            path: "a".into(),
            at: "a".into(),
        }],
    );
    assert_eq!(r.last_processed, Some(1));
    assert_eq!(applied(&r.index, ME), Some(1));
}

#[test]
fn put_edit_without_target_at_unrelated_path_goes_to_conflict_path() {
    // The head at the path is revision 5 of an unrelated chain; the walk reaches revision 2 of it,
    // which is not the edit's parent.
    let remote = idx(vec![ent("a", cid(0xc2, 5), 5, OTHER)], vec![], vec![]);
    let view = Chain::new(Lookup::Missing).chain(0xc2, 5);
    let r = run(&remote, &[put(1, "a", oid(2), 3, oid(1), ME)], &view);
    assert!(view.calls.get() > 0, "the walk ran");
    assert_eq!(
        heads(&r.index),
        vec![
            h("a", cid(0xc2, 5), 5, OTHER),
            h("a.conflict-laptop", oid(2), 3, ME)
        ]
    );
    assert_eq!(
        items(&get(&r.index, "a.conflict-laptop").ext),
        vec![cof("a")]
    );
    assert_report(
        &r.report,
        &[ReportItem::InsertedWithoutTarget {
            path: "a".into(),
            at: "a.conflict-laptop".into(),
        }],
    );
    assert_eq!(r.last_processed, Some(1));
    assert_eq!(applied(&r.index, ME), Some(1));
}

#[test]
fn remove_with_target_adds_tombstone() {
    let remote = idx(
        vec![ent("a", oid(1), 2, OTHER), ent("b", oid(9), 1, OTHER)],
        vec![],
        vec![],
    );
    let r = run(&remote, &[rm(1, "a", oid(1))], &NoChain);
    assert_eq!(heads(&r.index), vec![h("b", oid(9), 1, OTHER)]);
    assert_eq!(tombs(&r.index), vec![("a".into(), oid(1), 2, SEQ)]);
    let t = &r.index.tombstones[0];
    assert_eq!((t.device_id, t.head_sha256), (OTHER, [1; 32]));
    assert_report(&r.report, &[]);
    assert_eq!(r.last_processed, Some(1));
    assert_eq!(applied(&r.index, ME), Some(1));
}

#[test]
fn remove_finds_target_moved_elsewhere() {
    let remote = idx(vec![ent("moved", oid(1), 2, OTHER)], vec![], vec![]);
    let r = run(&remote, &[rm(1, "a", oid(1))], &NoChain);
    assert!(r.index.entries.is_empty());
    assert_eq!(tombs(&r.index), vec![("moved".into(), oid(1), 2, SEQ)]);
    assert_report(&r.report, &[]);
}

#[test]
fn remove_without_target_is_dropped_and_reported() {
    let remote = idx(vec![ent("a", oid(2), 3, OTHER)], vec![], vec![]);
    let r = run(&remote, &[rm(1, "a", oid(1))], &NoChain);
    assert_eq!(heads(&r.index), heads(&remote));
    assert!(r.index.tombstones.is_empty());
    assert_report(&r.report, &[ReportItem::RemoveDropped { path: "a".into() }]);
    assert_eq!(r.last_processed, Some(1));
    assert_eq!(applied(&r.index, ME), Some(1));
}

#[test]
fn move_with_target_to_free_path_moves() {
    let remote = idx(
        vec![ent_x(
            "a",
            oid(1),
            2,
            OTHER,
            vec![floor(2), (CS, vec![1]), (NCS, vec![2])],
        )],
        vec![],
        vec![],
    );
    let r = run(&remote, &[mv(1, "a", "b", oid(1))], &NoChain);
    assert_eq!(heads(&r.index), vec![h("b", oid(1), 2, OTHER)]);
    assert_eq!(
        items(&get(&r.index, "b").ext),
        vec![floor(2), (CS, vec![1])]
    );
    assert_report(&r.report, &[]);
    assert_eq!(r.last_processed, Some(1));
    assert_eq!(applied(&r.index, ME), Some(1));
}

#[test]
fn move_with_target_to_taken_path_goes_to_conflict_path_labelled_with_this_device() {
    let remote = idx(
        vec![ent("a", oid(1), 2, OTHER), ent("b", oid(2), 1, OTHER)],
        vec![],
        vec![],
    );
    let r = run(&remote, &[mv(1, "a", "b", oid(1))], &NoChain);
    // Labelled with this device even though OTHER wrote the moved revision.
    assert_eq!(
        heads(&r.index),
        vec![
            h("b", oid(2), 1, OTHER),
            h("b.conflict-laptop", oid(1), 2, OTHER)
        ]
    );
    assert_eq!(
        items(&get(&r.index, "b.conflict-laptop").ext),
        vec![cof("b")]
    );
    assert_report(
        &r.report,
        &[ReportItem::MovedToConflictPath {
            to: "b".into(),
            at: "b.conflict-laptop".into(),
        }],
    );
    assert_eq!(r.last_processed, Some(1));
    assert_eq!(applied(&r.index, ME), Some(1));
}

#[test]
fn move_without_target_moves_a_descendant_at_from() {
    let remote = idx(vec![ent("a", cid(0xc1, 3), 3, OTHER)], vec![], vec![]);
    let view = Chain::new(Lookup::Missing).chain(0xc1, 3);
    let r = run(&remote, &[mv(1, "a", "b", cid(0xc1, 1))], &view);
    assert_eq!(heads(&r.index), vec![h("b", cid(0xc1, 3), 3, OTHER)]);
    assert_report(&r.report, &[]);
    assert_eq!(r.last_processed, Some(1));
    assert_eq!(applied(&r.index, ME), Some(1));
}

#[test]
fn move_without_target_and_unrelated_entry_at_from_is_dropped() {
    let remote = idx(vec![ent("a", cid(0xc2, 3), 3, OTHER)], vec![], vec![]);
    let view = Chain::new(Lookup::Missing).chain(0xc2, 3);
    let r = run(&remote, &[mv(1, "a", "b", oid(1))], &view);
    assert_eq!(heads(&r.index), heads(&remote));
    assert_report(
        &r.report,
        &[ReportItem::MoveDropped {
            from: "a".into(),
            to: "b".into(),
        }],
    );
    assert_eq!(r.last_processed, Some(1));
    assert_eq!(applied(&r.index, ME), Some(1));
}

#[test]
fn move_without_target_and_empty_from_is_dropped() {
    let remote = idx(vec![ent("c", oid(9), 1, OTHER)], vec![], vec![]);
    let view = Chain::new(Lookup::Missing);
    let r = run(&remote, &[mv(1, "a", "b", oid(1))], &view);
    assert_eq!(view.calls.get(), 0);
    assert_eq!(heads(&r.index), heads(&remote));
    assert_report(
        &r.report,
        &[ReportItem::MoveDropped {
            from: "a".into(),
            to: "b".into(),
        }],
    );
    assert_eq!(r.last_processed, Some(1));
    assert_eq!(applied(&r.index, ME), Some(1));
}

// ---- revision order and conflict paths -------------------------------------------------------

#[test]
fn revision_order_compares_revision_then_device_then_object() {
    let (lo, hi) = ([1; 16], [2; 16]);
    // Revision dominates both IDs, numerically.
    assert_eq!(
        revision_order((10, &lo, &lo), (9, &hi, &hi)),
        Ordering::Greater
    );
    assert_eq!(
        revision_order((2, &hi, &hi), (256, &lo, &lo)),
        Ordering::Less
    );
    // Then device ID, ahead of object ID.
    assert_eq!(
        revision_order((3, &hi, &lo), (3, &lo, &hi)),
        Ordering::Greater
    );
    // Then object ID, as bytes.
    assert_eq!(
        revision_order((3, &lo, &hi), (3, &lo, &lo)),
        Ordering::Greater
    );
    assert_eq!(
        revision_order((3, &lo, &lo), (3, &lo, &lo)),
        Ordering::Equal
    );
}

#[test]
fn conflict_tie_on_revision_and_device_breaks_on_object_id() {
    let remote = idx(vec![ent("a", oid(5), 1, ME)], vec![], vec![]);
    let r = run(&remote, &[put(1, "a", oid(6), 1, ZERO, ME)], &NoChain);
    assert_eq!(
        heads(&r.index),
        vec![h("a", oid(6), 1, ME), h("a.conflict-laptop", oid(5), 1, ME)]
    );
    let r = run(&remote, &[put(1, "a", oid(4), 1, ZERO, ME)], &NoChain);
    assert_eq!(
        heads(&r.index),
        vec![h("a", oid(5), 1, ME), h("a.conflict-laptop", oid(4), 1, ME)]
    );
}

#[test]
fn later_ops_find_the_loser_at_its_conflict_path() {
    let remote = idx(vec![ent("a", oid(1), 3, OTHER)], vec![], vec![]);
    let ops = [
        put(1, "a", oid(2), 1, ZERO, ME),
        put(2, "a", oid(3), 2, oid(2), ME),
        mv(3, "a", "b", oid(3)),
        put(4, "b", oid(4), 3, oid(3), ME),
    ];
    let r = run(&remote, &ops, &NoChain);
    assert_eq!(
        heads(&r.index),
        vec![h("a", oid(1), 3, OTHER), h("b", oid(4), 3, ME)]
    );
    // The edit and the move kept the conflict copy's mark.
    assert_eq!(items(&get(&r.index, "b").ext), vec![cof("a")]);
    assert_report(&r.report, &[conflict("a", "a.conflict-laptop", ME)]);
    assert_eq!(r.last_processed, Some(4));

    // A removal of the loser follows it too, and a tombstone never carries conflict-of.
    let ops = [put(1, "a", oid(2), 1, ZERO, ME), rm(2, "a", oid(2))];
    let r = run(&remote, &ops, &NoChain);
    assert_eq!(heads(&r.index), vec![h("a", oid(1), 3, OTHER)]);
    assert_eq!(
        tombs(&r.index),
        vec![("a.conflict-laptop".into(), oid(2), 1, SEQ)]
    );
    assert!(r.index.tombstones[0].ext.items.is_empty());
}

#[test]
fn unenrolled_writer_is_labelled_by_eight_hex_characters() {
    assert_eq!(conflict_label(&labels(), &GONE), "01234567");
    assert_eq!(conflict_label(&labels(), &OTHER), "phone");
    let remote = idx(vec![ent("a", oid(1), 1, GONE)], vec![], vec![]);
    let r = run(&remote, &[put(1, "a", oid(2), 1, ZERO, ME)], &NoChain);
    assert_eq!(
        heads(&r.index),
        vec![
            h("a", oid(2), 1, ME),
            h("a.conflict-01234567", oid(1), 1, GONE)
        ]
    );
    assert_report(&r.report, &[conflict("a", "a.conflict-01234567", GONE)]);
}

#[test]
fn taken_conflict_paths_get_numbered_suffixes() {
    assert_eq!(
        conflict_path("d/a", "laptop", &oid(1), |_| false),
        "d/a.conflict-laptop"
    );
    assert_eq!(
        conflict_path("d/a", "laptop", &oid(1), |p| p == "d/a.conflict-laptop"),
        "d/a.conflict-laptop-2"
    );
    let remote = idx(
        vec![
            ent("a", oid(1), 3, OTHER),
            ent("a.conflict-laptop", oid(7), 1, OTHER),
            ent("a.conflict-laptop-2", oid(8), 1, OTHER),
        ],
        vec![],
        vec![],
    );
    let r = run(&remote, &[put(1, "a", oid(2), 1, ZERO, ME)], &NoChain);
    assert_eq!(get(&r.index, "a.conflict-laptop-3").head_object_id, oid(2));
    assert_report(&r.report, &[conflict("a", "a.conflict-laptop-3", ME)]);
}

#[test]
fn conflict_path_fills_exactly_1024_bytes_without_truncating() {
    let path = "a".repeat(1008);
    let got = conflict_path(&path, "laptop", &oid(1), |_| false);
    assert_eq!(got, format!("{path}.conflict-laptop"));
    assert_eq!(got.len(), 1024);
    let longer = "a".repeat(1009);
    let got = conflict_path(&longer, "laptop", &oid(1), |_| false);
    assert_eq!(got, format!("{path}.conflict-laptop"));
}

#[test]
fn conflict_path_truncates_last_segment_at_a_char_boundary() {
    // One ASCII byte, then two-byte characters, so even offsets fall inside a character.
    let last = format!("x{}", "é".repeat(510));
    let path = format!("d/{last}");
    assert!(is_valid_path(&path));
    let first = conflict_path(&path, "laptop", &oid(1), |_| false);
    // 1,024 - 2 - 16 = 1,006 bytes of room, which splits an é; the cut backs off to 1,005.
    assert_eq!(first, format!("d/{}.conflict-laptop", &last[..1005]));
    assert!(is_valid_path(&first));
    // The numbered suffix is tried again on a form truncated to fit it.
    let second = conflict_path(&path, "laptop", &oid(1), |p| p == first);
    assert_eq!(second, format!("d/{}.conflict-laptop-2", &last[..1003]));
    assert!(is_valid_path(&second));

    // Through replay the copy lands at the truncated path and the index seals.
    let remote = idx(vec![ent(&path, oid(1), 3, OTHER)], vec![], vec![]);
    let r = run(&remote, &[put(1, &path, oid(2), 1, ZERO, ME)], &NoChain);
    assert_eq!(get(&r.index, &first).head_object_id, oid(2));
    assert_eq!(items(&get(&r.index, &first).ext), vec![cof(&path)]);
}

#[test]
fn conflict_path_keeps_one_char_when_only_one_fits() {
    // Room for exactly one character of a four-byte last segment character.
    let parent = format!("{}/", "p".repeat(1003));
    let path = format!("{parent}😀😀");
    assert!(is_valid_path(&path));
    let got = conflict_path(&path, "laptop", &oid(1), |_| false);
    assert_eq!(got, format!("{parent}😀.conflict-laptop"));
    assert_eq!(got.len(), 1024);
}

#[test]
fn conflict_path_is_valid_whenever_one_character_fits() {
    let mut checked = 0;
    for label in ["laptop", "01234567", &"z".repeat(32)] {
        for ch in ["q", "é", "😀"] {
            for k in 1..1022 {
                let parent = format!("{}/", "p".repeat(k));
                // The longest suffix tried below is `-3`; past that the fallback applies.
                let suffix_len = ".conflict-".len() + label.len() + 2;
                if parent.len() + ch.len() + suffix_len > 1024 {
                    continue;
                }
                // The longest last segment of whole characters that keeps the path valid.
                let path = format!("{parent}{}", ch.repeat((1024 - parent.len()) / ch.len()));
                assert!(is_valid_path(&path));
                for taken in 0..3 {
                    let got = conflict_path(&path, label, &oid(1), |p| {
                        (taken > 0 && p.ends_with(&format!(".conflict-{label}")))
                            || (taken > 1 && p.ends_with(&format!(".conflict-{label}-2")))
                    });
                    assert!(is_valid_path(&got), "{} bytes", got.len());
                    assert!(got.starts_with(&parent));
                    assert!(got.contains(&format!(".conflict-{label}")));
                    checked += 1;
                }
            }
        }
    }
    assert!(checked > 1000);
}

#[test]
fn conflict_path_fallback_follows_the_spec_form() {
    let parent = format!("{}/", "p".repeat(1010));
    let path = format!("{parent}abc");
    assert!(is_valid_path(&path));
    assert_eq!(
        conflict_path(&path, "laptop", &oid(1), |_| false),
        "0b010000.conflict-laptop"
    );
    assert_eq!(
        conflict_path(&path, "laptop", &oid(1), |p| p.ends_with("-laptop")),
        "0b010000.conflict-laptop-2"
    );
}

#[test]
fn conflict_path_fallback_is_a_valid_path() {
    // The fallback applies only when parent + one character + suffix exceeds 1,024 bytes, so it
    // drops the parent and goes to the top level, where it always fits.
    let parent = format!("{}/", "p".repeat(1010));
    let path = format!("{parent}abc");
    let got = conflict_path(&path, "laptop", &oid(1), |_| false);
    assert!(is_valid_path(&got), "{} bytes", got.len());

    // A numbered suffix reaches the fallback too: one character fits beside `.conflict-laptop`
    // but not beside `.conflict-laptop-2`.
    let parent = format!("{}/", "p".repeat(1006));
    let short = format!("{parent}q");
    assert_eq!(
        conflict_path(&short, "laptop", &oid(1), |_| false).len(),
        1024
    );
    let got = conflict_path(&short, "laptop", &oid(1), |p| p.ends_with("-laptop"));
    assert!(is_valid_path(&got), "{} bytes", got.len());

    let remote = idx(vec![ent(&path, oid(1), 3, OTHER)], vec![], vec![]);
    run(&remote, &[put(1, &path, oid(2), 1, ZERO, ME)], &NoChain);
}

// ---- extension items -------------------------------------------------------------------------

#[test]
fn loser_that_is_already_a_conflict_copy_keeps_its_conflict_of() {
    let remote = idx(
        vec![ent_x("x", oid(1), 1, OTHER, vec![cof("orig")])],
        vec![],
        vec![],
    );
    let r = run(&remote, &[put(1, "x", oid(2), 1, ZERO, ME)], &NoChain);
    assert_eq!(
        heads(&r.index),
        vec![
            h("x", oid(2), 1, ME),
            h("x.conflict-phone", oid(1), 1, OTHER)
        ]
    );
    assert_eq!(
        items(&get(&r.index, "x.conflict-phone").ext),
        vec![cof("orig")]
    );
    assert_report(&r.report, &[conflict("x", "x.conflict-phone", OTHER)]);
}

#[test]
fn history_floor_goes_to_the_tombstone_and_back_on_edit_wins_over_delete() {
    let remote = idx(
        vec![ent_x(
            "a",
            oid(1),
            4,
            OTHER,
            vec![cof("z"), floor(3), (CS, vec![1]), (NCS, vec![2])],
        )],
        vec![],
        vec![],
    );
    let r = run(&remote, &[rm(1, "a", oid(1))], &NoChain);
    assert_eq!(tombs(&r.index), vec![("a".into(), oid(1), 4, SEQ)]);
    assert_eq!(
        items(&r.index.tombstones[0].ext),
        vec![floor(3), (CS, vec![1])]
    );

    let ops = [rm(1, "a", oid(1)), put(2, "a", oid(2), 5, oid(1), ME)];
    let r = run(&remote, &ops, &NoChain);
    assert_eq!(heads(&r.index), vec![h("a", oid(2), 5, ME)]);
    assert_eq!(
        items(&get(&r.index, "a").ext),
        vec![floor(3), (CS, vec![1])]
    );
    assert_eq!(tombs(&r.index), vec![("a".into(), oid(1), 4, SEQ)]);
    assert_report(
        &r.report,
        &[ReportItem::EditWonOverDelete {
            path: "a".into(),
            at: "a".into(),
        }],
    );
}

#[test]
fn history_floor_above_winner_revision_is_dropped() {
    // A floor above the record's own revision cannot come from a decoded index, so the branch is
    // reached here only with a hand-built remote; the winner must not carry it.
    let remote = idx(
        vec![ent_x("a", cid(0xc1, 2), 2, OTHER, vec![floor(3)])],
        vec![],
        vec![],
    );
    let view = Chain::new(Lookup::Missing).chain(0xc1, 2);
    let r = done(attempt(
        &remote,
        &[put(1, "a", oid(2), 2, cid(0xc1, 1), ME)],
        &view,
        SEQ,
    ));
    assert_eq!(get(&r.index, "a").head_object_id, oid(2));
    assert!(get(&r.index, "a").ext.history_floor().is_none());
}

#[test]
fn concurrent_edit_of_a_conflict_copy_keeps_the_mark_on_both_sides() {
    let remote = idx(
        vec![ent_x(
            "a.conflict-phone",
            cid(0xc1, 2),
            2,
            OTHER,
            vec![cof("a"), (CS, vec![1])],
        )],
        vec![],
        vec![],
    );
    let view = Chain::new(Lookup::Missing).chain(0xc1, 2);
    let ops = [put(1, "a.conflict-phone", oid(2), 2, cid(0xc1, 1), ME)];
    let r = run(&remote, &ops, &view);
    // The winner is a new head of the copy and keeps its mark; the loser keeps its first original
    // rather than naming the copy's path.
    assert_eq!(
        heads(&r.index),
        vec![
            h("a.conflict-phone", oid(2), 2, ME),
            h("a.conflict-phone.conflict-phone", cid(0xc1, 2), 2, OTHER)
        ]
    );
    assert_eq!(
        items(&get(&r.index, "a.conflict-phone").ext),
        vec![cof("a"), (CS, vec![1])]
    );
    assert_eq!(
        items(&get(&r.index, "a.conflict-phone.conflict-phone").ext),
        vec![cof("a"), (CS, vec![1])]
    );

    // Moving the winner onto its free original clears the mark.
    let ops = [ops[0].clone(), mv(2, "a.conflict-phone", "a", oid(2))];
    let r = run(&remote, &ops, &view);
    assert_eq!(items(&get(&r.index, "a").ext), vec![(CS, vec![1])]);
}

#[test]
fn moving_a_conflict_copy_onto_its_free_original_drops_conflict_of() {
    let remote = idx(
        vec![ent_x(
            "a.conflict-phone",
            oid(1),
            1,
            OTHER,
            vec![cof("a"), (CS, vec![1]), (NCS, vec![2])],
        )],
        vec![],
        vec![],
    );
    let r = run(&remote, &[mv(1, "a.conflict-phone", "a", oid(1))], &NoChain);
    assert_eq!(heads(&r.index), vec![h("a", oid(1), 1, OTHER)]);
    assert_eq!(items(&get(&r.index, "a").ext), vec![(CS, vec![1])]);

    // Moved anywhere else it stays a conflict copy.
    let r = run(&remote, &[mv(1, "a.conflict-phone", "c", oid(1))], &NoChain);
    assert_eq!(
        items(&get(&r.index, "c").ext),
        vec![cof("a"), (CS, vec![1])]
    );
}

#[test]
fn untouched_records_keep_every_ext_item() {
    let remote = idx(
        vec![
            ent_x("a", oid(1), 2, OTHER, vec![(NCS, vec![1]), floor(2)]),
            ent("b", oid(2), 1, OTHER),
        ],
        vec![tomb("t", oid(3), 2, 1, vec![(NCS, vec![2]), floor(2)])],
        vec![],
    );
    let r = run(&remote, &[put(1, "b", oid(4), 2, oid(2), ME)], &NoChain);
    assert!(r.index.entries[0] == remote.entries[0]);
    assert!(r.index.tombstones == remote.tombstones);
}

// ---- skips, restarts, and bounds -------------------------------------------------------------

#[test]
fn ops_at_or_below_applied_are_skipped() {
    let remote = idx(
        vec![ent("x", oid(1), 2, OTHER)],
        vec![],
        vec![(ME, 5), (OTHER, 9)],
    );
    let ops = [
        put(4, "z", oid(2), 1, ZERO, ME),
        rm(5, "x", oid(1)),
        put(6, "a", oid(3), 1, ZERO, ME),
    ];
    let r = run(&remote, &ops, &NoChain);
    assert_eq!(
        heads(&r.index),
        vec![h("a", oid(3), 1, ME), h("x", oid(1), 2, OTHER)]
    );
    assert!(r.index.tombstones.is_empty());
    assert_eq!(r.last_processed, Some(6));
    assert_eq!(applied(&r.index, ME), Some(6));
    assert_eq!(applied(&r.index, OTHER), Some(9));

    let r = run(&remote, &ops[..2], &NoChain);
    assert_eq!(r.last_processed, None);
    assert!(r.index == rewritten(&remote));
    assert_report(&r.report, &[]);
}

#[test]
fn put_whose_object_is_already_a_head_or_tombstone_head_is_skipped() {
    let remote = idx(
        vec![ent("a", oid(1), 1, ME)],
        vec![tomb("b", oid(2), 2, 1, vec![])],
        vec![],
    );
    // A publish whose response was lost: the same puts again.
    let ops = [
        put(1, "a", oid(1), 1, ZERO, ME),
        put(2, "b", oid(2), 2, oid(9), ME),
    ];
    let r = run(&remote, &ops, &NoChain);
    let mut want = rewritten(&remote);
    want.applied = vec![Applied {
        device_id: ME,
        last_op_seq: 2,
    }];
    assert!(r.index == want);
    assert_report(&r.report, &[]);
    assert_eq!(r.last_processed, Some(2));
}

#[test]
fn applied_counts_dropped_ops() {
    let remote = idx(vec![], vec![], vec![(ME, 2)]);
    let ops = [
        put(3, "a", oid(1), 1, ZERO, ME),
        rm(4, "x", oid(8)),
        mv(5, "y", "z", oid(9)),
    ];
    let r = run(&remote, &ops, &NoChain);
    assert_eq!(r.last_processed, Some(5));
    assert_eq!(applied(&r.index, ME), Some(5));
    assert_report(
        &r.report,
        &[
            ReportItem::RemoveDropped { path: "x".into() },
            ReportItem::MoveDropped {
                from: "y".into(),
                to: "z".into(),
            },
        ],
    );
}

#[test]
fn missing_link_returns_need_and_replay_finishes_once_fed() {
    let remote = idx(vec![ent("a", cid(0xc1, 3), 3, OTHER)], vec![], vec![]);
    let full = Chain::new(Lookup::Missing).chain(0xc1, 3);
    let ops = [put(1, "a", oid(2), 2, cid(0xc1, 1), ME)];
    let view = Chain::new(Lookup::Missing);
    let mut asked = vec![];
    let r = loop {
        match attempt(&remote, &ops, &view, SEQ) {
            ReplayOutcome::Done(r) => break r,
            ReplayOutcome::Need(id) => {
                asked.push(id);
                view.feed(id, full.lookup(&id));
            }
        }
    };
    assert_eq!(asked, vec![cid(0xc1, 3), cid(0xc1, 2)]);
    assert_report(&r.report, &[conflict("a", "a.conflict-laptop", ME)]);
    assert!(sealed(&r.index).unwrap() == r.index);
}

#[test]
fn missing_link_in_a_move_walk_returns_need() {
    let remote = idx(vec![ent("a", cid(0xc1, 3), 3, OTHER)], vec![], vec![]);
    let view = Chain::new(Lookup::Missing).link(cid(0xc1, 3), cid(0xc1, 2), 3);
    let ops = [mv(1, "a", "b", cid(0xc1, 1))];
    match attempt(&remote, &ops, &view, SEQ) {
        ReplayOutcome::Need(id) => assert_eq!(id, cid(0xc1, 2)),
        ReplayOutcome::Done(_) => panic!("expected Need"),
    }
    view.feed(
        cid(0xc1, 2),
        Lookup::Known {
            parent: cid(0xc1, 1),
            revision: 2,
        },
    );
    let r = run(&remote, &ops, &view);
    assert_eq!(heads(&r.index), vec![h("b", cid(0xc1, 3), 3, OTHER)]);
}

#[test]
fn unavailable_walk_in_a_put_is_a_concurrent_edit() {
    // The parent is unrelated to the head at the path, but the walk cannot tell: conflict, not
    // "inserted without target".
    let remote = idx(vec![ent("a", oid(1), 3, OTHER)], vec![], vec![]);
    let r = run(&remote, &[put(1, "a", oid(2), 2, oid(9), ME)], &NoChain);
    assert_eq!(
        heads(&r.index),
        vec![
            h("a", oid(1), 3, OTHER),
            h("a.conflict-laptop", oid(2), 2, ME)
        ]
    );
    assert_report(&r.report, &[conflict("a", "a.conflict-laptop", ME)]);
}

#[test]
fn unavailable_walk_in_a_move_drops_the_move() {
    // The spec's "a walk that cannot complete ... treats the case as a concurrent edit" is written
    // for `put`; for `move` the implementation drops rather than moving an entry it cannot relate.
    let remote = idx(vec![ent("a", oid(1), 3, OTHER)], vec![], vec![]);
    let r = run(&remote, &[mv(1, "a", "b", oid(9))], &NoChain);
    assert_eq!(heads(&r.index), heads(&remote));
    assert_report(
        &r.report,
        &[ReportItem::MoveDropped {
            from: "a".into(),
            to: "b".into(),
        }],
    );
}

#[test]
fn put_walk_longer_than_max_walk_is_a_concurrent_edit_without_lookups() {
    let remote = idx(vec![ent("a", oid(1), MAX_WALK + 2, OTHER)], vec![], vec![]);
    let view = Chain::new(Lookup::Missing);
    // Parent at revision 1: a gap of MAX_WALK + 1.
    let r = run(&remote, &[put(1, "a", oid(2), 2, oid(9), ME)], &view);
    assert_eq!(view.calls.get(), 0);
    assert_report(&r.report, &[conflict("a", "a.conflict-laptop", ME)]);

    // A gap of exactly MAX_WALK is walked.
    let remote = idx(vec![ent("a", oid(1), MAX_WALK + 1, OTHER)], vec![], vec![]);
    match attempt(&remote, &[put(1, "a", oid(2), 2, oid(9), ME)], &view, SEQ) {
        ReplayOutcome::Need(id) => assert_eq!(id, oid(1)),
        ReplayOutcome::Done(_) => panic!("expected Need"),
    }
}

#[test]
fn move_walk_stops_at_max_walk() {
    let top = MAX_WALK + 10;
    let view = Chain::new(Lookup::Missing).chain(0xc3, top);
    let remote = idx(vec![ent("a", cid(0xc3, top), top, OTHER)], vec![], vec![]);

    // Exactly MAX_WALK steps back is found.
    let r = run(
        &remote,
        &[mv(1, "a", "b", cid(0xc3, top - MAX_WALK))],
        &view,
    );
    assert_eq!(heads(&r.index), vec![h("b", cid(0xc3, top), top, OTHER)]);

    // One further is not looked for.
    view.calls.set(0);
    let r = run(
        &remote,
        &[mv(1, "a", "b", cid(0xc3, top - MAX_WALK - 1))],
        &view,
    );
    assert_eq!(view.calls.get() as u64, MAX_WALK);
    assert_eq!(heads(&r.index), heads(&remote));
    assert_report(
        &r.report,
        &[ReportItem::MoveDropped {
            from: "a".into(),
            to: "b".into(),
        }],
    );
}

#[test]
fn second_tombstone_for_one_path_defers_the_rest() {
    let remote = idx(vec![ent("a", oid(1), 2, OTHER)], vec![], vec![]);
    let ops = [
        rm(1, "a", oid(1)),
        put(2, "a", oid(2), 1, ZERO, ME),
        rm(3, "a", oid(2)),
        put(4, "b", oid(3), 1, ZERO, ME),
    ];
    let r = run(&remote, &ops, &NoChain);
    assert_eq!(r.deferred, 2);
    assert_eq!(r.last_processed, Some(2));
    assert_eq!(applied(&r.index, ME), Some(2));
    assert_eq!(heads(&r.index), vec![h("a", oid(2), 1, ME)]);
    assert_eq!(tombs(&r.index), vec![("a".into(), oid(1), 2, SEQ)]);

    // The next publish, on the published index, finishes the queue.
    let r2 = done(attempt(&r.index, &ops, &NoChain, SEQ + 1));
    assert_eq!(r2.deferred, 0);
    assert_eq!(r2.last_processed, Some(4));
    assert_eq!(heads(&r2.index), vec![h("b", oid(3), 1, ME)]);
    assert_eq!(
        tombs(&r2.index),
        vec![
            ("a".into(), oid(1), 2, SEQ),
            ("a".into(), oid(2), 1, SEQ + 1)
        ]
    );
    assert!(sealed(&r2.index).unwrap() == r2.index);
}

// ---- properties ------------------------------------------------------------------------------

/// Paths chosen to collide with each other and with conflict paths.
const PATHS: &[&str] = &[
    "a",
    "b",
    "d/e",
    "d/f",
    "a.conflict-laptop",
    "a.conflict-phone",
    "b.conflict-01234567",
];
const DEVICES: [[u8; 16]; 3] = [ME, OTHER, GONE];

#[derive(Debug, Clone)]
struct Scenario {
    remote: IndexPlain,
    ops: Vec<Op>,
    links: HashMap<[u8; 16], Lookup>,
}

fn gid(tag: u8, i: usize, rev: u64) -> [u8; 16] {
    let mut a = [0; 16];
    a[0] = tag;
    a[1] = i as u8;
    a[2..10].copy_from_slice(&rev.to_be_bytes());
    a
}

type EntryChoice = (usize, u64, usize, u8);
type TombChoice = (usize, u64, u8);
type OpChoice = (u8, u8, u8, u8);

fn build(
    entry_choices: Vec<EntryChoice>,
    tomb_choices: Vec<TombChoice>,
    applied_me: u64,
    op_choices: Vec<OpChoice>,
) -> Scenario {
    let mut links = HashMap::new();
    // Every object an operation may name, with its revision.
    let mut known: Vec<([u8; 16], u64)> = vec![];
    let mut entries = vec![];
    let mut seen = BTreeSet::new();
    for (i, (p, rev, dev, flags)) in entry_choices.into_iter().enumerate() {
        let path = PATHS[p];
        if !seen.insert(path) {
            continue;
        }
        let head = gid(0x10, i, rev);
        let anc = |r: u64| if r == 0 { ZERO } else { gid(0x20, i, r) };
        if flags & 8 == 0 {
            links.insert(
                head,
                Lookup::Known {
                    parent: anc(rev - 1),
                    revision: rev,
                },
            );
            for r in 1..rev {
                links.insert(
                    anc(r),
                    Lookup::Known {
                        parent: anc(r - 1),
                        revision: r,
                    },
                );
            }
        }
        for r in 1..rev {
            known.push((anc(r), r));
        }
        known.push((head, rev));
        let mut x = vec![];
        if flags & 1 != 0 && rev >= 2 {
            x.push(floor(2));
        }
        if flags & 2 != 0 {
            x.push((CS, vec![i as u8]));
        }
        if flags & 4 != 0 {
            x.push((NCS, vec![1]));
        }
        if flags & 16 != 0 {
            x.push(cof(if path == "a" { "b" } else { "a" }));
        }
        entries.push(ent_x(path, head, rev, DEVICES[dev], x));
    }
    let mut tombstones = vec![];
    for (j, (p, rev, flags)) in tomb_choices.into_iter().enumerate() {
        let head = gid(0x30, j, rev);
        known.push((head, rev));
        let mut x = vec![];
        if flags & 1 != 0 && rev >= 2 {
            x.push(floor(2));
        }
        if flags & 2 != 0 {
            x.push((CS, vec![j as u8]));
        }
        tombstones.push(tomb(PATHS[p], head, rev, j as u64 + 1, x));
    }
    let mut applied = vec![(OTHER, 7)];
    if applied_me > 0 {
        applied.push((ME, applied_me));
    }
    let remote = idx(entries, tombstones, applied);

    let pick = |known: &[([u8; 16], u64)], n: usize, x: u8, z: u8| {
        if known.is_empty() || z.is_multiple_of(7) {
            (gid(0x50, n, 0), 1 + u64::from(x % 4))
        } else {
            known[x as usize % known.len()]
        }
    };
    let mut ops = vec![];
    for (n, (kind, x, y, z)) in op_choices.into_iter().enumerate() {
        let seq = n as u64 + 1;
        let path = PATHS[y as usize % PATHS.len()];
        match kind % 10 {
            0 | 1 => {
                let obj = gid(0x40, n, 1);
                links.insert(
                    obj,
                    Lookup::Known {
                        parent: ZERO,
                        revision: 1,
                    },
                );
                known.push((obj, 1));
                ops.push(put(seq, path, obj, 1, ZERO, ME));
            }
            2..=4 => {
                let (parent, prev) = pick(&known, n, x, z);
                let rev = prev + 1;
                let obj = gid(0x40, n, rev);
                links.insert(
                    obj,
                    Lookup::Known {
                        parent,
                        revision: rev,
                    },
                );
                known.push((obj, rev));
                ops.push(put(seq, path, obj, rev, parent, ME));
            }
            5 => {
                // A retried put of an object that may already be published.
                let (obj, rev) = pick(&known, n, x, z);
                ops.push(put(seq, path, obj, rev, ZERO, ME));
            }
            6 | 7 => ops.push(rm(seq, path, pick(&known, n, x, z).0)),
            _ => {
                let to = PATHS[z as usize % PATHS.len()];
                ops.push(mv(seq, path, to, pick(&known, n, x, z).0));
            }
        }
    }
    Scenario { remote, ops, links }
}

prop_compose! {
    fn scenario()(
        entry_choices in vec((0..PATHS.len(), 1u64..6, 0..DEVICES.len(), 0u8..32), 0..6),
        tomb_choices in vec((0..PATHS.len(), 1u64..6, 0u8..4), 0..3),
        applied_me in 0u64..3,
        op_choices in vec(any::<OpChoice>(), 0..10),
    ) -> Scenario {
        build(entry_choices, tomb_choices, applied_me, op_choices)
    }
}

fn replay_all(s: &Scenario, remote: &IndexPlain, seq: u64) -> ReplayResult {
    let view = Chain::with(s.links.clone(), Lookup::Unavailable);
    done(attempt(remote, &s.ops, &view, seq))
}

proptest! {
    #[test]
    fn replay_result_seals_and_reopens(s in scenario()) {
        let r = replay_all(&s, &s.remote, SEQ);
        let back = sealed(&r.index);
        prop_assert!(back.is_ok(), "{:?}", back.err());
        prop_assert!(back.unwrap() == r.index);
    }

    #[test]
    fn replay_loses_no_revision(s in scenario()) {
        let r = replay_all(&s, &s.remote, SEQ);
        let after: HashSet<[u8; 16]> = r.index.entries.iter().map(|e| e.head_object_id)
            .chain(r.index.tombstones.iter().map(|t| t.head_object_id))
            .collect();
        let applied_me = applied(&s.remote, ME).unwrap_or(0);
        let processed: Vec<&PutOp> = s.ops[..s.ops.len() - r.deferred]
            .iter()
            .filter(|o| o.op_seq() > applied_me)
            .filter_map(|o| match o { Op::Put(p) => Some(p), _ => None })
            .collect();
        // An object survives if it is a head or tombstone head of the result, or if a processed
        // put names it as parent and that put's object survives: an edit replaces its parent, but
        // the edit itself must not vanish with it.
        fn survives(
            id: [u8; 16],
            after: &HashSet<[u8; 16]>,
            processed: &[&PutOp],
            seen: &mut HashSet<[u8; 16]>,
        ) -> bool {
            if after.contains(&id) {
                return true;
            }
            if id == ZERO || !seen.insert(id) {
                return false;
            }
            processed
                .iter()
                .filter(|p| p.parent_object_id == id)
                .any(|p| survives(p.object_id, after, processed, seen))
        }
        let must_keep = s.remote.entries.iter().map(|e| e.head_object_id)
            .chain(s.remote.tombstones.iter().map(|t| t.head_object_id))
            .chain(processed.iter().map(|p| p.object_id));
        for id in must_keep {
            prop_assert!(
                survives(id, &after, &processed, &mut HashSet::new()),
                "lost {}", hex::encode(id)
            );
        }
    }

    #[test]
    fn replay_is_deterministic(s in scenario()) {
        let a = replay_all(&s, &s.remote, SEQ);
        let b = replay_all(&s, &s.remote, SEQ);
        prop_assert!(a.index == b.index);
        prop_assert_eq!(&a.report, &b.report);
        prop_assert_eq!(a.last_processed, b.last_processed);
        prop_assert_eq!(a.deferred, b.deferred);
    }

    #[test]
    fn replay_is_idempotent(s in scenario()) {
        let first = replay_all(&s, &s.remote, SEQ);
        prop_assume!(first.deferred == 0);
        let again = replay_all(&s, &first.index, SEQ + 1);
        prop_assert!(again.index == first.index);
        prop_assert!(again.report.is_empty());
        prop_assert_eq!(again.last_processed, None);
        prop_assert_eq!(again.deferred, 0);
    }

    #[test]
    fn replay_never_lowers_applied(s in scenario()) {
        let r = replay_all(&s, &s.remote, SEQ);
        for a in &s.remote.applied {
            let now = applied(&r.index, a.device_id);
            if a.device_id == ME {
                prop_assert_eq!(now, Some(a.last_op_seq.max(r.last_processed.unwrap_or(0))));
            } else {
                prop_assert_eq!(now, Some(a.last_op_seq));
            }
        }
        if let Some(last) = r.last_processed {
            prop_assert!(applied(&r.index, ME) >= Some(last));
        }
    }

    #[test]
    fn replay_restarts_after_need_to_the_same_result(s in scenario()) {
        let full = Chain::with(s.links.clone(), Lookup::Unavailable);
        let want = replay_all(&s, &s.remote, SEQ);
        let view = Chain::new(Lookup::Missing);
        let mut rounds = 0;
        let got = loop {
            match attempt(&s.remote, &s.ops, &view, SEQ) {
                ReplayOutcome::Done(r) => break r,
                ReplayOutcome::Need(id) => {
                    view.feed(id, full.lookup(&id));
                    rounds += 1;
                    prop_assert!(rounds < 1000);
                }
            }
        };
        prop_assert!(got.index == want.index);
        prop_assert_eq!(&got.report, &want.report);
        prop_assert_eq!(got.last_processed, want.last_processed);
        prop_assert_eq!(got.deferred, want.deferred);
    }
}
