//! Property tests of the mirror state and the sync engine: the sealed `state` round trip over
//! random states, and convergence of several devices that edit and sync in random interleavings.

use super::sync::{Fx, World};
use crate::header::{RotationCommitment, VaultKeys, parse_header};
use crate::mirror_state::{
    HistoryMode, MirrorState, ObjectMeta, PublishFailure, StoredNotice, open_state, seal_state,
};
use crate::notice::{Notice, ObjectKind};
use crate::ops::{MoveOp, Op, PutOp, RemoveOp};
use crate::pins::{HeaderPin, IndexPin, OwnRecord, OwnRecords};
use crate::vault::find;
use proptest::collection::{btree_map, vec};
use proptest::prelude::*;
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

/// Section tags the state serialisation uses; `other` sections must avoid them.
const KNOWN_TAGS: u16 = 8;
const CAP: u64 = crate::limits::COUNTER_CAP;

/// The keys of a fixed one-device vault, built once: the state only needs `K_mirror`.
fn keys() -> &'static (VaultKeys, [u8; 16]) {
    static KEYS: OnceLock<(VaultKeys, [u8; 16])> = OnceLock::new();
    KEYS.get_or_init(|| {
        let fx = Fx::new(1);
        let h = fx.header(1, 1, 0, RotationCommitment::default(), &[0]);
        let (_, k) = parse_header(&h)
            .unwrap()
            .unlock_with_device(&fx.devs[0].id, &fx.devs[0].secrets)
            .unwrap();
        (k, fx.vault_id)
    })
}

fn path() -> impl Strategy<Value = String> {
    "[A-Za-z0-9._é-]{1,8}(/[A-Za-z0-9 ü-]{1,8}){0,2}"
        .prop_filter("path rules", |p| crate::path::is_valid_path(p))
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        (
            1..=CAP,
            path(),
            any::<[u8; 16]>(),
            any::<[u8; 32]>(),
            1..=CAP,
            any::<[u8; 16]>(),
            any::<[u8; 16]>(),
            any::<[u8; 16]>(),
            any::<u32>(),
            any::<bool>(),
        )
            .prop_map(
                |(op_seq, path, oid, sha, rev, parent, dev, vid, epoch, up)| {
                    Op::Put(PutOp {
                        op_seq,
                        path,
                        object_id: oid,
                        object_sha256: sha,
                        revision: rev,
                        parent_object_id: parent,
                        device_id: dev,
                        entry_vault_id: vid,
                        entry_epoch: epoch,
                        uploaded: up,
                    })
                }
            ),
        (1..=CAP, path(), any::<[u8; 16]>()).prop_map(|(op_seq, path, expected_head)| {
            Op::Remove(RemoveOp {
                op_seq,
                path,
                expected_head,
            })
        }),
        (1..=CAP, path(), path(), any::<[u8; 16]>()).prop_map(
            |(op_seq, from, to, expected_head)| Op::Move(MoveOp {
                op_seq,
                from,
                to,
                expected_head,
            })
        ),
    ]
}

fn kind() -> impl Strategy<Value = ObjectKind> {
    prop_oneof![Just(ObjectKind::Header), Just(ObjectKind::Index)]
}

fn notice() -> impl Strategy<Value = Notice> {
    prop_oneof![
        (any::<[u8; 16]>(), any::<u32>())
            .prop_map(|(writer, epoch)| Notice::VaultKeyChanged { writer, epoch }),
        (kind(), any::<[u8; 16]>(), any::<u64>(), any::<u64>()).prop_map(
            |(kind, writer, from, to)| Notice::CounterJump {
                kind,
                writer,
                from,
                to
            }
        ),
        (kind(), any::<[u8; 16]>())
            .prop_map(|(kind, writer)| Notice::UnenrolledWriter { kind, writer }),
        (kind(), any::<u64>()).prop_map(|(kind, seq)| Notice::OwnWriteUnverified { kind, seq }),
        (any::<[u8; 16]>(), any::<u64>()).prop_map(|(writer, next_op_seq)| {
            Notice::OpSeqRaised {
                writer,
                next_op_seq,
            }
        }),
    ]
}

fn stored_notice() -> impl Strategy<Value = StoredNotice> {
    (notice(), any::<i64>(), any::<bool>()).prop_map(|(notice, unix, read)| StoredNotice {
        notice,
        unix,
        read,
    })
}

fn records() -> impl Strategy<Value = Vec<OwnRecord>> {
    vec(
        (0..=CAP, any::<[u8; 32]>(), any::<i64>()).prop_map(|(seq, sha256, unix)| OwnRecord {
            seq,
            sha256,
            unix,
        }),
        0..4,
    )
}

/// Objects sorted and unique by ID, as the state keeps them.
fn objects() -> impl Strategy<Value = Vec<ObjectMeta>> {
    btree_map(
        any::<[u8; 16]>(),
        (
            any::<[u8; 16]>(),
            any::<[u8; 32]>(),
            0..=CAP,
            any::<[i64; 3]>(),
            any::<[bool; 3]>(),
        ),
        0..5,
    )
    .prop_map(|m| {
        m.into_iter()
            .map(
                |(object_id, (parent, parent_sha256, revision, t, f))| ObjectMeta {
                    object_id,
                    parent,
                    parent_sha256,
                    revision,
                    published_unix: t[0],
                    displayed_unix: t[1],
                    unreachable_since: t[2],
                    purged: f[0],
                    local_only: f[1],
                    gone_checked: f[2],
                },
            )
            .collect()
    })
}

fn etag() -> impl Strategy<Value = Option<String>> {
    proptest::option::of("\"[0-9a-f]{0,32}\"")
}

prop_compose! {
    fn header_pin()(
        epoch in any::<u32>(),
        fingerprint in any::<[u8; 32]>(),
        header_seq in 0..=CAP,
        header_sha256 in any::<[u8; 32]>(),
        legacy_sha256 in any::<[u8; 32]>(),
        devices in vec(any::<[u8; 16]>(), 0..4),
    ) -> HeaderPin {
        HeaderPin {
            vault_id: keys().1,
            epoch,
            fingerprint,
            header_seq,
            header_sha256,
            legacy_sha256,
            devices,
        }
    }
}

prop_compose! {
    fn mirror_state()(
        device_id in any::<[u8; 16]>(),
        next_op_seq in 1..=CAP + 1,
        header_pin in header_pin(),
        index_pin in proptest::option::of((0..=CAP, any::<[u8; 32]>(), any::<u32>())),
        etags in (etag(), etag()),
        queue in vec(op(), 0..5),
        own in (any::<[u64; 2]>(), records(), records()),
        notices in vec(stored_notice(), 0..5),
        objects in objects(),
        last_sync_unix in proptest::option::of(any::<i64>()),
        last_publish_error in proptest::option::of((any::<u8>(), "[ -~]{0,40}", any::<i64>())),
        flags in (any::<bool>(), any::<bool>()),
        other in btree_map(KNOWN_TAGS + 1.., vec(any::<u8>(), 0..16), 0..3),
    ) -> MirrorState {
        MirrorState {
            device_id,
            next_op_seq,
            header_pin,
            index_pin: index_pin.map(|(index_seq, index_sha256, index_epoch)| IndexPin {
                index_seq,
                index_sha256,
                index_epoch,
            }),
            header_etag: etags.0,
            index_etag: etags.1,
            queue,
            own: OwnRecords {
                headers_from: own.0[0],
                indexes_from: own.0[1],
                headers: own.1,
                indexes: own.2,
            },
            notices,
            objects,
            last_sync_unix,
            last_publish_error: last_publish_error.map(|(exit_code, message, unix)| {
                PublishFailure { exit_code, message, unix }
            }),
            rotation_pending: flags.0,
            history: if flags.1 { HistoryMode::Full } else { HistoryMode::Heads },
            other: other.into_iter().collect(),
        }
    }
}

proptest! {
    #[test]
    fn state_seals_and_opens(st in mirror_state()) {
        let (k, _) = keys();
        let sealed = seal_state(k, &st).unwrap();
        let (back, epoch) = open_state(k, &sealed).unwrap();
        prop_assert_eq!(epoch, 1);
        prop_assert!(back == st, "{:?} != {:?}", back, st);
    }
}

// Convergence.

const PATHS: [&str; 4] = ["a", "b", "c", "d/e"];

#[derive(Debug, Clone)]
enum Step {
    /// A new entry (revision 1) at a path; on a taken path this makes a conflict.
    PutNew(usize, usize),
    /// An edit of the head the device sees at a path.
    Edit(usize, usize),
    Remove(usize, usize),
    Move(usize, usize, usize),
    Sync(usize),
    /// Restart a device from its mirror files.
    Reopen(usize),
    /// Take the bucket offline or bring it back.
    ToggleOffline,
}

fn step(devices: usize) -> impl Strategy<Value = Step> {
    let d = 0..devices;
    let p = 0..PATHS.len();
    prop_oneof![
        2 => (d.clone(), p.clone()).prop_map(|(d, p)| Step::PutNew(d, p)),
        3 => (d.clone(), p.clone()).prop_map(|(d, p)| Step::Edit(d, p)),
        1 => (d.clone(), p.clone()).prop_map(|(d, p)| Step::Remove(d, p)),
        1 => (d.clone(), p.clone(), p).prop_map(|(d, f, t)| Step::Move(d, f, t)),
        4 => d.clone().prop_map(Step::Sync),
        1 => d.prop_map(Step::Reopen),
        1 => Just(Step::ToggleOffline),
    ]
}

fn scenario() -> impl Strategy<Value = (usize, Vec<Step>)> {
    (2usize..=4).prop_flat_map(|n| (Just(n), vec(step(n), 1..24)))
}

/// Every put's object ID with its parent.
type Puts = Vec<([u8; 16], [u8; 16])>;

/// Runs the steps.
fn run(w: &mut World, steps: &[Step]) -> Result<Puts, TestCaseError> {
    let mut puts = Vec::new();
    for s in steps {
        match *s {
            Step::PutNew(d, p) => {
                let id = w.put(d, PATHS[p], format!("{s:?}").as_bytes(), None);
                puts.push((id, [0; 16]));
            }
            Step::Edit(d, p) => {
                let Ok(e) = find(&w.vaults[d].view().unwrap(), PATHS[p]).cloned() else {
                    continue;
                };
                let id = w.put(
                    d,
                    PATHS[p],
                    format!("{s:?}").as_bytes(),
                    Some(e.head_object_id),
                );
                puts.push((id, e.head_object_id));
            }
            Step::Remove(d, p) => {
                if w.vaults[d].remove(PATHS[p]).is_ok() {
                    w.mirrors[d].state = w.vaults[d].commit().unwrap();
                }
            }
            Step::Move(d, f, t) => {
                if w.vaults[d].rename(PATHS[f], PATHS[t]).is_ok() {
                    w.mirrors[d].state = w.vaults[d].commit().unwrap();
                }
            }
            Step::Sync(d) => {
                let r = w.sync(d);
                prop_assert!(r.is_ok(), "sync of device {} failed: {:?}", d, r.err());
            }
            Step::Reopen(d) => w.reopen(d),
            Step::ToggleOffline => w.bucket.offline = !w.bucket.offline,
        }
    }
    Ok(puts)
}

proptest! {
    // Each case builds a vault and runs real crypto on every sync; a few dozen cases cover the
    // interleavings without slowing the suite.
    #![proptest_config(ProptestConfig::with_cases(40))]

    #[test]
    fn devices_converge_and_lose_no_put((n, steps) in scenario()) {
        let mut w = World::new(n);
        let puts = run(&mut w, &steps)?;
        w.bucket.offline = false;
        for _ in 0..2 {
            for d in 0..n {
                let r = w.sync(d);
                prop_assert!(r.is_ok(), "final sync of device {} failed: {:?}", d, r.err());
                let r = r.unwrap();
                prop_assert!(r.failure.is_none() && !r.offline && r.error.is_none());
            }
        }
        let first = w.vaults[0].view().unwrap();
        for d in 0..n {
            prop_assert!(w.vaults[d].state().queue.is_empty(), "device {} has a queue", d);
            prop_assert!(w.vaults[d].view().unwrap() == first, "device {} differs", d);
        }
        // No loss: every put's object is a head, a tombstone head, or an ancestor of one.
        let parents: HashMap<[u8; 16], [u8; 16]> = puts.iter().copied().collect();
        let mut kept: HashSet<[u8; 16]> = HashSet::new();
        let heads = first
            .entries
            .iter()
            .map(|e| e.head_object_id)
            .chain(first.tombstones.iter().map(|t| t.head_object_id));
        for mut id in heads {
            while kept.insert(id) {
                match parents.get(&id) {
                    Some(p) if *p != [0; 16] => id = *p,
                    _ => break,
                }
            }
        }
        for (id, _) in &puts {
            prop_assert!(kept.contains(id), "lost {}", hex::encode(id));
        }
    }
}
