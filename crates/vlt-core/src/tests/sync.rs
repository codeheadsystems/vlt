//! Pins, mirror state, and the sync session, driven end to end against an in-memory bucket and
//! per-device mirrors. The driver here is the reference executor of [`Action`]s.

use crate::error::{Error, IntegrityKind as K};
use crate::ext::ExtList;
use crate::header::{DeviceInfo, HeaderDraft, RotationCommitment, parse_header};
use crate::index::index_prefix;
use crate::keys::{DevicePublic, generate_device_keys};
use crate::merge::ReportItem;
use crate::mirror_state::{HistoryMode, open_state, seal_state};
use crate::notice::{Notice, ObjectKind};
use crate::pins::{HeaderPin, IndexVerdict, OwnRecords, check_header, check_index};
use crate::prim::sha256;
use crate::secret::{DeviceSecrets, SecretKey, VaultKey};
use crate::session::{
    Action, Failure, Fetched, ObjectFetch, Response, Source, Stored, SyncOptions, SyncReport,
};
use crate::vault::{Vault, find};
use std::collections::HashMap;

pub(crate) struct Dev {
    pub(crate) id: [u8; 16],
    pub(crate) secrets: DeviceSecrets,
    pub(crate) public: DevicePublic,
    pub(crate) label: String,
}

/// A vault's fixed secrets and enrolled devices, from which headers at any epoch can be built.
pub(crate) struct Fx {
    pub(crate) vault_id: [u8; 16],
    sk: [u8; 16],
    vks: Vec<[u8; 32]>,
    pub(crate) devs: Vec<Dev>,
}

impl Fx {
    pub(crate) fn new(n: usize) -> Fx {
        let devs = (0..n)
            .map(|i| {
                let (secrets, public) = generate_device_keys().unwrap();
                let mut id = [0u8; 16];
                id[0] = i as u8 + 1;
                Dev {
                    id,
                    secrets,
                    public,
                    label: format!("dev{i}"),
                }
            })
            .collect();
        Fx {
            vault_id: [0x5a; 16],
            sk: [7; 16],
            vks: (1..=20u8).map(|e| [e; 32]).collect(),
            devs,
        }
    }

    pub(crate) fn header(
        &self,
        epoch: u32,
        header_seq: u64,
        writer: usize,
        rotation: RotationCommitment,
        devs: &[usize],
    ) -> Vec<u8> {
        let base = HeaderDraft::new_vault(
            self.vault_id,
            self.devs[writer].id,
            VaultKey::from_bytes(self.vks[epoch as usize - 1]),
            SecretKey::from_bytes(self.sk),
        );
        let keyring = (1..epoch)
            .map(|e| (e, VaultKey::from_bytes(self.vks[e as usize - 1])))
            .collect();
        let mut d = HeaderDraft::from_parts(base, keyring, vec![]);
        d.epoch = epoch;
        d.header_seq = header_seq;
        d.rotation = rotation;
        d.set_password("correct horse battery", 64, 1, 1, true)
            .unwrap();
        for &i in devs {
            let dev = &self.devs[i];
            d.add_device(
                DeviceInfo {
                    device_id: dev.id,
                    kind: 1,
                    label: dev.label.clone(),
                    enrolled_header_seq: 1,
                    enrolled_unix: 0,
                    enrolled_by: [0; 16],
                },
                dev.public.device_pk,
                &dev.public.kem_ek,
            )
            .unwrap();
        }
        d.encode().unwrap()
    }
}

/// An in-memory bucket with conditional writes and fault injection.
#[derive(Default)]
pub(crate) struct Bucket {
    objs: HashMap<String, (Vec<u8>, String)>,
    ctr: u64,
    pub(crate) offline: bool,
    /// Answer this many index `PUT`s with `412` without writing.
    pub(crate) refuse_index_puts: u32,
    /// Write the next index `PUT`, then report the connection as lost.
    pub(crate) lose_index_response: bool,
}

impl Bucket {
    fn etag(&mut self) -> String {
        self.ctr += 1;
        format!("\"{}\"", self.ctr)
    }

    pub(crate) fn get(&self, key: &str, inm: Option<&str>) -> Fetched {
        match self.objs.get(key) {
            None => Fetched::NotFound,
            Some((_, e)) if Some(e.as_str()) == inm => Fetched::NotModified,
            Some((b, e)) => Fetched::Found {
                bytes: b.clone(),
                etag: e.clone(),
            },
        }
    }

    pub(crate) fn create(&mut self, key: &str, bytes: &[u8]) -> Stored {
        if self.objs.contains_key(key) {
            return Stored::PreconditionFailed;
        }
        let etag = self.etag();
        self.objs.insert(key.into(), (bytes.to_vec(), etag.clone()));
        Stored::Written { etag }
    }

    pub(crate) fn replace(&mut self, key: &str, bytes: &[u8], if_match: &str) -> Stored {
        match self.objs.get(key) {
            Some((_, e)) if e == if_match => {
                let etag = self.etag();
                self.objs.insert(key.into(), (bytes.to_vec(), etag.clone()));
                Stored::Written { etag }
            }
            _ => Stored::PreconditionFailed,
        }
    }

    /// Overwrite without conditions, as a holder of a device key could.
    pub(crate) fn put_raw(&mut self, key: &str, bytes: &[u8]) {
        let etag = self.etag();
        self.objs.insert(key.into(), (bytes.to_vec(), etag));
    }

    pub(crate) fn bytes(&self, key: &str) -> Option<Vec<u8>> {
        self.objs.get(key).map(|(b, _)| b.clone())
    }

    pub(crate) fn remove(&mut self, key: &str) {
        self.objs.remove(key);
    }
}

fn ekey(id: &[u8; 16]) -> String {
    format!("e/{}", hex::encode(id))
}

/// One device's mirror directory.
#[derive(Default, Clone)]
pub(crate) struct Mirror {
    pub(crate) header: Vec<u8>,
    pub(crate) index: Vec<u8>,
    pub(crate) state: Vec<u8>,
    pub(crate) objects: HashMap<[u8; 16], Vec<u8>>,
    /// Every `state` committed, oldest first, to simulate a crash before a later one.
    pub(crate) states: Vec<Vec<u8>>,
}

/// Execute a session's actions against the bucket and the mirror.
pub(crate) fn drive(
    vault: &mut Vault,
    opts: SyncOptions,
    bucket: &mut Bucket,
    mirror: &mut Mirror,
    dev: &Dev,
) -> Result<SyncReport, Error> {
    let mut s = vault.sync(opts);
    let mut action = s.start()?;
    loop {
        let resp = match action {
            Action::Done(r) => return Ok(r),
            _ if bucket.offline
                && matches!(
                    action,
                    Action::GetIndex { .. }
                        | Action::GetHeader { .. }
                        | Action::PutObjects { .. }
                        | Action::PutIndex { .. }
                ) =>
            {
                Response::Failed(Failure::Offline)
            }
            Action::GetIndex { if_none_match } => {
                Response::Index(bucket.get("index", if_none_match.as_deref()))
            }
            Action::GetHeader { if_none_match } => {
                Response::Header(bucket.get("header", if_none_match.as_deref()))
            }
            Action::Unlock { header } => {
                let p = parse_header(&header)?;
                match p.unlock_with_device(&dev.id, &dev.secrets) {
                    Ok(x) => Response::Unlocked(Box::new(x)),
                    Err(_) => Response::UnlockFailed,
                }
            }
            Action::GetObjects { ids, source } => Response::Objects(
                ids.iter()
                    .map(|id| {
                        if source == Source::MirrorThenBackend
                            && let Some(b) = mirror.objects.get(id)
                        {
                            return (
                                *id,
                                ObjectFetch::Found {
                                    bytes: b.clone(),
                                    from_mirror: true,
                                },
                            );
                        }
                        if bucket.offline {
                            return (*id, ObjectFetch::Unavailable);
                        }
                        let r = match bucket.get(&ekey(id), None) {
                            Fetched::Found { bytes, .. } => ObjectFetch::Found {
                                bytes,
                                from_mirror: false,
                            },
                            _ => ObjectFetch::NotFound,
                        };
                        (*id, r)
                    })
                    .collect(),
            ),
            Action::PutObjects { objects } => Response::Stored(
                objects
                    .iter()
                    .map(|(id, b)| (*id, bucket.create(&ekey(id), b)))
                    .collect(),
            ),
            Action::PutIndex { index, if_match } => {
                if bucket.refuse_index_puts > 0 {
                    bucket.refuse_index_puts -= 1;
                    Response::IndexStored(Stored::PreconditionFailed)
                } else {
                    let r = bucket.replace("index", &index, &if_match);
                    if bucket.lose_index_response {
                        bucket.lose_index_response = false;
                        Response::Failed(Failure::Offline)
                    } else {
                        Response::IndexStored(r)
                    }
                }
            }
            Action::Backoff { .. } => Response::Waited,
            Action::Commit(c) => {
                for (id, b) in c.objects {
                    mirror.objects.insert(id, b);
                }
                if let Some(h) = c.header {
                    mirror.header = h;
                }
                if let Some(i) = c.index {
                    mirror.index = i;
                }
                mirror.states.push(c.state.clone());
                mirror.state = c.state;
                Response::Committed
            }
        };
        action = s.feed(resp)?;
    }
}

const NOW: i64 = 1_800_000_000;

fn opts() -> SyncOptions {
    SyncOptions {
        publish: true,
        check_header: false,
        now: NOW,
    }
}

/// A two-or-more-device world: device 0 created the vault; the others joined.
pub(crate) struct World {
    pub(crate) fx: Fx,
    pub(crate) bucket: Bucket,
    pub(crate) vaults: Vec<Vault>,
    pub(crate) mirrors: Vec<Mirror>,
}

impl World {
    pub(crate) fn new(n: usize) -> World {
        let fx = Fx::new(n);
        let all: Vec<usize> = (0..n).collect();
        let header = fx.header(1, 1, 0, RotationCommitment::default(), &all);
        let mut bucket = Bucket::default();
        let (mut v0, index) = Vault::create(
            fx.devs[0].id,
            &fx.devs[0].secrets,
            &header,
            HistoryMode::Full,
            NOW,
        )
        .unwrap();
        let he = match bucket.create("header", &header) {
            Stored::Written { etag } => etag,
            _ => unreachable!(),
        };
        let ie = match bucket.create("index", &index) {
            Stored::Written { etag } => etag,
            _ => unreachable!(),
        };
        v0.set_etags(Some(he.clone()), Some(ie.clone()));
        let m0 = Mirror {
            header: header.clone(),
            index: index.clone(),
            state: v0.commit().unwrap(),
            objects: HashMap::new(),
            states: Vec::new(),
        };
        let mut vaults = vec![v0];
        let mut mirrors = vec![m0];
        for d in &fx.devs[1..] {
            let v = Vault::join(
                d.id,
                &d.secrets,
                &header,
                Some(he.clone()),
                None,
                &index,
                Some(ie.clone()),
                HistoryMode::Full,
            )
            .unwrap();
            mirrors.push(Mirror {
                header: header.clone(),
                index: index.clone(),
                state: v.commit().unwrap(),
                objects: HashMap::new(),
                states: Vec::new(),
            });
            vaults.push(v);
        }
        World {
            fx,
            bucket,
            vaults,
            mirrors,
        }
    }

    pub(crate) fn sync(&mut self, i: usize) -> Result<SyncReport, Error> {
        drive(
            &mut self.vaults[i],
            opts(),
            &mut self.bucket,
            &mut self.mirrors[i],
            &self.fx.devs[i],
        )
    }

    /// Queue a put on device `i` and write the object to its mirror, as a driver does.
    pub(crate) fn put(
        &mut self,
        i: usize,
        path: &str,
        content: &[u8],
        parent: Option<[u8; 16]>,
    ) -> [u8; 16] {
        let q = self.vaults[i]
            .put(path, content, parent, ExtList::new(), NOW)
            .unwrap();
        self.mirrors[i].objects.insert(q.object_id, q.object);
        self.mirrors[i].state = self.vaults[i].commit().unwrap();
        q.object_id
    }

    pub(crate) fn head(&self, i: usize, path: &str) -> [u8; 16] {
        find(&self.vaults[i].view().unwrap(), path)
            .unwrap()
            .head_object_id
    }

    pub(crate) fn content(&self, i: usize, path: &str) -> Vec<u8> {
        let view = self.vaults[i].view().unwrap();
        let e = find(&view, path).unwrap();
        let b = &self.mirrors[i].objects[&e.head_object_id];
        self.vaults[i]
            .open_entry_of(e, b)
            .unwrap()
            .1
            .content
            .to_vec()
    }

    pub(crate) fn paths(&self, i: usize) -> Vec<String> {
        self.vaults[i]
            .view()
            .unwrap()
            .entries
            .iter()
            .map(|e| e.path.clone())
            .collect()
    }

    /// Reopen device `i` from its mirror files, as after a restart.
    pub(crate) fn reopen(&mut self, i: usize) {
        let m = &self.mirrors[i];
        let d = &self.fx.devs[i];
        self.vaults[i] = Vault::open(d.id, &d.secrets, &m.header, &m.index, &m.state).unwrap();
    }
}

#[test]
fn publish_and_fetch_between_devices() {
    let mut w = World::new(2);
    w.put(0, "Email/example.com", b"s3cr3t\nusername: ned\n", None);
    assert_eq!(w.paths(0), vec!["Email/example.com"]);
    let r = w.sync(0).unwrap();
    assert_eq!(r.published, 1);
    assert!(w.vaults[0].state().queue.is_empty());
    let r = w.sync(1).unwrap();
    assert!(r.index_changed);
    assert_eq!(r.fetched, 1);
    assert_eq!(
        w.content(1, "Email/example.com"),
        b"s3cr3t\nusername: ned\n"
    );
    // An unchanged index costs one conditional request and changes nothing.
    let r = w.sync(1).unwrap();
    assert!(!r.index_changed && r.fetched == 0 && r.published == 0);
    // Both mirrors reopen from their files.
    w.reopen(0);
    w.reopen(1);
    assert_eq!(
        w.content(1, "Email/example.com"),
        b"s3cr3t\nusername: ned\n"
    );
}

#[test]
fn concurrent_edits_make_a_conflict_copy() {
    let mut w = World::new(2);
    w.put(0, "a", b"v1", None);
    w.sync(0).unwrap();
    w.sync(1).unwrap();
    let h = w.head(0, "a");
    w.put(0, "a", b"from-0", Some(h));
    w.put(1, "a", b"from-1", Some(h));
    w.sync(0).unwrap();
    let r = w.sync(1).unwrap();
    assert_eq!(r.items.len(), 1);
    let ReportItem::Conflict {
        path, copy_path, ..
    } = &r.items[0]
    else {
        panic!("expected a conflict");
    };
    assert_eq!(path, "a");
    w.sync(0).unwrap();
    for i in 0..2 {
        let mut paths = w.paths(i);
        paths.sort();
        assert_eq!(paths, vec!["a".to_string(), copy_path.clone()]);
    }
    // Equal revisions: the higher device ID keeps the path.
    assert_eq!(w.content(0, "a"), b"from-1");
    assert_eq!(w.content(0, copy_path), b"from-0");
    assert_eq!(copy_path, "a.conflict-dev0");
    let view = w.vaults[0].view().unwrap();
    assert_eq!(find(&view, copy_path).unwrap().ext.conflict_of(), Some("a"));
}

#[test]
fn edit_wins_over_delete_and_tombstone_stays() {
    let mut w = World::new(2);
    w.put(0, "a", b"v1", None);
    w.sync(0).unwrap();
    w.sync(1).unwrap();
    let h = w.head(1, "a");
    w.vaults[0].remove("a").unwrap();
    w.mirrors[0].state = w.vaults[0].commit().unwrap();
    w.sync(0).unwrap();
    w.put(1, "a", b"v2", Some(h));
    let r = w.sync(1).unwrap();
    assert!(matches!(
        r.items[..],
        [ReportItem::EditWonOverDelete { .. }]
    ));
    assert_eq!(w.content(1, "a"), b"v2");
    assert_eq!(w.vaults[1].index().tombstones.len(), 1);
}

#[test]
fn lost_response_retry_is_harmless() {
    let mut w = World::new(1);
    w.put(0, "a", b"v1", None);
    w.bucket.lose_index_response = true;
    let r = w.sync(0).unwrap();
    assert_eq!(r.failure, Some(Failure::Offline));
    assert_eq!(w.vaults[0].state().queue.len(), 1);
    // The retry sees its own index, already applied, and publishes nothing new.
    let r = w.sync(0).unwrap();
    assert!(r.index_changed);
    assert!(r.notices.is_empty(), "own write recorded before the PUT");
    assert!(w.vaults[0].state().queue.is_empty());
    assert_eq!(w.paths(0), vec!["a"]);
}

#[test]
fn contention_gives_up_after_eight_attempts() {
    let mut w = World::new(1);
    w.put(0, "a", b"v1", None);
    w.bucket.refuse_index_puts = 8;
    let r = w.sync(0).unwrap();
    assert_eq!(r.error, Some(Error::PublishContention));
    let st = w.vaults[0].state();
    assert_eq!(st.queue.len(), 1);
    assert_eq!(st.last_publish_error.as_ref().unwrap().exit_code, 7);
    let mut w = World::new(1);
    w.put(0, "a", b"v1", None);
    w.bucket.refuse_index_puts = 7;
    let r = w.sync(0).unwrap();
    assert_eq!(r.published, 1);
    assert!(w.vaults[0].state().last_publish_error.is_none());
}

#[test]
fn offline_keeps_the_queue_and_reads_work() {
    let mut w = World::new(1);
    w.put(0, "a", b"v1", None);
    w.bucket.offline = true;
    let r = w.sync(0).unwrap();
    assert!(r.offline);
    assert_eq!(w.vaults[0].state().queue.len(), 1);
    assert_eq!(w.content(0, "a"), b"v1");
    w.bucket.offline = false;
    assert_eq!(w.sync(0).unwrap().published, 1);
}

#[test]
fn rollback_and_fork_are_integrity_errors() {
    let mut w = World::new(1);
    let old = w.bucket.bytes("index").unwrap();
    w.put(0, "a", b"v1", None);
    w.sync(0).unwrap();
    w.bucket.put_raw("index", &old);
    assert_eq!(w.sync(0).err(), Some(Error::Integrity(K::IndexRollback)));

    // A fork: another index with the pinned index_seq.
    let mut w = World::new(2);
    w.put(0, "a", b"v1", None);
    w.sync(0).unwrap();
    let pinned = w.bucket.bytes("index").unwrap();
    let keys = w.vaults[0].keys();
    let p = index_prefix(&pinned).unwrap();
    let forged =
        crate::index::seal_index(keys, p.index_seq, p.header_seq, w.vaults[0].index()).unwrap();
    w.bucket.put_raw("index", &forged);
    assert_eq!(w.sync(0).err(), Some(Error::Integrity(K::IndexFork)));
}

#[test]
fn forged_own_writer_is_detected() {
    let mut w = World::new(2);
    w.sync(1).unwrap();
    // Device 1's key holder writes an index naming device 0 as writer.
    let keys = w.vaults[1].keys();
    let mut plain = w.vaults[1].index().clone();
    plain.writer_device_id = w.fx.devs[0].id;
    let p = *w.vaults[1].index_prefix();
    let forged = crate::index::seal_index(keys, p.index_seq + 1, p.header_seq, &plain).unwrap();
    w.bucket.put_raw("index", &forged);
    assert_eq!(w.sync(0).err(), Some(Error::Integrity(K::ForgedWriter)));
    // The other device only sees an ordinary write by device 0.
    assert!(w.sync(1).is_ok());
}

#[test]
fn overwritten_head_is_rejected_and_missing_head_reported() {
    let mut w = World::new(2);
    let id = w.put(0, "a", b"v1", None);
    w.sync(0).unwrap();
    let other = w.put(0, "b", b"other", None);
    w.sync(0).unwrap();
    let bytes = w.bucket.bytes(&ekey(&other)).unwrap();
    w.bucket.put_raw(&ekey(&id), &bytes);
    assert_eq!(w.sync(1).err(), Some(Error::Integrity(K::ShaMismatch)));
    w.bucket.remove(&ekey(&id));
    assert_eq!(w.sync(1).err(), Some(Error::Integrity(K::HeadMissing)));
}

#[test]
fn newer_header_is_fetched_and_rotation_reseals_the_queue() {
    let mut w = World::new(2);
    w.put(0, "a", b"v1", None);
    w.sync(0).unwrap();
    w.sync(1).unwrap();
    // Device 1 queues an edit offline under epoch 1.
    let h = w.head(1, "a");
    w.put(1, "a", b"v2", Some(h));
    // Device 0 rotates: header at epoch 2 committing to the current index, then publishes the
    // index re-sealed under epoch 2.
    let cur = w.bucket.bytes("index").unwrap();
    let cp = index_prefix(&cur).unwrap();
    let rot = RotationCommitment {
        from_epoch: 1,
        from_index_seq: cp.index_seq,
        from_index_sha256: sha256(&[&cur]),
    };
    let header = w.fx.header(2, 2, 0, rot, &[0, 1]);
    // Device 0 records the header as its own before writing it, as a rotation does.
    w.vaults[0]
        .state_mut()
        .own
        .record(ObjectKind::Header, 2, sha256(&[&header]), NOW);
    let he = w.vaults[0].state().header_etag.clone().unwrap();
    assert!(matches!(
        w.bucket.replace("header", &header, &he),
        Stored::Written { .. }
    ));
    // Before device 0 republishes, the bucket holds the committed rotation index: device 1, on
    // `vlt sync`, accepts the header, publishes on that index, and so completes the rotation,
    // re-sealing its queued edit.
    let r = drive(
        &mut w.vaults[1],
        SyncOptions {
            check_header: true,
            ..opts()
        },
        &mut w.bucket,
        &mut w.mirrors[1],
        &w.fx.devs[1],
    )
    .unwrap();
    assert!(r.header_changed);
    assert!(
        r.notices
            .iter()
            .any(|n| matches!(n, Notice::VaultKeyChanged { epoch: 2, .. }))
    );
    assert_eq!(r.published, 1);
    let idx = w.bucket.bytes("index").unwrap();
    assert_eq!(index_prefix(&idx).unwrap().epoch, 2);
    let e = find(w.vaults[1].index(), "a").unwrap().clone();
    let obj = w.bucket.bytes(&ekey(&e.head_object_id)).unwrap();
    assert_eq!(crate::entry::entry_prefix(&obj).unwrap().epoch, 2);
    assert_ne!(e.head_object_id, h);
    w.sync(0).unwrap();
    assert_eq!(w.content(0, "a"), b"v2");
}

#[test]
fn unmatched_rotation_index_is_pending_not_an_error() {
    let mut w = World::new(2);
    w.put(0, "a", b"v1", None);
    w.sync(0).unwrap();
    w.sync(1).unwrap();
    let cur = w.bucket.bytes("index").unwrap();
    let cp = index_prefix(&cur).unwrap();
    let rot = RotationCommitment {
        from_epoch: 1,
        from_index_seq: cp.index_seq,
        from_index_sha256: [9; 32],
    };
    let header = w.fx.header(2, 2, 0, rot, &[0, 1]);
    w.bucket.put_raw("header", &header);
    // An epoch-1 index the commitment does not match, naming the new header.
    let keys = w.vaults[0].keys();
    let forged = crate::index::seal_index(keys, cp.index_seq + 1, 2, w.vaults[0].index()).unwrap();
    w.bucket.put_raw("index", &forged);
    let h = w.head(1, "a");
    w.put(1, "a", b"v2", Some(h));
    let r = w.sync(1).unwrap();
    assert!(r.rotation_pending);
    assert_eq!(r.published, 0);
    assert_eq!(w.vaults[1].state().queue.len(), 1);
    assert_eq!(w.content(1, "a"), b"v2");
}

#[test]
fn removed_device_cannot_unlock_a_new_header() {
    let mut w = World::new(2);
    let cur = w.bucket.bytes("index").unwrap();
    let rot = RotationCommitment {
        from_epoch: 1,
        from_index_seq: 1,
        from_index_sha256: sha256(&[&cur]),
    };
    let header = w.fx.header(2, 2, 0, rot, &[0]);
    w.bucket.put_raw("header", &header);
    let keys = w.vaults[0].keys();
    let idx = crate::index::seal_index(keys, 2, 2, w.vaults[0].index()).unwrap();
    w.bucket.put_raw("index", &idx);
    assert_eq!(w.sync(1).err(), Some(Error::WrongPasswordOrUnknownDevice));
}

#[test]
fn op_seq_is_raised_past_a_forged_applied_value() {
    let mut w = World::new(2);
    w.sync(1).unwrap();
    let keys = w.vaults[1].keys();
    let mut plain = w.vaults[1].index().clone();
    plain.writer_device_id = w.fx.devs[1].id;
    plain.applied.push(crate::index::Applied {
        device_id: w.fx.devs[0].id,
        last_op_seq: 50,
    });
    let p = *w.vaults[1].index_prefix();
    let forged = crate::index::seal_index(keys, p.index_seq + 1, p.header_seq, &plain).unwrap();
    w.bucket.put_raw("index", &forged);
    w.put(0, "a", b"v1", None);
    let r = w.sync(0).unwrap();
    assert!(r.notices.iter().any(|n| matches!(
        n,
        Notice::OpSeqRaised {
            next_op_seq: 52,
            ..
        }
    )));
    assert_eq!(r.published, 1, "the renumbered op is not skipped");
    assert_eq!(w.paths(0), vec!["a"]);
}

#[test]
fn three_devices_converge() {
    let mut w = World::new(3);
    for i in 0..3 {
        w.put(i, "shared", format!("from {i}").as_bytes(), None);
        w.put(i, &format!("own/{i}"), b"x", None);
    }
    for _ in 0..2 {
        for i in 0..3 {
            w.sync(i).unwrap();
        }
    }
    let p0 = w.paths(0);
    assert_eq!(p0.len(), 6, "{p0:?}");
    assert_eq!(w.paths(1), p0);
    assert_eq!(w.paths(2), p0);
    for i in 0..3 {
        assert!(w.vaults[i].state().queue.is_empty());
    }
}

// Pins.

#[test]
fn header_pin_rules() {
    let fx = Fx::new(2);
    let h1 = fx.header(1, 1, 0, RotationCommitment::default(), &[0, 1]);
    let (i1, k1) = parse_header(&h1)
        .unwrap()
        .unlock_with_device(&fx.devs[0].id, &fx.devs[0].secrets)
        .unwrap();
    let pin = HeaderPin::from_header(&i1);
    let own = OwnRecords::default();
    let me = fx.devs[1].id;
    assert_eq!(check_header(&pin, &i1, &k1, &own, &me), Ok(vec![]));
    let open = |h: &[u8]| {
        parse_header(h)
            .unwrap()
            .unlock_with_device(&fx.devs[0].id, &fx.devs[0].secrets)
            .unwrap()
    };
    // Same seq, other bytes: fork.
    let h1b = fx.header(1, 1, 0, RotationCommitment::default(), &[0, 1]);
    let (i, k) = open(&h1b);
    assert_eq!(
        check_header(&pin, &i, &k, &own, &me),
        Err(Error::Integrity(K::HeaderFork))
    );
    // A newer header is fine; an older one against its pin is a rollback.
    let h2 = fx.header(1, 2, 0, RotationCommitment::default(), &[0, 1]);
    let (i2, k2) = open(&h2);
    assert_eq!(check_header(&pin, &i2, &k2, &own, &me), Ok(vec![]));
    let pin2 = HeaderPin::from_header(&i2);
    assert_eq!(
        check_header(&pin2, &i1, &k1, &own, &me),
        Err(Error::Integrity(K::HeaderRollback))
    );
    // A writer not enrolled in the pinned header is reported.
    let h3 = fx.header(1, 3, 1, RotationCommitment::default(), &[0, 1]);
    let (i3, k3) = open(&h3);
    let mut pin_one = pin2.clone();
    pin_one.devices = vec![fx.devs[0].id];
    assert_eq!(
        check_header(&pin_one, &i3, &k3, &own, &[0; 16]),
        Ok(vec![Notice::UnenrolledWriter {
            kind: ObjectKind::Header,
            writer: fx.devs[1].id
        }])
    );
    // A header naming this device that it never recorded: forged, unless older than records.
    assert_eq!(
        check_header(&pin2, &i3, &k3, &own, &fx.devs[1].id),
        Err(Error::Integrity(K::ForgedWriter))
    );
    let late = OwnRecords::starting_at(10, 0);
    assert_eq!(
        check_header(&pin2, &i3, &k3, &late, &fx.devs[1].id),
        Ok(vec![Notice::OwnWriteUnverified {
            kind: ObjectKind::Header,
            seq: 3
        }])
    );
    // Counter jumps above 2^32 are reported, exactly 2^32 is not.
    let far = fx.header(1, 2 + (1 << 32), 0, RotationCommitment::default(), &[0, 1]);
    let (i, k) = open(&far);
    assert!(check_header(&pin2, &i, &k, &own, &me).unwrap().is_empty());
    let farther = fx.header(1, 3 + (1 << 32), 0, RotationCommitment::default(), &[0, 1]);
    let (i, k) = open(&farther);
    assert!(matches!(
        check_header(&pin2, &i, &k, &own, &me).unwrap()[..],
        [Notice::CounterJump { .. }]
    ));
    // A different vault ID never passes.
    let mut other = pin2.clone();
    other.vault_id = [1; 16];
    assert_eq!(
        check_header(&other, &i2, &k2, &own, &me),
        Err(Error::Integrity(K::VaultIdMismatch))
    );
    // A different legacy block never passes.
    let mut leg = pin.clone();
    leg.legacy_sha256 = [1; 32];
    assert_eq!(
        check_header(&leg, &i2, &k2, &own, &me),
        Err(Error::Integrity(K::Legacy))
    );
}

#[test]
fn header_epoch_rules() {
    let fx = Fx::new(1);
    let open = |h: &[u8]| {
        parse_header(h)
            .unwrap()
            .unlock_with_device(&fx.devs[0].id, &fx.devs[0].secrets)
            .unwrap()
    };
    let rot = |e: u32| RotationCommitment {
        from_epoch: e - 1,
        from_index_seq: 1,
        from_index_sha256: [3; 32],
    };
    let (i1, _) = open(&fx.header(1, 1, 0, RotationCommitment::default(), &[0]));
    let pin = HeaderPin::from_header(&i1);
    let own = OwnRecords::default();
    let me = [0; 16];
    let (i, k) = open(&fx.header(17, 2, 0, rot(17), &[0]));
    assert!(matches!(
        check_header(&pin, &i, &k, &own, &me).unwrap()[..],
        [Notice::VaultKeyChanged { epoch: 17, .. }]
    ));
    let (i, k) = open(&fx.header(18, 2, 0, rot(18), &[0]));
    assert_eq!(
        check_header(&pin, &i, &k, &own, &me),
        Err(Error::Integrity(K::EpochJump))
    );
    // A lower epoch is a rollback; a wrong fingerprint in the keyring fails the chain.
    let (i5, _) = open(&fx.header(5, 5, 0, rot(5), &[0]));
    let pin5 = HeaderPin::from_header(&i5);
    let (i, k) = open(&fx.header(4, 6, 0, rot(4), &[0]));
    assert_eq!(
        check_header(&pin5, &i, &k, &own, &me),
        Err(Error::Integrity(K::HeaderRollback))
    );
    let mut bad = pin5.clone();
    bad.fingerprint = [0; 32];
    let (i, k) = open(&fx.header(6, 6, 0, rot(6), &[0]));
    assert_eq!(
        check_header(&bad, &i, &k, &own, &me),
        Err(Error::Integrity(K::PinFingerprint))
    );
    assert!(check_header(&pin5, &i, &k, &own, &me).is_ok());
    let (i, k) = open(&fx.header(5, 6, 0, rot(5), &[0]));
    assert_eq!(
        check_header(&bad, &i, &k, &own, &me),
        Err(Error::Integrity(K::PinFingerprint))
    );
}

#[test]
fn index_verdicts() {
    let w = World::new(1);
    let info = w.vaults[0].header();
    let pin = w.vaults[0].state().index_pin.unwrap();
    let idx = w.bucket.bytes("index").unwrap();
    let p = index_prefix(&idx).unwrap();
    let sha = sha256(&[&idx]);
    assert_eq!(
        check_index(Some(&pin), info, &p, &sha),
        Ok(IndexVerdict::Unchanged)
    );
    assert_eq!(
        check_index(Some(&pin), info, &p, &[0; 32]),
        Err(Error::Integrity(K::IndexFork))
    );
    let mut newer = p;
    newer.index_seq += 1;
    assert_eq!(
        check_index(Some(&pin), info, &newer, &[0; 32]),
        Ok(IndexVerdict::Accept)
    );
    newer.header_seq += 1;
    assert_eq!(
        check_index(Some(&pin), info, &newer, &[0; 32]),
        Ok(IndexVerdict::NeedHeader)
    );
    let mut older = pin;
    older.index_seq += 1;
    assert_eq!(
        check_index(Some(&older), info, &p, &sha),
        Err(Error::Integrity(K::IndexRollback))
    );
    let mut ep = pin;
    ep.index_epoch = 2;
    assert_eq!(
        check_index(Some(&ep), info, &newer, &sha),
        Ok(IndexVerdict::NeedHeader)
    );
    let mut low = p;
    low.index_seq += 1;
    assert_eq!(
        check_index(Some(&ep), info, &low, &sha),
        Err(Error::Integrity(K::IndexEpoch))
    );
    let mut wrong_epoch = p;
    wrong_epoch.index_seq += 1;
    wrong_epoch.epoch = 2;
    assert_eq!(
        check_index(Some(&pin), info, &wrong_epoch, &sha),
        Err(Error::Integrity(K::IndexEpoch))
    );
    let mut wrong_vault = p;
    wrong_vault.vault_id = [0; 16];
    assert_eq!(
        check_index(Some(&pin), info, &wrong_vault, &sha),
        Err(Error::Integrity(K::VaultIdMismatch))
    );
}

#[test]
fn own_records_prune_keeps_the_newest_and_raises_coverage() {
    let mut o = OwnRecords::starting_at(1, 1);
    let day = 86_400;
    for s in 1..=5000u64 {
        let mut sha = [0u8; 32];
        sha[..8].copy_from_slice(&s.to_be_bytes());
        o.record(ObjectKind::Index, s, sha, s as i64);
    }
    // Nothing is older than 400 days relative to "now" near the records: nothing is dropped.
    o.prune(5000);
    assert_eq!(o.indexes.len(), 5000);
    o.prune(5000 + 401 * day);
    assert_eq!(o.indexes.len(), 4096);
    assert_eq!(o.indexes_from, 905);
    assert!(matches!(
        o.check(ObjectKind::Index, 10, &[1; 32]),
        Ok(Some(Notice::OwnWriteUnverified { .. }))
    ));
}

// Mirror state.

#[test]
fn state_round_trip_older_epoch_and_tamper() {
    let mut w = World::new(1);
    w.put(0, "a", b"v1", None);
    w.vaults[0].state_mut().push_notice(
        Notice::VaultKeyChanged {
            writer: [1; 16],
            epoch: 1,
        },
        5,
    );
    w.vaults[0].state_mut().other.push((900, vec![1, 2, 3]));
    let keys = w.vaults[0].keys();
    let sealed = seal_state(keys, w.vaults[0].state()).unwrap();
    let (back, epoch) = open_state(keys, &sealed).unwrap();
    assert_eq!(epoch, 1);
    assert!(back == *w.vaults[0].state());
    for at in 0..sealed.len() {
        let mut t = sealed.clone();
        t[at] ^= 1;
        assert!(open_state(keys, &t).is_err(), "byte {at}");
    }
    // A state sealed at epoch 1 opens under epoch-2 keys; one from a later epoch does not.
    let fx = &w.fx;
    let rot = RotationCommitment {
        from_epoch: 1,
        from_index_seq: 1,
        from_index_sha256: [0; 32],
    };
    let h2 = fx.header(2, 2, 0, rot, &[0]);
    let (_, k2) = parse_header(&h2)
        .unwrap()
        .unlock_with_device(&fx.devs[0].id, &fx.devs[0].secrets)
        .unwrap();
    assert_eq!(open_state(&k2, &sealed).unwrap().1, 1);
    let later = seal_state(&k2, w.vaults[0].state()).unwrap();
    assert_eq!(
        open_state(keys, &later).err(),
        Some(Error::Integrity(K::UnknownLineage))
    );
}

#[test]
fn state_records_own_index_before_the_put() {
    let mut w = World::new(1);
    w.put(0, "a", b"v1", None);
    // Crash right after the index PUT: the bucket has the index, the mirror has the state from
    // the write-ahead commit only.
    w.bucket.lose_index_response = true;
    let _ = w.sync(0).unwrap();
    w.reopen(0);
    let r = w.sync(0).unwrap();
    assert!(r.index_changed);
    assert!(r.notices.is_empty());
}

#[test]
fn view_shows_queued_moves_and_removals() {
    let mut w = World::new(1);
    w.put(0, "a", b"v1", None);
    w.put(0, "b", b"v2", None);
    w.vaults[0].rename("a", "c").unwrap();
    w.vaults[0].remove("b").unwrap();
    assert_eq!(w.paths(0), vec!["c"]);
    assert_eq!(
        w.vaults[0].rename("c", "c").err(),
        Some(Error::InvalidInput(crate::error::InputKind::PathTaken))
    );
    w.sync(0).unwrap();
    assert_eq!(w.paths(0), vec!["c"]);
    assert_eq!(w.vaults[0].index().tombstones.len(), 1);
}

// Retention and history fill.

#[test]
fn history_fill_walks_to_the_floor_and_records_purges() {
    let mut w = World::new(2);
    let mut parent = None;
    for v in 1..=4u8 {
        let id = w.put(0, "a", &[v], parent);
        w.sync(0).unwrap();
        parent = Some(id);
    }
    w.sync(1).unwrap();
    // Device 1 holds only the head; three ancestors are missing.
    let mut fetched = 0;
    loop {
        let need = w.vaults[1].history_missing(16);
        if need.is_empty() {
            break;
        }
        for n in need {
            let b = w.bucket.bytes(&ekey(&n.object_id));
            if n.revision == 1 {
                // Purged by an admin: the backend answers 404.
                w.vaults[1].add_history(&n, None).unwrap();
            } else {
                w.vaults[1].add_history(&n, b.as_deref()).unwrap();
                fetched += 1;
            }
        }
    }
    assert_eq!(fetched, 2);
    let st = w.vaults[1].state();
    assert_eq!(st.objects.len(), 4);
    assert_eq!(st.objects.iter().filter(|o| o.purged).count(), 1);
    // A wrong object for a need is rejected.
    let mut w2 = World::new(2);
    let a = w2.put(0, "a", b"1", None);
    w2.sync(0).unwrap();
    w2.put(0, "a", b"2", Some(a));
    w2.sync(0).unwrap();
    w2.sync(1).unwrap();
    let n = w2.vaults[1].history_missing(1)[0];
    let head = w2.head(1, "a");
    let wrong = w2.bucket.bytes(&ekey(&head)).unwrap();
    assert!(w2.vaults[1].add_history(&n, Some(&wrong)).is_err());
}

#[test]
fn retention_keeps_queued_and_recent_objects_and_checks_purges() {
    let mut w = World::new(1);
    let a = w.put(0, "a", b"1", None);
    w.sync(0).unwrap();
    // A queued object far in the future is still a root.
    let q = w.put(0, "q", b"queued", None);
    let later = NOW + 40 * 86_400;
    let plan = w.vaults[0].refresh_retention(later);
    assert_eq!(plan, crate::retention::RetentionPlan::default());
    // Remove "a" and purge its tombstone: the object becomes unreachable.
    w.vaults[0].remove("a").unwrap();
    w.sync(0).unwrap();
    let mut idx = w.vaults[0].index().clone();
    idx.tombstones.clear();
    w.vaults[0].index = idx;
    let plan = w.vaults[0].refresh_retention(later);
    assert_eq!(plan.check_gone, vec![a]);
    // Not confirmed gone, so kept for 30 days after it became unreachable; its publication at
    // NOW is too old by then to keep it longer.
    let plan = w.vaults[0].refresh_retention(later + 31 * 86_400);
    assert_eq!(plan.delete, vec![a]);
    assert!(w.vaults[0].state().object(&q).is_some());
}

#[test]
fn crash_between_index_file_and_state_does_not_republish_forever() {
    let mut w = World::new(1);
    w.put(0, "a", b"v1", None);
    w.mirrors[0].states.clear();
    let r = w.sync(0).unwrap();
    assert_eq!(r.published, 1);
    let seq = index_prefix(&w.bucket.bytes("index").unwrap())
        .unwrap()
        .index_seq;
    // The commits were: the sync's, the write-ahead record, then the published index and state.
    // Crash after the `index` file was renamed but before the last `state`.
    let n = w.mirrors[0].states.len();
    w.mirrors[0].state = w.mirrors[0].states[n - 2].clone();
    w.reopen(0);
    assert!(w.vaults[0].state().queue.is_empty());
    for _ in 0..3 {
        let r = w.sync(0).unwrap();
        assert_eq!(r.published, 0);
        assert!(r.notices.is_empty());
    }
    assert_eq!(
        index_prefix(&w.bucket.bytes("index").unwrap())
            .unwrap()
            .index_seq,
        seq
    );
}

#[test]
fn forged_applied_never_drops_unuploaded_writes() {
    let mut w = World::new(2);
    w.sync(1).unwrap();
    w.put(0, "a", b"offline", None);
    // A member publishes an index claiming device 0's op 1 was applied.
    let keys = w.vaults[1].keys();
    let mut plain = w.vaults[1].index().clone();
    plain.writer_device_id = w.fx.devs[1].id;
    plain.applied.push(crate::index::Applied {
        device_id: w.fx.devs[0].id,
        last_op_seq: 1,
    });
    let p = *w.vaults[1].index_prefix();
    let forged = crate::index::seal_index(keys, p.index_seq + 1, p.header_seq, &plain).unwrap();
    w.bucket.put_raw("index", &forged);
    let r = w.sync(0).unwrap();
    assert!(
        r.notices
            .iter()
            .any(|n| matches!(n, Notice::OpSeqRaised { .. }))
    );
    assert_eq!(r.published, 1);
    assert_eq!(w.paths(0), vec!["a"]);
    w.sync(1).unwrap();
    assert_eq!(w.content(1, "a"), b"offline");
}

#[test]
fn local_only_objects_are_never_purge_checked() {
    let mut w = World::new(1);
    let q = w.put(0, "a", b"queued", None);
    // Even if the queue lost the op, a never-uploaded object is not checked against the backend,
    // but it is not kept forever either: the 30-day rule applies.
    w.vaults[0].state_mut().queue.clear();
    let plan = w.vaults[0].refresh_retention(NOW + 1);
    assert_eq!(plan, crate::retention::RetentionPlan::default());
    let plan = w.vaults[0].refresh_retention(NOW + 1 + KEEP - 1);
    assert_eq!(plan, crate::retention::RetentionPlan::default());
    let plan = w.vaults[0].refresh_retention(NOW + 1 + KEEP);
    assert_eq!(plan.delete, vec![q]);
    assert!(plan.check_gone.is_empty());
    assert!(w.vaults[0].state().object(&q).is_none());
}

const KEEP: i64 = crate::retention::KEEP_SECS;

/// A one-device world with "a" published at NOW and then made unreachable at `at`: removed, and
/// its tombstone dropped as a purge would.
fn unreachable_at(at: i64) -> (World, [u8; 16]) {
    let mut w = World::new(1);
    let a = w.put(0, "a", b"1", None);
    w.sync(0).unwrap();
    w.vaults[0].remove("a").unwrap();
    w.sync(0).unwrap();
    w.vaults[0].index.tombstones.clear();
    let plan = w.vaults[0].refresh_retention(at);
    assert_eq!(plan.check_gone, vec![a]);
    assert!(plan.delete.is_empty());
    (w, a)
}

#[test]
fn retention_keeps_an_unreachable_object_for_exactly_30_days() {
    let t = NOW + 40 * 86_400;
    let (mut w, a) = unreachable_at(t);
    assert_eq!(w.vaults[0].state().object(&a).unwrap().unreachable_since, t);
    let plan = w.vaults[0].refresh_retention(t + KEEP - 1);
    assert!(plan.delete.is_empty());
    // No answer from the backend yet, so the purge check is still pending.
    assert_eq!(plan.check_gone, vec![a]);
    let plan = w.vaults[0].refresh_retention(t + KEEP);
    assert_eq!(plan.delete, vec![a]);
    assert!(w.vaults[0].state().object(&a).is_none());
}

#[test]
fn retention_checks_until_the_backend_answers() {
    let t = NOW + 40 * 86_400;
    let (mut w, a) = unreachable_at(t);
    // The backend said it still exists: no further checks while it stays unreachable.
    w.vaults[0].mark_present(&a);
    assert!(w.vaults[0].refresh_retention(t + 1).check_gone.is_empty());
    // The flag survives the state file. The mirror's index file still has the tombstone, so after
    // the reopen the object is reachable again, which clears the flag.
    w.mirrors[0].state = w.vaults[0].commit().unwrap();
    w.reopen(0);
    assert!(w.vaults[0].state().object(&a).unwrap().gone_checked);
    assert_eq!(w.vaults[0].refresh_retention(t + 2), Default::default());
    let o = *w.vaults[0].state().object(&a).unwrap();
    assert!(!o.gone_checked && o.unreachable_since == 0);
    // Unreachable once more: checked afresh.
    w.vaults[0].index.tombstones.clear();
    assert_eq!(w.vaults[0].refresh_retention(t + 4).check_gone, vec![a]);
    // A purge answer ends the checks and keeps the bookkeeping.
    w.vaults[0].mark_purged(&a);
    let plan = w.vaults[0].refresh_retention(t + 5 + KEEP);
    assert_eq!(plan, Default::default());
    assert!(w.vaults[0].state().object(&a).unwrap().purged);
}

#[test]
fn retention_keeps_objects_displayed_in_the_last_30_days() {
    let t = NOW + 40 * 86_400;
    let (mut w, a) = unreachable_at(t);
    let shown = t + 10 * 86_400;
    w.vaults[0].mark_displayed(&a, shown);
    assert!(w.vaults[0].refresh_retention(t + KEEP).delete.is_empty());
    assert!(
        w.vaults[0]
            .refresh_retention(shown + KEEP - 1)
            .delete
            .is_empty()
    );
    assert_eq!(w.vaults[0].refresh_retention(shown + KEEP).delete, vec![a]);
}

#[test]
fn retention_keeps_objects_published_in_the_last_30_days() {
    let t = NOW + 40 * 86_400;
    let (mut w, a) = unreachable_at(t);
    let published = t + 5 * 86_400;
    let st = w.vaults[0].state_mut();
    let i = st.objects.iter().position(|o| o.object_id == a).unwrap();
    st.objects[i].published_unix = published;
    assert!(w.vaults[0].refresh_retention(t + KEEP).delete.is_empty());
    assert!(
        w.vaults[0]
            .refresh_retention(published + KEEP - 1)
            .delete
            .is_empty()
    );
    assert_eq!(
        w.vaults[0].refresh_retention(published + KEEP).delete,
        vec![a]
    );
}

#[test]
fn history_fill_never_asks_below_the_floor() {
    let mut w = World::new(2);
    let mut parent = None;
    let mut revs = HashMap::new();
    for v in 1..=6u64 {
        let id = w.put(0, "a", &[v as u8], parent);
        w.sync(0).unwrap();
        revs.insert(id, v);
        parent = Some(id);
    }
    w.sync(1).unwrap();
    // A floor of 3 on the record: revisions 1 and 2 lie below it.
    let mut idx = w.vaults[1].index().clone();
    idx.entries[0]
        .ext
        .set(crate::ext::HISTORY_FLOOR, 3u64.to_be_bytes().to_vec());
    w.vaults[1].index = idx;
    let mut asked = Vec::new();
    loop {
        let need = w.vaults[1].history_missing(1);
        if need.is_empty() {
            break;
        }
        for n in need {
            assert!(n.revision >= 3, "asked for revision {}", n.revision);
            assert_eq!(revs[&n.object_id], n.revision);
            asked.push(n.revision);
            let b = w.bucket.bytes(&ekey(&n.object_id));
            w.vaults[1].add_history(&n, b.as_deref()).unwrap();
        }
    }
    asked.sort();
    assert_eq!(asked, vec![3, 4, 5]);
}
