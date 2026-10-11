//! The driver against the in-memory fake and the local store, with real mirror directories.

mod common;

use common::{NOW, world};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use vlt_core::ext::ExtList;
use vlt_core::ext::HISTORY_FLOOR;
use vlt_core::header::HeaderDraft;
use vlt_core::index::index_prefix;
use vlt_core::index::seal_index;
use vlt_core::merge::ReportItem;
use vlt_core::retention::KEEP_SECS;
use vlt_core::session::Failure;
use vlt_store::driver::fill_history;
use vlt_store::fake::{FakeBackend, FakeBucket, FakeOp, Fault};
use vlt_store::mirror::Mirror;
use vlt_store::{Backend, Etag, Get, LocalStore, OfflineKind, Put, StoreError};

fn converge(backend: &dyn Backend) {
    let mut d = world(backend, 2);
    d[0].put("a", b"v1", None);
    assert_eq!(d[0].sync(backend).unwrap().published, 1);
    assert_eq!(d[1].sync(backend).unwrap().fetched, 1);
    let h = d[1].head("a");
    d[0].put("a", b"zero", Some(h));
    d[1].put("a", b"one", Some(h));
    d[0].sync(backend).unwrap();
    let r = d[1].sync(backend).unwrap();
    assert!(matches!(r.items[..], [ReportItem::Conflict { .. }]));
    d[0].sync(backend).unwrap();
    for dev in d.iter_mut() {
        dev.reopen();
        assert_eq!(dev.paths().len(), 2);
    }
    assert_eq!(d[0].paths(), d[1].paths());
}

#[test]
fn two_devices_converge_on_the_fake() {
    converge(&FakeBackend::new());
}

#[test]
fn two_devices_converge_on_the_local_store() {
    let tmp = tempfile::tempdir().unwrap();
    let store = LocalStore::open(&tmp.path().join("store")).unwrap();
    converge(&store);
}

#[test]
fn mirror_lock_excludes_a_second_owner() {
    let fake = FakeBackend::new();
    let d = world(&fake, 1);
    match Mirror::open(&d[0].dir) {
        Err(StoreError::Io { kind, .. }) => assert_eq!(kind, io::ErrorKind::WouldBlock),
        _ => panic!("second owner admitted"),
    }
}

#[test]
fn crash_after_the_index_put_recovers_without_accusing_itself() {
    let fake = FakeBackend::new();
    let mut d = world(&fake, 1);
    d[0].put("a", b"v1", None);
    fake.inject(Some(FakeOp::Replace), Some("index"), 1, Fault::LostResponse);
    let r = d[0].sync(&fake).unwrap();
    assert_eq!(r.failure, Some(Failure::Offline));
    // The process dies here; the mirror holds the write-ahead state.
    d[0].reopen();
    let r = d[0].sync(&fake).unwrap();
    assert!(r.index_changed);
    assert!(r.notices.is_empty());
    assert!(d[0].vault.state().queue.is_empty());
    assert_eq!(d[0].content("a"), b"v1");
}

#[test]
fn offline_queues_and_publishes_later() {
    let fake = FakeBackend::new();
    let mut d = world(&fake, 2);
    d[0].put("a", b"v1", None);
    fake.inject(
        None,
        None,
        1,
        Fault::Offline(vlt_store::OfflineKind::Connect),
    );
    let r = d[0].sync(&fake).unwrap();
    assert!(r.offline);
    assert_eq!(d[0].vault.state().queue.len(), 1);
    assert_eq!(d[0].sync(&fake).unwrap().published, 1);
    d[1].sync(&fake).unwrap();
    assert_eq!(d[1].content("a"), b"v1");
}

#[test]
fn http_errors_are_reported_not_queued_silently() {
    let fake = FakeBackend::new();
    let mut d = world(&fake, 1);
    d[0].put("a", b"v1", None);
    fake.inject(
        Some(FakeOp::Create),
        None,
        1,
        Fault::Http {
            status: 403,
            code: Some("AccessDenied".into()),
        },
    );
    let r = d[0].sync(&fake).unwrap();
    assert!(matches!(r.failure, Some(Failure::Http { status: 403, .. })));
    assert!(d[0].vault.state().last_publish_error.is_some());
    assert_eq!(d[0].sync(&fake).unwrap().published, 1);
    assert!(d[0].vault.state().last_publish_error.is_none());
}

fn exists_calls(fake: &FakeBackend) -> usize {
    fake.log().iter().filter(|l| l.op == FakeOp::Exists).count()
}

fn ekey(id: &[u8; 16]) -> String {
    format!("e/{}", hex::encode(id))
}

#[test]
fn history_fill_and_prune_on_a_new_device() {
    let fake = FakeBackend::with_bucket(FakeBucket {
        delete_allowed: true,
        ..FakeBucket::default()
    });
    let mut d = world(&fake, 2);
    let mut parent = None;
    let mut revs = Vec::new();
    for v in 0..5u8 {
        parent = Some(d[0].put("a", &[v], parent));
        revs.push(parent.unwrap());
        d[0].sync(&fake).unwrap();
    }
    d[1].sync(&fake).unwrap();
    let dev = &mut d[1];
    let n = fill_history(&mut dev.vault, &fake, dev.mirror.as_ref().unwrap(), 2).unwrap();
    assert_eq!(n, 4);
    assert_eq!(
        fill_history(&mut dev.vault, &fake, dev.mirror.as_ref().unwrap(), 2).unwrap(),
        0
    );
    dev.reopen();
    assert_eq!(dev.vault.state().objects.len(), 5);
    // Everything is reachable: nothing is checked or deleted.
    fake.clear_log();
    dev.prune(&fake, NOW, true);
    assert_eq!(exists_calls(&fake), 0);
    assert_eq!(dev.vault.state().objects.len(), 5);

    // Device 0 publishes a history floor of 4 on "a": revisions 1 to 3 become unreachable. An
    // admin purge removes revisions 1 and 2 from the bucket; revision 3 is still there, as it would
    // be after a floor forged by a member.
    let keys = d[0].vault.keys();
    let p = *d[0].vault.index_prefix();
    let mut plain = d[0].vault.index().clone();
    plain.entries[0]
        .ext
        .set(HISTORY_FLOOR, 4u64.to_be_bytes().to_vec());
    let index = seal_index(keys, p.index_seq + 1, p.header_seq, &plain).unwrap();
    fake.put_admin("index", &index);
    for id in &revs[..2] {
        fake.delete(&ekey(id)).unwrap();
    }
    let dev = &mut d[1];
    let r = dev.sync(&fake).unwrap();
    assert!(r.index_changed);
    let on_disk = |dev: &common::Device, i: usize| dev.mirror().object(&revs[i]).unwrap().is_some();
    let purged =
        |dev: &common::Device, i: usize| dev.vault.state().object(&revs[i]).unwrap().purged;

    // Without proof of a healthy backend in this run, nothing is checked.
    fake.clear_log();
    dev.prune(&fake, NOW, false);
    assert_eq!(exists_calls(&fake), 0);
    assert!((0..5).all(|i| on_disk(dev, i)));

    // A failed check in the run makes every 404 of that run untrusted.
    fake.inject(
        Some(FakeOp::Exists),
        Some(&ekey(&revs[2])),
        1,
        Fault::Http {
            status: 500,
            code: None,
        },
    );
    dev.prune(&fake, NOW + 1, true);
    assert_eq!(exists_calls(&fake), 3);
    assert!((0..5).all(|i| on_disk(dev, i) && !purged(dev, i)));

    // A healthy run: the 404s are purges, deleted at once; the object still present is kept.
    fake.clear_log();
    dev.prune(&fake, NOW + 2, true);
    assert_eq!(exists_calls(&fake), 3);
    assert!(purged(dev, 0) && purged(dev, 1) && !purged(dev, 2));
    assert!(!on_disk(dev, 0) && !on_disk(dev, 1));
    assert!((2..5).all(|i| on_disk(dev, i)));
    // Answered objects are not checked again, and the answers survive a restart.
    dev.reopen();
    fake.clear_log();
    dev.prune(&fake, NOW + 3, true);
    assert_eq!(exists_calls(&fake), 0);
    assert!(purged(dev, 0) && purged(dev, 1));

    // The present object goes 30 days after it became unreachable (at NOW), not before.
    dev.prune(&fake, NOW + KEEP_SECS - 1, true);
    assert!(on_disk(dev, 2));
    dev.prune(&fake, NOW + KEEP_SECS, true);
    assert!(!on_disk(dev, 2));
    assert!(dev.vault.state().object(&revs[2]).is_none());
    assert!((3..5).all(|i| on_disk(dev, i)));
    assert_eq!(dev.content("a"), [4]);
    assert_eq!(exists_calls(&fake), 0);
}

// Crash matrix: a publish interrupted at each commit point, then a restart from the mirror
// directory and another sync.

/// A mirror directory's files by relative path, without `lock` and temporary files.
type Files = BTreeMap<String, Vec<u8>>;

fn snapshot(dir: &Path) -> Files {
    let mut out = Files::new();
    for sub in ["", "e"] {
        for e in fs::read_dir(dir.join(sub)).unwrap() {
            let e = e.unwrap();
            let name = e.file_name().into_string().unwrap();
            if e.file_type().unwrap().is_file() && name != "lock" && !name.starts_with(".tmp-") {
                let rel = if sub.is_empty() {
                    name
                } else {
                    format!("{sub}/{name}")
                };
                out.insert(rel, fs::read(e.path()).unwrap());
            }
        }
    }
    out
}

/// Where the publish is interrupted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Point {
    /// After the write-ahead state, before the index `PUT` is sent.
    BeforeIndexPut,
    /// After the index `PUT` landed, before its response arrived.
    AfterIndexPut,
    /// After the index `PUT` succeeded: the snapshot holds the write-ahead state, and the test
    /// combines it with the later `index` file.
    IndexFileNotState,
    /// When the publish fetches a changed header: the snapshot holds the state from before the
    /// header was accepted, and the test combines it with the later `header` file. The index
    /// `PUT` fails, so only the restarted sync publishes.
    HeaderFileNotState,
}

/// A backend that snapshots a mirror directory at a crash point.
struct Crashing<'a> {
    inner: &'a FakeBackend,
    dir: PathBuf,
    at: Point,
    snap: Mutex<Option<Files>>,
}

impl Crashing<'_> {
    fn take(&self) {
        let mut s = self.snap.lock().unwrap();
        if s.is_none() {
            *s = Some(snapshot(&self.dir));
        }
    }
}

impl Backend for Crashing<'_> {
    fn get(&self, key: &str, inm: Option<&Etag>, max: usize) -> Result<Get, StoreError> {
        if key == "header" && self.at == Point::HeaderFileNotState {
            self.take();
        }
        self.inner.get(key, inm, max)
    }

    fn exists(&self, key: &str) -> Result<bool, StoreError> {
        self.inner.exists(key)
    }

    fn create(&self, key: &str, bytes: &[u8]) -> Result<Put, StoreError> {
        self.inner.create(key, bytes)
    }

    fn replace(&self, key: &str, bytes: &[u8], expected: &Etag) -> Result<Put, StoreError> {
        if key != "index" {
            return self.inner.replace(key, bytes, expected);
        }
        match self.at {
            Point::BeforeIndexPut | Point::HeaderFileNotState => {
                self.take();
                Err(StoreError::Offline(OfflineKind::Connect))
            }
            Point::AfterIndexPut => {
                assert!(matches!(
                    self.inner.replace(key, bytes, expected),
                    Ok(Put::Written { .. })
                ));
                self.take();
                Err(StoreError::Offline(OfflineKind::ConnectionLost))
            }
            Point::IndexFileNotState => {
                self.take();
                self.inner.replace(key, bytes, expected)
            }
        }
    }

    fn list(&self, prefix: &str) -> Result<Vec<String>, StoreError> {
        self.inner.list(prefix)
    }

    fn delete(&self, key: &str) -> Result<vlt_store::Delete, StoreError> {
        self.inner.delete(key)
    }
}

/// Replace the mirror directory's files with `snap`, overlaid with the current versions of the
/// files named in `newer`: the disk as a crash at that point leaves it. Then restart the device.
fn crash_and_reopen(dev: &mut common::Device, snap: Files, newer: &[&str]) {
    let now = snapshot(&dev.dir);
    dev.mirror = None;
    let mut disk = snap;
    for name in newer {
        disk.insert((*name).to_owned(), now[*name].clone());
    }
    for name in now.keys() {
        fs::remove_file(dev.dir.join(name)).unwrap();
    }
    for (name, bytes) in &disk {
        fs::write(dev.dir.join(name), bytes).unwrap();
    }
    dev.reopen();
}

fn index_seq(fake: &FakeBackend) -> u64 {
    index_prefix(&fake.current("index").unwrap())
        .unwrap()
        .index_seq
}

/// A publish by device 1 crashes at `at`; after a restart, two syncs leave it published exactly
/// once, with no notice or integrity error, and device 2 reads the entry.
fn crash_at(at: Point) {
    let fake = FakeBackend::new();
    let mut d = world(&fake, 3);
    if at == Point::HeaderFileNotState {
        // Device 0 rewrites the header (same keys, next header_seq), unannounced by any index.
        let v = &d[0].vault;
        let parsed = vlt_core::parse_header(v.header_bytes()).unwrap();
        let draft = HeaderDraft::from_verified(&parsed, v.header(), v.keys()).unwrap();
        fake.put_admin("header", &draft.encode().unwrap());
    }
    let seq0 = index_seq(&fake);
    d[1].put("a", b"v1", None);
    let crashing = Crashing {
        inner: &fake,
        dir: d[1].dir.clone(),
        at,
        snap: Mutex::new(None),
    };
    d[1].sync(&crashing).unwrap();
    let snap = crashing
        .snap
        .into_inner()
        .unwrap()
        .expect("crash point reached");
    let newer: &[&str] = match at {
        Point::BeforeIndexPut | Point::AfterIndexPut => &[],
        Point::IndexFileNotState => &["index"],
        Point::HeaderFileNotState => &["header"],
    };
    if !newer.is_empty() {
        assert_ne!(snap[newer[0]], snapshot(&d[1].dir)[newer[0]], "{at:?}");
    }
    crash_and_reopen(&mut d[1], snap, newer);
    for _ in 0..2 {
        let r = d[1].sync(&fake).unwrap();
        assert!(r.failure.is_none() && r.error.is_none(), "{at:?}: {r:?}");
        assert!(r.notices.is_empty(), "{at:?}: {:?}", r.notices);
    }
    assert!(d[1].vault.state().queue.is_empty(), "{at:?}");
    assert!(d[1].vault.state().notices.is_empty(), "{at:?}");
    assert_eq!(index_seq(&fake), seq0 + 1, "{at:?}");
    assert_eq!(d[1].content("a"), b"v1");
    d[2].sync(&fake).unwrap();
    assert_eq!(d[2].content("a"), b"v1");
    // The restarted device stays clean across another restart.
    d[1].reopen();
    assert_eq!(d[1].sync(&fake).unwrap().published, 0);
}

#[test]
fn crash_after_the_write_ahead_state_before_the_index_put() {
    crash_at(Point::BeforeIndexPut);
}

#[test]
fn crash_after_the_index_put_before_its_response() {
    crash_at(Point::AfterIndexPut);
}

#[test]
fn crash_after_the_index_file_before_the_state() {
    crash_at(Point::IndexFileNotState);
}

#[test]
fn crash_after_an_accepted_header_file_before_the_state() {
    crash_at(Point::HeaderFileNotState);
}

/// Device 0 queues a put: the object reaches `e/`, and the process dies before the state that
/// records the operation. The operation is lost; the stray object is harmless.
fn crash_between_enqueue_object_and_state(fake: &FakeBackend) -> (Vec<common::Device>, [u8; 16]) {
    let mut d = world(fake, 2);
    let seq0 = index_seq(fake);
    let q = d[0]
        .vault
        .put("a", b"lost", None, ExtList::new(), NOW)
        .unwrap();
    d[0].mirror().write_object(&q.object_id, &q.object).unwrap();
    d[0].reopen();
    assert!(d[0].vault.state().queue.is_empty());
    assert!(d[0].vault.state().object(&q.object_id).is_none());
    assert!(d[0].paths().is_empty());
    let r = d[0].sync(fake).unwrap();
    assert_eq!(r.published, 0);
    assert_eq!(index_seq(fake), seq0);
    // The user writes again; that write publishes once and reaches the other device.
    d[0].put("a", b"v1", None);
    assert_eq!(d[0].sync(fake).unwrap().published, 1);
    assert_eq!(index_seq(fake), seq0 + 1);
    assert!(d[0].vault.state().queue.is_empty());
    d[1].sync(fake).unwrap();
    assert_eq!(d[1].content("a"), b"v1");
    // The stray object never left the device and is never purge-checked.
    assert!(fake.current(&ekey(&q.object_id)).is_none());
    fake.clear_log();
    d[0].prune(fake, NOW, true);
    d[0].prune(fake, NOW + KEEP_SECS - 1, true);
    assert!(
        !fake
            .log()
            .iter()
            .any(|l| l.op == FakeOp::Exists && l.key == ekey(&q.object_id))
    );
    assert!(d[0].mirror().object(&q.object_id).unwrap().is_some());
    (d, q.object_id)
}

#[test]
fn crash_after_an_enqueued_object_before_the_state() {
    crash_between_enqueue_object_and_state(&FakeBackend::new());
}

#[test]
fn stray_object_from_an_interrupted_enqueue_is_pruned_after_30_days() {
    let fake = FakeBackend::new();
    let (mut d, stray) = crash_between_enqueue_object_and_state(&fake);
    // The first prune finds and records the stray; it is kept for 30 days from then.
    d[0].prune(&fake, NOW, true);
    assert!(d[0].mirror().object(&stray).unwrap().is_some());
    d[0].prune(&fake, NOW + KEEP_SECS - 1, true);
    assert!(d[0].mirror().object(&stray).unwrap().is_some());
    d[0].prune(&fake, NOW + KEEP_SECS, true);
    assert!(d[0].mirror().object(&stray).unwrap().is_none());
}
