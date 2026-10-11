//! A multi-device world over any backend: device 0 creates a vault, the others join, and each has
//! its own mirror directory. Shared by the driver tests and the RustFS integration tests.
#![allow(dead_code)]

use std::path::PathBuf;
use std::time::Duration;
use tempfile::TempDir;
use vlt_core::ext::ExtList;
use vlt_core::header::{DeviceInfo, HeaderDraft, parse_header};
use vlt_core::keys::{device_public, generate_secret_key, generate_vault_key};
use vlt_core::mirror_state::HistoryMode;
use vlt_core::secret::DeviceSecrets;
use vlt_core::session::{SyncOptions, SyncReport};
use vlt_core::vault::{Vault, find};
use vlt_store::driver::{DriveError, DriverOptions, prune, sync_once};
use vlt_store::mirror::Mirror;
use vlt_store::{Backend, Etag, Put};

pub const NOW: i64 = 1_800_000_000;

pub struct Device {
    pub id: [u8; 16],
    x25519: [u8; 32],
    seed: [u8; 64],
    pub vault: Vault,
    pub mirror: Option<Mirror>,
    pub dir: PathBuf,
    _tmp: TempDir,
}

fn rand<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).unwrap();
    b
}

impl Device {
    pub fn secrets(&self) -> DeviceSecrets {
        DeviceSecrets::from_bytes(self.x25519, self.seed)
    }

    pub fn mirror(&self) -> &Mirror {
        self.mirror.as_ref().expect("mirror open")
    }

    pub fn sync(&mut self, backend: &dyn Backend) -> Result<SyncReport, DriveError> {
        self.sync_with(backend, false)
    }

    pub fn sync_with(
        &mut self,
        backend: &dyn Backend,
        check_header: bool,
    ) -> Result<SyncReport, DriveError> {
        let (id, secrets) = (self.id, self.secrets());
        let unlock = move |h: &[u8]| parse_header(h)?.unlock_with_device(&id, &secrets);
        sync_once(
            &mut self.vault,
            SyncOptions {
                publish: true,
                check_header,
                now: NOW,
            },
            backend,
            self.mirror.as_ref().expect("mirror open"),
            &unlock,
            DriverOptions {
                backoff_base: Duration::ZERO,
            },
        )
    }

    /// Run retention and purge checks; `store_ok` as a caller sets it from a clean sync.
    pub fn prune(&mut self, backend: &dyn Backend, now: i64, store_ok: bool) {
        prune(
            &mut self.vault,
            backend,
            self.mirror.as_ref().expect("mirror open"),
            now,
            store_ok,
        )
        .unwrap();
    }

    pub fn put(&mut self, path: &str, content: &[u8], parent: Option<[u8; 16]>) -> [u8; 16] {
        let q = self
            .vault
            .put(path, content, parent, ExtList::new(), NOW)
            .unwrap();
        self.mirror().write_object(&q.object_id, &q.object).unwrap();
        self.mirror()
            .write_state(&self.vault.commit().unwrap())
            .unwrap();
        q.object_id
    }

    pub fn head(&self, path: &str) -> [u8; 16] {
        find(&self.vault.view().unwrap(), path)
            .unwrap()
            .head_object_id
    }

    pub fn content(&self, path: &str) -> Vec<u8> {
        let view = self.vault.view().unwrap();
        let e = find(&view, path).unwrap();
        let b = self
            .mirror()
            .object(&e.head_object_id)
            .unwrap()
            .expect("object in mirror");
        self.vault.open_entry_of(e, &b).unwrap().1.content.to_vec()
    }

    pub fn paths(&self) -> Vec<String> {
        self.vault
            .view()
            .unwrap()
            .entries
            .iter()
            .map(|e| e.path.clone())
            .collect()
    }

    /// Drop the in-memory vault and the lock, then reopen both from the mirror directory.
    pub fn reopen(&mut self) {
        self.mirror = None;
        let m = Mirror::open(&self.dir).unwrap();
        self.vault = Vault::open(
            self.id,
            &self.secrets(),
            &m.header().unwrap(),
            &m.index().unwrap(),
            &m.state().unwrap(),
        )
        .unwrap();
        self.mirror = Some(m);
    }
}

fn written(p: Put) -> Etag {
    match p {
        Put::Written { etag } => etag,
        Put::PreconditionFailed => panic!("precondition failed"),
    }
}

/// Create a vault with `n` enrolled devices on `backend`, at the floor KDF parameters.
pub fn world(backend: &dyn Backend, n: usize) -> Vec<Device> {
    let keys: Vec<([u8; 16], [u8; 32], [u8; 64])> =
        (0..n).map(|_| (rand(), rand(), rand())).collect();
    let vault_id: [u8; 16] = rand();
    let mut d = HeaderDraft::new_vault(
        vault_id,
        keys[0].0,
        generate_vault_key().unwrap(),
        generate_secret_key().unwrap(),
    );
    d.set_password("correct horse battery staple", 65536, 3, 1, false)
        .unwrap();
    for (i, (id, x, s)) in keys.iter().enumerate() {
        let p = device_public(&DeviceSecrets::from_bytes(*x, *s));
        d.add_device(
            DeviceInfo {
                device_id: *id,
                kind: 1,
                label: format!("dev{i}"),
                enrolled_header_seq: 1,
                enrolled_unix: NOW,
                enrolled_by: [0; 16],
            },
            p.device_pk,
            &p.kem_ek,
        )
        .unwrap();
    }
    let header = d.encode().unwrap();
    let (id0, x0, s0) = keys[0];
    let (mut v0, index) = Vault::create(
        id0,
        &DeviceSecrets::from_bytes(x0, s0),
        &header,
        HistoryMode::Full,
        NOW,
    )
    .unwrap();
    let he = written(backend.create("header", &header).unwrap());
    let ie = written(backend.create("index", &index).unwrap());
    v0.set_etags(Some(he.0.clone()), Some(ie.0.clone()));
    let mut first = Some(v0);
    let mut out = Vec::new();
    for (i, (id, x, s)) in keys.into_iter().enumerate() {
        let vault = if i == 0 {
            first.take().expect("device 0")
        } else {
            Vault::join(
                id,
                &DeviceSecrets::from_bytes(x, s),
                &header,
                Some(he.0.clone()),
                None,
                &index,
                Some(ie.0.clone()),
                HistoryMode::Full,
            )
            .unwrap()
        };
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("mirror");
        let mirror = Mirror::create(&dir).unwrap();
        mirror
            .write_initial(&header, &index, &vault.commit().unwrap())
            .unwrap();
        out.push(Device {
            id,
            x25519: x,
            seed: s,
            vault,
            mirror: Some(mirror),
            dir,
            _tmp: tmp,
        });
    }
    out
}
