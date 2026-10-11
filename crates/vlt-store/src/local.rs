//! The local store for a local vault: a directory holding objects under the bucket layout's keys,
//! without the prefix, as ciphertext only. See the spec's "Local backend".
//!
//! The etag is the hex SHA-256 of the bytes. Create writes a temporary file, `fsync`s it, links it
//! into place (failing if the name exists), and `fsync`s the directory. Compare and swap runs under
//! an exclusive lock on a stable lock file in the store, writes and `fsync`s a temporary file,
//! renames it over the old one, and `fsync`s the directory. Directories are created with mode
//! `0700` and files with `0600`.

use crate::backend::{Backend, Delete, Etag, Get, Put};
use crate::error::StoreError;
use crate::fsutil::{dir_builder, file_options, sync_dir, write_temp};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

/// The lock file that serialises compare-and-swap and delete. It is never renamed, so every
/// process locks the same inode.
const LOCK_FILE: &str = ".lock";
/// The subdirectories that hold write-once objects.
const SUBDIRS: [&str; 2] = ["e", "enroll"];

/// A local store rooted at a directory.
#[derive(Debug)]
pub struct LocalStore {
    root: PathBuf,
    on_nfs: bool,
}

/// The etag the local store gives `bytes`: their hex SHA-256.
pub fn local_etag(bytes: &[u8]) -> Etag {
    Etag(hex::encode(Sha256::digest(bytes)))
}

fn is_object_id(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_valid_key(key: &str) -> bool {
    match key.split_once('/') {
        None => key == "header" || key == "index",
        Some((dir, id)) => SUBDIRS.contains(&dir) && is_object_id(id),
    }
}

/// Whether a `statfs` file system type is NFS.
fn is_nfs_magic(f_type: i64) -> bool {
    const NFS_SUPER_MAGIC: i64 = 0x6969;
    f_type == NFS_SUPER_MAGIC
}

#[cfg(target_os = "linux")]
fn detect_nfs(path: &Path) -> bool {
    #[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
    rustix::fs::statfs(path).is_ok_and(|s| is_nfs_magic(s.f_type as i64))
}

#[cfg(not(target_os = "linux"))]
fn detect_nfs(_path: &Path) -> bool {
    false
}

impl LocalStore {
    /// Opens the store at `root`, creating the directory with mode `0700` if it does not exist.
    pub fn open(root: &Path) -> Result<LocalStore, StoreError> {
        match dir_builder().recursive(true).create(root) {
            Ok(()) => {}
            Err(e) => return Err(StoreError::io(&e, "")),
        }
        Ok(LocalStore {
            root: root.to_owned(),
            on_nfs: detect_nfs(root),
        })
    }

    /// The store directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Whether the store is on NFS, where `flock` is unreliable. The CLI warns.
    pub fn on_nfs(&self) -> bool {
        self.on_nfs
    }

    fn path(&self, key: &str) -> Result<PathBuf, StoreError> {
        if !is_valid_key(key) {
            return Err(StoreError::Io {
                kind: io::ErrorKind::InvalidInput,
                key: key.to_owned(),
            });
        }
        Ok(self.root.join(key))
    }

    /// The directory that holds `path`, created (and made durable) if needed.
    fn parent_of(&self, path: &Path) -> io::Result<PathBuf> {
        let parent = path.parent().unwrap_or(&self.root).to_owned();
        if parent != self.root {
            match dir_builder().create(&parent) {
                Ok(()) => sync_dir(&self.root)?,
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
        Ok(parent)
    }

    fn lock(&self) -> io::Result<File> {
        let f = file_options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.root.join(LOCK_FILE))?;
        f.lock()?;
        Ok(f)
    }

    fn create_inner(&self, path: &Path, bytes: &[u8]) -> io::Result<bool> {
        let parent = self.parent_of(path)?;
        let tmp = write_temp(&parent, bytes)?;
        let linked = fs::hard_link(&tmp, path);
        let _ = fs::remove_file(&tmp);
        match linked {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Ok(false),
            Err(e) => return Err(e),
        }
        sync_dir(&parent)?;
        Ok(true)
    }

    fn replace_inner(&self, path: &Path, bytes: &[u8], expected: &Etag) -> io::Result<bool> {
        let _lock = self.lock()?;
        let current = match fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e),
        };
        if local_etag(&current) != *expected {
            return Ok(false);
        }
        let parent = self.parent_of(path)?;
        let tmp = write_temp(&parent, bytes)?;
        if let Err(e) = fs::rename(&tmp, path) {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
        sync_dir(&parent)?;
        Ok(true)
    }

    fn list_dir(&self, dir: &str, out: &mut Vec<String>) -> io::Result<()> {
        let entries = match fs::read_dir(self.root.join(dir)) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        for entry in entries {
            let name = entry?.file_name();
            if let Some(name) = name.to_str().filter(|n| is_object_id(n)) {
                out.push(format!("{dir}/{name}"));
            }
        }
        Ok(())
    }
}

impl Backend for LocalStore {
    fn get(
        &self,
        key: &str,
        if_none_match: Option<&Etag>,
        max_len: usize,
    ) -> Result<Get, StoreError> {
        let path = self.path(key)?;
        let err = |e: io::Error| StoreError::io(&e, key);
        let mut f = match File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Get::NotFound),
            Err(e) => return Err(err(e)),
        };
        let too_large = || StoreError::TooLarge {
            key: key.to_owned(),
        };
        if f.metadata().map_err(err)?.len() > max_len as u64 {
            return Err(too_large());
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut f)
            .take(max_len as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(err)?;
        if bytes.len() > max_len {
            return Err(too_large());
        }
        let etag = local_etag(&bytes);
        if if_none_match == Some(&etag) {
            return Ok(Get::NotModified);
        }
        Ok(Get::Found { bytes, etag })
    }

    fn exists(&self, key: &str) -> Result<bool, StoreError> {
        let path = self.path(key)?;
        match fs::metadata(&path) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(StoreError::io(&e, key)),
        }
    }

    fn create(&self, key: &str, bytes: &[u8]) -> Result<Put, StoreError> {
        let path = self.path(key)?;
        match self.create_inner(&path, bytes) {
            Ok(true) => Ok(Put::Written {
                etag: local_etag(bytes),
            }),
            Ok(false) => Ok(Put::PreconditionFailed),
            Err(e) => Err(StoreError::io(&e, key)),
        }
    }

    fn replace(&self, key: &str, bytes: &[u8], expected: &Etag) -> Result<Put, StoreError> {
        let path = self.path(key)?;
        match self.replace_inner(&path, bytes, expected) {
            Ok(true) => Ok(Put::Written {
                etag: local_etag(bytes),
            }),
            Ok(false) => Ok(Put::PreconditionFailed),
            Err(e) => Err(StoreError::io(&e, key)),
        }
    }

    fn list(&self, prefix: &str) -> Result<Vec<String>, StoreError> {
        let mut keys = Vec::new();
        for top in ["header", "index"] {
            if self.root.join(top).is_file() {
                keys.push(top.to_owned());
            }
        }
        for dir in SUBDIRS {
            self.list_dir(dir, &mut keys)
                .map_err(|e| StoreError::io(&e, ""))?;
        }
        keys.retain(|k| k.starts_with(prefix));
        keys.sort();
        Ok(keys)
    }

    fn delete(&self, key: &str) -> Result<Delete, StoreError> {
        let path = self.path(key)?;
        let err = |e: io::Error| StoreError::io(&e, key);
        let _lock = self.lock().map_err(err)?;
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Delete::NotFound),
            Err(e) => return Err(err(e)),
        }
        sync_dir(path.parent().unwrap_or(&self.root)).map_err(err)?;
        Ok(Delete::Deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    const E1: &str = "e/00112233445566778899aabbccddeeff";
    const E2: &str = "e/ffeeddccbbaa99887766554433221100";
    const R1: &str = "enroll/0123456789abcdef0123456789abcdef";

    fn store() -> (tempfile::TempDir, LocalStore) {
        let dir = tempfile::tempdir().unwrap();
        let s = LocalStore::open(&dir.path().join("stores/abc")).unwrap();
        (dir, s)
    }

    #[test]
    fn etag_is_hex_sha256() {
        let (_d, s) = store();
        let Put::Written { etag } = s.create("header", b"abc").unwrap() else {
            panic!()
        };
        assert_eq!(
            etag.0,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let Get::Found { bytes, etag: got } = s.get("header", None, 100).unwrap() else {
            panic!()
        };
        assert_eq!(bytes, b"abc");
        assert_eq!(got, etag);
    }

    #[test]
    fn create_refuses_existing() {
        let (_d, s) = store();
        assert!(matches!(s.create(E1, b"one").unwrap(), Put::Written { .. }));
        assert_eq!(s.create(E1, b"two").unwrap(), Put::PreconditionFailed);
        let Get::Found { bytes, .. } = s.get(E1, None, 100).unwrap() else {
            panic!()
        };
        assert_eq!(bytes, b"one");
        // No temporary file is left behind.
        let names: Vec<_> = fs::read_dir(s.root().join("e"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 1);
    }

    #[test]
    fn replace_compares_etag() {
        let (_d, s) = store();
        let Put::Written { etag: e1 } = s.create("index", b"v1").unwrap() else {
            panic!()
        };
        assert_eq!(
            s.replace("index", b"v2", &local_etag(b"other")).unwrap(),
            Put::PreconditionFailed
        );
        let Put::Written { etag: e2 } = s.replace("index", b"v2", &e1).unwrap() else {
            panic!()
        };
        assert_eq!(e2, local_etag(b"v2"));
        assert_eq!(
            s.replace("index", b"v3", &e1).unwrap(),
            Put::PreconditionFailed
        );
        assert_eq!(
            s.replace("header", b"v1", &e1).unwrap(),
            Put::PreconditionFailed
        );
        let Get::Found { bytes, .. } = s.get("index", None, 100).unwrap() else {
            panic!()
        };
        assert_eq!(bytes, b"v2");
    }

    #[test]
    fn get_size_cap_and_not_modified() {
        let (_d, s) = store();
        s.create("header", b"0123456789").unwrap();
        assert_eq!(
            s.get("header", None, 9).unwrap_err(),
            StoreError::TooLarge {
                key: "header".into()
            }
        );
        assert!(matches!(
            s.get("header", None, 10).unwrap(),
            Get::Found { .. }
        ));
        let etag = local_etag(b"0123456789");
        assert_eq!(s.get("header", Some(&etag), 10).unwrap(), Get::NotModified);
        assert_eq!(s.get("index", None, 10).unwrap(), Get::NotFound);
    }

    #[test]
    fn list_returns_only_objects() {
        let (_d, s) = store();
        s.create(E2, b"x").unwrap();
        s.create(E1, b"x").unwrap();
        s.create(R1, b"x").unwrap();
        s.create("index", b"x").unwrap();
        fs::write(s.root().join("e/.tmp-stray"), b"x").unwrap();
        fs::write(s.root().join("stray"), b"x").unwrap();
        assert_eq!(s.list("").unwrap(), vec![E1, E2, R1, "index"]);
        assert_eq!(s.list("e/").unwrap(), vec![E1, E2]);
        assert_eq!(s.list("enroll/").unwrap(), vec![R1]);
        assert!(s.exists(E1).unwrap());
        assert!(!s.exists("header").unwrap());
    }

    #[test]
    fn delete_removes() {
        let (_d, s) = store();
        s.create(E1, b"x").unwrap();
        assert_eq!(s.delete(E1).unwrap(), Delete::Deleted);
        assert_eq!(s.delete(E1).unwrap(), Delete::NotFound);
        assert_eq!(s.get(E1, None, 10).unwrap(), Get::NotFound);
    }

    #[test]
    fn invalid_keys_are_refused() {
        let (_d, s) = store();
        for key in [
            "../header",
            "e/../../x",
            "e/00112233445566778899AABBCCDDEEFF",
            "e/0011",
            ".lock",
            "x/00112233445566778899aabbccddeeff",
            "",
        ] {
            assert_eq!(
                s.create(key, b"x").unwrap_err(),
                StoreError::Io {
                    kind: io::ErrorKind::InvalidInput,
                    key: key.into()
                },
                "{key}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn modes() {
        use std::os::unix::fs::PermissionsExt;
        let (_d, s) = store();
        s.create(E1, b"x").unwrap();
        let e = s.create("index", b"x").unwrap();
        let Put::Written { etag } = e else { panic!() };
        s.replace("index", b"y", &etag).unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(s.root()), 0o700);
        assert_eq!(mode(&s.root().join("e")), 0o700);
        assert_eq!(mode(&s.root().join(E1)), 0o600);
        assert_eq!(mode(&s.root().join("index")), 0o600);
        assert_eq!(mode(&s.root().join(LOCK_FILE)), 0o600);
    }

    #[test]
    fn nfs_magic() {
        assert!(is_nfs_magic(0x6969));
        assert!(!is_nfs_magic(0xEF53)); // ext4
        assert!(!is_nfs_magic(0x0102_1994)); // tmpfs
    }

    #[test]
    fn tempdir_is_not_nfs() {
        let (_d, s) = store();
        assert!(!s.on_nfs());
    }

    const THREADS: usize = 16;

    #[test]
    fn concurrent_create_has_one_winner() {
        for round in 0..20 {
            let (_d, s) = store();
            let s = Arc::new(s);
            let barrier = Arc::new(Barrier::new(THREADS));
            let handles: Vec<_> = (0..THREADS)
                .map(|i| {
                    let (s, barrier) = (Arc::clone(&s), Arc::clone(&barrier));
                    thread::spawn(move || {
                        barrier.wait();
                        s.create(E1, format!("{round}-{i}").as_bytes()).unwrap()
                    })
                })
                .collect();
            let results: Vec<Put> = handles.into_iter().map(|h| h.join().unwrap()).collect();
            let winners: Vec<_> = results
                .iter()
                .filter_map(|r| match r {
                    Put::Written { etag } => Some(etag.clone()),
                    Put::PreconditionFailed => None,
                })
                .collect();
            assert_eq!(winners.len(), 1, "round {round}");
            let Get::Found { etag, .. } = s.get(E1, None, 100).unwrap() else {
                panic!()
            };
            assert_eq!(etag, winners[0]);
        }
    }

    #[test]
    fn concurrent_replace_has_one_winner_per_etag() {
        let (_d, s) = store();
        let s = Arc::new(s);
        let Put::Written { etag: mut current } = s.create("index", b"start").unwrap() else {
            panic!()
        };
        for round in 0..20 {
            let barrier = Arc::new(Barrier::new(THREADS));
            let handles: Vec<_> = (0..THREADS)
                .map(|i| {
                    let (s, barrier, expected) =
                        (Arc::clone(&s), Arc::clone(&barrier), current.clone());
                    thread::spawn(move || {
                        barrier.wait();
                        s.replace("index", format!("{round}-{i}").as_bytes(), &expected)
                            .unwrap()
                    })
                })
                .collect();
            let winners: Vec<Etag> = handles
                .into_iter()
                .filter_map(|h| match h.join().unwrap() {
                    Put::Written { etag } => Some(etag),
                    Put::PreconditionFailed => None,
                })
                .collect();
            assert_eq!(winners.len(), 1, "round {round}");
            let Get::Found { etag, .. } = s.get("index", None, 100).unwrap() else {
                panic!()
            };
            assert_eq!(etag, winners[0]);
            current = etag;
        }
    }

    #[test]
    fn two_handles_on_one_store_exclude_each_other() {
        // Separate `LocalStore` values model separate processes: each opens its own lock file
        // description, so `flock` excludes them from each other.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("s");
        let a = Arc::new(LocalStore::open(&root).unwrap());
        let b = Arc::new(LocalStore::open(&root).unwrap());
        let Put::Written { etag } = a.create("index", b"0").unwrap() else {
            panic!()
        };
        let barrier = Arc::new(Barrier::new(2));
        let run = |s: Arc<LocalStore>, tag: &'static [u8]| {
            let (barrier, etag) = (Arc::clone(&barrier), etag.clone());
            thread::spawn(move || {
                barrier.wait();
                s.replace("index", tag, &etag).unwrap()
            })
        };
        let (ha, hb) = (run(a, b"a"), run(b, b"b"));
        let wins = [ha.join().unwrap(), hb.join().unwrap()]
            .iter()
            .filter(|p| matches!(p, Put::Written { .. }))
            .count();
        assert_eq!(wins, 1);
    }
}
