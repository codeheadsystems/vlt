//! The mirror directory, `$XDG_DATA_HOME/vlt/<vault_id hex>/`, from the spec's "Local mirror and
//! write queue": `header`, `index`, `e/<object_id hex>`, `state`, and `lock`.
//!
//! Every file is the bucket's ciphertext or the sealed `state`, so the mirror holds no plaintext.
//! Each write goes to a temporary file that is `fsync`ed and renamed into place, followed by an
//! `fsync` of the directory. [`Mirror::apply`] writes a commit in the spec's order: entry objects,
//! `header`, `index`, then `state`, which is the commit record. One process owns a mirror at a
//! time, through an exclusive lock on the stable `lock` file that a [`Mirror`] holds while it
//! lives.

use crate::error::StoreError;
use crate::fsutil::{dir_builder, file_options, sync_dir, write_temp};
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use vlt_core::session::Commit;

const LOCK_FILE: &str = "lock";
const OBJECTS: &str = "e";

/// An open, locked mirror directory.
pub struct Mirror {
    dir: PathBuf,
    _lock: File,
}

fn io_err(what: &str) -> impl Fn(io::Error) -> StoreError + '_ {
    move |e| StoreError::Io {
        kind: e.kind(),
        key: what.to_owned(),
    }
}

fn hex_id(id: &[u8; 16]) -> String {
    hex::encode(id)
}

impl Mirror {
    /// Create a new mirror directory (mode `0700`) and lock it. Fails if it already exists.
    pub fn create(dir: &Path) -> Result<Mirror, StoreError> {
        dir_builder().create(dir).map_err(io_err("mirror"))?;
        dir_builder()
            .create(dir.join(OBJECTS))
            .map_err(io_err("mirror"))?;
        if let Some(parent) = dir.parent() {
            sync_dir(parent).map_err(io_err("mirror"))?;
        }
        sync_dir(dir).map_err(io_err("mirror"))?;
        Mirror::open(dir)
    }

    /// Open and lock an existing mirror directory. Another owner makes this fail with
    /// [`io::ErrorKind::WouldBlock`].
    pub fn open(dir: &Path) -> Result<Mirror, StoreError> {
        let f = file_options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(dir.join(LOCK_FILE))
            .map_err(io_err(LOCK_FILE))?;
        match f.try_lock() {
            Ok(()) => {}
            Err(fs::TryLockError::WouldBlock) => {
                return Err(StoreError::Io {
                    kind: io::ErrorKind::WouldBlock,
                    key: LOCK_FILE.into(),
                });
            }
            Err(fs::TryLockError::Error(e)) => return Err(io_err(LOCK_FILE)(e)),
        }
        Ok(Mirror {
            dir: dir.to_owned(),
            _lock: f,
        })
    }

    /// The directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn read(&self, name: &str) -> Result<Option<Vec<u8>>, StoreError> {
        match fs::read(self.dir.join(name)) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_err(name)(e)),
        }
    }

    fn read_required(&self, name: &str) -> Result<Vec<u8>, StoreError> {
        self.read(name)?.ok_or(StoreError::Io {
            kind: io::ErrorKind::NotFound,
            key: name.into(),
        })
    }

    /// The `header` file.
    pub fn header(&self) -> Result<Vec<u8>, StoreError> {
        self.read_required("header")
    }

    /// The `index` file.
    pub fn index(&self) -> Result<Vec<u8>, StoreError> {
        self.read_required("index")
    }

    /// The `state` file.
    pub fn state(&self) -> Result<Vec<u8>, StoreError> {
        self.read_required("state")
    }

    /// An entry object, if the mirror holds it.
    pub fn object(&self, id: &[u8; 16]) -> Result<Option<Vec<u8>>, StoreError> {
        self.read(&format!("{OBJECTS}/{}", hex_id(id)))
    }

    fn write(&self, dir: &Path, name: &str, bytes: &[u8]) -> Result<(), StoreError> {
        let tmp = write_temp(dir, bytes).map_err(io_err(name))?;
        if let Err(e) = fs::rename(&tmp, dir.join(name)) {
            let _ = fs::remove_file(&tmp);
            return Err(io_err(name)(e));
        }
        Ok(())
    }

    /// Write an entry object queued by a write, before the state that references it.
    pub fn write_object(&self, id: &[u8; 16], bytes: &[u8]) -> Result<(), StoreError> {
        let dir = self.dir.join(OBJECTS);
        self.write(&dir, &hex_id(id), bytes)?;
        sync_dir(&dir).map_err(io_err(OBJECTS))
    }

    /// Write the `state` file alone, after a queued write or other bookkeeping.
    pub fn write_state(&self, bytes: &[u8]) -> Result<(), StoreError> {
        self.write(&self.dir, "state", bytes)?;
        sync_dir(&self.dir).map_err(io_err("state"))
    }

    /// Write a commit in the spec's order: entry objects, `header`, `index`, then `state`.
    pub fn apply(&self, c: &Commit) -> Result<(), StoreError> {
        if !c.objects.is_empty() {
            let dir = self.dir.join(OBJECTS);
            for (id, b) in &c.objects {
                self.write(&dir, &hex_id(id), b)?;
            }
            sync_dir(&dir).map_err(io_err(OBJECTS))?;
        }
        if let Some(h) = &c.header {
            self.write(&self.dir, "header", h)?;
            sync_dir(&self.dir).map_err(io_err("header"))?;
        }
        if let Some(i) = &c.index {
            self.write(&self.dir, "index", i)?;
            sync_dir(&self.dir).map_err(io_err("index"))?;
        }
        self.write_state(&c.state)
    }

    /// Write a new vault's first files: `header`, `index`, then `state`.
    pub fn write_initial(
        &self,
        header: &[u8],
        index: &[u8],
        state: &[u8],
    ) -> Result<(), StoreError> {
        self.apply(&Commit {
            objects: Vec::new(),
            header: Some(header.to_vec()),
            index: Some(index.to_vec()),
            state: state.to_vec(),
        })
    }

    /// The IDs of every entry object file in `e/`. Other names, such as temporary files, are
    /// skipped.
    pub fn object_ids(&self) -> Result<Vec<[u8; 16]>, StoreError> {
        let dir = self.dir.join(OBJECTS);
        let mut out = Vec::new();
        for e in fs::read_dir(&dir).map_err(io_err(OBJECTS))? {
            let e = e.map_err(io_err(OBJECTS))?;
            let name = e.file_name();
            let Some(name) = name.to_str() else { continue };
            let mut id = [0u8; 16];
            if name.len() == 32 && hex::decode_to_slice(name, &mut id).is_ok() {
                out.push(id);
            }
        }
        out.sort();
        Ok(out)
    }

    /// Delete an entry object's file, for retention and purges.
    pub fn delete_object(&self, id: &[u8; 16]) -> Result<(), StoreError> {
        let name = format!("{OBJECTS}/{}", hex_id(id));
        match fs::remove_file(self.dir.join(&name)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io_err(&name)(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::process::{Command, Stdio};

    const ID: [u8; 16] = [0xab; 16];

    fn commit(tag: u8) -> Commit {
        Commit {
            objects: vec![(ID, vec![tag; 3])],
            header: Some(vec![tag; 4]),
            index: Some(vec![tag; 5]),
            state: vec![tag; 6],
        }
    }

    fn fresh() -> (tempfile::TempDir, Mirror) {
        let tmp = tempfile::tempdir().unwrap();
        let m = Mirror::create(&tmp.path().join("m")).unwrap();
        m.apply(&commit(1)).unwrap();
        (tmp, m)
    }

    fn files(m: &Mirror) -> (Option<Vec<u8>>, Vec<u8>, Vec<u8>, Vec<u8>) {
        (
            m.object(&ID).unwrap(),
            m.header().unwrap(),
            m.index().unwrap(),
            m.state().unwrap(),
        )
    }

    #[cfg(unix)]
    #[test]
    fn directories_are_0700_and_files_0600() {
        use std::os::unix::fs::PermissionsExt;
        let (_tmp, m) = fresh();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(m.dir()), 0o700);
        assert_eq!(mode(&m.dir().join(OBJECTS)), 0o700);
        for f in ["header", "index", "state", LOCK_FILE] {
            assert_eq!(mode(&m.dir().join(f)), 0o600, "{f}");
        }
        assert_eq!(mode(&m.dir().join(OBJECTS).join(hex_id(&ID))), 0o600);
        m.write_object(&[1; 16], b"x").unwrap();
        assert_eq!(mode(&m.dir().join(OBJECTS).join(hex_id(&[1; 16]))), 0o600);
    }

    #[test]
    fn create_refuses_an_existing_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("m");
        fs::create_dir(&dir).unwrap();
        match Mirror::create(&dir) {
            Err(StoreError::Io { kind, .. }) => assert_eq!(kind, io::ErrorKind::AlreadyExists),
            _ => panic!("created over an existing directory"),
        }
        let (_tmp, m) = fresh();
        drop(m);
        assert!(Mirror::create(&_tmp.path().join("m")).is_err());
    }

    #[test]
    fn deleting_a_missing_object_is_ok() {
        let (_tmp, m) = fresh();
        m.delete_object(&ID).unwrap();
        assert_eq!(m.object(&ID).unwrap(), None);
        m.delete_object(&ID).unwrap();
        m.delete_object(&[7; 16]).unwrap();
    }

    /// Put a directory where `name` goes, so the rename onto it fails and `apply` stops there.
    fn block(m: &Mirror, name: &str) {
        let p = m.dir().join(name);
        let _ = fs::remove_file(&p);
        fs::create_dir(&p).unwrap();
        fs::write(p.join("keep"), b"").unwrap();
    }

    #[test]
    fn apply_writes_objects_header_index_then_state() {
        // A failure at each file leaves every earlier file new and every later file old.
        let (_tmp, m) = fresh();
        block(&m, "state");
        assert!(m.apply(&commit(2)).is_err());
        assert_eq!(m.object(&ID).unwrap(), Some(vec![2; 3]));
        assert_eq!(m.header().unwrap(), vec![2; 4]);
        assert_eq!(m.index().unwrap(), vec![2; 5]);

        let (_tmp, m) = fresh();
        block(&m, "index");
        assert!(m.apply(&commit(2)).is_err());
        assert_eq!(m.object(&ID).unwrap(), Some(vec![2; 3]));
        assert_eq!(m.header().unwrap(), vec![2; 4]);
        assert_eq!(m.state().unwrap(), vec![1; 6]);

        let (_tmp, m) = fresh();
        block(&m, "header");
        assert!(m.apply(&commit(2)).is_err());
        assert_eq!(m.object(&ID).unwrap(), Some(vec![2; 3]));
        assert_eq!(m.index().unwrap(), vec![1; 5]);
        assert_eq!(m.state().unwrap(), vec![1; 6]);

        let (_tmp, m) = fresh();
        block(&m, &format!("{OBJECTS}/{}", hex_id(&ID)));
        assert!(m.apply(&commit(2)).is_err());
        assert_eq!(m.header().unwrap(), vec![1; 4]);
        assert_eq!(m.index().unwrap(), vec![1; 5]);
        assert_eq!(m.state().unwrap(), vec![1; 6]);

        // Without a failure every file is new, and no temporary file is left behind.
        let (_tmp, m) = fresh();
        m.apply(&commit(3)).unwrap();
        assert_eq!(
            files(&m),
            (Some(vec![3; 3]), vec![3; 4], vec![3; 5], vec![3; 6])
        );
        for d in [m.dir().to_owned(), m.dir().join(OBJECTS)] {
            for e in fs::read_dir(d).unwrap() {
                let name = e.unwrap().file_name();
                assert!(!name.to_string_lossy().starts_with(".tmp-"), "{name:?}");
            }
        }
    }

    #[test]
    fn stale_temporary_files_do_not_break_reopen() {
        let (tmp, m) = fresh();
        let before = files(&m);
        fs::write(m.dir().join(".tmp-00ff"), b"half a state").unwrap();
        fs::write(m.dir().join(OBJECTS).join(".tmp-00ff"), b"half an object").unwrap();
        drop(m);
        let m = Mirror::open(&tmp.path().join("m")).unwrap();
        assert_eq!(files(&m), before);
        m.apply(&commit(4)).unwrap();
        assert_eq!(m.state().unwrap(), vec![4; 6]);
    }

    /// Runs only as the child of `lock_excludes_another_process`: holds the mirror's lock until
    /// its standard input closes.
    #[test]
    fn lock_holder_child() {
        let Some(dir) = std::env::var_os("VLT_TEST_LOCK_HOLDER") else {
            return;
        };
        let m = Mirror::open(Path::new(&dir)).unwrap();
        // Straight to the pipe, past the harness's output capture, on a line of its own.
        let mut out = io::stdout();
        out.write_all(b"\nVLT-LOCK-HELD\n").unwrap();
        out.flush().unwrap();
        let _ = io::stdin().read_to_end(&mut Vec::new());
        drop(m);
    }

    #[test]
    fn lock_excludes_another_process() {
        let (tmp, m) = fresh();
        let dir = tmp.path().join("m");
        drop(m);
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "mirror::tests::lock_holder_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("VLT_TEST_LOCK_HOLDER", &dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut out = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        loop {
            line.clear();
            assert!(out.read_line(&mut line).unwrap() > 0, "child exited early");
            if line.trim() == "VLT-LOCK-HELD" {
                break;
            }
        }
        match Mirror::open(&dir) {
            Err(StoreError::Io { kind, .. }) => assert_eq!(kind, io::ErrorKind::WouldBlock),
            _ => panic!("second process admitted"),
        }
        drop(child.stdin.take());
        let mut rest = String::new();
        out.read_to_string(&mut rest).unwrap();
        assert!(child.wait().unwrap().success(), "{rest}");
        // The lock goes with the process.
        Mirror::open(&dir).unwrap();
    }
}
