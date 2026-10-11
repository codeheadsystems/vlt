//! The backend descriptor: where each vault's objects live, kept in `vaults.toml` in vlt's data
//! directory (`$XDG_DATA_HOME/vlt` on the CLI) and keyed by `vault_id`. See the spec's "Backend
//! descriptor". It holds no secrets.
//!
//! Several vaults share the file, so every change is a read-modify-write under an exclusive lock on
//! a sibling lock file, and the file is replaced atomically (temporary file, `fsync`, rename,
//! directory `fsync`). Readers need no lock, because they only ever see a whole file.
//!
//! ```toml
//! [vaults.00112233445566778899aabbccddeeff]
//! backend = "s3:vlt-vault:1:00112233445566778899aabbccddeeff:eu-west-1:my-vault:vlt/:"
//! aws_account_id = "111122223333"
//! history_sources = ["/home/u/.local/share/vlt/stores/store.attached-2026-10-11"]
//! ```

use crate::fsutil::{dir_builder, file_options, sync_dir, write_temp};
use core::fmt;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use vlt_core::enroll::VaultConfig;

const FILE_NAME: &str = "vaults.toml";
const LOCK_NAME: &str = "vaults.toml.lock";

/// Where a vault's objects live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendLocation {
    /// `local:<store path>`: a local store at an absolute path.
    Local(PathBuf),
    /// `s3:<vault configuration line>`: a bucket.
    S3(VaultConfig),
}

/// One vault's descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultDescriptor {
    /// Where the vault's objects live.
    pub backend: BackendLocation,
    /// The bucket owner's AWS account ID, where known. Only an S3 backend has one.
    pub aws_account_id: Option<String>,
    /// Absolute paths of kept local stores and earlier mirrors that hold history objects.
    pub history_sources: Vec<PathBuf>,
}

/// Why the descriptor file could not be read or written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DescriptorError {
    /// A file system error.
    Io(io::ErrorKind),
    /// The file is not valid TOML of the expected shape. The detail names the line.
    Malformed(String),
    /// An entry breaks a rule.
    Invalid {
        /// The entry's key as written in the file.
        vault_id: String,
        /// What is wrong.
        what: &'static str,
    },
}

impl fmt::Display for DescriptorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DescriptorError::Io(kind) => write!(f, "cannot access {FILE_NAME}: {kind}"),
            DescriptorError::Malformed(detail) => write!(f, "{FILE_NAME} is malformed: {detail}"),
            DescriptorError::Invalid { vault_id, what } => {
                write!(f, "{FILE_NAME} entry {vault_id}: {what}")
            }
        }
    }
}

impl std::error::Error for DescriptorError {}

impl From<io::Error> for DescriptorError {
    fn from(e: io::Error) -> Self {
        DescriptorError::Io(e.kind())
    }
}

#[derive(Serialize, Deserialize, Default)]
struct RawFile {
    #[serde(default)]
    vaults: BTreeMap<String, RawEntry>,
}

#[derive(Serialize, Deserialize)]
struct RawEntry {
    backend: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    aws_account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    history_sources: Vec<String>,
}

fn invalid(vault_id: &str, what: &'static str) -> DescriptorError {
    DescriptorError::Invalid {
        vault_id: vault_id.to_owned(),
        what,
    }
}

fn parse_vault_id(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut id = [0u8; 16];
    hex::decode_to_slice(s, &mut id).ok()?;
    Some(id)
}

fn is_account_id(s: &str) -> bool {
    s.len() == 12 && s.bytes().all(|b| b.is_ascii_digit())
}

fn absolute(vault_id: &str, s: &str) -> Result<PathBuf, DescriptorError> {
    let p = PathBuf::from(s);
    if p.is_absolute() {
        Ok(p)
    } else {
        Err(invalid(vault_id, "path is not absolute"))
    }
}

fn path_str<'a>(vault_id: &str, p: &'a Path) -> Result<&'a str, DescriptorError> {
    if !p.is_absolute() {
        return Err(invalid(vault_id, "path is not absolute"));
    }
    p.to_str()
        .ok_or_else(|| invalid(vault_id, "path is not valid UTF-8"))
}

impl RawEntry {
    fn decode(&self, key: &str) -> Result<([u8; 16], VaultDescriptor), DescriptorError> {
        let vault_id = parse_vault_id(key).ok_or_else(|| invalid(key, "bad vault ID"))?;
        let backend = if let Some(path) = self.backend.strip_prefix("local:") {
            BackendLocation::Local(absolute(key, path)?)
        } else if let Some(line) = self.backend.strip_prefix("s3:") {
            // The line was checked when it was written, including any `--allow-http`.
            let config = VaultConfig::from_line(line, true)
                .map_err(|_| invalid(key, "bad vault configuration line"))?;
            if config.vault_id != vault_id {
                return Err(invalid(key, "vault configuration line names another vault"));
            }
            BackendLocation::S3(config)
        } else {
            return Err(invalid(key, "backend is neither local: nor s3:"));
        };
        if let Some(account) = &self.aws_account_id {
            if !is_account_id(account) {
                return Err(invalid(key, "bad AWS account ID"));
            }
            if matches!(backend, BackendLocation::Local(_)) {
                return Err(invalid(key, "a local store has no AWS account ID"));
            }
        }
        let history_sources = self
            .history_sources
            .iter()
            .map(|s| absolute(key, s))
            .collect::<Result<_, _>>()?;
        Ok((
            vault_id,
            VaultDescriptor {
                backend,
                aws_account_id: self.aws_account_id.clone(),
                history_sources,
            },
        ))
    }

    fn encode(vault_id: &[u8; 16], d: &VaultDescriptor) -> Result<RawEntry, DescriptorError> {
        let key = hex::encode(vault_id);
        let backend = match &d.backend {
            BackendLocation::Local(p) => format!("local:{}", path_str(&key, p)?),
            BackendLocation::S3(config) => {
                if config.vault_id != *vault_id {
                    return Err(invalid(
                        &key,
                        "vault configuration line names another vault",
                    ));
                }
                let line = config
                    .to_line()
                    .map_err(|_| invalid(&key, "bad vault configuration line"))?;
                format!("s3:{line}")
            }
        };
        let history_sources = d
            .history_sources
            .iter()
            .map(|p| path_str(&key, p).map(str::to_owned))
            .collect::<Result<_, _>>()?;
        let entry = RawEntry {
            backend,
            aws_account_id: d.aws_account_id.clone(),
            history_sources,
        };
        // Refuse to write anything that would not read back.
        entry.decode(&key)?;
        Ok(entry)
    }
}

/// The descriptor file in a data directory.
#[derive(Debug, Clone)]
pub struct Descriptors {
    dir: PathBuf,
}

impl Descriptors {
    /// The descriptor file in `data_dir` (`$XDG_DATA_HOME/vlt` on the CLI). Nothing is touched
    /// until the first read or write.
    pub fn new(data_dir: &Path) -> Descriptors {
        Descriptors {
            dir: data_dir.to_owned(),
        }
    }

    /// The path of `vaults.toml`.
    pub fn path(&self) -> PathBuf {
        self.dir.join(FILE_NAME)
    }

    /// Every vault's descriptor. A missing file is an empty map.
    pub fn load(&self) -> Result<BTreeMap<[u8; 16], VaultDescriptor>, DescriptorError> {
        let text = match fs::read_to_string(self.path()) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
            Err(e) => return Err(e.into()),
        };
        let raw: RawFile =
            toml::from_str(&text).map_err(|e| DescriptorError::Malformed(e.message().into()))?;
        raw.vaults
            .iter()
            .map(|(key, entry)| entry.decode(key))
            .collect()
    }

    /// One vault's descriptor.
    pub fn get(&self, vault_id: &[u8; 16]) -> Result<Option<VaultDescriptor>, DescriptorError> {
        Ok(self.load()?.remove(vault_id))
    }

    /// Reads every descriptor, lets `f` change them, and writes the result atomically, all under
    /// the exclusive lock. Nothing is written when `f` leaves the map unchanged.
    pub fn update<T>(
        &self,
        f: impl FnOnce(&mut BTreeMap<[u8; 16], VaultDescriptor>) -> T,
    ) -> Result<T, DescriptorError> {
        dir_builder().recursive(true).create(&self.dir)?;
        let lock = file_options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.dir.join(LOCK_NAME))?;
        lock.lock()?;
        let before = self.load()?;
        let mut map = before.clone();
        let out = f(&mut map);
        if map != before {
            self.write(&map)?;
        }
        Ok(out)
    }

    /// Sets one vault's descriptor.
    pub fn set(&self, vault_id: &[u8; 16], d: VaultDescriptor) -> Result<(), DescriptorError> {
        // Check before taking the lock, so a bad descriptor leaves the file alone.
        RawEntry::encode(vault_id, &d)?;
        self.update(|m| {
            m.insert(*vault_id, d);
        })
    }

    /// Removes one vault's descriptor, returning it.
    pub fn remove(&self, vault_id: &[u8; 16]) -> Result<Option<VaultDescriptor>, DescriptorError> {
        self.update(|m| m.remove(vault_id))
    }

    fn write(&self, map: &BTreeMap<[u8; 16], VaultDescriptor>) -> Result<(), DescriptorError> {
        let mut raw = RawFile::default();
        for (id, d) in map {
            raw.vaults.insert(hex::encode(id), RawEntry::encode(id, d)?);
        }
        let text = toml::to_string(&raw).map_err(|e| DescriptorError::Malformed(e.to_string()))?;
        let tmp = write_temp(&self.dir, text.as_bytes())?;
        if let Err(e) = fs::rename(&tmp, self.path()) {
            let _ = fs::remove_file(&tmp);
            return Err(e.into());
        }
        sync_dir(&self.dir)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    const ID_A: [u8; 16] = [0xaa; 16];
    const ID_B: [u8; 16] = [0xbb; 16];

    fn s3(id: [u8; 16]) -> VaultDescriptor {
        VaultDescriptor {
            backend: BackendLocation::S3(VaultConfig {
                vault_id: id,
                region: "eu-west-1".into(),
                bucket: "my-vault".into(),
                prefix: "vlt/".into(),
                endpoint: String::new(),
            }),
            aws_account_id: Some("111122223333".into()),
            history_sources: vec![PathBuf::from("/data/vlt/stores/store.attached-2026-10-11")],
        }
    }

    fn local(path: &str) -> VaultDescriptor {
        VaultDescriptor {
            backend: BackendLocation::Local(PathBuf::from(path)),
            aws_account_id: None,
            history_sources: vec![],
        }
    }

    #[test]
    fn round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let d = Descriptors::new(&dir.path().join("vlt"));
        assert!(d.load().unwrap().is_empty());
        d.set(&ID_A, s3(ID_A)).unwrap();
        d.set(&ID_B, local("/data/vlt/stores/0123")).unwrap();
        assert_eq!(d.get(&ID_A).unwrap(), Some(s3(ID_A)));
        assert_eq!(d.get(&ID_B).unwrap(), Some(local("/data/vlt/stores/0123")));
        let text = fs::read_to_string(d.path()).unwrap();
        assert!(text.contains(&format!(
            "backend = \"s3:vlt-vault:1:{}:eu-west-1:my-vault:vlt/:\"",
            hex::encode(ID_A)
        )));
        assert!(text.contains("backend = \"local:/data/vlt/stores/0123\""));
        assert_eq!(d.remove(&ID_A).unwrap(), Some(s3(ID_A)));
        assert_eq!(d.get(&ID_A).unwrap(), None);
        assert_eq!(d.load().unwrap().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let d = Descriptors::new(&dir.path().join("vlt"));
        d.set(&ID_B, local("/x")).unwrap();
        let mode = fs::metadata(d.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let mode = fs::metadata(dir.path().join("vlt"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn rejects_bad_entries_on_write() {
        let dir = tempfile::tempdir().unwrap();
        let d = Descriptors::new(dir.path());
        assert!(d.set(&ID_A, local("relative/path")).is_err());
        assert!(d.set(&ID_A, s3(ID_B)).is_err());
        let mut bad_account = s3(ID_A);
        bad_account.aws_account_id = Some("1234".into());
        assert!(d.set(&ID_A, bad_account).is_err());
        let mut local_with_account = local("/x");
        local_with_account.aws_account_id = Some("111122223333".into());
        assert!(d.set(&ID_A, local_with_account).is_err());
        assert!(!d.path().exists());
    }

    fn load_text(text: &str) -> Result<BTreeMap<[u8; 16], VaultDescriptor>, DescriptorError> {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(FILE_NAME), text).unwrap();
        Descriptors::new(dir.path()).load()
    }

    #[test]
    fn rejects_bad_entries_on_read() {
        let a = hex::encode(ID_A);
        assert!(matches!(
            load_text("vaults = 3"),
            Err(DescriptorError::Malformed(_))
        ));
        for (key, backend, what) in [
            ("AA", "local:/x", "bad vault ID"),
            (&a.to_uppercase(), "local:/x", "bad vault ID"),
            (&a, "ftp:/x", "backend is neither local: nor s3:"),
            (&a, "local:x", "path is not absolute"),
            (&a, "s3:vlt-vault:1:zz", "bad vault configuration line"),
            (
                &a,
                &format!("s3:vlt-vault:1:{}:r:bucket:vlt/:", hex::encode(ID_B)),
                "vault configuration line names another vault",
            ),
        ] {
            let text = format!("[vaults.{key}]\nbackend = \"{backend}\"\n");
            assert_eq!(
                load_text(&text),
                Err(DescriptorError::Invalid {
                    vault_id: key.to_string(),
                    what
                }),
                "{backend}"
            );
        }
    }

    #[test]
    fn has_no_secret_fields() {
        // The file's fields are exactly these; a secret field would have to be added here.
        let dir = tempfile::tempdir().unwrap();
        let d = Descriptors::new(dir.path());
        d.set(&ID_A, s3(ID_A)).unwrap();
        let raw: toml::Table = toml::from_str(&fs::read_to_string(d.path()).unwrap()).unwrap();
        let entry = raw["vaults"][&hex::encode(ID_A)].as_table().unwrap();
        let mut keys: Vec<_> = entry.keys().map(String::as_str).collect();
        keys.sort();
        assert_eq!(keys, ["aws_account_id", "backend", "history_sources"]);
    }

    #[test]
    fn concurrent_updates_from_several_vaults_all_land() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("vlt");
        const N: u8 = 16;
        let barrier = Arc::new(Barrier::new(N as usize));
        let handles: Vec<_> = (0..N)
            .map(|i| {
                let (base, barrier) = (base.clone(), Arc::clone(&barrier));
                thread::spawn(move || {
                    // Each thread has its own `Descriptors`, as separate processes would.
                    let d = Descriptors::new(&base);
                    barrier.wait();
                    d.set(&[i; 16], local(&format!("/stores/{i}"))).unwrap();
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let all = Descriptors::new(&base).load().unwrap();
        assert_eq!(all.len(), N as usize);
        // No temporary files are left.
        let stray = fs::read_dir(&base)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".tmp-")
            })
            .count();
        assert_eq!(stray, 0);
    }

    #[test]
    fn update_without_change_does_not_write() {
        let dir = tempfile::tempdir().unwrap();
        let d = Descriptors::new(dir.path());
        d.update(|_| ()).unwrap();
        assert!(!d.path().exists());
    }
}
