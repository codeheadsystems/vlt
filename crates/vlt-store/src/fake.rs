//! An in-memory backend for tests in this crate and others. It keeps every version of every key as
//! a versioned bucket does, computes etags from the bytes, logs every operation, and can inject
//! faults: a forced `412`, an offline error, an HTTP error, or a lost response (the write lands
//! and the caller sees an error). It also answers [`BucketProbe`] from configurable settings, so
//! the capability probe can be tested against every row of the backend table.

use crate::backend::{Backend, Delete, Etag, Get, Put};
use crate::error::{OfflineKind, StoreError};
use crate::probe::{BucketProbe, Lifecycle, ObjectLock, RawCond, RawResponse, Versioning};
use crate::retry::Backoff;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

/// An operation on the fake, for fault targeting and the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum FakeOp {
    Get,
    Exists,
    Create,
    Replace,
    List,
    Delete,
    Versioning,
    ObjectLock,
    Lifecycle,
    ListVersions,
    PutRaw,
    Multipart,
    DeleteRaw,
    TotalBytes,
}

/// A fault to inject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fault {
    /// A `412`: `Put::PreconditionFailed` from `create` and `replace`, status `412` from raw
    /// requests, and an HTTP error elsewhere. Nothing is written.
    PreconditionFailed,
    /// A transport failure. Nothing is written.
    Offline(OfflineKind),
    /// An HTTP error response. Nothing is written; raw requests return it as a response.
    Http {
        /// The status.
        status: u16,
        /// The S3 error code.
        code: Option<String>,
    },
    /// The operation takes effect and the caller sees `Offline(ConnectionLost)`.
    LostResponse,
}

/// One logged operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    /// The operation.
    pub op: FakeOp,
    /// The prefix-relative key or list prefix; empty for bucket-level operations.
    pub key: String,
}

/// The bucket settings the fake reports through [`BucketProbe`], and how strictly it enforces the
/// device policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeBucket {
    /// Reported versioning state.
    pub versioning: Versioning,
    /// Reported Object Lock configuration.
    pub object_lock: ObjectLock,
    /// Reported lifecycle rules.
    pub lifecycle: Lifecycle,
    /// Whether `delete` and `delete_raw` succeed. A device key's policy forbids it, so the
    /// default is `false` (`403`).
    pub delete_allowed: bool,
    /// Whether entry and enrollment keys refuse writes without `If-None-Match: *` with `403`, as
    /// the device policy does. Default `true`.
    pub entry_write_once: bool,
    /// The vault prefix, used only to report bucket-absolute keys.
    pub prefix: String,
}

impl Default for FakeBucket {
    fn default() -> Self {
        FakeBucket {
            versioning: Versioning::Enabled,
            object_lock: ObjectLock {
                enabled: false,
                default_mode: None,
            },
            lifecycle: Lifecycle {
                header_noncurrent_days: Some(365),
                index_noncurrent_days: Some(365),
            },
            delete_allowed: false,
            entry_write_once: true,
            prefix: "vlt/".to_owned(),
        }
    }
}

struct Injected {
    op: Option<FakeOp>,
    key: Option<String>,
    skip: usize,
    remaining: usize,
    fault: Fault,
}

#[derive(Default)]
struct State {
    /// Every version of every key, oldest first; `None` is a delete marker.
    versions: BTreeMap<String, Vec<Option<Vec<u8>>>>,
    /// Bucket-absolute keys outside the vault.
    foreign: Vec<String>,
    faults: Vec<Injected>,
    log: Vec<LogEntry>,
    ignore_conditions: bool,
    bucket: FakeBucket,
}

impl State {
    fn current(&self, key: &str) -> Option<&Vec<u8>> {
        self.versions.get(key)?.last()?.as_ref()
    }

    fn write(&mut self, key: &str, bytes: &[u8]) -> Etag {
        self.versions
            .entry(key.to_owned())
            .or_default()
            .push(Some(bytes.to_vec()));
        etag_of(bytes)
    }

    /// Logs the operation and takes the first matching fault, if any.
    fn enter(&mut self, op: FakeOp, key: &str) -> Option<Fault> {
        self.log.push(LogEntry {
            op,
            key: key.to_owned(),
        });
        let i = self.faults.iter().position(|f| {
            f.remaining > 0
                && f.op.is_none_or(|o| o == op)
                && f.key.as_deref().is_none_or(|k| k == key)
        })?;
        let f = &mut self.faults[i];
        if f.skip > 0 {
            f.skip -= 1;
            return None;
        }
        f.remaining -= 1;
        let fault = f.fault.clone();
        if f.remaining == 0 {
            self.faults.remove(i);
        }
        Some(fault)
    }

    fn write_once_key(&self, key: &str) -> bool {
        self.bucket.entry_write_once && (key.starts_with("e/") || key.starts_with("enroll/"))
    }
}

/// The etag the fake gives `bytes`: like S3's, it depends on the bytes alone.
pub fn etag_of(bytes: &[u8]) -> Etag {
    let h = Sha256::digest(bytes);
    Etag(format!("\"{}\"", hex::encode(&h[..16])))
}

fn http(status: u16, code: Option<String>, method: &'static str, key: &str) -> StoreError {
    StoreError::Http {
        status,
        code,
        method,
        key: key.to_owned(),
    }
}

fn lost() -> StoreError {
    StoreError::Offline(OfflineKind::ConnectionLost)
}

fn raw(status: u16, etag: Option<Etag>) -> RawResponse {
    RawResponse {
        status,
        etag,
        code: None,
    }
}

/// The in-memory backend.
#[derive(Default)]
pub struct FakeBackend {
    state: Mutex<State>,
}

impl FakeBackend {
    /// An empty fake with the default bucket settings: versioning on, no Object Lock, 365-day
    /// lifecycle rules, deletes forbidden, and entry keys write-once.
    pub fn new() -> FakeBackend {
        FakeBackend::default()
    }

    /// An empty fake with the given bucket settings.
    pub fn with_bucket(bucket: FakeBucket) -> FakeBackend {
        let fake = FakeBackend::default();
        fake.lock().bucket = bucket;
        fake
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // A test that panicked while holding the lock has already failed; keep the state usable.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Injects `fault` into the next `times` operations matching `op` (any when `None`) and `key`
    /// (any when `None`). Faults are taken in the order they were injected.
    pub fn inject(&self, op: Option<FakeOp>, key: Option<&str>, times: usize, fault: Fault) {
        self.inject_after(op, key, 0, times, fault);
    }

    /// Like [`FakeBackend::inject`], but lets the first `skip` matching operations through first.
    pub fn inject_after(
        &self,
        op: Option<FakeOp>,
        key: Option<&str>,
        skip: usize,
        times: usize,
        fault: Fault,
    ) {
        self.lock().faults.push(Injected {
            op,
            key: key.map(str::to_owned),
            skip,
            remaining: times,
            fault,
        });
    }

    /// Removes every pending fault.
    pub fn clear_faults(&self) {
        self.lock().faults.clear();
    }

    /// When set, `create`, `replace`, and raw `PUT`s ignore their conditions and always write, as
    /// a backend that does not honour conditional writes would.
    pub fn set_ignore_conditions(&self, ignore: bool) {
        self.lock().ignore_conditions = ignore;
    }

    /// Changes the reported bucket settings.
    pub fn set_bucket(&self, bucket: FakeBucket) {
        self.lock().bucket = bucket;
    }

    /// Adds a bucket-absolute key outside the vault, which step 2 of the probe sees.
    pub fn add_foreign_object(&self, key: &str) {
        self.lock().foreign.push(key.to_owned());
    }

    /// Writes an object with no condition and no fault or log entry, as an admin would.
    pub fn put_admin(&self, key: &str, bytes: &[u8]) -> Etag {
        self.lock().write(key, bytes)
    }

    /// The current bytes of a key.
    pub fn current(&self, key: &str) -> Option<Vec<u8>> {
        self.lock().current(key).cloned()
    }

    /// How many versions (including delete markers) a key has.
    pub fn version_count(&self, key: &str) -> usize {
        self.lock().versions.get(key).map_or(0, Vec::len)
    }

    /// The operation log, oldest first.
    pub fn log(&self) -> Vec<LogEntry> {
        self.lock().log.clone()
    }

    /// Clears the operation log.
    pub fn clear_log(&self) {
        self.lock().log.clear();
    }
}

impl Backend for FakeBackend {
    fn get(
        &self,
        key: &str,
        if_none_match: Option<&Etag>,
        max_len: usize,
    ) -> Result<Get, StoreError> {
        let mut s = self.lock();
        match s.enter(FakeOp::Get, key) {
            Some(Fault::Offline(k)) => return Err(StoreError::Offline(k)),
            Some(Fault::LostResponse) => return Err(lost()),
            Some(Fault::PreconditionFailed) => return Err(http(412, None, "GET", key)),
            Some(Fault::Http { status, code }) => return Err(http(status, code, "GET", key)),
            None => {}
        }
        let Some(bytes) = s.current(key) else {
            return Ok(Get::NotFound);
        };
        let etag = etag_of(bytes);
        if if_none_match == Some(&etag) {
            return Ok(Get::NotModified);
        }
        if bytes.len() > max_len {
            return Err(StoreError::TooLarge {
                key: key.to_owned(),
            });
        }
        Ok(Get::Found {
            bytes: bytes.clone(),
            etag,
        })
    }

    fn exists(&self, key: &str) -> Result<bool, StoreError> {
        let mut s = self.lock();
        match s.enter(FakeOp::Exists, key) {
            Some(Fault::Offline(k)) => return Err(StoreError::Offline(k)),
            Some(Fault::LostResponse) => return Err(lost()),
            Some(Fault::PreconditionFailed) => return Err(http(412, None, "HEAD", key)),
            Some(Fault::Http { status, code }) => return Err(http(status, code, "HEAD", key)),
            None => {}
        }
        Ok(s.current(key).is_some())
    }

    fn create(&self, key: &str, bytes: &[u8]) -> Result<Put, StoreError> {
        let mut s = self.lock();
        let fault = s.enter(FakeOp::Create, key);
        match fault {
            Some(Fault::Offline(k)) => return Err(StoreError::Offline(k)),
            Some(Fault::PreconditionFailed) => return Ok(Put::PreconditionFailed),
            Some(Fault::Http { status, code }) => return Err(http(status, code, "PUT", key)),
            Some(Fault::LostResponse) | None => {}
        }
        if s.current(key).is_some() && !s.ignore_conditions {
            return Ok(Put::PreconditionFailed);
        }
        let etag = s.write(key, bytes);
        if fault == Some(Fault::LostResponse) {
            return Err(lost());
        }
        Ok(Put::Written { etag })
    }

    fn replace(&self, key: &str, bytes: &[u8], expected: &Etag) -> Result<Put, StoreError> {
        let mut s = self.lock();
        let fault = s.enter(FakeOp::Replace, key);
        match fault {
            Some(Fault::Offline(k)) => return Err(StoreError::Offline(k)),
            Some(Fault::PreconditionFailed) => return Ok(Put::PreconditionFailed),
            Some(Fault::Http { status, code }) => return Err(http(status, code, "PUT", key)),
            Some(Fault::LostResponse) | None => {}
        }
        let matches = s.current(key).is_some_and(|b| &etag_of(b) == expected);
        if !matches && !s.ignore_conditions {
            return Ok(Put::PreconditionFailed);
        }
        let etag = s.write(key, bytes);
        if fault == Some(Fault::LostResponse) {
            return Err(lost());
        }
        Ok(Put::Written { etag })
    }

    fn list(&self, prefix: &str) -> Result<Vec<String>, StoreError> {
        let mut s = self.lock();
        match s.enter(FakeOp::List, prefix) {
            Some(Fault::Offline(k)) => return Err(StoreError::Offline(k)),
            Some(Fault::LostResponse) => return Err(lost()),
            Some(Fault::PreconditionFailed) => return Err(http(412, None, "GET", "")),
            Some(Fault::Http { status, code }) => return Err(http(status, code, "GET", "")),
            None => {}
        }
        Ok(s.versions
            .iter()
            .filter(|(k, v)| k.starts_with(prefix) && matches!(v.last(), Some(Some(_))))
            .map(|(k, _)| k.clone())
            .collect())
    }

    fn delete(&self, key: &str) -> Result<Delete, StoreError> {
        let mut s = self.lock();
        let fault = s.enter(FakeOp::Delete, key);
        match fault {
            Some(Fault::Offline(k)) => return Err(StoreError::Offline(k)),
            Some(Fault::PreconditionFailed) => return Err(http(412, None, "DELETE", key)),
            Some(Fault::Http { status, code }) => return Err(http(status, code, "DELETE", key)),
            Some(Fault::LostResponse) | None => {}
        }
        if !s.bucket.delete_allowed {
            return Err(http(403, Some("AccessDenied".into()), "DELETE", key));
        }
        let existed = s.versions.remove(key).is_some();
        if fault == Some(Fault::LostResponse) {
            return Err(lost());
        }
        Ok(if existed {
            Delete::Deleted
        } else {
            Delete::NotFound
        })
    }
}

impl FakeBackend {
    /// Applies a fault to a bucket-level read.
    fn bucket_read(&self, op: FakeOp) -> Result<MutexGuard<'_, State>, StoreError> {
        let mut s = self.lock();
        match s.enter(op, "") {
            Some(Fault::Offline(k)) => Err(StoreError::Offline(k)),
            Some(Fault::LostResponse) => Err(lost()),
            Some(Fault::PreconditionFailed) => Err(http(412, None, "GET", "")),
            Some(Fault::Http { status, code }) => Err(http(status, code, "GET", "")),
            None => Ok(s),
        }
    }

    /// Applies a fault to a raw request. `Ok(Err(resp))` is a forced response.
    fn raw_enter(
        &self,
        op: FakeOp,
        key: &str,
    ) -> Result<(MutexGuard<'_, State>, bool), Result<RawResponse, StoreError>> {
        let mut s = self.lock();
        match s.enter(op, key) {
            Some(Fault::Offline(k)) => Err(Err(StoreError::Offline(k))),
            Some(Fault::PreconditionFailed) => Err(Ok(raw(412, None))),
            Some(Fault::Http { status, code }) => Err(Ok(RawResponse {
                status,
                etag: None,
                code,
            })),
            Some(Fault::LostResponse) => Ok((s, true)),
            None => Ok((s, false)),
        }
    }
}

impl BucketProbe for FakeBackend {
    fn versioning(&self) -> Result<Versioning, StoreError> {
        Ok(self.bucket_read(FakeOp::Versioning)?.bucket.versioning)
    }

    fn object_lock(&self) -> Result<ObjectLock, StoreError> {
        Ok(self.bucket_read(FakeOp::ObjectLock)?.bucket.object_lock)
    }

    fn lifecycle(&self) -> Result<Lifecycle, StoreError> {
        Ok(self.bucket_read(FakeOp::Lifecycle)?.bucket.lifecycle)
    }

    fn any_object_or_version(&self) -> Result<Option<String>, StoreError> {
        let s = self.bucket_read(FakeOp::ListVersions)?;
        if let Some(k) = s.foreign.first() {
            return Ok(Some(k.clone()));
        }
        Ok(s.versions
            .keys()
            .next()
            .map(|k| format!("{}{k}", s.bucket.prefix)))
    }

    fn put_raw(&self, key: &str, bytes: &[u8], cond: &RawCond) -> Result<RawResponse, StoreError> {
        let (mut s, lose) = match self.raw_enter(FakeOp::PutRaw, key) {
            Ok(v) => v,
            Err(forced) => return forced,
        };
        let resp = if s.ignore_conditions {
            raw(200, Some(s.write(key, bytes)))
        } else if s.write_once_key(key) && *cond != RawCond::IfNoneMatchStar {
            RawResponse {
                status: 403,
                etag: None,
                code: Some("AccessDenied".into()),
            }
        } else {
            let current = s.current(key).map(|b| etag_of(b));
            match (cond, current) {
                (RawCond::IfNoneMatchStar, Some(_)) => raw(412, None),
                (RawCond::IfMatch(_), None) => raw(404, None),
                (RawCond::IfMatch(want), Some(have)) if *want != have => raw(412, None),
                // S3 supports only `*` with If-None-Match on PUT.
                (RawCond::IfNoneMatch(_), _) => raw(501, None),
                _ => raw(200, Some(s.write(key, bytes))),
            }
        };
        if lose {
            return Err(lost());
        }
        Ok(resp)
    }

    fn create_multipart(&self, key: &str) -> Result<RawResponse, StoreError> {
        let (s, _) = match self.raw_enter(FakeOp::Multipart, key) {
            Ok(v) => v,
            Err(forced) => return forced,
        };
        let status = if s.write_once_key(key) && !s.ignore_conditions {
            403
        } else {
            200
        };
        Ok(raw(status, None))
    }

    fn delete_raw(&self, key: &str) -> Result<RawResponse, StoreError> {
        let (mut s, _) = match self.raw_enter(FakeOp::DeleteRaw, key) {
            Ok(v) => v,
            Err(forced) => return forced,
        };
        if !s.bucket.delete_allowed {
            return Ok(raw(403, None));
        }
        s.versions.remove(key);
        Ok(raw(204, None))
    }

    /// The default number of attempts, with no delay, so tests stay fast.
    fn backoff(&self) -> Backoff {
        Backoff {
            base: Duration::ZERO,
            ..Backoff::default()
        }
    }

    fn total_stored_bytes(&self) -> Result<u64, StoreError> {
        let s = self.bucket_read(FakeOp::TotalBytes)?;
        Ok(s.versions
            .values()
            .flatten()
            .flatten()
            .map(|b| b.len() as u64)
            .sum())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_then_create_is_412() {
        let f = FakeBackend::new();
        let Put::Written { etag } = f.create("index", b"a").unwrap() else {
            panic!()
        };
        assert_eq!(etag, etag_of(b"a"));
        assert_eq!(f.create("index", b"b").unwrap(), Put::PreconditionFailed);
        assert_eq!(f.current("index").unwrap(), b"a");
    }

    #[test]
    fn replace_checks_etag_and_keeps_versions() {
        let f = FakeBackend::new();
        let e1 = f.put_admin("index", b"a");
        assert_eq!(
            f.replace("index", b"b", &etag_of(b"x")).unwrap(),
            Put::PreconditionFailed
        );
        assert_eq!(
            f.replace("missing", b"b", &e1).unwrap(),
            Put::PreconditionFailed
        );
        assert!(matches!(
            f.replace("index", b"b", &e1).unwrap(),
            Put::Written { .. }
        ));
        assert_eq!(f.version_count("index"), 2);
        assert_eq!(f.total_stored_bytes().unwrap(), 2);
    }

    #[test]
    fn get_conditional_and_size_cap() {
        let f = FakeBackend::new();
        let e = f.put_admin("header", b"abcd");
        assert_eq!(f.get("header", Some(&e), 10).unwrap(), Get::NotModified);
        assert_eq!(
            f.get("header", None, 3).unwrap_err(),
            StoreError::TooLarge {
                key: "header".into()
            }
        );
        assert_eq!(f.get("nope", None, 3).unwrap(), Get::NotFound);
    }

    #[test]
    fn forced_412_counts_down_per_key() {
        let f = FakeBackend::new();
        let e = f.put_admin("index", b"a");
        f.inject(
            Some(FakeOp::Replace),
            Some("index"),
            2,
            Fault::PreconditionFailed,
        );
        assert_eq!(
            f.replace("index", b"b", &e).unwrap(),
            Put::PreconditionFailed
        );
        // A create on another key is not affected.
        assert!(matches!(
            f.create("e/00", b"x").unwrap(),
            Put::Written { .. }
        ));
        assert_eq!(
            f.replace("index", b"b", &e).unwrap(),
            Put::PreconditionFailed
        );
        assert!(matches!(
            f.replace("index", b"b", &e).unwrap(),
            Put::Written { .. }
        ));
    }

    #[test]
    fn inject_after_skips_matching_operations() {
        let f = FakeBackend::new();
        f.inject_after(
            Some(FakeOp::Exists),
            None,
            2,
            1,
            Fault::Offline(OfflineKind::Timeout),
        );
        assert!(!f.exists("a").unwrap());
        f.get("a", None, 1).unwrap();
        assert!(!f.exists("b").unwrap());
        assert!(f.exists("c").unwrap_err().is_offline());
        assert!(!f.exists("d").unwrap());
    }

    #[test]
    fn offline_and_http_faults() {
        let f = FakeBackend::new();
        f.inject(None, None, 1, Fault::Offline(OfflineKind::Dns));
        assert_eq!(
            f.get("index", None, 10).unwrap_err(),
            StoreError::Offline(OfflineKind::Dns)
        );
        f.inject(
            Some(FakeOp::Get),
            Some("header"),
            1,
            Fault::Http {
                status: 403,
                code: Some("AccessDenied".into()),
            },
        );
        let err = f.get("header", None, 10).unwrap_err();
        assert!(err.is_access_key_rejected());
        assert_eq!(f.get("header", None, 10).unwrap(), Get::NotFound);
    }

    #[test]
    fn lost_response_lands_the_write() {
        let f = FakeBackend::new();
        f.inject(Some(FakeOp::Create), Some("e/01"), 1, Fault::LostResponse);
        assert!(f.create("e/01", b"x").unwrap_err().is_offline());
        assert_eq!(f.current("e/01").unwrap(), b"x");
        // The retry sees the object already there.
        assert_eq!(f.create("e/01", b"x").unwrap(), Put::PreconditionFailed);
    }

    #[test]
    fn ignore_conditions_overwrites() {
        let f = FakeBackend::new();
        f.set_ignore_conditions(true);
        f.create("index", b"a").unwrap();
        assert!(matches!(
            f.create("index", b"b").unwrap(),
            Put::Written { .. }
        ));
        assert_eq!(f.current("index").unwrap(), b"b");
    }

    #[test]
    fn log_records_operations() {
        let f = FakeBackend::new();
        f.create("index", b"a").unwrap();
        f.list("e/").unwrap();
        let log = f.log();
        assert_eq!(
            log,
            vec![
                LogEntry {
                    op: FakeOp::Create,
                    key: "index".into()
                },
                LogEntry {
                    op: FakeOp::List,
                    key: "e/".into()
                },
            ]
        );
        f.clear_log();
        assert!(f.log().is_empty());
    }

    #[test]
    fn list_and_delete() {
        let f = FakeBackend::new();
        f.put_admin("e/02", b"x");
        f.put_admin("e/01", b"x");
        f.put_admin("index", b"x");
        assert_eq!(f.list("e/").unwrap(), vec!["e/01", "e/02"]);
        assert_eq!(f.delete("e/01").unwrap_err().status(), Some(403));
        f.set_bucket(FakeBucket {
            delete_allowed: true,
            ..FakeBucket::default()
        });
        assert_eq!(f.delete("e/01").unwrap(), Delete::Deleted);
        assert_eq!(f.delete("e/01").unwrap(), Delete::NotFound);
        assert_eq!(f.list("").unwrap(), vec!["e/02", "index"]);
    }
}
