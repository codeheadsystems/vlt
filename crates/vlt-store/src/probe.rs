//! The capability probe that `vlt init` and `vlt attach` run before writing anything that matters,
//! and the checks `vlt doctor` repeats. See the spec's "Capability probe".
//!
//! Results are data: warnings, notes, and refusals with their exit codes. Nothing here prints.

use crate::backend::{Backend, Etag};
use crate::error::StoreError;
use crate::retry::{Backoff, is_transient};
use core::fmt;
use vlt_core::kdf::KdfParams;

/// A bucket's versioning state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Versioning {
    /// Versioning is on.
    Enabled,
    /// Versioning was on and is now suspended.
    Suspended,
    /// Versioning was never turned on.
    Off,
}

/// An Object Lock retention mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionMode {
    /// Governance mode: an admin with `s3:BypassGovernanceRetention` can delete.
    Governance,
    /// Compliance mode: nobody can delete until retention expires.
    Compliance,
}

/// A bucket's Object Lock configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectLock {
    /// Whether Object Lock is enabled on the bucket.
    pub enabled: bool,
    /// The default retention mode, when a default retention rule exists.
    pub default_mode: Option<RetentionMode>,
}

/// The lifecycle rules that expire noncurrent versions of the header and the index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Lifecycle {
    /// The shortest `NoncurrentDays` among enabled rules whose filter covers `<prefix>header`, or
    /// `None` when no rule expires its noncurrent versions.
    pub header_noncurrent_days: Option<u32>,
    /// The same for `<prefix>index`.
    pub index_noncurrent_days: Option<u32>,
}

/// The condition on a raw `PUT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawCond {
    /// `If-None-Match: *`.
    IfNoneMatchStar,
    /// `If-Match: <etag>`.
    IfMatch(Etag),
    /// No condition.
    None,
    /// `If-None-Match: <value>`, a value other than `*`.
    IfNoneMatch(String),
}

/// An HTTP response to a raw probe request, whatever its status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawResponse {
    /// The HTTP status.
    pub status: u16,
    /// The `ETag` header, when present.
    pub etag: Option<Etag>,
    /// The S3 error code, when the body has one.
    pub code: Option<String>,
}

impl RawResponse {
    fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// The S3-only requests that the capability probe and `vlt doctor` need. The local store and the
/// fake used by sync tests do not implement it; [`crate::fake::FakeBackend`] does, for probe tests.
pub trait BucketProbe {
    /// `GetBucketVersioning`.
    fn versioning(&self) -> Result<Versioning, StoreError>;
    /// `GetObjectLockConfiguration`. A bucket without a configuration is `enabled: false`.
    fn object_lock(&self) -> Result<ObjectLock, StoreError>;
    /// `GetBucketLifecycleConfiguration`, reduced to the rules that cover the header and index.
    fn lifecycle(&self) -> Result<Lifecycle, StoreError>;
    /// The key of any object version or delete marker in the bucket, inside or outside the prefix
    /// (`ListObjectVersions` with `max-keys=1` at the bucket root, or `ListObjectsV2` where the
    /// backend does not implement it). The key is bucket-absolute.
    fn any_object_or_version(&self) -> Result<Option<String>, StoreError>;
    /// `PUT` of a prefix-relative key with the given condition, returning the response whatever
    /// its status. Only transport failures are errors.
    fn put_raw(&self, key: &str, bytes: &[u8], cond: &RawCond) -> Result<RawResponse, StoreError>;
    /// `CreateMultipartUpload` to a prefix-relative key, returning the response.
    fn create_multipart(&self, key: &str) -> Result<RawResponse, StoreError>;
    /// `DeleteObject` of a prefix-relative key, returning the response.
    fn delete_raw(&self, key: &str) -> Result<RawResponse, StoreError>;
    /// The bucket's total stored bytes, summed over every version.
    fn total_stored_bytes(&self) -> Result<u64, StoreError>;
    /// How the probe retries a conditional `PUT` that got a transient `5xx`.
    fn backoff(&self) -> Backoff {
        Backoff::default()
    }
}

/// A raw `PUT`, retried while the server answers with a transient `5xx`.
fn put_retrying(
    probe: &impl BucketProbe,
    key: &str,
    bytes: &[u8],
    cond: &RawCond,
) -> Result<RawResponse, StoreError> {
    probe.backoff().run(
        || probe.put_raw(key, bytes, cond),
        |r| matches!(r, Ok(resp) if is_transient(resp.status)),
    )
}

/// The warning for a non-AWS bucket without versioning.
pub const NO_VERSIONING_WARNING: &str = "Without versioning a stolen device key can overwrite \
history and entries; vlt's mirrors are the only copy.";

/// What `vlt doctor` reports on a backend that cannot make entry keys write-once.
pub const ENTRY_KEYS_NOT_WRITE_ONCE: &str = "entry keys are not write-once on this backend";

/// A warning the probe reports; the command continues.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeWarning {
    /// A non-AWS bucket without versioning; the text is [`NO_VERSIONING_WARNING`].
    NoVersioning,
    /// An AWS bucket with Object Lock where no lifecycle rule keeps the noncurrent versions of
    /// `key` (`header` or `index`) at least 365 days.
    ShortNoncurrentRetention {
        /// `header` or `index`.
        key: &'static str,
        /// The shortest rule, or `None` when no rule covers the key.
        days: Option<u32>,
    },
}

/// A note the probe reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeNote {
    /// An AWS bucket with versioning and without Object Lock: Object Lock is available.
    ObjectLockAvailable,
}

/// The bucket settings read in step 1, and what the backend table makes of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// Versioning state.
    pub versioning: Versioning,
    /// Object Lock configuration.
    pub object_lock: ObjectLock,
    /// Lifecycle rules for the header and index.
    pub lifecycle: Lifecycle,
    /// Warnings from the backend table.
    pub warnings: Vec<ProbeWarning>,
    /// Notes from the backend table.
    pub notes: Vec<ProbeNote>,
}

/// A successful probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeReport {
    /// Step 1's settings, warnings, and notes.
    pub settings: Settings,
    /// The header's etag after step 6.
    pub header_etag: Etag,
    /// The index's etag after step 7.
    pub index_etag: Etag,
}

/// Why the probe refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeError {
    /// A transport failure or an HTTP error that does not bear on capabilities. Exit code 7.
    Store(StoreError),
    /// Step 1: an AWS bucket without versioning. The CLI prints the command that enables it.
    /// Exit code 8.
    VersioningRequired {
        /// The bucket's state, `Off` or `Suspended`.
        state: Versioning,
    },
    /// Step 2: the bucket holds an object version or delete marker. Exit code 10.
    BucketNotEmpty {
        /// One bucket-absolute key found.
        key: String,
        /// Whether a vlt header exists under the prefix; the CLI then suggests `vlt enroll`.
        holds_vault: bool,
    },
    /// Steps 3 to 7: the backend does not honour conditional writes. Exit code 8. A transient
    /// `5xx` is retried first and, if it persists, is a [`ProbeError::Store`] error instead.
    ConditionalWrites {
        /// The step, 3 to 7.
        step: u8,
        /// The status the step got.
        status: u16,
        /// Whether the bucket now holds a header, so the CLI prints the admin command that
        /// empties it.
        header_written: bool,
    },
}

impl ProbeError {
    /// The CLI exit code for this refusal.
    pub fn exit_code(&self) -> u8 {
        match self {
            ProbeError::Store(_) => 7,
            ProbeError::VersioningRequired { .. } | ProbeError::ConditionalWrites { .. } => 8,
            ProbeError::BucketNotEmpty { .. } => 10,
        }
    }
}

impl From<StoreError> for ProbeError {
    fn from(e: StoreError) -> Self {
        ProbeError::Store(e)
    }
}

impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProbeError::Store(e) => e.fmt(f),
            ProbeError::VersioningRequired { .. } => {
                f.write_str("the bucket does not have versioning enabled")
            }
            ProbeError::BucketNotEmpty {
                holds_vault: true, ..
            } => f.write_str("the bucket already holds a vault"),
            ProbeError::BucketNotEmpty { .. } => f.write_str("the bucket is not empty"),
            ProbeError::ConditionalWrites { step, status, .. } => write!(
                f,
                "the store does not honour conditional writes (probe step {step} got {status})"
            ),
        }
    }
}

impl std::error::Error for ProbeError {}

/// Which rows of the backend table apply: AWS (endpoint empty) or any other S3 store (RustFS).
/// Behaviour that differs between the two hangs off this one input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    /// AWS: the endpoint is AWS or unset.
    Aws,
    /// Any other S3-compatible store, such as RustFS.
    Other,
}

/// The noncurrent-version retention the AWS Object Lock row asks lifecycle rules to keep.
const MIN_NONCURRENT_DAYS: u32 = 365;

/// Step 1: read the bucket settings and apply the backend table.
pub fn probe_settings(probe: &impl BucketProbe, kind: BackendKind) -> Result<Settings, ProbeError> {
    let versioning = probe.versioning()?;
    let object_lock = probe.object_lock()?;
    let lifecycle = probe.lifecycle()?;
    let mut warnings = Vec::new();
    let mut notes = Vec::new();
    match (kind, versioning) {
        (BackendKind::Aws, Versioning::Off | Versioning::Suspended) => {
            return Err(ProbeError::VersioningRequired { state: versioning });
        }
        (BackendKind::Aws, Versioning::Enabled) if !object_lock.enabled => {
            notes.push(ProbeNote::ObjectLockAvailable);
        }
        (BackendKind::Aws, Versioning::Enabled) => {
            for (key, days) in [
                ("header", lifecycle.header_noncurrent_days),
                ("index", lifecycle.index_noncurrent_days),
            ] {
                if days.is_none_or(|d| d < MIN_NONCURRENT_DAYS) {
                    warnings.push(ProbeWarning::ShortNoncurrentRetention { key, days });
                }
            }
        }
        (BackendKind::Other, Versioning::Enabled) => {}
        (BackendKind::Other, Versioning::Off | Versioning::Suspended) => {
            warnings.push(ProbeWarning::NoVersioning);
        }
    }
    Ok(Settings {
        versioning,
        object_lock,
        lifecycle,
        warnings,
        notes,
    })
}

/// Step 2: refuse unless the bucket holds no object version or delete marker anywhere.
pub fn probe_empty_bucket(backend: &(impl Backend + BucketProbe)) -> Result<(), ProbeError> {
    match backend.any_object_or_version()? {
        None => Ok(()),
        Some(key) => {
            let holds_vault = backend.exists("header")?;
            Err(ProbeError::BucketNotEmpty { key, holds_vault })
        }
    }
}

/// Whether an unexpected status is about capability (exit 8) rather than access or availability
/// (exit 7). Authentication failures and server errors keep their own classification so that the
/// CLI's access-key message still applies.
fn capability_status(status: u16) -> bool {
    !(status == 401 || status == 403 || (status >= 500 && status != 501))
}

fn expect(
    step: u8,
    resp: &RawResponse,
    want_success: bool,
    key: &str,
    header_written: bool,
) -> Result<(), ProbeError> {
    let ok = if want_success {
        resp.is_success()
    } else {
        resp.status == 412
    };
    if ok {
        return Ok(());
    }
    if !capability_status(resp.status) {
        return Err(ProbeError::Store(StoreError::Http {
            status: resp.status,
            code: resp.code.clone(),
            method: "PUT",
            key: key.to_owned(),
        }));
    }
    Err(ProbeError::ConditionalWrites {
        step,
        status: resp.status,
        header_written,
    })
}

/// The `If-Match` value step 5 uses, which no object has.
const ZERO_ETAG: &str = "\"00000000000000000000000000000000\"";

/// Steps 4 to 6 against a header already in the bucket with etag `etag`: a second create gets
/// `412`, a mismatched `If-Match` gets `412`, and the matching `If-Match` succeeds. Returns the
/// header's etag after step 6. These steps are idempotent, so attach runs them on every resume.
pub fn probe_existing_header(
    probe: &impl BucketProbe,
    header: &[u8],
    etag: &Etag,
) -> Result<Etag, ProbeError> {
    let r4 = put_retrying(probe, "header", header, &RawCond::IfNoneMatchStar)?;
    expect(4, &r4, false, "header", true)?;
    let r5 = put_retrying(
        probe,
        "header",
        header,
        &RawCond::IfMatch(Etag(ZERO_ETAG.into())),
    )?;
    expect(5, &r5, false, "header", true)?;
    let r6 = put_retrying(probe, "header", header, &RawCond::IfMatch(etag.clone()))?;
    expect(6, &r6, true, "header", true)?;
    r6.etag.ok_or(ProbeError::Store(StoreError::Protocol {
        what: "missing ETag",
    }))
}

/// Steps 3 to 6: create the header with `If-None-Match: *`, then check the conditions against it.
/// Returns the header's etag.
pub fn probe_header(probe: &impl BucketProbe, header: &[u8]) -> Result<Etag, ProbeError> {
    let r3 = put_retrying(probe, "header", header, &RawCond::IfNoneMatchStar)?;
    expect(3, &r3, true, "header", false)?;
    let etag = r3.etag.ok_or(ProbeError::Store(StoreError::Protocol {
        what: "missing ETag",
    }))?;
    probe_existing_header(probe, header, &etag)
}

/// Step 7: create the index with `If-None-Match: *`. Returns its etag.
pub fn probe_index(probe: &impl BucketProbe, index: &[u8]) -> Result<Etag, ProbeError> {
    let r7 = put_retrying(probe, "index", index, &RawCond::IfNoneMatchStar)?;
    expect(7, &r7, true, "index", true)?;
    r7.etag.ok_or(ProbeError::Store(StoreError::Protocol {
        what: "missing ETag",
    }))
}

/// The whole probe for `vlt init`: steps 1 to 7, with the vault's real header and index as the
/// probe bodies.
pub fn run_probe(
    backend: &(impl Backend + BucketProbe),
    kind: BackendKind,
    header: &[u8],
    index: &[u8],
) -> Result<ProbeReport, ProbeError> {
    let settings = probe_settings(backend, kind)?;
    probe_empty_bucket(backend)?;
    let header_etag = probe_header(backend, header)?;
    let index_etag = probe_index(backend, index)?;
    Ok(ProbeReport {
        settings,
        header_etag,
        index_etag,
    })
}

/// One of `vlt doctor`'s request checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoctorCheck {
    /// Step 4: `If-None-Match: *` on the existing header gets `412`.
    HeaderCreateRefused,
    /// Step 5: a mismatched `If-Match` on the header gets `412`.
    HeaderMismatchRefused,
    /// Step 6: the matching `If-Match` re-puts the current header bytes.
    HeaderMatchAccepted,
    /// `DeleteObject` of a non-existent key gets `403`.
    DeleteRefused,
    /// An unconditional `PUT` to a fresh entry key is refused.
    EntryUnconditionalRefused,
    /// A `PUT` with `If-None-Match: "x"` to a fresh entry key is refused.
    EntryOtherConditionRefused,
    /// `CreateMultipartUpload` to a fresh entry key is refused.
    EntryMultipartRefused,
}

/// The outcome of one doctor check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckResult {
    /// Which check.
    pub check: DoctorCheck,
    /// The status the request got.
    pub status: u16,
    /// Whether the status is the expected one.
    pub passed: bool,
}

/// What `vlt doctor` found about an S3 backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorReport {
    /// Step 1, as the probe would judge it now. A refusal here is reported, not fatal.
    pub settings: Result<Settings, ProbeError>,
    /// The request checks, in the order they ran.
    pub checks: Vec<CheckResult>,
    /// Whether entry keys were checked for write-once, or the backend cannot enforce it.
    pub entry_keys: EntryKeys,
    /// The bucket's total stored bytes, including noncurrent versions.
    pub total_stored_bytes: u64,
    /// Whether the vault's KDF parameters exceed the calibration set (`m_kib` over 256 MiB, `t`
    /// over 3, or `p` over 1), which a member could set to slow password unlock on phones.
    pub kdf_above_calibration: bool,
}

/// How doctor treated entry keys' write-once property.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKeys {
    /// AWS: the three write-once checks ran and are in [`DoctorReport::checks`].
    Checked,
    /// A non-AWS backend (RustFS) cannot make entry keys write-once, so the checks were skipped;
    /// doctor reports [`ENTRY_KEYS_NOT_WRITE_ONCE`]. Only a versioned bucket keeps an overwritten
    /// entry as a noncurrent version, so doctor fails when `versioned` is false.
    NotWriteOnce {
        /// Whether the bucket has versioning enabled.
        versioned: bool,
    },
}

impl DoctorReport {
    /// Whether every check passed, step 1 did not refuse, and a backend without write-once entry
    /// keys has versioning on.
    pub fn all_passed(&self) -> bool {
        self.settings.is_ok()
            && self.checks.iter().all(|c| c.passed)
            && self.entry_keys != EntryKeys::NotWriteOnce { versioned: false }
    }
}

/// The largest calibrated parameters: 256 MiB, `t = 3`, `p = 1`.
const CALIBRATION_MAX: (u32, u32, u32) = (256 * 1024, 3, 1);

/// Whether KDF parameters exceed the calibration set.
pub fn kdf_above_calibration(kdf: &KdfParams) -> bool {
    kdf.m_kib > CALIBRATION_MAX.0 || kdf.t > CALIBRATION_MAX.1 || kdf.p > CALIBRATION_MAX.2
}

fn fresh_entry_key() -> Result<String, StoreError> {
    let mut id = [0u8; 16];
    getrandom::fill(&mut id).map_err(|_| StoreError::Io {
        kind: std::io::ErrorKind::Other,
        key: String::new(),
    })?;
    Ok(format!("e/{}", hex::encode(id)))
}

/// `vlt doctor`'s checks: probe steps 1, 4, 5, and 6 against the current header (`header` and its
/// `etag`, which the caller has just fetched and verified), that the device key cannot delete, on
/// AWS that fresh entry keys are write-once, the bucket's total stored bytes, and the KDF
/// parameters. A non-AWS backend cannot make entry keys write-once, so those checks are skipped
/// there (they would leave objects the device key cannot remove); see [`EntryKeys`].
///
/// Statuses are results; only a transport failure or a failed bucket listing is an error.
pub fn doctor_checks(
    probe: &impl BucketProbe,
    kind: BackendKind,
    header: &[u8],
    etag: &Etag,
    kdf: &KdfParams,
) -> Result<DoctorReport, StoreError> {
    let settings = match probe_settings(probe, kind) {
        Err(ProbeError::Store(e)) if e.is_offline() => return Err(e),
        other => other,
    };
    let mut checks = Vec::new();
    let mut record = |check, resp: RawResponse, passed: fn(&RawResponse) -> bool| {
        checks.push(CheckResult {
            check,
            status: resp.status,
            passed: passed(&resp),
        });
    };
    let refused_412 = |r: &RawResponse| r.status == 412;
    let refused = |r: &RawResponse| !r.is_success();

    record(
        DoctorCheck::HeaderCreateRefused,
        put_retrying(probe, "header", header, &RawCond::IfNoneMatchStar)?,
        refused_412,
    );
    record(
        DoctorCheck::HeaderMismatchRefused,
        put_retrying(
            probe,
            "header",
            header,
            &RawCond::IfMatch(Etag(ZERO_ETAG.into())),
        )?,
        refused_412,
    );
    record(
        DoctorCheck::HeaderMatchAccepted,
        put_retrying(probe, "header", header, &RawCond::IfMatch(etag.clone()))?,
        RawResponse::is_success,
    );
    record(
        DoctorCheck::DeleteRefused,
        probe.delete_raw(&fresh_entry_key()?)?,
        |r| r.status == 403,
    );
    let entry_keys = match kind {
        BackendKind::Aws => {
            record(
                DoctorCheck::EntryUnconditionalRefused,
                put_retrying(probe, &fresh_entry_key()?, b"", &RawCond::None)?,
                refused,
            );
            record(
                DoctorCheck::EntryOtherConditionRefused,
                put_retrying(
                    probe,
                    &fresh_entry_key()?,
                    b"",
                    &RawCond::IfNoneMatch("\"x\"".into()),
                )?,
                refused,
            );
            record(
                DoctorCheck::EntryMultipartRefused,
                probe.create_multipart(&fresh_entry_key()?)?,
                refused,
            );
            EntryKeys::Checked
        }
        BackendKind::Other => EntryKeys::NotWriteOnce {
            versioned: matches!(&settings, Ok(s) if s.versioning == Versioning::Enabled),
        },
    };
    let total_stored_bytes = probe.total_stored_bytes()?;
    Ok(DoctorReport {
        settings,
        checks,
        entry_keys,
        total_stored_bytes,
        kdf_above_calibration: kdf_above_calibration(kdf),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::OfflineKind;
    use crate::fake::{FakeBackend, FakeBucket, FakeOp, Fault};

    const HEADER: &[u8] = b"header bytes";
    const INDEX: &[u8] = b"index bytes";

    fn bucket(versioning: Versioning, lock: bool, days: Option<u32>) -> FakeBackend {
        FakeBackend::with_bucket(FakeBucket {
            versioning,
            object_lock: ObjectLock {
                enabled: lock,
                default_mode: lock.then_some(RetentionMode::Governance),
            },
            lifecycle: Lifecycle {
                header_noncurrent_days: days,
                index_noncurrent_days: days,
            },
            ..FakeBucket::default()
        })
    }

    fn wrote_nothing(f: &FakeBackend) -> bool {
        f.log().iter().all(|e| e.op != FakeOp::PutRaw) && f.current("header").is_none()
    }

    #[test]
    fn aws_without_versioning_refuses_before_writing() {
        for state in [Versioning::Off, Versioning::Suspended] {
            for lock in [false, true] {
                let f = bucket(state, lock, Some(365));
                let err = run_probe(&f, BackendKind::Aws, HEADER, INDEX).unwrap_err();
                assert_eq!(err, ProbeError::VersioningRequired { state });
                assert_eq!(err.exit_code(), 8);
                assert!(wrote_nothing(&f));
            }
        }
    }

    #[test]
    fn aws_versioned_without_lock_notes_object_lock() {
        let f = bucket(Versioning::Enabled, false, None);
        let r = run_probe(&f, BackendKind::Aws, HEADER, INDEX).unwrap();
        assert_eq!(r.settings.notes, vec![ProbeNote::ObjectLockAvailable]);
        assert!(r.settings.warnings.is_empty());
        assert_eq!(f.current("header").unwrap(), HEADER);
        assert_eq!(f.current("index").unwrap(), INDEX);
        assert_eq!(r.header_etag, crate::fake::etag_of(HEADER));
        assert_eq!(r.index_etag, crate::fake::etag_of(INDEX));
    }

    #[test]
    fn aws_versioned_with_lock_checks_lifecycle() {
        let ok = bucket(Versioning::Enabled, true, Some(365));
        let r = run_probe(&ok, BackendKind::Aws, HEADER, INDEX).unwrap();
        assert!(r.settings.warnings.is_empty());
        assert!(r.settings.notes.is_empty());

        let longer = bucket(Versioning::Enabled, true, Some(400));
        let r = run_probe(&longer, BackendKind::Aws, HEADER, INDEX).unwrap();
        assert!(r.settings.warnings.is_empty());

        for days in [Some(364), Some(30), None] {
            let f = bucket(Versioning::Enabled, true, days);
            let r = run_probe(&f, BackendKind::Aws, HEADER, INDEX).unwrap();
            assert_eq!(
                r.settings.warnings,
                vec![
                    ProbeWarning::ShortNoncurrentRetention {
                        key: "header",
                        days
                    },
                    ProbeWarning::ShortNoncurrentRetention { key: "index", days },
                ]
            );
        }

        // Only the index rule is short.
        let f = FakeBackend::with_bucket(FakeBucket {
            object_lock: ObjectLock {
                enabled: true,
                default_mode: None,
            },
            lifecycle: Lifecycle {
                header_noncurrent_days: Some(365),
                index_noncurrent_days: Some(10),
            },
            ..FakeBucket::default()
        });
        let r = run_probe(&f, BackendKind::Aws, HEADER, INDEX).unwrap();
        assert_eq!(
            r.settings.warnings,
            vec![ProbeWarning::ShortNoncurrentRetention {
                key: "index",
                days: Some(10)
            }]
        );
    }

    #[test]
    fn other_s3_versioned_continues_quietly() {
        for lock in [false, true] {
            let f = bucket(Versioning::Enabled, lock, None);
            let r = run_probe(&f, BackendKind::Other, HEADER, INDEX).unwrap();
            assert!(r.settings.warnings.is_empty());
            assert!(r.settings.notes.is_empty());
        }
    }

    #[test]
    fn other_s3_unversioned_warns_and_continues() {
        for state in [Versioning::Off, Versioning::Suspended] {
            for lock in [false, true] {
                let f = bucket(state, lock, None);
                let r = run_probe(&f, BackendKind::Other, HEADER, INDEX).unwrap();
                assert_eq!(r.settings.warnings, vec![ProbeWarning::NoVersioning]);
                assert_eq!(f.current("index").unwrap(), INDEX);
            }
        }
    }

    #[test]
    fn step1_read_errors_are_store_errors() {
        for op in [FakeOp::Versioning, FakeOp::ObjectLock, FakeOp::Lifecycle] {
            let f = FakeBackend::new();
            f.inject(
                Some(op),
                None,
                1,
                Fault::Http {
                    status: 403,
                    code: Some("AccessDenied".into()),
                },
            );
            let err = run_probe(&f, BackendKind::Aws, HEADER, INDEX).unwrap_err();
            assert_eq!(err.exit_code(), 7);
            assert!(wrote_nothing(&f));
        }
        let f = FakeBackend::new();
        f.inject(None, None, 1, Fault::Offline(OfflineKind::Connect));
        let err = run_probe(&f, BackendKind::Aws, HEADER, INDEX).unwrap_err();
        assert_eq!(
            err,
            ProbeError::Store(StoreError::Offline(OfflineKind::Connect))
        );
    }

    #[test]
    fn step2_refuses_foreign_objects() {
        let f = FakeBackend::new();
        f.add_foreign_object("photos/cat.jpg");
        let err = run_probe(&f, BackendKind::Aws, HEADER, INDEX).unwrap_err();
        assert_eq!(
            err,
            ProbeError::BucketNotEmpty {
                key: "photos/cat.jpg".into(),
                holds_vault: false
            }
        );
        assert_eq!(err.exit_code(), 10);
        assert!(wrote_nothing(&f));
    }

    #[test]
    fn step2_refuses_existing_vault_and_suggests_enroll() {
        let f = FakeBackend::new();
        f.put_admin("header", b"someone else's header");
        let err = run_probe(&f, BackendKind::Aws, HEADER, INDEX).unwrap_err();
        assert_eq!(
            err,
            ProbeError::BucketNotEmpty {
                key: "vlt/header".into(),
                holds_vault: true
            }
        );
        assert_eq!(f.version_count("header"), 1);
    }

    #[test]
    fn step2_refuses_leftover_entry_without_header() {
        let f = FakeBackend::new();
        f.put_admin("e/00112233445566778899aabbccddeeff", b"x");
        let err = run_probe(&f, BackendKind::Aws, HEADER, INDEX).unwrap_err();
        assert!(matches!(
            err,
            ProbeError::BucketNotEmpty {
                holds_vault: false,
                ..
            }
        ));
    }

    #[test]
    fn ignored_conditions_are_a_capability_refusal_at_step4() {
        let f = FakeBackend::new();
        f.set_ignore_conditions(true);
        let err = run_probe(&f, BackendKind::Aws, HEADER, INDEX).unwrap_err();
        assert_eq!(
            err,
            ProbeError::ConditionalWrites {
                step: 4,
                status: 200,
                header_written: true
            }
        );
        assert_eq!(err.exit_code(), 8);
        // The backend only rewrote identical bytes, and no index was written.
        assert_eq!(f.current("header").unwrap(), HEADER);
        assert!(f.current("index").is_none());
    }

    /// Forces the `n`th raw header `PUT` (0-based) to answer `status`.
    fn fail_header_put(n: usize, status: u16) -> FakeBackend {
        let f = FakeBackend::new();
        f.inject_after(
            Some(FakeOp::PutRaw),
            Some("header"),
            n,
            1,
            Fault::Http { status, code: None },
        );
        f
    }

    #[test]
    fn each_conditional_step_failure_names_its_step() {
        // Step 3 expects 200; steps 4 and 5 expect 412; step 6 expects 200.
        let cases = [(0, 3, 501), (1, 4, 200), (2, 5, 200), (3, 6, 412)];
        for (n, step, status) in cases {
            let f = fail_header_put(n, status);
            let err = run_probe(&f, BackendKind::Aws, HEADER, INDEX).unwrap_err();
            assert_eq!(
                err,
                ProbeError::ConditionalWrites {
                    step,
                    status,
                    header_written: step > 3
                },
                "step {step}"
            );
            assert_eq!(err.exit_code(), 8);
            assert!(f.current("index").is_none());
        }
    }

    #[test]
    fn step5_404_is_a_capability_refusal() {
        let f = fail_header_put(2, 404);
        let err = run_probe(&f, BackendKind::Aws, HEADER, INDEX).unwrap_err();
        assert!(matches!(err, ProbeError::ConditionalWrites { step: 5, .. }));
    }

    #[test]
    fn step7_failure_is_a_capability_refusal() {
        let f = FakeBackend::new();
        f.inject(
            Some(FakeOp::PutRaw),
            Some("index"),
            1,
            Fault::PreconditionFailed,
        );
        let err = run_probe(&f, BackendKind::Aws, HEADER, INDEX).unwrap_err();
        assert_eq!(
            err,
            ProbeError::ConditionalWrites {
                step: 7,
                status: 412,
                header_written: true
            }
        );
    }

    #[test]
    fn access_errors_in_steps_3_to_7_are_store_errors() {
        for status in [401, 403] {
            let f = fail_header_put(0, status);
            let err = run_probe(&f, BackendKind::Aws, HEADER, INDEX).unwrap_err();
            assert_eq!(err.exit_code(), 7, "status {status}");
            assert_eq!(
                err,
                ProbeError::Store(StoreError::Http {
                    status,
                    code: None,
                    method: "PUT",
                    key: "header".into()
                })
            );
        }
    }

    #[test]
    fn transient_server_errors_in_steps_3_to_7_are_retried() {
        // One 503 at each header step and at the index step: every step retries and passes.
        for n in 0..4 {
            let f = fail_header_put(n, 503);
            run_probe(&f, BackendKind::Aws, HEADER, INDEX).unwrap();
        }
        let f = FakeBackend::new();
        f.inject(
            Some(FakeOp::PutRaw),
            Some("index"),
            3,
            Fault::Http {
                status: 500,
                code: None,
            },
        );
        run_probe(&f, BackendKind::Other, HEADER, INDEX).unwrap();
        assert_eq!(f.current("index").unwrap(), INDEX);
    }

    #[test]
    fn persistent_server_errors_are_store_errors_not_refusals() {
        let f = FakeBackend::new();
        f.inject(
            Some(FakeOp::PutRaw),
            Some("header"),
            4,
            Fault::Http {
                status: 503,
                code: Some("SlowDownRead".into()),
            },
        );
        let err = run_probe(&f, BackendKind::Other, HEADER, INDEX).unwrap_err();
        assert_eq!(err.exit_code(), 7);
        assert_eq!(
            err,
            ProbeError::Store(StoreError::Http {
                status: 503,
                code: Some("SlowDownRead".into()),
                method: "PUT",
                key: "header".into()
            })
        );
        let puts = f.log().iter().filter(|e| e.op == FakeOp::PutRaw).count();
        assert_eq!(puts, 4);
    }

    #[test]
    fn not_implemented_is_a_refusal_without_retry() {
        let f = fail_header_put(0, 501);
        let err = run_probe(&f, BackendKind::Other, HEADER, INDEX).unwrap_err();
        assert_eq!(err.exit_code(), 8);
        assert_eq!(f.log().iter().filter(|e| e.op == FakeOp::PutRaw).count(), 1);
    }

    #[test]
    fn offline_mid_probe_is_a_store_error() {
        let f = FakeBackend::new();
        f.inject_after(
            Some(FakeOp::PutRaw),
            None,
            2,
            1,
            Fault::Offline(OfflineKind::Timeout),
        );
        let err = run_probe(&f, BackendKind::Aws, HEADER, INDEX).unwrap_err();
        assert_eq!(
            err,
            ProbeError::Store(StoreError::Offline(OfflineKind::Timeout))
        );
    }

    #[test]
    fn existing_header_steps_are_idempotent() {
        let f = FakeBackend::new();
        let etag = f.put_admin("header", HEADER);
        assert_eq!(probe_existing_header(&f, HEADER, &etag).unwrap(), etag);
        assert_eq!(probe_existing_header(&f, HEADER, &etag).unwrap(), etag);
        assert_eq!(f.current("header").unwrap(), HEADER);
    }

    fn kdf(m_kib: u32, t: u32, p: u32) -> KdfParams {
        KdfParams {
            m_kib,
            t,
            p,
            salt: [0; 16],
        }
    }

    #[test]
    fn kdf_calibration_bounds() {
        assert!(!kdf_above_calibration(&kdf(65536, 3, 1)));
        assert!(!kdf_above_calibration(&kdf(262_144, 3, 1)));
        assert!(kdf_above_calibration(&kdf(262_145, 3, 1)));
        assert!(kdf_above_calibration(&kdf(65536, 4, 1)));
        assert!(kdf_above_calibration(&kdf(65536, 3, 2)));
    }

    #[test]
    fn doctor_passes_on_a_well_configured_bucket() {
        let f = FakeBackend::new();
        let etag = f.put_admin("header", HEADER);
        f.put_admin("index", INDEX);
        let r = doctor_checks(&f, BackendKind::Aws, HEADER, &etag, &kdf(65536, 3, 1)).unwrap();
        assert!(r.all_passed(), "{r:?}");
        assert_eq!(r.checks.len(), 7);
        assert!(!r.kdf_above_calibration);
        // Step 6 re-put the header, so its bytes are stored twice.
        assert_eq!(
            r.total_stored_bytes,
            (2 * HEADER.len() + INDEX.len()) as u64
        );
        // Nothing new appeared under e/.
        assert!(f.list("e/").unwrap().is_empty());
    }

    #[test]
    fn doctor_reports_each_failure() {
        let f = FakeBackend::with_bucket(FakeBucket {
            delete_allowed: true,
            entry_write_once: false,
            ..FakeBucket::default()
        });
        let etag = f.put_admin("header", HEADER);
        let r = doctor_checks(&f, BackendKind::Aws, HEADER, &etag, &kdf(524_288, 3, 1)).unwrap();
        let failed: Vec<_> = r
            .checks
            .iter()
            .filter(|c| !c.passed)
            .map(|c| c.check)
            .collect();
        assert_eq!(
            failed,
            vec![
                DoctorCheck::DeleteRefused,
                DoctorCheck::EntryUnconditionalRefused,
                DoctorCheck::EntryMultipartRefused,
            ]
        );
        assert!(r.kdf_above_calibration);
        assert!(!r.all_passed());
    }

    #[test]
    fn doctor_catches_ignored_conditions() {
        let f = FakeBackend::new();
        let etag = f.put_admin("header", HEADER);
        f.set_ignore_conditions(true);
        let r = doctor_checks(&f, BackendKind::Aws, HEADER, &etag, &kdf(65536, 3, 1)).unwrap();
        let failed: Vec<_> = r
            .checks
            .iter()
            .filter(|c| !c.passed)
            .map(|c| c.check)
            .collect();
        assert_eq!(
            failed,
            vec![
                DoctorCheck::HeaderCreateRefused,
                DoctorCheck::HeaderMismatchRefused,
                DoctorCheck::EntryUnconditionalRefused,
                DoctorCheck::EntryOtherConditionRefused,
                DoctorCheck::EntryMultipartRefused,
            ]
        );
        assert_eq!(r.entry_keys, EntryKeys::Checked);
    }

    #[test]
    fn doctor_skips_write_once_checks_on_other_backends() {
        let f = FakeBackend::with_bucket(FakeBucket {
            entry_write_once: false,
            ..FakeBucket::default()
        });
        let etag = f.put_admin("header", HEADER);
        let r = doctor_checks(&f, BackendKind::Other, HEADER, &etag, &kdf(65536, 3, 1)).unwrap();
        assert_eq!(
            r.checks.iter().map(|c| c.check).collect::<Vec<_>>(),
            vec![
                DoctorCheck::HeaderCreateRefused,
                DoctorCheck::HeaderMismatchRefused,
                DoctorCheck::HeaderMatchAccepted,
                DoctorCheck::DeleteRefused,
            ]
        );
        assert_eq!(r.entry_keys, EntryKeys::NotWriteOnce { versioned: true });
        assert!(r.all_passed(), "{r:?}");
        // No probe objects were left under e/.
        assert!(f.list("e/").unwrap().is_empty());
    }

    #[test]
    fn doctor_fails_an_unversioned_other_backend() {
        for state in [Versioning::Off, Versioning::Suspended] {
            let f = bucket(state, false, None);
            let etag = f.put_admin("header", HEADER);
            let r =
                doctor_checks(&f, BackendKind::Other, HEADER, &etag, &kdf(65536, 3, 1)).unwrap();
            assert!(r.settings.is_ok());
            assert!(r.checks.iter().all(|c| c.passed));
            assert_eq!(r.entry_keys, EntryKeys::NotWriteOnce { versioned: false });
            assert!(!r.all_passed());
        }
    }

    #[test]
    fn warning_texts() {
        assert_eq!(
            NO_VERSIONING_WARNING,
            "Without versioning a stolen device key can overwrite history and entries; \
             vlt's mirrors are the only copy."
        );
        assert_eq!(
            ENTRY_KEYS_NOT_WRITE_ONCE,
            "entry keys are not write-once on this backend"
        );
    }

    #[test]
    fn doctor_reports_a_settings_refusal_and_still_checks() {
        let f = bucket(Versioning::Suspended, false, None);
        let etag = f.put_admin("header", HEADER);
        let r = doctor_checks(&f, BackendKind::Aws, HEADER, &etag, &kdf(65536, 3, 1)).unwrap();
        assert_eq!(
            r.settings,
            Err(ProbeError::VersioningRequired {
                state: Versioning::Suspended
            })
        );
        assert_eq!(r.checks.len(), 7);
        assert!(!r.all_passed());
    }

    #[test]
    fn doctor_offline_is_an_error() {
        let f = FakeBackend::new();
        let etag = f.put_admin("header", HEADER);
        f.inject(None, None, 1, Fault::Offline(OfflineKind::Dns));
        assert!(
            doctor_checks(&f, BackendKind::Aws, HEADER, &etag, &kdf(65536, 3, 1))
                .unwrap_err()
                .is_offline()
        );
    }
}
