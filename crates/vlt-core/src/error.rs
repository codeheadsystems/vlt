//! Errors. Variants carry no strings or bytes from their inputs, so no path, entry content, or key
//! material can reach an error message.

use core::fmt;

/// Every error `vlt-core` returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// An object failed authentication or a decode rule. Maps to CLI exit code 6.
    Integrity(IntegrityKind),
    /// An object carries a format version this client does not know.
    UnsupportedFormatVersion(u16),
    /// A wrap did not open: a wrong password or secret key, or a device not enrolled. A tampered
    /// wrap is deliberately indistinguishable from a wrong password.
    WrongPasswordOrUnknownDevice,
    /// A secret key's text form has a wrong check value or shape.
    SecretKeyTypo,
    /// A value supplied by the caller breaks a rule; nothing was encoded.
    InvalidInput(InputKind),
    /// The operating system random number generator failed.
    Rng,
    /// The index changed under every one of the publish attempts the spec allows. The write queue
    /// is kept. Maps to CLI exit code 7.
    PublishContention,
}

/// The decode rule an object broke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum IntegrityKind {
    BadMagic,
    UnknownFlags,
    KdfParams,
    TestKdfInRelease,
    Truncated,
    TrailingBytes,
    InvalidUtf8,
    CounterCap,
    Order,
    Duplicate,
    PathRule,
    LabelRule,
    PrefixRule,
    ExtCritical,
    ExtValue,
    ExtCount,
    Padding,
    PaddedSize,
    SizeLimit,
    Aead,
    Mac,
    KemEk,
    LowOrderPoint,
    Keyring,
    Legacy,
    DeviceInfoMismatch,
    DeviceKind,
    Base64,
    ShaMismatch,
    ObjectIdMismatch,
    VaultIdMismatch,
    UnknownLineage,
    ParentRule,
    IndexEpoch,
    EndpointRule,
    RegionRule,
    BucketRule,
    SkCheck,
    Rotation,
    HeadMismatch,
    /// A header older than the pinned one.
    HeaderRollback,
    /// A header with the pinned `header_seq` but different bytes.
    HeaderFork,
    /// An index older than the pinned one.
    IndexRollback,
    /// An index with the pinned `index_seq` but a different hash.
    IndexFork,
    /// A vault key fingerprint that does not match the pin.
    PinFingerprint,
    /// An epoch more than 16 past the pinned one.
    EpochJump,
    /// A header or index that names this device as writer but that this device did not write.
    ForgedWriter,
    /// An index that names a `header_seq` newer than the header in the bucket.
    IndexHeaderSeq,
    /// A live entry's head that the backend no longer holds.
    HeadMissing,
    /// A stored object that differs from the bytes this device wrote under the same key.
    ObjectMismatch,
    /// A mirror file that does not match the mirror's own records.
    MirrorMismatch,
    /// The header or index is missing from the backend.
    ObjectMissing,
}

/// The rule a caller-supplied value broke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum InputKind {
    PasswordTooShort,
    PasswordUnassigned,
    Path,
    Label,
    Prefix,
    Bucket,
    Region,
    Endpoint,
    VaultConfig,
    ComparisonCode,
    TooLarge,
    Order,
    Duplicate,
    CounterCap,
    DeviceKind,
    KdfParams,
    Keyring,
    Ext,
    ParentRule,
    UnknownLineage,
    /// No entry at that path or with that head.
    NotFound,
    /// The destination path already holds an entry.
    PathTaken,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Integrity(k) => write!(f, "integrity error: {k:?}"),
            Error::UnsupportedFormatVersion(v) => {
                write!(f, "format version {v} is not supported; upgrade vlt")
            }
            Error::WrongPasswordOrUnknownDevice => {
                f.write_str("wrong password or secret key, or this device is not enrolled")
            }
            Error::SecretKeyTypo => f.write_str("the secret key has a typo"),
            Error::InvalidInput(k) => write!(f, "invalid input: {k:?}"),
            Error::Rng => f.write_str("the system random number generator failed"),
            Error::PublishContention => {
                f.write_str("the vault index kept changing while publishing; changes stay queued")
            }
        }
    }
}

impl core::error::Error for Error {}

/// Result alias.
pub type Result<T> = core::result::Result<T, Error>;

pub(crate) fn integrity<T>(k: IntegrityKind) -> Result<T> {
    Err(Error::Integrity(k))
}

pub(crate) fn input<T>(k: InputKind) -> Result<T> {
    Err(Error::InvalidInput(k))
}
