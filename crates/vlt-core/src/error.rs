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
