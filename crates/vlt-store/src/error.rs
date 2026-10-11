//! Store errors, classified as the spec's "Sync policy" requires: a transport failure is offline,
//! and any HTTP response is not.

use core::fmt;
use std::io;

/// Why a backend could not be reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineKind {
    /// The connection was refused or could not be opened.
    Connect,
    /// The host name did not resolve.
    Dns,
    /// A connect, send, or receive timeout expired.
    Timeout,
    /// The connection dropped before the response was complete.
    ConnectionLost,
}

impl fmt::Display for OfflineKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            OfflineKind::Connect => "connection failed",
            OfflineKind::Dns => "host name not found",
            OfflineKind::Timeout => "timed out",
            OfflineKind::ConnectionLost => "connection lost",
        })
    }
}

/// Every error a backend returns. No variant carries an object body or a credential; keys are
/// prefix-relative (`header`, `index`, `e/<hex>`, `enroll/<hex>`), and bucket-level requests carry
/// an empty key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// A connection failure, DNS failure, or timeout: the spec's "offline". Maps to exit code 0
    /// with writes queued, or 9 with `--strict`.
    Offline(OfflineKind),
    /// An HTTP error response. Maps to exit code 7.
    Http {
        /// The HTTP status.
        status: u16,
        /// The S3 error code from the response body, when it has one.
        code: Option<String>,
        /// The HTTP method of the request.
        method: &'static str,
        /// The prefix-relative key, or empty for a bucket-level request.
        key: String,
    },
    /// A response or object body larger than the size limit for its key.
    TooLarge {
        /// The prefix-relative key.
        key: String,
    },
    /// A local file system error.
    Io {
        /// The kind of the underlying error.
        kind: io::ErrorKind,
        /// The prefix-relative key, or empty for the store itself.
        key: String,
    },
    /// A TLS failure other than a dropped connection, such as an untrusted certificate. It is not
    /// "offline", because it persists until someone fixes it.
    Tls {
        /// The TLS library's description of the failure, which names no secret.
        detail: String,
    },
    /// The S3 configuration breaks a rule; nothing was sent.
    InvalidConfig {
        /// Which value.
        what: &'static str,
    },
    /// A malformed response, such as unparseable XML or a missing `ETag`.
    Protocol {
        /// What was wrong.
        what: &'static str,
    },
}

impl StoreError {
    /// Whether the backend could not be reached, as opposed to answering with an error.
    pub fn is_offline(&self) -> bool {
        matches!(self, StoreError::Offline(_))
    }

    /// Whether the error means the device's access key was rejected: S3 error code
    /// `InvalidAccessKeyId` or `SignatureDoesNotMatch` on any request, or `AccessDenied` on a read
    /// of the header. The CLI then says "This device's access key was rejected; it may have been
    /// revoked or deleted". Every other HTTP error names its code and key instead.
    pub fn is_access_key_rejected(&self) -> bool {
        let StoreError::Http {
            code: Some(code),
            method,
            key,
            ..
        } = self
        else {
            return false;
        };
        match code.as_str() {
            "InvalidAccessKeyId" | "SignatureDoesNotMatch" => true,
            "AccessDenied" => key == "header" && matches!(*method, "GET" | "HEAD"),
            _ => false,
        }
    }

    /// The HTTP status, for an HTTP error.
    pub fn status(&self) -> Option<u16> {
        match self {
            StoreError::Http { status, .. } => Some(*status),
            _ => None,
        }
    }

    pub(crate) fn io(err: &io::Error, key: &str) -> StoreError {
        StoreError::Io {
            kind: err.kind(),
            key: key.to_owned(),
        }
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Offline(kind) => write!(f, "the vault's store cannot be reached: {kind}"),
            StoreError::Http {
                status,
                code,
                method,
                key,
            } => {
                write!(f, "the store answered {status}")?;
                if let Some(code) = code {
                    write!(f, " {code}")?;
                }
                if key.is_empty() {
                    write!(f, " to a bucket {method}")
                } else {
                    write!(f, " to {method} {key}")
                }
            }
            StoreError::TooLarge { key } => write!(f, "{key} is larger than its size limit"),
            StoreError::Io { kind, key } if key.is_empty() => {
                write!(f, "local store error: {kind}")
            }
            StoreError::Io { kind, key } => write!(f, "local store error on {key}: {kind}"),
            StoreError::Tls { detail } => write!(f, "TLS error talking to the store: {detail}"),
            StoreError::InvalidConfig { what } => write!(f, "invalid store configuration: {what}"),
            StoreError::Protocol { what } => write!(f, "malformed response from the store: {what}"),
        }
    }
}

impl std::error::Error for StoreError {}

/// Keeps a server-supplied string printable and short before it reaches an error message.
/// S3 error codes are short ASCII identifiers; anything else is dropped.
pub(crate) fn sanitise_code(code: &str) -> Option<String> {
    let ok = !code.is_empty()
        && code.len() <= 64
        && code
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-');
    ok.then(|| code.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn http(code: &str, method: &'static str, key: &str) -> StoreError {
        StoreError::Http {
            status: 403,
            code: Some(code.to_owned()),
            method,
            key: key.to_owned(),
        }
    }

    #[test]
    fn access_key_rejected_classification() {
        assert!(http("InvalidAccessKeyId", "PUT", "index").is_access_key_rejected());
        assert!(http("SignatureDoesNotMatch", "GET", "e/00").is_access_key_rejected());
        assert!(http("AccessDenied", "GET", "header").is_access_key_rejected());
        assert!(http("AccessDenied", "HEAD", "header").is_access_key_rejected());
        assert!(!http("AccessDenied", "PUT", "header").is_access_key_rejected());
        assert!(!http("AccessDenied", "GET", "index").is_access_key_rejected());
        assert!(!http("InvalidObjectState", "GET", "header").is_access_key_rejected());
        assert!(!StoreError::Offline(OfflineKind::Dns).is_access_key_rejected());
    }

    #[test]
    fn offline_is_only_transport() {
        assert!(StoreError::Offline(OfflineKind::Timeout).is_offline());
        assert!(!http("AccessDenied", "GET", "header").is_offline());
        assert!(!StoreError::Tls { detail: "x".into() }.is_offline());
    }

    #[test]
    fn display_names_code_and_key() {
        assert_eq!(
            http("AccessDenied", "PUT", "e/0a").to_string(),
            "the store answered 403 AccessDenied to PUT e/0a"
        );
        let bucket = StoreError::Http {
            status: 500,
            code: None,
            method: "GET",
            key: String::new(),
        };
        assert_eq!(bucket.to_string(), "the store answered 500 to a bucket GET");
    }

    #[test]
    fn sanitise_drops_odd_codes() {
        assert_eq!(sanitise_code("NoSuchKey").as_deref(), Some("NoSuchKey"));
        assert_eq!(sanitise_code("bad\x1b[31m"), None);
        assert_eq!(sanitise_code(""), None);
        assert_eq!(sanitise_code(&"A".repeat(65)), None);
    }
}
