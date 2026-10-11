//! The `Backend` trait every store implements: S3, the local store, and the in-memory fake.
//!
//! Keys are prefix-relative: `header`, `index`, `e/<object_id hex>`, and `enroll/<device_id hex>`.
//! The S3 backend adds the vault's prefix; the local store uses the keys as relative paths.

use crate::error::StoreError;

/// An opaque etag as the backend returns it: the quoted `ETag` header value on S3, the hex
/// SHA-256 of the bytes on the local store.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Etag(pub String);

/// The result of a `GET`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Get {
    /// The object, and its etag.
    Found {
        /// The object's bytes.
        bytes: Vec<u8>,
        /// The object's etag.
        etag: Etag,
    },
    /// The object's etag equals the `If-None-Match` value. A backend may always answer `Found`
    /// instead.
    NotModified,
    /// No object has the key.
    NotFound,
}

/// The result of a conditional `PUT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Put {
    /// The write landed.
    Written {
        /// The new object's etag.
        etag: Etag,
    },
    /// The condition failed: the key already exists (create), or its etag differs or it is absent
    /// (replace). Nothing was written.
    PreconditionFailed,
}

/// The result of a `DELETE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delete {
    /// The object was deleted.
    Deleted,
    /// No object had the key.
    NotFound,
}

/// A store of vault objects. Every method blocks.
pub trait Backend: Send + Sync {
    /// Fetches an object. A body larger than `max_len` is refused with
    /// [`StoreError::TooLarge`] before it is read: the length is checked first, and the read is
    /// capped as well.
    fn get(
        &self,
        key: &str,
        if_none_match: Option<&Etag>,
        max_len: usize,
    ) -> Result<Get, StoreError>;

    /// Whether an object exists (`HEAD`; `404` is `false`).
    fn exists(&self, key: &str) -> Result<bool, StoreError>;

    /// Writes an object only if the key is absent (`If-None-Match: *`).
    fn create(&self, key: &str, bytes: &[u8]) -> Result<Put, StoreError>;

    /// Replaces an object only if its etag equals `expected` (`If-Match`).
    fn replace(&self, key: &str, bytes: &[u8], expected: &Etag) -> Result<Put, StoreError>;

    /// Every key that starts with `prefix`, sorted, across every page of the listing.
    fn list(&self, prefix: &str) -> Result<Vec<String>, StoreError>;

    /// Deletes an object. Only `vlt purge` on a local vault uses it; S3 device keys get `403`.
    fn delete(&self, key: &str) -> Result<Delete, StoreError>;
}
