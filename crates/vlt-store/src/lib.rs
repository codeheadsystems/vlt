//! vlt-store: the blocking storage backends behind `vlt-core`'s sans-I/O sync logic.
//!
//! The crate moves ciphertext only. It holds the [`Backend`] trait and its implementations (S3,
//! the local store, and an in-memory fake for tests), the S3-only [`BucketProbe`] with the
//! capability probe and `vlt doctor` checks, and the backend descriptor in `vaults.toml`.
//! It also holds the mirror directory and the driver that runs `vlt-core`'s sync session against a
//! backend and a mirror. `spec/crypto-and-storage.md` is normative.
#![forbid(unsafe_code)]

pub mod backend;
pub mod descriptor;
pub mod driver;
pub mod error;
pub mod fake;
mod fsutil;
pub mod local;
pub mod mirror;
pub mod probe;
pub mod retry;
pub mod s3;
mod xml;

pub use backend::{Backend, Delete, Etag, Get, Put};
pub use error::{OfflineKind, StoreError};
pub use local::LocalStore;
pub use probe::{BackendKind, BucketProbe};
pub use s3::{Credentials, S3Backend, S3Config};
