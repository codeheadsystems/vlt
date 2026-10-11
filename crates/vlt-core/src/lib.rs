//! vlt-core: the key hierarchy, object formats, and pure vault logic that every vlt client shares.
//!
//! The crate does no file or network I/O and exposes no async API, so it builds for
//! `wasm32-unknown-unknown` and binds through UniFFI. `spec/crypto-and-storage.md` is normative;
//! every format here follows it and is checked against `spec/vectors/`.
#![forbid(unsafe_code)]

mod codec;
pub mod device;
pub mod enroll;
pub mod entry;
pub mod entry_text;
pub mod error;
pub mod export;
pub mod ext;
pub mod header;
pub mod index;
pub mod kdf;
pub mod keys;
pub mod limits;
pub mod merge;
pub mod mirror_state;
pub mod notice;
pub mod ops;
pub mod path;
pub mod pins;
mod prim;
pub mod retention;
mod rng;
pub mod secret;
pub mod secret_key_text;
pub mod session;
mod textcodec;
pub mod vault;
pub mod wrap;

#[cfg(test)]
mod tests;

pub use error::{Error, InputKind, IntegrityKind, Result};
pub use header::{HeaderInfo, ParsedHeader, VaultKeys, parse_header};
pub use prim::sha256;
pub use secret::{Auk, DeviceSecrets, SecretKey, VaultKey};

/// The format version this client reads and writes.
pub const FORMAT_VERSION: u16 = 1;
