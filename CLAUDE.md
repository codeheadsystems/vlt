# vlt

vlt is a single-user, zero-knowledge password manager with pass ergonomics. Its shared storage is an
S3-compatible bucket (AWS S3 or RustFS) that holds ciphertext; a vault can also start local on one
device and attach a bucket later. The project is MIT licensed.

## Documents

| Path | Contents |
| --- | --- |
| `docs/Personal Password Manager Requirements.md` | Requirements, threat model, architecture |
| `docs/vlt PRFAQ A Password Manager You Own.md` | Product intent |
| `docs/style.md` | Documentation style for the spec, `README.md`, this file, and rustdoc |
| `spec/crypto-and-storage.md` | Crypto and storage spec; the normative description of every format |
| `spec/vectors/` | Known-answer test vectors that every client checks |

The spec is normative. Where code and spec disagree, the code is wrong until a spec change is
proposed and approved.

## Repository layout

The repository is a monorepo for every vlt client: the CLI, Android, the Firefox extension, and the
optional Linux desktop app all build from it against the one Rust core.

| Path | Role | Phase |
| --- | --- | --- |
| `crates/vlt-core` | Crypto, formats, index, merge, history, sync engine. No I/O beyond traits, no async runtime in the public API, no filesystem access. Builds for `wasm32-unknown-unknown` and stays UniFFI-friendly | 2 |
| `crates/vlt-store` | S3 and local backends, local encrypted mirror, write queue, capability probe | 2 |
| `crates/vlt-cli` | The `vlt` binary, agent, clipboard, completion | 2 |
| `crates/vlt-import` | Bitwarden and pass import, pass export | 2 |
| `crates/vlt-ffi` | UniFFI bindings over `vlt-core` for Android | 3 |
| `crates/vlt-wasm` | `wasm-bindgen` bindings over `vlt-core` for the Firefox extension | 4 |
| `android/` | Kotlin app (Gradle), consuming `vlt-ffi` | 3 |
| `firefox/` | WebExtension and native-messaging manifest, consuming the CLI agent and later `vlt-wasm` | 4 |
| `desktop/` | Optional Linux desktop app | 5 |
| `spec/` | Spec and test vectors | 1 |

Paths marked with a later phase do not exist yet. Platform code outside `crates/` keeps its own
native build tool (Gradle, `web-ext`) and reaches Rust only through the binding crates.

## Commands

```sh
cargo build --workspace
cargo test --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check
cargo audit
cargo build -p vlt-core --target wasm32-unknown-unknown
```

Integration tests against RustFS run in Docker. AWS integration tests run only when
`VLT_TEST_AWS_BUCKET` and AWS credentials are set.

## Crypto rules

- Primitives come from RustCrypto only: `argon2`, `chacha20poly1305` (XChaCha20-Poly1305),
  `x25519-dalek`, `ml-kem` (ML-KEM-768, only in the hybrid device wrap), `hkdf`, `sha2`, `zeroize`.
  No custom primitives and no hand-rolled constructions beyond what the spec defines.
- No `unsafe` outside narrowly justified blocks, each with a comment giving the justification.
- No plaintext on disk. No secrets in logs, error messages, or panics.
- Secret types hold their bytes in `zeroize` buffers and do not implement `Debug` or `Display`.
- Argon2id parameters are never lowered below the spec's floor. Tests use the test-only parameter
  set, which the header marks as such and release builds reject.
- The header carries the format version. A client refuses to write a format version newer than it
  knows.
- Every object format change updates the spec and the test vectors in the same commit.

## Licensing

Dependencies are MIT, Apache-2.0, BSD, ISC, Zlib, or Unicode licensed. `cargo-deny` enforces the
list.

## Style

Documentation in scope follows `docs/style.md`: third person, present tense, no em dashes, serial
comma, British spelling in prose, prose wrapped at 100 columns.
