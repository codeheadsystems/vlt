# vlt

vlt is a single-user, zero-knowledge password manager with pass ergonomics. Its only storage is an
S3-compatible bucket (AWS S3 or RustFS) that holds ciphertext. The project is MIT licensed.

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

## Workspace layout

| Crate | Role |
| --- | --- |
| `crates/vlt-core` | Crypto, formats, index, merge, history, sync engine. No I/O beyond traits, no async runtime in the public API, no filesystem access. Builds for `wasm32-unknown-unknown` and stays UniFFI-friendly |
| `crates/vlt-store` | S3 backend, local encrypted mirror, write queue, capability probe |
| `crates/vlt-cli` | The `vlt` binary, agent, clipboard, completion |
| `crates/vlt-import` | Bitwarden and pass import, pass export |

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
  `x25519-dalek`, `hkdf`, `sha2`, `zeroize`. No custom primitives and no hand-rolled constructions
  beyond what the spec defines.
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
