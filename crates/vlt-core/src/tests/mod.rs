//! Known-answer, malformed, tamper, and property tests. Every file in `spec/vectors/` has a harness
//! here; [`vectors::every_vector_file_has_a_harness`] fails if one is added without one.

mod props;
mod rules;
mod vectors;

use serde_json::Value;

pub(crate) fn load(name: &str) -> Value {
    let path = format!("{}/../../spec/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&text).unwrap()
}

pub(crate) fn hx(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string")).expect("valid hex")
}

pub(crate) fn arr<const N: usize>(v: &Value) -> [u8; N] {
    hx(v).try_into().expect("length")
}

pub(crate) fn u(v: &Value) -> u64 {
    v.as_u64().expect("integer")
}

pub(crate) fn s(v: &Value) -> &str {
    v.as_str().expect("string")
}
