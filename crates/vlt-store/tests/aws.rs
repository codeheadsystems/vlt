//! AWS S3 integration tests. They run only when `VLT_TEST_AWS_BUCKET` is set, with credentials
//! in `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` (read here by the test harness only; vlt
//! itself never reads a default credential chain). Optional: `VLT_TEST_AWS_REGION` (default
//! `us-east-1`) and `VLT_TEST_AWS_ACCOUNT_ID`, sent as the expected bucket owner. With
//! `VLT_REQUIRE_AWS=1` a missing bucket fails every test instead of skipping it.
//!
//! The bucket outlives a run, so these tests write under a fresh random prefix and do not run
//! probe step 2, which needs an empty bucket. The credentials need `s3:PutObject`,
//! `s3:GetObject`, listing, and the settings reads on the bucket.

use std::time::Duration;
use vlt_core::enroll::VaultConfig;
use vlt_store::probe::{BackendKind, ProbeError, probe_existing_header, probe_settings};
use vlt_store::{Backend, BucketProbe, Credentials, Get, Put, S3Backend, S3Config};
use zeroize::Zeroizing;

struct Env {
    bucket: String,
    region: String,
    key: String,
    secret: String,
    account: Option<String>,
}

fn env() -> Option<Env> {
    let Ok(bucket) = std::env::var("VLT_TEST_AWS_BUCKET") else {
        // A job that must run these tests sets this, so a missing bucket fails instead of passing.
        if std::env::var("VLT_REQUIRE_AWS").as_deref() == Ok("1") {
            panic!("VLT_REQUIRE_AWS=1 but VLT_TEST_AWS_BUCKET is not set");
        }
        eprintln!("skipped: set VLT_TEST_AWS_BUCKET and AWS credentials to run");
        return None;
    };
    let var = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"));
    Some(Env {
        bucket,
        region: std::env::var("VLT_TEST_AWS_REGION").unwrap_or_else(|_| "us-east-1".into()),
        key: var("AWS_ACCESS_KEY_ID"),
        secret: var("AWS_SECRET_ACCESS_KEY"),
        account: std::env::var("VLT_TEST_AWS_ACCOUNT_ID").ok(),
    })
}

fn random_hex(bytes: usize) -> String {
    let mut b = vec![0u8; bytes];
    getrandom::fill(&mut b).unwrap();
    hex::encode(b)
}

fn backend(env: &Env, owner: Option<&str>) -> S3Backend {
    let mut c = S3Config::new(VaultConfig {
        vault_id: [0x5a; 16],
        region: env.region.clone(),
        bucket: env.bucket.clone(),
        prefix: format!("vlt-it-{}/", random_hex(8)),
        endpoint: String::new(),
    });
    c.expected_bucket_owner = owner.map(str::to_owned);
    c.io_timeout = Duration::from_secs(30);
    S3Backend::new(
        &c,
        Credentials::new(env.key.clone(), Zeroizing::new(env.secret.clone())),
    )
    .unwrap()
}

#[test]
fn settings_reads() {
    let Some(env) = env() else { return };
    let b = backend(&env, env.account.as_deref());
    match probe_settings(&b, BackendKind::Aws) {
        Ok(_) | Err(ProbeError::VersioningRequired { .. }) => {}
        Err(e) => panic!("{e:?}"),
    }
    b.any_object_or_version().unwrap();
    b.total_stored_bytes().unwrap();
}

#[test]
fn conditional_writes() {
    let Some(env) = env() else { return };
    let d = backend(&env, env.account.as_deref());
    let Put::Written { etag: e1 } = d.create("index", b"v1").unwrap() else {
        panic!()
    };
    assert_eq!(d.create("index", b"v1").unwrap(), Put::PreconditionFailed);
    let Put::Written { etag: e2 } = d.replace("index", b"v2", &e1).unwrap() else {
        panic!()
    };
    assert_eq!(
        d.replace("index", b"v3", &e1).unwrap(),
        Put::PreconditionFailed
    );
    assert_eq!(d.get("index", Some(&e2), 10).unwrap(), Get::NotModified);
    let entry = format!("e/{}", random_hex(16));
    assert!(matches!(
        d.create(&entry, b"x").unwrap(),
        Put::Written { .. }
    ));
    assert_eq!(d.create(&entry, b"x").unwrap(), Put::PreconditionFailed);
    assert_eq!(d.list("").unwrap(), vec![entry, "index".to_owned()]);
}

#[test]
fn header_conditions_hold() {
    let Some(env) = env() else { return };
    let d = backend(&env, env.account.as_deref());
    let Put::Written { etag } = d.create("header", b"h").unwrap() else {
        panic!()
    };
    assert_eq!(probe_existing_header(&d, b"h", &etag).unwrap(), etag);
}

#[test]
fn wrong_expected_owner_is_refused() {
    let Some(env) = env() else { return };
    let d = backend(&env, Some("000000000000"));
    let err = d.get("index", None, 10).unwrap_err();
    assert_eq!(err.status(), Some(403), "{err:?}");
}
