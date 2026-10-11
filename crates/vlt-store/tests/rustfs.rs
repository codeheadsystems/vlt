//! RustFS integration tests. They run only when `VLT_TEST_RUSTFS=1`, against a server started by
//! `scripts/rustfs-up.sh <single|multi>` whose output variables are in the environment. With
//! `VLT_REQUIRE_RUSTFS=1`, as the CI RustFS job sets, a missing variable fails every test instead
//! of skipping it:
//!
//! ```sh
//! set -a; eval "$(scripts/rustfs-up.sh single)"; set +a
//! VLT_TEST_RUSTFS=1 cargo test -p vlt-store --test rustfs
//! ```
//!
//! Each test creates its own bucket and a device user holding the RustFS device policy from
//! `prompts/rustfs-findings.md`, using RustFS's `rc` client in Docker.

mod common;

use std::process::Command;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;
use vlt_core::enroll::VaultConfig;
use vlt_core::kdf::KdfParams;
use vlt_store::probe::{
    self, BackendKind, DoctorCheck, EntryKeys, ProbeError, ProbeWarning, RawCond, RetentionMode,
    Versioning, doctor_checks, probe_settings, run_probe,
};
use vlt_store::{
    Backend, BucketProbe, Credentials, Etag, Get, OfflineKind, Put, S3Backend, S3Config, StoreError,
};
use zeroize::Zeroizing;

const RC_IMAGE: &str =
    "rustfs/rc:v0.1.36@sha256:ab024bfebee49a750ce886b4c70963ccd9ddaa03f491704a90710641d7a26699";
const PREFIX: &str = "vlt/";
const HEADER: &[u8] = b"probe header bytes";
const INDEX: &[u8] = b"probe index bytes";
const ENTRY: &str = "e/00112233445566778899aabbccddeeff";

struct Env {
    endpoint: String,
    region: String,
    admin_key: String,
    admin_secret: String,
}

fn env() -> Option<Env> {
    if std::env::var("VLT_TEST_RUSTFS").as_deref() != Ok("1") {
        // The CI RustFS job sets this, so a missing server fails there instead of passing.
        if std::env::var("VLT_REQUIRE_RUSTFS").as_deref() == Ok("1") {
            panic!("VLT_REQUIRE_RUSTFS=1 but VLT_TEST_RUSTFS is not 1");
        }
        eprintln!("skipped: set VLT_TEST_RUSTFS=1 and start scripts/rustfs-up.sh to run");
        return None;
    }
    let var = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"));
    Some(Env {
        endpoint: var("VLT_RUSTFS_ENDPOINT"),
        region: var("VLT_RUSTFS_REGION"),
        admin_key: var("VLT_RUSTFS_ACCESS_KEY"),
        admin_secret: var("VLT_RUSTFS_SECRET_KEY"),
    })
}

fn random_hex(bytes: usize) -> String {
    let mut b = vec![0u8; bytes];
    getrandom::fill(&mut b).unwrap();
    hex::encode(b)
}

/// The RustFS device policy (findings D7) for `bucket` and the `vlt/` prefix.
fn device_policy(bucket: &str) -> String {
    let obj = |k: &str| format!("\"arn:aws:s3:::{bucket}/{PREFIX}{k}\"");
    let bucket_arn = format!("\"arn:aws:s3:::{bucket}\"");
    let all = format!("\"arn:aws:s3:::{bucket}/*\"");
    format!(
        r#"{{"Version":"2012-10-17","Statement":[
{{"Effect":"Allow","Action":["s3:GetObject","s3:GetObjectVersion","s3:PutObject"],
 "Resource":[{h},{i},{e},{r}]}},
{{"Effect":"Allow","Action":["s3:ListBucket","s3:ListBucketVersions","s3:GetBucketVersioning",
 "s3:GetBucketObjectLockConfiguration","s3:GetBucketLifecycle"],"Resource":{bucket_arn}}},
{{"Effect":"Deny","Action":"s3:PutObject","Resource":{all},
 "Condition":{{"Null":{{"s3:x-amz-storage-class":"false"}},"StringNotEquals":{{"s3:x-amz-storage-class":"STANDARD"}}}}}},
{{"Effect":"Deny","Action":"s3:PutObject","Resource":{all},
 "Condition":{{"Null":{{"s3:x-amz-server-side-encryption":"false"}},"StringNotEquals":{{"s3:x-amz-server-side-encryption":"AES256"}}}}}},
{{"Effect":"Deny","Action":"s3:PutObject","Resource":{all},
 "Condition":{{"Null":{{"s3:x-amz-server-side-encryption-customer-algorithm":"false"}}}}}},
{{"Effect":"Deny","Action":["s3:DeleteObject","s3:DeleteObjectVersion","s3:ForceDeleteObject",
 "s3:PutBucketVersioning","s3:PutBucketLifecycle","s3:PutBucketPolicy",
 "s3:PutBucketObjectLockConfiguration","s3:PutBucketEncryption","s3:PutObjectRetention",
 "s3:PutObjectLegalHold","s3:BypassGovernanceRetention","s3:PutObjectAcl","s3:PutBucketAcl",
 "s3:DeleteBucket","s3:ForceDeleteBucket","s3:DeleteBucketPolicy"],
 "Resource":[{bucket_arn},{all}]}}]}}"#,
        h = obj("header"),
        i = obj("index"),
        e = obj("e/*"),
        r = obj("enroll/*"),
    )
}

/// Runs an admin script with `rc`, the alias `A` already set.
fn rc(env: &Env, script: &str) {
    let full = format!(
        "set -eu\nrc alias set A '{}' '{}' '{}' >/dev/null\n{script}",
        env.endpoint, env.admin_key, env.admin_secret
    );
    let out = Command::new("docker")
        .args(["run", "--rm", "--network", "host", "--entrypoint", "sh"])
        .arg(RC_IMAGE)
        .args(["-c", &full])
        .output()
        .expect("docker runs");
    assert!(
        out.status.success(),
        "rc failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[derive(Default)]
struct BucketOpts {
    versioned: bool,
    lock: bool,
    lifecycle_days: Option<u32>,
}

struct Vault {
    bucket: String,
    device: S3Backend,
    device_key: String,
    device_secret: String,
}

fn config(env: &Env, bucket: &str, prefix: &str) -> S3Config {
    let mut c = S3Config::new(VaultConfig {
        vault_id: [0x5a; 16],
        region: env.region.clone(),
        bucket: bucket.to_owned(),
        prefix: prefix.to_owned(),
        endpoint: env.endpoint.clone(),
    });
    c.connect_timeout = Duration::from_secs(3);
    c.io_timeout = Duration::from_secs(20);
    c
}

fn backend(env: &Env, bucket: &str, prefix: &str, key: &str, secret: &str) -> S3Backend {
    S3Backend::new(
        &config(env, bucket, prefix),
        Credentials::new(key.to_owned(), Zeroizing::new(secret.to_owned())),
    )
    .unwrap()
}

/// A fresh bucket and a device user with the device policy for it.
fn setup(env: &Env, opts: BucketOpts) -> Vault {
    let tag = random_hex(4);
    let bucket = format!("vlt-it-{tag}");
    let user = format!("vlt-{tag}-{}", random_hex(4));
    let secret = random_hex(20);
    let mut flags = String::new();
    if opts.versioned {
        flags.push_str(" --with-versioning");
    }
    if opts.lock {
        flags.push_str(" --with-lock");
    }
    let mut script = format!("rc bucket create{flags} 'A/{bucket}' >/dev/null\n");
    if let Some(days) = opts.lifecycle_days {
        for key in ["header", "index"] {
            script.push_str(&format!(
                "rc bucket lifecycle rule add --prefix '{PREFIX}{key}' --noncurrent-expiry-days {days} 'A/{bucket}' >/dev/null\n"
            ));
        }
    }
    script.push_str(&format!(
        "rc admin policy create A 'vlt-device-{tag}' /dev/stdin >/dev/null <<'EOF'\n{}\nEOF\n\
         rc admin user add A '{user}' '{secret}' >/dev/null\n\
         rc admin policy attach A 'vlt-device-{tag}' --user '{user}' >/dev/null\n",
        device_policy(&bucket)
    ));
    rc(env, &script);
    Vault {
        device: backend(env, &bucket, PREFIX, &user, &secret),
        bucket,
        device_key: user,
        device_secret: secret,
    }
}

fn kdf() -> KdfParams {
    KdfParams {
        m_kib: 65536,
        t: 3,
        p: 1,
        salt: [0; 16],
    }
}

#[test]
fn probe_passes_on_a_versioned_bucket() {
    let Some(env) = env() else { return };
    let v = setup(
        &env,
        BucketOpts {
            versioned: true,
            ..BucketOpts::default()
        },
    );
    let report = run_probe(&v.device, BackendKind::Other, HEADER, INDEX).unwrap();
    assert_eq!(report.settings.versioning, Versioning::Enabled);
    assert!(report.settings.warnings.is_empty());
    assert!(report.settings.notes.is_empty());

    let Get::Found { bytes, etag } = v.device.get("header", None, 1024).unwrap() else {
        panic!("header missing")
    };
    assert_eq!(bytes, HEADER);
    assert_eq!(etag, report.header_etag);
    assert_eq!(
        v.device
            .get("index", Some(&report.index_etag), 1024)
            .unwrap(),
        Get::NotModified
    );
    // A second probe sees the vault and suggests enrolling.
    assert_eq!(
        run_probe(&v.device, BackendKind::Other, HEADER, INDEX).unwrap_err(),
        ProbeError::BucketNotEmpty {
            key: format!("{PREFIX}header"),
            holds_vault: true
        }
    );
}

#[test]
fn probe_warns_on_an_unversioned_bucket() {
    let Some(env) = env() else { return };
    let v = setup(&env, BucketOpts::default());
    let report = run_probe(&v.device, BackendKind::Other, HEADER, INDEX).unwrap();
    assert_eq!(report.settings.versioning, Versioning::Off);
    assert_eq!(report.settings.warnings, vec![ProbeWarning::NoVersioning]);
    // As AWS, the same answers refuse.
    assert_eq!(
        probe_settings(&v.device, BackendKind::Aws).unwrap_err(),
        ProbeError::VersioningRequired {
            state: Versioning::Off
        }
    );
}

#[test]
fn probe_refuses_a_bucket_with_foreign_objects() {
    let Some(env) = env() else { return };
    let v = setup(
        &env,
        BucketOpts {
            versioned: true,
            ..BucketOpts::default()
        },
    );
    let admin = backend(
        &env,
        &v.bucket,
        "photos/",
        &env.admin_key,
        &env.admin_secret,
    );
    assert!(matches!(
        admin.create("cat.jpg", b"meow").unwrap(),
        Put::Written { .. }
    ));
    let err = run_probe(&v.device, BackendKind::Other, HEADER, INDEX).unwrap_err();
    assert_eq!(
        err,
        ProbeError::BucketNotEmpty {
            key: "photos/cat.jpg".into(),
            holds_vault: false
        }
    );
    assert_eq!(err.exit_code(), 10);
    assert_eq!(v.device.get("header", None, 1024).unwrap(), Get::NotFound);
}

#[test]
fn settings_reads_with_object_lock_and_lifecycle() {
    let Some(env) = env() else { return };
    let v = setup(
        &env,
        BucketOpts {
            versioned: true,
            lock: true,
            lifecycle_days: Some(365),
        },
    );
    let lock = v.device.object_lock().unwrap();
    assert!(lock.enabled);
    assert_ne!(lock.default_mode, Some(RetentionMode::Compliance));
    let lc = v.device.lifecycle().unwrap();
    assert_eq!(lc.header_noncurrent_days, Some(365));
    assert_eq!(lc.index_noncurrent_days, Some(365));
    // RustFS's answers, judged as the AWS row with Object Lock on: no warnings.
    let s = probe_settings(&v.device, BackendKind::Aws).unwrap();
    assert!(s.warnings.is_empty(), "{:?}", s.warnings);
}

#[test]
fn settings_reads_without_lock_or_lifecycle() {
    let Some(env) = env() else { return };
    let v = setup(
        &env,
        BucketOpts {
            versioned: true,
            ..BucketOpts::default()
        },
    );
    assert!(!v.device.object_lock().unwrap().enabled);
    assert_eq!(v.device.lifecycle().unwrap(), probe::Lifecycle::default());
    let s = probe_settings(&v.device, BackendKind::Aws).unwrap();
    assert_eq!(s.notes, vec![probe::ProbeNote::ObjectLockAvailable]);
}

#[test]
fn conditional_writes() {
    let Some(env) = env() else { return };
    let v = setup(
        &env,
        BucketOpts {
            versioned: true,
            ..BucketOpts::default()
        },
    );
    let d = &v.device;
    let Put::Written { etag: e1 } = d.create("index", b"v1").unwrap() else {
        panic!()
    };
    assert_eq!(d.create("index", b"v1").unwrap(), Put::PreconditionFailed);
    assert_eq!(
        d.replace("index", b"v2", &Etag("\"0000\"".into())).unwrap(),
        Put::PreconditionFailed
    );
    let Put::Written { etag: e2 } = d.replace("index", b"v2", &e1).unwrap() else {
        panic!()
    };
    assert_ne!(e1, e2);
    assert_eq!(
        d.replace("index", b"v3", &e1).unwrap(),
        Put::PreconditionFailed
    );
    // `If-Match` on a missing key is `404 NoSuchKey`, which replace reports as a failed condition.
    assert_eq!(
        d.replace("header", b"x", &e1).unwrap(),
        Put::PreconditionFailed
    );
    assert!(matches!(
        d.create(ENTRY, b"entry").unwrap(),
        Put::Written { .. }
    ));
    assert_eq!(d.create(ENTRY, b"entry").unwrap(), Put::PreconditionFailed);
    assert!(d.exists(ENTRY).unwrap());
    assert!(!d.exists("header").unwrap());
    assert_eq!(d.list("").unwrap(), vec![ENTRY, "index"]);
    assert_eq!(d.list("e/").unwrap(), vec![ENTRY]);
    assert_eq!(
        d.get("index", None, 1).unwrap_err(),
        StoreError::TooLarge {
            key: "index".into()
        }
    );
    assert_eq!(d.get("index", Some(&e2), 10).unwrap(), Get::NotModified);
    // Two versions of the index, one entry.
    assert_eq!(d.total_stored_bytes().unwrap(), 2 + 2 + 5);
}

#[test]
fn device_policy_refuses_deletes_and_other_keys() {
    let Some(env) = env() else { return };
    let v = setup(
        &env,
        BucketOpts {
            versioned: true,
            ..BucketOpts::default()
        },
    );
    let err = v.device.create("other", b"x").unwrap_err();
    assert_eq!(err.status(), Some(403));
    assert!(!err.is_access_key_rejected());
    v.device.create(ENTRY, b"x").unwrap();
    assert_eq!(v.device.delete(ENTRY).unwrap_err().status(), Some(403));
}

fn doctor_report(env: &Env, versioned: bool) -> probe::DoctorReport {
    let v = setup(
        env,
        BucketOpts {
            versioned,
            ..BucketOpts::default()
        },
    );
    let report = run_probe(&v.device, BackendKind::Other, HEADER, INDEX).unwrap();
    doctor_checks(
        &v.device,
        BackendKind::Other,
        HEADER,
        &report.header_etag,
        &kdf(),
    )
    .unwrap()
}

#[test]
fn doctor_on_a_versioned_rustfs_bucket() {
    let Some(env) = env() else { return };
    let r = doctor_report(&env, true);
    assert!(r.all_passed(), "{r:?}");
    // The write-once probes are skipped on RustFS (findings D6).
    assert_eq!(
        r.checks.iter().map(|c| c.check).collect::<Vec<_>>(),
        vec![
            DoctorCheck::HeaderCreateRefused,
            DoctorCheck::HeaderMismatchRefused,
            DoctorCheck::HeaderMatchAccepted,
            DoctorCheck::DeleteRefused,
        ]
    );
    assert_eq!(r.entry_keys, EntryKeys::NotWriteOnce { versioned: true });
    assert!(r.total_stored_bytes >= (2 * HEADER.len() + INDEX.len()) as u64);
    assert!(!r.kdf_above_calibration);
}

#[test]
fn doctor_fails_an_unversioned_rustfs_bucket() {
    let Some(env) = env() else { return };
    let r = doctor_report(&env, false);
    assert!(r.checks.iter().all(|c| c.passed), "{r:?}");
    assert_eq!(r.entry_keys, EntryKeys::NotWriteOnce { versioned: false });
    assert!(!r.all_passed());
}

/// RustFS has no `s3:if-none-match` condition key, so the device policy cannot make entry keys
/// write-once (findings, "Guarantees RustFS does not enforce", and D2). A versioned bucket keeps
/// the overwritten original as a noncurrent version, which the device key cannot delete.
#[test]
fn entry_keys_are_not_write_once_on_rustfs() {
    let Some(env) = env() else { return };
    let v = setup(
        &env,
        BucketOpts {
            versioned: true,
            ..BucketOpts::default()
        },
    );
    let d = &v.device;
    assert!(matches!(
        d.create(ENTRY, b"original").unwrap(),
        Put::Written { .. }
    ));
    assert_eq!(
        d.put_raw(ENTRY, b"overwrite", &RawCond::None)
            .unwrap()
            .status,
        200
    );
    let other = "e/ffeeddccbbaa99887766554433221100";
    let r = d
        .put_raw(other, b"x", &RawCond::IfNoneMatch("\"x\"".into()))
        .unwrap();
    assert_eq!(r.status, 200);
    let mp = d
        .create_multipart("e/0123456789abcdef0123456789abcdef")
        .unwrap();
    assert_eq!(mp.status, 200);
    let Get::Found { bytes, .. } = d.get(ENTRY, None, 64).unwrap() else {
        panic!()
    };
    assert_eq!(bytes, b"overwrite");
    // Both versions of the entry are still stored, and the device key cannot delete either.
    assert_eq!(d.total_stored_bytes().unwrap(), (8 + 9 + 1) as u64);
    assert_eq!(d.delete_raw(ENTRY).unwrap().status, 403);
}

#[test]
fn rejected_access_keys() {
    let Some(env) = env() else { return };
    let v = setup(
        &env,
        BucketOpts {
            versioned: true,
            ..BucketOpts::default()
        },
    );
    let wrong_secret = backend(&env, &v.bucket, PREFIX, &v.device_key, "not-the-secret");
    let err = wrong_secret.get("header", None, 1024).unwrap_err();
    assert!(err.is_access_key_rejected(), "{err:?}");
    let unknown = backend(
        &env,
        &v.bucket,
        PREFIX,
        "vlt-00000000-00000000",
        &v.device_secret,
    );
    let err = unknown.get("index", None, 1024).unwrap_err();
    assert!(err.is_access_key_rejected(), "{err:?}");
    assert!(!err.to_string().contains(&v.device_secret));
}

/// RustFS can answer `503 SlowDownRead` instead of `412` under contention (findings, 5e).
fn slow_down(e: &StoreError) -> bool {
    e.status() == Some(503)
}

#[test]
fn concurrent_conditional_writes_have_one_winner() {
    let Some(env) = env() else { return };
    let v = setup(
        &env,
        BucketOpts {
            versioned: true,
            ..BucketOpts::default()
        },
    );
    let device = Arc::new(v.device);
    const N: usize = 16;
    let race = |op: Arc<dyn Fn(usize) -> Result<Put, StoreError> + Send + Sync>| {
        let barrier = Arc::new(Barrier::new(N));
        let handles: Vec<_> = (0..N)
            .map(|i| {
                let (op, barrier) = (Arc::clone(&op), Arc::clone(&barrier));
                thread::spawn(move || {
                    barrier.wait();
                    op(i)
                })
            })
            .collect();
        let mut winners = Vec::new();
        for h in handles {
            match h.join().unwrap() {
                Ok(Put::Written { etag }) => winners.push(etag),
                Ok(Put::PreconditionFailed) => {}
                Err(e) if slow_down(&e) => {}
                Err(e) => panic!("{e:?}"),
            }
        }
        assert_eq!(winners.len(), 1);
        winners.pop().unwrap()
    };
    let d = Arc::clone(&device);
    let etag = race(Arc::new(move |i| {
        d.create("index", format!("create {i}").as_bytes())
    }));
    let d = Arc::clone(&device);
    let expected = etag.clone();
    let next = race(Arc::new(move |i| {
        d.replace("index", format!("replace {i}").as_bytes(), &expected)
    }));
    let Get::Found { etag: current, .. } = device.get("index", None, 1024).unwrap() else {
        panic!()
    };
    assert_eq!(current, next);
}

#[test]
fn closed_port_is_offline() {
    let Some(env) = env() else { return };
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let mut c = config(&env, "vlt-test", PREFIX);
    c.location.endpoint = format!("http://127.0.0.1:{port}");
    let b = S3Backend::new(&c, Credentials::new("k".into(), Zeroizing::new("s".into()))).unwrap();
    assert_eq!(
        b.get("index", None, 10).unwrap_err(),
        StoreError::Offline(OfflineKind::Connect)
    );
    assert!(matches!(
        run_probe(&b, BackendKind::Other, HEADER, INDEX).unwrap_err(),
        ProbeError::Store(StoreError::Offline(_))
    ));
}

#[test]
fn sync_engine_end_to_end() {
    use vlt_core::merge::ReportItem;
    use vlt_store::Get;
    use vlt_store::probe::{BucketProbe, RawCond};
    let Some(env) = env() else { return };
    let v = setup(
        &env,
        BucketOpts {
            versioned: true,
            ..Default::default()
        },
    );
    let b = &v.device;
    let mut d = common::world(b, 2);
    d[0].put("Email/example.com", b"s3cr3t\nusername: ned\n", None);
    assert_eq!(d[0].sync(b).unwrap().published, 1);
    let Get::Found {
        bytes: old_index, ..
    } = b.get("index", None, 1 << 24).unwrap()
    else {
        panic!("no index");
    };
    assert_eq!(d[1].sync(b).unwrap().fetched, 1);
    assert_eq!(
        d[1].content("Email/example.com"),
        b"s3cr3t\nusername: ned\n"
    );
    let h = d[1].head("Email/example.com");
    d[0].put("Email/example.com", b"zero", Some(h));
    d[1].put("Email/example.com", b"one", Some(h));
    d[0].sync(b).unwrap();
    let r = d[1].sync(b).unwrap();
    assert!(matches!(r.items[..], [ReportItem::Conflict { .. }]));
    d[0].sync(b).unwrap();
    assert_eq!(d[0].paths(), d[1].paths());
    assert_eq!(d[0].paths().len(), 2);
    // A holder of a device key replays an older index: every device that saw a newer one refuses.
    let r = b.put_raw("index", &old_index, &RawCond::None).unwrap();
    assert_eq!(r.status, 200);
    let e = d[0].sync(b).unwrap_err();
    assert!(e.to_string().contains("IndexRollback"), "{e}");
}
