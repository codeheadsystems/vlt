//! One test per decode rule. Each builds an object that still authenticates (or a cleartext field
//! that is checked before authentication) and asserts the specific rule that rejects it.

use super::{arr, hx, load};
use crate::codec::Writer;
use crate::device::{self, Bundle};
use crate::enroll::{self, EnrollmentRequest, Invite, VaultConfig, is_valid_endpoint};
use crate::entry::{self, EntryPlain, EntryPrefix};
use crate::error::{Error, InputKind, IntegrityKind as K};
use crate::export::{self, ExportInfo, ExportPayload, ExportRecord, ExportRevision};
use crate::ext::ExtList;
use crate::header::{Meta, parse_header};
use crate::index;
use crate::kdf::KdfParams;
use crate::keys;
use crate::prim::{hmac, seal, sha256};
use crate::secret::{
    DeviceSecrets, EntryKey, ExportKey, HeaderMacKey, InviteKey, LocalWrapKey, MetaKey, SecretKey,
    VaultKey,
};
use crate::textcodec::b64url;
use crate::wrap::DEVICE_RECORD_LEN;
use zeroize::Zeroizing;

fn int(k: K) -> Option<Error> {
    Some(Error::Integrity(k))
}

// ---------------------------------------------------------------- header

struct HeaderKeys {
    bytes: Vec<u8>,
    vk: [u8; 32],
    vid: [u8; 16],
}

fn header() -> HeaderKeys {
    let h = load("header.json");
    HeaderKeys {
        bytes: hx(&h["header"]),
        vk: arr(&h["inputs"]["vk"]),
        vid: arr(&h["inputs"]["vault_id"]),
    }
}

impl HeaderKeys {
    fn keys(&self) -> (HeaderMacKey, MetaKey) {
        let vk = VaultKey::from_bytes(self.vk);
        (
            keys::header_mac_key(&vk, &self.vid),
            keys::meta_key(&vk, &self.vid),
        )
    }

    fn verify(&self, bytes: &[u8]) -> Result<(), Error> {
        let (hmk, mk) = self.keys();
        parse_header(bytes)?.verify_with_keys(&hmk, &mk).map(|_| ())
    }

    fn meta_offset(&self) -> usize {
        let n = u16::from_be_bytes([self.bytes[137], self.bytes[138]]) as usize;
        139 + n * DEVICE_RECORD_LEN
    }

    /// Re-MAC a header after changing cleartext bytes.
    fn remac(&self, mut b: Vec<u8>) -> Vec<u8> {
        let (hmk, _) = self.keys();
        let n = b.len();
        let mac = hmac(hmk.expose(), &b[..n - 32]);
        b[n - 32..].copy_from_slice(&mac);
        b
    }

    /// Change the metadata plaintext, reseal it under `K_meta`, and re-MAC.
    fn with_meta(&self, f: impl FnOnce(&mut Meta), extra: &[u8]) -> Vec<u8> {
        let (hmk, mk) = self.keys();
        let off = self.meta_offset();
        let nonce: [u8; 24] = self.bytes[off..off + 24].try_into().unwrap();
        let len = u32::from_be_bytes(self.bytes[off + 24..off + 28].try_into().unwrap()) as usize;
        let epoch = u32::from_be_bytes(self.bytes[32..36].try_into().unwrap());
        let ad = [b"vlt/v1/meta".as_slice(), &self.vid, &epoch.to_be_bytes()].concat();
        let plain = crate::prim::open(
            mk.expose(),
            &nonce,
            &self.bytes[off + 28..off + 28 + len],
            &ad,
        )
        .unwrap();
        let mut meta = Meta::decode(&plain).unwrap();
        f(&mut meta);
        let mut p = meta.encode().unwrap().to_vec();
        p.extend_from_slice(extra);
        let ct = seal(mk.expose(), &nonce, &p, &ad);
        let mut out = self.bytes[..off + 24].to_vec();
        out.extend((ct.len() as u32).to_be_bytes());
        out.extend(ct);
        let mac = hmac(hmk.expose(), &out);
        out.extend(mac);
        out
    }
}

#[test]
fn header_metadata_rules() {
    let h = header();
    assert!(h.verify(&h.bytes).is_ok());
    // The with_meta helper reproduces the original exactly when nothing changes.
    assert_eq!(h.with_meta(|_| {}, &[]), h.bytes);
    type MetaEdit = Box<dyn FnOnce(&mut Meta)>;
    let cases: Vec<(&str, MetaEdit, K)> = vec![
        ("kind 0", Box::new(|m| m.devices[0].kind = 0), K::DeviceKind),
        ("kind 5", Box::new(|m| m.devices[1].kind = 5), K::DeviceKind),
        (
            "label charset",
            Box::new(|m| m.devices[0].label = "Laptop".into()),
            K::LabelRule,
        ),
        (
            "empty label",
            Box::new(|m| m.devices[0].label = String::new()),
            K::LabelRule,
        ),
        (
            "duplicate label",
            Box::new(|m| m.devices[1].label = m.devices[0].label.clone()),
            K::Duplicate,
        ),
        (
            "device id mismatch",
            Box::new(|m| m.devices[0].device_id[0] ^= 1),
            K::DeviceInfoMismatch,
        ),
        (
            "device info missing",
            Box::new(|m| {
                m.devices.pop();
            }),
            K::DeviceInfoMismatch,
        ),
        (
            "keyring missing",
            Box::new(|m| m.keyring.clear()),
            K::Keyring,
        ),
        (
            "keyring wrong epoch",
            Box::new(|m| m.keyring[0].0 = 2),
            K::Keyring,
        ),
        (
            "keyring extra",
            Box::new(|m| m.keyring.push((2, VaultKey::from_bytes([1; 32])))),
            K::Keyring,
        ),
        (
            "legacy equals vault",
            Box::new(|m| m.legacy[0].0 = header().vid),
            K::Legacy,
        ),
        (
            "legacy empty lineage",
            Box::new(|m| m.legacy[0].1.clear()),
            K::Legacy,
        ),
        (
            "legacy epochs",
            Box::new(|m| m.legacy[0].1[0].0 = 2),
            K::Legacy,
        ),
        (
            "legacy unsorted",
            Box::new(|m| {
                let mut second = m.legacy[0].0;
                second[0] = 0;
                m.legacy
                    .push((second, vec![(1, VaultKey::from_bytes([2; 32]))]));
            }),
            K::Legacy,
        ),
        (
            "rotation from 0 with seq",
            Box::new(|m| {
                m.rotation.from_epoch = 0;
            }),
            K::Rotation,
        ),
        (
            "rotation from wrong epoch",
            Box::new(|m| m.rotation.from_epoch = 5),
            K::Rotation,
        ),
        (
            "rotation epoch max",
            Box::new(|m| m.rotation.from_epoch = u32::MAX),
            K::Rotation,
        ),
    ];
    for (name, f, want) in cases {
        assert_eq!(h.verify(&h.with_meta(f, &[])).err(), int(want), "{name}");
    }
    assert_eq!(
        h.verify(&h.with_meta(|_| {}, &[0])).err(),
        int(K::TrailingBytes)
    );
    // A never-rotated commitment is all zeros, which is valid at any epoch.
    let zeroed = h.with_meta(|m| m.rotation = Default::default(), &[]);
    assert!(h.verify(&zeroed).is_ok());
}

#[test]
fn header_cleartext_rules() {
    let h = header();
    let b = &h.bytes;
    let mut flags = b.clone();
    flags[7] |= 2;
    assert_eq!(parse_header(&flags).err(), int(K::UnknownFlags));
    // Clearing test_kdf leaves the test parameters, which are below the floor.
    let mut no_test = b.clone();
    no_test[7] = 0;
    assert_eq!(parse_header(&no_test).err(), int(K::KdfParams));
    let mut alg = b.clone();
    alg[36] = 2;
    assert_eq!(parse_header(&alg).err(), int(K::KdfParams));
    let mut big = b.clone();
    big.resize(crate::limits::HEADER_MAX + 1, 0);
    assert_eq!(parse_header(&big).err(), int(K::SizeLimit));
    let mut epoch0 = b.clone();
    epoch0[32..36].copy_from_slice(&0u32.to_be_bytes());
    assert_eq!(parse_header(&epoch0).err(), int(K::Keyring));
    let mut seq = b.clone();
    seq[24..32].copy_from_slice(&((1u64 << 48) + 1).to_be_bytes());
    assert_eq!(parse_header(&seq).err(), int(K::CounterCap));
    // Device records out of order and duplicated.
    let (r0, r1) = (139, 139 + DEVICE_RECORD_LEN);
    let mut swapped = b.clone();
    let first = b[r0..r1].to_vec();
    swapped.copy_within(r1..r1 + DEVICE_RECORD_LEN, r0);
    swapped[r1..r1 + DEVICE_RECORD_LEN].copy_from_slice(&first);
    assert_eq!(parse_header(&h.remac(swapped)).err(), int(K::Order));
    let mut dup = b.clone();
    dup.copy_within(r0..r1, r1);
    assert_eq!(parse_header(&h.remac(dup)).err(), int(K::Duplicate));
    // A newer version is reported as such even when the MAC no longer matches.
    let mut v2 = b.clone();
    v2[5] = 2;
    assert_eq!(
        parse_header(&v2).err(),
        Some(Error::UnsupportedFormatVersion(2))
    );
    // The MAC covers the KDF block: a different salt within bounds fails the MAC.
    let mut salt = b.clone();
    salt[49] ^= 1;
    assert_eq!(h.verify(&salt).err(), int(K::Mac));
    let mut trailing = b.clone();
    trailing.push(0);
    assert_eq!(parse_header(&trailing).err(), int(K::TrailingBytes));
}

// ---------------------------------------------------------------- entry

fn raw_entry(
    key: &EntryKey,
    version: u16,
    flags: u16,
    vault_id: [u8; 16],
    epoch: u32,
    plain: &[u8],
) -> Vec<u8> {
    let nonce = [5u8; 24];
    let mut w = Writer::new();
    w.bytes(b"VLTE")
        .u16(version)
        .u16(flags)
        .bytes(&vault_id)
        .u32(epoch)
        .bytes(&[7; 16])
        .bytes(&nonce);
    let ad = w.into_vec();
    let mut out = ad.clone();
    out.extend(seal(key.expose(), &nonce, plain, &ad));
    out
}

fn entry_body(
    revision: u64,
    parent: [u8; 16],
    parent_sha: [u8; 32],
    content_len_field: u32,
    content: &[u8],
) -> Vec<u8> {
    let mut w = Writer::new();
    w.u64(revision)
        .bytes(&parent)
        .bytes(&parent_sha)
        .bytes(&[1; 16])
        .i64(0);
    w.u32(content_len_field).bytes(content).u16(0);
    w.into_vec()
}

fn padded(mut body: Vec<u8>, blocks: usize) -> Vec<u8> {
    body.resize(blocks * 512 - 68 - 16, 0);
    body
}

#[test]
fn entry_rules() {
    let k = EntryKey::from_bytes([3; 32]);
    let open = |o: &[u8]| entry::open_with_key(o, &k).map(|_| ());
    let ok = raw_entry(
        &k,
        1,
        0,
        [0; 16],
        1,
        &padded(entry_body(1, [0; 16], [0; 32], 2, b"pw"), 1),
    );
    assert!(open(&ok).is_ok());
    let cases = [
        (
            "revision 1 with a parent",
            padded(entry_body(1, [1; 16], [1; 32], 0, b""), 1),
            K::ParentRule,
        ),
        (
            "revision 2 without a parent id",
            padded(entry_body(2, [0; 16], [1; 32], 0, b""), 1),
            K::ParentRule,
        ),
        (
            "revision 2 without a parent hash",
            padded(entry_body(2, [1; 16], [0; 32], 0, b""), 1),
            K::ParentRule,
        ),
        (
            "revision 0",
            padded(entry_body(0, [0; 16], [0; 32], 0, b""), 1),
            K::ParentRule,
        ),
        (
            "over-padded",
            padded(entry_body(1, [0; 16], [0; 32], 0, b""), 2),
            K::PaddedSize,
        ),
        (
            "content over the cap",
            padded(entry_body(1, [0; 16], [0; 32], (1 << 20) + 1, b""), 1),
            K::SizeLimit,
        ),
        (
            "content longer than the plaintext",
            padded(entry_body(1, [0; 16], [0; 32], 400, b""), 1),
            K::Padding,
        ),
    ];
    for (name, plain, want) in cases {
        let r = open(&raw_entry(&k, 1, 0, [0; 16], 1, &plain));
        assert!(matches!(r, Err(Error::Integrity(_))), "{name}: {r:?}");
        if want != K::Padding {
            assert_eq!(r.err(), int(want), "{name}");
        }
    }
    let mut nz = padded(entry_body(1, [0; 16], [0; 32], 0, b""), 1);
    *nz.last_mut().unwrap() = 1;
    assert_eq!(
        open(&raw_entry(&k, 1, 0, [0; 16], 1, &nz)).err(),
        int(K::Padding)
    );
    let body = padded(entry_body(1, [0; 16], [0; 32], 0, b""), 1);
    assert_eq!(
        open(&raw_entry(&k, 1, 1, [0; 16], 1, &body)).err(),
        int(K::UnknownFlags)
    );
    assert_eq!(
        open(&raw_entry(&k, 2, 0, [0; 16], 1, &body)).err(),
        Some(Error::UnsupportedFormatVersion(2))
    );
    // A future version is reported even when its size does not follow version 1's padding.
    let mut future = raw_entry(&k, 2, 0, [0; 16], 1, &body);
    future.push(0);
    assert_eq!(
        open(&future).err(),
        Some(Error::UnsupportedFormatVersion(2))
    );
    assert_eq!(open(&ok[..100]).err(), int(K::PaddedSize));
    // An object whose (vault_id, epoch) names no lineage of the header is refused before AEAD.
    let (_, _, keys) = super::vectors::header_fixture_pub();
    let stray = raw_entry(&k, 1, 0, [0xee; 16], 1, &body);
    let r = entry::open_entry(&keys, &[7; 16], &sha256(&[&stray]), &stray);
    assert_eq!(r.err(), int(K::UnknownLineage));
    let future_epoch = raw_entry(&k, 1, 0, keys.vault_id(), keys.epoch() + 1, &body);
    let r = entry::open_entry(&keys, &[7; 16], &sha256(&[&future_epoch]), &future_epoch);
    assert_eq!(r.err(), int(K::UnknownLineage));
}

#[test]
fn entry_encoder_limits() {
    let k = EntryKey::from_bytes([3; 32]);
    let pfx = EntryPrefix {
        vault_id: [0; 16],
        epoch: 1,
        object_id: [1; 16],
    };
    let mut p = EntryPlain {
        revision: 1,
        parent_object_id: [0; 16],
        parent_sha256: [0; 32],
        device_id: [0; 16],
        created_unix: 0,
        content: Zeroizing::new(vec![0; crate::limits::CONTENT_MAX + 1]),
        ext: ExtList::new(),
    };
    assert_eq!(
        entry::seal_with_key(&k, &pfx, &p, &[0; 24]).err(),
        Some(Error::InvalidInput(InputKind::TooLarge))
    );
    p.content = Zeroizing::new(vec![0; crate::limits::CONTENT_MAX]);
    p.ext.set(0x0001, vec![0; 8192]);
    assert_eq!(
        entry::seal_with_key(&k, &pfx, &p, &[0; 24]).err(),
        Some(Error::InvalidInput(InputKind::TooLarge))
    );
    p.ext = ExtList::new();
    let obj = entry::seal_with_key(&k, &pfx, &p, &[0; 24]).unwrap();
    assert!(obj.len() <= crate::limits::ENTRY_OBJECT_MAX);
    assert!(entry::open_with_key(&obj, &k).is_ok());
}

// ---------------------------------------------------------------- index

#[test]
fn index_rules() {
    let v = load("index.json");
    let (_, _, keys) = super::vectors::header_fixture_pub();
    let main = hx(&v["object"]);
    assert_eq!(
        index::open_index(&keys, b"VLTI\x00\x02\x00\x00").err(),
        Some(Error::UnsupportedFormatVersion(2))
    );
    let mut vid = main.clone();
    vid[8] ^= 1;
    assert_eq!(
        index::open_index(&keys, &vid).err(),
        int(K::VaultIdMismatch)
    );
    let mut epoch = main.clone();
    epoch[24..28].copy_from_slice(&7u32.to_be_bytes());
    assert_eq!(index::open_index(&keys, &epoch).err(), int(K::IndexEpoch));
    // An epoch-1 index that is not the committed one is refused before decryption.
    let mut rot = hx(&v["rotation_index"]["object"]);
    assert!(index::open_index(&keys, &rot).is_ok());
    let n = rot.len();
    rot[n - 1] ^= 1;
    assert_eq!(index::open_index(&keys, &rot).err(), int(K::IndexEpoch));
}

// ---------------------------------------------------------------- enrollment

fn invite_fixture() -> Invite {
    Invite::from_text(
        load("enrollment.json")["invite"]["text"].as_str().unwrap(),
        false,
    )
    .unwrap()
}

fn raw_request(
    key: &InviteKey,
    vault_id: &[u8; 16],
    device_id: &[u8; 16],
    plain: &[u8],
) -> Vec<u8> {
    let nonce = [9u8; 24];
    let mut w = Writer::new();
    w.bytes(b"VLTR")
        .u16(1)
        .u16(0)
        .bytes(vault_id)
        .bytes(device_id)
        .bytes(&nonce);
    let ad = w.into_vec();
    let mut out = ad.clone();
    out.extend(seal(key.expose(), &nonce, plain, &ad));
    out
}

#[test]
fn enrollment_request_rules() {
    let inv = invite_fixture();
    let key = inv.key();
    let v = load("enrollment.json");
    let pk: [u8; 32] = arr(&v["request"]["device_pk"]);
    let ek = hx(&v["request"]["kem_ek"]);
    let body = |kind: u8, ek: &[u8], extra: &[u8]| [&[kind][..], &pk, ek, &[0, 0], extra].concat();
    let open = |o: &[u8]| enroll::open_request(&inv, o).map(|_| ());
    assert!(
        open(&raw_request(
            &key,
            &inv.vault_id,
            &inv.device_id,
            &body(2, &ek, &[])
        ))
        .is_ok()
    );
    assert_eq!(
        open(&raw_request(
            &key,
            &inv.vault_id,
            &inv.device_id,
            &body(0, &ek, &[])
        ))
        .err(),
        int(K::DeviceKind)
    );
    assert_eq!(
        open(&raw_request(
            &key,
            &inv.vault_id,
            &inv.device_id,
            &body(5, &ek, &[])
        ))
        .err(),
        int(K::DeviceKind)
    );
    assert_eq!(
        open(&raw_request(
            &key,
            &[1; 16],
            &inv.device_id,
            &body(2, &ek, &[])
        ))
        .err(),
        int(K::VaultIdMismatch)
    );
    assert_eq!(
        open(&raw_request(
            &key,
            &inv.vault_id,
            &[1; 16],
            &body(2, &ek, &[])
        ))
        .err(),
        int(K::ObjectIdMismatch)
    );
    assert_eq!(
        open(&raw_request(
            &key,
            &inv.vault_id,
            &inv.device_id,
            &body(2, &ek, &[0])
        ))
        .err(),
        int(K::TrailingBytes)
    );
    let mut bad_ek = ek.clone();
    bad_ek[0] = 0xff;
    bad_ek[1] = 0x0f;
    assert_eq!(
        open(&raw_request(
            &key,
            &inv.vault_id,
            &inv.device_id,
            &body(2, &bad_ek, &[])
        ))
        .err(),
        int(K::KemEk)
    );
    let wrong_key = InviteKey::from_bytes([1; 32]);
    assert_eq!(
        open(&raw_request(
            &wrong_key,
            &inv.vault_id,
            &inv.device_id,
            &body(2, &ek, &[])
        ))
        .err(),
        int(K::Aead)
    );
    let mut v2 = raw_request(&key, &inv.vault_id, &inv.device_id, &body(2, &ek, &[]));
    v2[5] = 2;
    assert_eq!(open(&v2).err(), Some(Error::UnsupportedFormatVersion(2)));
    // The sealer refuses what the opener would reject.
    let req = EnrollmentRequest {
        kind: 9,
        device_pk: pk,
        kem_ek: ek.clone(),
        ext: ExtList::new(),
    };
    assert_eq!(
        enroll::seal_request(&inv, &req).err(),
        Some(Error::InvalidInput(InputKind::DeviceKind))
    );
    let crit = EnrollmentRequest {
        kind: 2,
        device_pk: pk,
        kem_ek: ek,
        ext: ExtList {
            items: vec![crate::ext::ExtItem {
                ty: 0x8001,
                value: vec![],
            }],
        },
    };
    assert_eq!(
        enroll::seal_request(&inv, &crit).err(),
        Some(Error::InvalidInput(InputKind::Ext))
    );
}

fn raw_invite(
    label: &str,
    endpoint: &str,
    region: &str,
    bucket: &str,
    prefix: &str,
    extra: &[u8],
) -> String {
    let mut w = Writer::new();
    w.bytes(&[1; 16])
        .bytes(&[2; 16])
        .u32(1)
        .bytes(&[3; 32])
        .bytes(&[4; 32])
        .bytes(&[5; 32]);
    for f in [label, endpoint, region, bucket, prefix, "AKID", "SECRET"] {
        w.str16(f.as_bytes()).unwrap();
    }
    w.u16(0).bytes(extra);
    format!("vlt-invite:1:{}", b64url(&w.into_vec()))
}

#[test]
fn invite_rules() {
    let ok = raw_invite("pixel", "", "eu-west-2", "ned-vlt", "vlt/", &[]);
    assert!(Invite::from_text(&ok, false).is_ok());
    assert!(Invite::from_text(&format!("  {ok}\n"), false).is_ok());
    let cases = [
        (
            raw_invite("Pixel", "", "eu-west-2", "ned-vlt", "vlt/", &[]),
            K::LabelRule,
        ),
        (
            raw_invite("", "", "eu-west-2", "ned-vlt", "vlt/", &[]),
            K::LabelRule,
        ),
        (
            raw_invite("pixel", "", "eu-west-2", "ned-vlt", "vlt", &[]),
            K::PrefixRule,
        ),
        (
            raw_invite("pixel", "", "eu-west-2", "ned-vlt", "v:t/", &[]),
            K::PrefixRule,
        ),
        (
            raw_invite(
                "pixel",
                "ftp://x.example",
                "eu-west-2",
                "ned-vlt",
                "vlt/",
                &[],
            ),
            K::EndpointRule,
        ),
        (
            raw_invite(
                "pixel",
                "https://user@x.example",
                "eu-west-2",
                "ned-vlt",
                "vlt/",
                &[],
            ),
            K::EndpointRule,
        ),
        (
            raw_invite(
                "pixel",
                "http://nas.example",
                "eu-west-2",
                "ned-vlt",
                "vlt/",
                &[],
            ),
            K::EndpointRule,
        ),
        (
            raw_invite("pixel", "", "EU", "ned-vlt", "vlt/", &[]),
            K::RegionRule,
        ),
        (
            raw_invite("pixel", "", "eu-west-2", "A", "vlt/", &[]),
            K::BucketRule,
        ),
        (
            raw_invite("pixel", "", "eu-west-2", "-bucket", "vlt/", &[]),
            K::BucketRule,
        ),
        (
            raw_invite("pixel", "", "eu-west-2", "ned-vlt", "vlt/", &[0]),
            K::TrailingBytes,
        ),
    ];
    for (text, want) in cases {
        assert_eq!(Invite::from_text(&text, false).err(), int(want), "{want:?}");
    }
    let http = raw_invite(
        "pixel",
        "http://nas.example",
        "eu-west-2",
        "ned-vlt",
        "vlt/",
        &[],
    );
    assert!(Invite::from_text(&http, true).is_ok());
    let loopback = raw_invite(
        "pixel",
        "http://127.0.0.1:9000",
        "eu-west-2",
        "ned-vlt",
        "vlt/",
        &[],
    );
    assert!(Invite::from_text(&loopback, false).is_ok());
    assert_eq!(
        Invite::from_text("vlt-invite:2:AAAA", false).err(),
        int(K::BadMagic)
    );
    assert!(VaultConfig::from_line("vlt-vault:1:00:eu:bucket:vlt/:", false).is_err());
    let line = "vlt-vault:1:7F9C67544C9DB6E3EE2A2D77FD1E1BE3:eu-west-2:ned-vlt:vlt/:";
    assert!(VaultConfig::from_line(line, false).is_ok());
    assert!(
        VaultConfig::from_line(&line.replace(":vlt/:", ":vlt/:http://nas.example"), false).is_err()
    );
    assert!(
        VaultConfig::from_line(&line.replace(":vlt/:", ":vlt/:http://nas.example"), true).is_ok()
    );
}

#[test]
fn endpoint_grammar() {
    for good in [
        "",
        "https://s3.eu-west-2.amazonaws.com",
        "https://nas.example:9000",
        "https://nas.example:9000/minio",
        "https://[::1]:9000",
        "https://[fd00::1]",
        "http://localhost:9000",
        "http://127.0.0.1:9000",
        "http://[::1]",
    ] {
        assert!(is_valid_endpoint(good, false), "{good:?}");
    }
    for bad in [
        "https://[::1]\u{e9}",
        "https://[",
        "https://[]",
        "https://[zz::1]",
        "http://127.evil.com",
        "http://127.0.0.256",
        "https://a';id;'",
        "https://`id`.x",
        "https://good.com\\.evil.com",
        "https://user@host",
        "https://host?x=1",
        "https://host#f",
        "https://host:",
        "https://host:99999",
        "https://host:12a",
        "https://-host.example",
        "https://host..example",
        "s3.amazonaws.com",
        "https://",
        "https://host/pa th",
    ] {
        assert!(!is_valid_endpoint(bad, false), "{bad:?}");
        assert!(
            !is_valid_endpoint(bad, true) || bad.starts_with("http://"),
            "{bad:?}"
        );
    }
    assert!(is_valid_endpoint("http://nas.example", true));
    assert!(!is_valid_endpoint("http://nas.example", false));
}

// ---------------------------------------------------------------- export

fn raw_export(key: &ExportKey, flags: u16, sk_check: [u8; 4], plain: &[u8]) -> Vec<u8> {
    let nonce = [8u8; 24];
    let kdf = KdfParams {
        m_kib: 64,
        t: 1,
        p: 1,
        salt: [1; 16],
    };
    let mut w = Writer::new();
    w.bytes(b"VLTX")
        .u16(1)
        .u16(flags)
        .bytes(&[2; 16])
        .bytes(&kdf.to_block())
        .bytes(&sk_check)
        .bytes(&nonce);
    let ad = w.into_vec();
    let mut out = ad.clone();
    out.extend(seal(key.expose(), &nonce, plain, &ad));
    out
}

fn export_plain(records: &[(&str, &[u64])]) -> Vec<u8> {
    let mut w = Writer::new();
    w.i64(0).u32(records.len() as u32);
    for (path, revs) in records {
        w.str16(path.as_bytes()).unwrap();
        w.u32(revs.len() as u32);
        for r in *revs {
            w.u64(*r).i64(0).bytes(&[0; 16]).u32(1).u8(b'x');
        }
    }
    w.u32(0).u16(0);
    w.into_vec()
}

#[test]
fn export_rules() {
    let k = ExportKey::from_bytes([4; 32]);
    let open = |o: &[u8]| export::open_with_key(o, &k).map(|_| ());
    assert!(
        open(&raw_export(
            &k,
            1,
            [1; 4],
            &export_plain(&[("a", &[2, 1]), ("b", &[1])])
        ))
        .is_ok()
    );
    let cases = [
        (
            "unsorted",
            export_plain(&[("b", &[1]), ("a", &[1])]),
            K::Order,
        ),
        (
            "duplicate",
            export_plain(&[("a", &[1]), ("a", &[1])]),
            K::Order,
        ),
        (
            "ascending revisions",
            export_plain(&[("a", &[1, 2])]),
            K::Order,
        ),
        ("equal revisions", export_plain(&[("a", &[2, 2])]), K::Order),
        ("path rule", export_plain(&[("a/../b", &[1])]), K::PathRule),
        (
            "revision cap",
            export_plain(&[("a", &[(1 << 48) + 1])]),
            K::CounterCap,
        ),
    ];
    for (name, plain, want) in cases {
        assert_eq!(
            open(&raw_export(&k, 1, [1; 4], &plain)).err(),
            int(want),
            "{name}"
        );
    }
    let good = export_plain(&[("a", &[1])]);
    assert_eq!(
        open(&raw_export(&k, 3, [1; 4], &good)).err(),
        int(K::SkCheck)
    );
    assert_eq!(
        open(&raw_export(&k, 5, [1; 4], &good)).err(),
        int(K::UnknownFlags)
    );
    assert_eq!(
        open(&raw_export(&k, 1, [1; 4], &good)[..80]).err(),
        int(K::Truncated)
    );
    let mut v2 = raw_export(&k, 1, [1; 4], &good);
    v2[5] = 2;
    assert_eq!(open(&v2).err(), Some(Error::UnsupportedFormatVersion(2)));
    let mut trailing = good.clone();
    trailing.push(0);
    assert_eq!(
        open(&raw_export(&k, 1, [1; 4], &trailing)).err(),
        int(K::TrailingBytes)
    );
    // The sealer refuses unsorted payloads too.
    let rec = |p: &str, r: u64| ExportRecord {
        path: p.into(),
        revisions: vec![ExportRevision {
            revision: r,
            created_unix: 0,
            device_id: [0; 16],
            content: Zeroizing::new(vec![]),
        }],
    };
    let payload = ExportPayload {
        created_unix: 0,
        entries: vec![rec("b", 1), rec("a", 1)],
        tombstones: vec![],
        ext: ExtList::new(),
    };
    let info = export::export_info(&raw_export(&k, 1, [1; 4], &good)).unwrap();
    assert_eq!(
        export::seal_with_key(&k, &info, &[0; 24], &payload).err(),
        Some(Error::InvalidInput(InputKind::Order))
    );
}

#[test]
fn export_secret_key_helpers() {
    let v = load("export.json");
    let sk = SecretKey::from_bytes(arr(&v["secret_key"]));
    let other = SecretKey::from_bytes([1; 16]);
    let pw = String::from_utf8(hx(&v["password_utf8"])).unwrap();
    for c in v["cases"].as_array().unwrap() {
        let file = hx(&c["file"]);
        let info: ExportInfo = export::export_info(&file).unwrap();
        if info.password_only {
            assert!(info.sk_matches(&other));
            assert_eq!(info.needed_ending(), None);
            // A supplied secret key is ignored, and a wrong password fails as such.
            assert!(export::open_export(&file, &pw, Some(&other)).is_ok());
            assert_eq!(
                export::open_export(&file, "wrong", None).err(),
                Some(Error::WrongPasswordOrUnknownDevice)
            );
        } else {
            assert!(info.sk_matches(&sk));
            assert!(!info.sk_matches(&other));
            assert!(
                v["secret_key_text"]
                    .as_str()
                    .unwrap()
                    .ends_with(&info.needed_ending().unwrap())
            );
            assert_eq!(
                export::open_export(&file, &pw, None).err(),
                Some(Error::SecretKeyTypo)
            );
        }
    }
}

// ---------------------------------------------------------------- device file

#[test]
fn device_file_rules() {
    let v = load("device-file.json");
    let file = hx(&v["file"]);
    let lk = LocalWrapKey::from_bytes(arr(&v["lk"]));
    let mut flags = file.clone();
    flags[7] |= 2;
    assert_eq!(
        device::open_with_key(&flags, &lk).err(),
        int(K::UnknownFlags)
    );
    let mut v2 = file.clone();
    v2[5] = 2;
    assert_eq!(
        device::open_with_key(&v2, &lk).err(),
        Some(Error::UnsupportedFormatVersion(2))
    );
    let mut big = file.clone();
    big.resize(device::DEVICE_FILE_MAX + 1, 0);
    assert_eq!(device::open_with_key(&big, &lk).err(), int(K::SizeLimit));
    let mut bundle = Bundle::decode(&hx(&v["bundle_plain"])).unwrap();
    let plain = hx(&v["bundle_plain"]);
    assert_eq!(
        Bundle::decode(&[plain.as_slice(), &[0]].concat()).err(),
        int(K::TrailingBytes)
    );
    bundle.secret_access_key = Zeroizing::new("x".repeat(70_000));
    assert_eq!(
        bundle.encode().err(),
        Some(Error::InvalidInput(InputKind::TooLarge))
    );
    let _ = DeviceSecrets::from_bytes([0; 32], [0; 64]);
}

// ---------------------------------------------------------------- errors

#[test]
fn errors_never_carry_secrets() {
    let pw = "correct horse battery staple";
    let v = load("device-file.json");
    let file = hx(&v["file"]);
    let mut texts = vec![];
    let e = device::open_device_file(&file, pw).err().unwrap();
    texts.push(format!("{e} {e:?}"));
    let inv = raw_invite("Bad-Label", "", "eu-west-2", "ned-vlt", "vlt/", &[]);
    let e = Invite::from_text(&inv, false).err().unwrap();
    texts.push(format!("{e} {e:?}"));
    let e = crate::secret_key_text::decode("VLT1-7XH6-NSCF-5P9Y-QKXJ-J745-SZYF-BEQY-C51B")
        .err()
        .unwrap();
    texts.push(format!("{e} {e:?}"));
    let e = crate::kdf::validate_new_password("hunter2").unwrap_err();
    texts.push(format!("{e} {e:?}"));
    for t in texts {
        for secret in [pw, "SECRET", "AKID", "hunter2", "7XH6", "Bad-Label"] {
            assert!(!t.contains(secret), "{t}");
        }
    }
}
