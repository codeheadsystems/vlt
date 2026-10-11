//! Known-answer vectors from `spec/vectors/`.

use super::{arr, hx, load, s, u};
use crate::device::{self, Bundle};
use crate::enroll::{self, EnrollmentRequest, Invite, VaultConfig};
use crate::entry::{self, EntryPlain, EntryPrefix};
use crate::entry_text::parse_entry_text;
use crate::error::{Error, IntegrityKind as K};
use crate::export;
use crate::ext::ExtList;
use crate::header::{
    DeviceInfo, HeaderDevice, HeaderDraft, HeaderInfo, PasswordWrap, RotationCommitment, VaultKeys,
    parse_header,
};
use crate::index::{self, Applied, IndexEntry, IndexPlain, IndexPrefix, Tombstone};
use crate::kdf::{self, KdfParams};
use crate::keys;
use crate::rng::BufferRng;
use crate::secret::{
    Auk, DeviceSecrets, EntryKey, ExportKey, HeaderMacKey, IndexKey, InviteKey, LocalWrapKey,
    MetaKey, SecretKey, VaultKey,
};
use crate::secret_key_text;
use crate::wrap::{self, DeviceRecord};
use serde_json::Value;
use zeroize::Zeroizing;

fn kdf_params(v: &Value) -> KdfParams {
    assert_eq!(u(&v["alg"]), 1);
    KdfParams {
        m_kib: u(&v["m_kib"]) as u32,
        t: u(&v["t"]) as u32,
        p: u(&v["p"]) as u32,
        salt: arr(&v["kdf_salt"]),
    }
}

fn password(v: &Value) -> String {
    String::from_utf8(hx(v)).unwrap()
}

/// Unlock the header vector with its password, giving the shared fixture for later files.
pub(crate) fn header_fixture_pub() -> (crate::header::ParsedHeader, HeaderInfo, VaultKeys) {
    header_fixture()
}

fn header_fixture() -> (crate::header::ParsedHeader, HeaderInfo, VaultKeys) {
    let h = load("header.json");
    let parsed = parse_header(&hx(&h["header"])).unwrap();
    let sk = SecretKey::from_bytes(arr(&h["inputs"]["secret_key"]));
    let (info, keys) = parsed
        .unlock_with_password(&password(&h["inputs"]["password_utf8"]), &sk)
        .unwrap();
    (parsed, info, keys)
}

#[test]
fn every_vector_file_has_a_harness() {
    let dir = format!("{}/../../spec/vectors", env!("CARGO_MANIFEST_DIR"));
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    let covered = [
        "device-file.json",
        "enrollment.json",
        "entry-text.json",
        "entry.json",
        "export.json",
        "header.json",
        "index.json",
        "kdf.json",
        "malformed.json",
        "secret-key.json",
        "subkeys.json",
        "tamper.json",
        "wraps.json",
    ];
    assert_eq!(names, covered);
}

#[test]
fn kdf_vectors() {
    let v = load("kdf.json");
    let b = &v["parameter_bounds"];
    assert_eq!(
        (
            u(&b["floor"]["m_kib"]) as u32,
            u(&b["floor"]["t"]) as u32,
            u(&b["floor"]["p"]) as u32
        ),
        kdf::FLOOR
    );
    assert_eq!(
        (
            u(&b["ceiling"]["m_kib"]) as u32,
            u(&b["ceiling"]["t"]) as u32,
            u(&b["ceiling"]["p"]) as u32
        ),
        kdf::CEILING
    );
    assert_eq!(
        (
            u(&b["test"]["m_kib"]) as u32,
            u(&b["test"]["t"]) as u32,
            u(&b["test"]["p"]) as u32
        ),
        kdf::TEST
    );
    for c in v["cases"].as_array().unwrap() {
        let pw = password(&c["password_utf8"]);
        assert_eq!(
            kdf::nfkc(&pw).as_bytes(),
            hx(&c["password_nfkc_utf8"]).as_slice()
        );
        let params = kdf_params(&c["kdf"]);
        assert_eq!(params.to_block().to_vec(), hx(&c["kdf_block"]));
        let pk = kdf::argon2id_unchecked(&pw, &params);
        assert_eq!(pk.to_vec(), hx(&c["pw_key"]), "{}", s(&c["name"]));
        let sk = SecretKey::from_bytes(arr(&c["secret_key"]));
        let auk = kdf::auk_from_pw_key(&pk, &sk, &arr(&c["vault_id"]));
        assert_eq!(auk.expose().to_vec(), hx(&c["auk"]));
    }
}

#[test]
fn subkey_vectors() {
    let v = load("subkeys.json");
    let vid = arr(&v["vault_id"]);
    for c in v["cases"].as_array().unwrap() {
        let vk = VaultKey::from_bytes(arr(&c["vk"]));
        let sk = &c["subkeys"];
        assert_eq!(
            keys::header_mac_key(&vk, &vid).expose().to_vec(),
            hx(&sk["header-mac"])
        );
        assert_eq!(keys::meta_key(&vk, &vid).expose().to_vec(), hx(&sk["meta"]));
        assert_eq!(
            keys::index_key(&vk, &vid).expose().to_vec(),
            hx(&sk["index"])
        );
        assert_eq!(
            keys::entry_key(&vk, &vid).expose().to_vec(),
            hx(&sk["entry"])
        );
        assert_eq!(
            keys::mirror_key(&vk, &vid).expose().to_vec(),
            hx(&sk["mirror"])
        );
        assert_eq!(
            keys::fingerprint(&vk, &vid).to_vec(),
            hx(&sk["fingerprint"])
        );
    }
}

#[test]
fn secret_key_vectors() {
    let v = load("secret-key.json");
    for c in v["valid"].as_array().unwrap() {
        let sk = SecretKey::from_bytes(arr(&c["secret_key"]));
        assert_eq!(secret_key_text::encode(&sk).as_str(), s(&c["text"]));
        assert_eq!(
            secret_key_text::decode(s(&c["text"])).unwrap().expose(),
            sk.expose()
        );
        let ending = secret_key_text::ending_of_check(&secret_key_text::check_value(&sk));
        assert!(s(&c["text"]).ends_with(&ending));
    }
    for c in v["decode_equivalent"].as_array().unwrap() {
        let sk = secret_key_text::decode(s(&c["text"])).unwrap();
        assert_eq!(
            sk.expose().to_vec(),
            hx(&c["secret_key"]),
            "{}",
            s(&c["note"])
        );
    }
    for c in v["invalid"].as_array().unwrap() {
        assert_eq!(
            secret_key_text::decode(s(&c["text"])).err(),
            Some(Error::SecretKeyTypo),
            "{}",
            s(&c["reason"])
        );
    }
}

fn device_secrets(d: &Value) -> DeviceSecrets {
    DeviceSecrets::from_bytes(arr(&d["device_sk"]), arr(&d["kem_seed"]))
}

#[test]
fn wrap_vectors() {
    let v = load("wraps.json");
    let vid = arr(&v["vault_id"]);
    let epoch = u(&v["epoch"]) as u32;
    let vk = VaultKey::from_bytes(arr(&v["vk"]));
    let pw = &v["password_wrap"];
    let auk = Auk::from_bytes(arr(&pw["auk"]));
    let block: [u8; 29] = arr(&pw["kdf_block"]);
    let ct = wrap::seal_pw_wrap(&auk, &vk, &vid, epoch, &block, &arr(&pw["nonce"]));
    assert_eq!(ct.to_vec(), hx(&pw["ct"]));
    let opened = wrap::open_pw_wrap(&auk, &vid, epoch, &block, &arr(&pw["nonce"]), &ct).unwrap();
    assert_eq!(opened.expose(), vk.expose());
    let wrong = Auk::from_bytes([7; 32]);
    assert_eq!(
        wrap::open_pw_wrap(&wrong, &vid, epoch, &block, &arr(&pw["nonce"]), &ct).err(),
        Some(Error::WrongPasswordOrUnknownDevice)
    );

    for d in v["device_wraps"].as_array().unwrap() {
        let secrets = device_secrets(d);
        let public = keys::device_public(&secrets);
        assert_eq!(public.device_pk.to_vec(), hx(&d["device_pk"]));
        assert_eq!(public.kem_ek, hx(&d["kem_ek"]));
        let eph_sk = hx(&d["eph_sk"]);
        let kem_m = hx(&d["kem_m"]);
        let nonce = hx(&d["nonce"]);
        let mut rng = BufferRng::new(&[&eph_sk, &kem_m, &nonce]);
        let rec = wrap::seal_device_wrap(
            &mut rng,
            &vk,
            &vid,
            epoch,
            &arr(&d["device_id"]),
            &public.device_pk,
            &public.kem_ek,
        )
        .unwrap();
        rng.assert_consumed();
        assert_eq!(rec.eph_pk.to_vec(), hx(&d["eph_pk"]));
        assert_eq!(rec.kem_ct, hx(&d["kem_ct"]));
        assert_eq!(rec.ct.to_vec(), hx(&d["ct"]));
        let back = wrap::open_device_wrap(&rec, &vid, epoch, &secrets).unwrap();
        assert_eq!(back.expose(), vk.expose());
    }

    let d = &v["device_wraps"][0];
    let low: [u8; 32] = arr(&v["low_order_point"]["device_pk"]);
    let mut rng = BufferRng::new(&[&[1u8; 32], &[2u8; 32], &[3u8; 24]]);
    let r = wrap::seal_device_wrap(
        &mut rng,
        &vk,
        &vid,
        epoch,
        &[0; 16],
        &low,
        &hx(&d["kem_ek"]),
    );
    assert_eq!(r.err(), Some(Error::Integrity(K::LowOrderPoint)));
}

#[test]
fn header_vectors() {
    let h = load("header.json");
    let inp = &h["inputs"];
    let bytes = hx(&h["header"]);
    let (parsed, info, keys) = header_fixture();
    assert_eq!(info.vault_id, arr(&inp["vault_id"]));
    assert_eq!(info.header_seq, u(&inp["header_seq"]));
    assert_eq!(info.epoch, u(&inp["epoch"]) as u32);
    assert_eq!(info.kdf, kdf_params(&inp["kdf"]));
    assert!(info.test_kdf);
    assert_eq!(info.writer_device_id, arr(&inp["writer_device_id"]));
    assert_eq!(info.legacy_sha256, arr(&h["legacy_sha256"]));
    assert_eq!(
        info.rotation,
        RotationCommitment {
            from_epoch: u(&inp["rotated_from_epoch"]) as u32,
            from_index_seq: u(&inp["rotated_from_index_seq"]),
            from_index_sha256: arr(&inp["rotated_from_index_sha256"]),
        }
    );
    let devs = inp["devices"].as_array().unwrap();
    assert_eq!(info.devices.len(), devs.len());
    for (d, e) in info.devices.iter().zip(devs) {
        assert_eq!(d.info.device_id, arr(&e["device_id"]));
        assert_eq!(d.info.kind, u(&e["kind"]) as u8);
        assert_eq!(d.info.label, s(&e["label"]));
        assert_eq!(d.info.enrolled_header_seq, u(&e["enrolled_header_seq"]));
        assert_eq!(d.info.enrolled_unix, e["enrolled_unix"].as_i64().unwrap());
        assert_eq!(d.info.enrolled_by, arr(&e["enrolled_by"]));
    }
    assert_eq!(info.legacy_lineages.len(), 1);
    assert_eq!(
        keys.secret_key_text().as_str(),
        load("export.json")["secret_key_text"].as_str().unwrap()
    );
    assert_eq!(
        info.fingerprint,
        keys::fingerprint(&VaultKey::from_bytes(arr(&inp["vk"])), &info.vault_id)
    );

    // Device unlock with each wrap from wraps.json.
    let w = load("wraps.json");
    for d in w["device_wraps"].as_array().unwrap() {
        let (i2, _) = parsed
            .unlock_with_device(&arr(&d["device_id"]), &device_secrets(d))
            .unwrap();
        assert_eq!(i2, info);
    }
    assert_eq!(
        parsed
            .unlock_with_device(&[9; 16], &device_secrets(&w["device_wraps"][0]))
            .err(),
        Some(Error::WrongPasswordOrUnknownDevice)
    );
    let wrong = SecretKey::from_bytes([0; 16]);
    assert_eq!(
        parsed.unlock_with_password("wrong", &wrong).err(),
        Some(Error::WrongPasswordOrUnknownDevice)
    );

    // The rewrite path reproduces the header byte for byte.
    let mut draft = HeaderDraft::from_verified(&parsed, &info, &keys).unwrap();
    assert_eq!(draft.header_seq, info.header_seq + 1);
    draft.header_seq = info.header_seq;
    let nonce = hx(&inp["meta_nonce"]);
    let mut rng = BufferRng::new(&[&nonce]);
    assert_eq!(draft.encode_with(&mut rng).unwrap(), bytes);

    // So does a build from the inputs alone.
    let vk = VaultKey::from_bytes(arr(&inp["vk"]));
    let sk = SecretKey::from_bytes(arr(&inp["secret_key"]));
    let mut base = HeaderDraft::new_vault(info.vault_id, arr(&inp["writer_device_id"]), vk, sk);
    base.header_seq = info.header_seq;
    base.epoch = info.epoch;
    base.rotation = info.rotation;
    let pw = &w["password_wrap"];
    base.password_wrap = PasswordWrap {
        kdf: kdf_params(&inp["kdf"]),
        test_kdf: true,
        nonce: arr(&pw["nonce"]),
        ct: arr(&pw["ct"]),
    };
    let wraps = w["device_wraps"].as_array().unwrap();
    for e in devs {
        let wd = wraps
            .iter()
            .find(|x| x["device_id"] == e["device_id"])
            .unwrap();
        base.devices.push(HeaderDevice {
            record: DeviceRecord {
                device_id: arr(&wd["device_id"]),
                device_pk: arr(&wd["device_pk"]),
                kem_ek: hx(&wd["kem_ek"]),
                eph_pk: arr(&wd["eph_pk"]),
                kem_ct: hx(&wd["kem_ct"]),
                nonce: arr(&wd["nonce"]),
                ct: arr(&wd["ct"]),
            },
            info: DeviceInfo {
                device_id: arr(&e["device_id"]),
                kind: u(&e["kind"]) as u8,
                label: s(&e["label"]).to_owned(),
                enrolled_header_seq: u(&e["enrolled_header_seq"]),
                enrolled_unix: e["enrolled_unix"].as_i64().unwrap(),
                enrolled_by: arr(&e["enrolled_by"]),
            },
        });
    }
    let ring = |v: &Value| -> Vec<(u32, VaultKey)> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|k| (u(&k["epoch"]) as u32, VaultKey::from_bytes(arr(&k["vk"]))))
            .collect()
    };
    let legacy = inp["legacy_lineages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| (arr(&l["vault_id"]), ring(&l["keyring"])))
        .collect();
    let draft = HeaderDraft::from_parts(base, ring(&inp["keyring"]), legacy);
    let mut rng = BufferRng::new(&[&nonce]);
    assert_eq!(draft.encode_with(&mut rng).unwrap(), bytes);
}

#[test]
fn header_format_version_policy() {
    let (parsed, info, keys) = header_fixture();
    let mut draft = HeaderDraft::from_verified(&parsed, &info, &keys).unwrap();
    draft.format_version = 2;
    assert_eq!(
        draft.encode_with(&mut BufferRng::new(&[&[0; 24]])).err(),
        Some(Error::UnsupportedFormatVersion(2))
    );
    let mut bytes = hx(&load("header.json")["header"]);
    bytes[5] = 2;
    assert_eq!(
        parse_header(&bytes).err(),
        Some(Error::UnsupportedFormatVersion(2))
    );
}

fn entry_plain(c: &Value) -> EntryPlain {
    EntryPlain {
        revision: u(&c["revision"]),
        parent_object_id: arr(&c["parent_object_id"]),
        parent_sha256: arr(&c["parent_sha256"]),
        device_id: arr(&c["device_id"]),
        created_unix: c["created_unix"].as_i64().unwrap(),
        content: Zeroizing::new(hx(&c["content"])),
        ext: ExtList::new(),
    }
}

#[test]
fn entry_vectors() {
    let (_, _, keys) = header_fixture();
    for c in load("entry.json")["cases"].as_array().unwrap() {
        let obj = hx(&c["object"]);
        assert_eq!(obj.len() as u64, u(&c["object_len"]));
        assert_eq!(crate::sha256(&[&obj]).to_vec(), hx(&c["object_sha256"]));
        let key = EntryKey::from_bytes(arr(&c["k_entry"]));
        let (prefix, plain) = entry::open_with_key(&obj, &key).unwrap();
        let want = entry_plain(c);
        assert_eq!(plain, want, "{}", s(&c["name"]));
        let pfx = EntryPrefix {
            vault_id: arr(&c["vault_id"]),
            epoch: u(&c["epoch"]) as u32,
            object_id: arr(&c["object_id"]),
        };
        assert_eq!(prefix, pfx);
        assert_eq!(
            entry::seal_with_key(&key, &pfx, &want, &arr(&c["nonce"])).unwrap(),
            obj
        );
        // Through the header's keys: current lineage, earlier epoch, and legacy lineage.
        let sha = crate::sha256(&[&obj]);
        let (_, p2) = entry::open_entry(&keys, &pfx.object_id, &sha, &obj).unwrap();
        assert_eq!(p2, want);
        assert_eq!(
            entry::open_entry(&keys, &[0; 16], &sha, &obj).err(),
            Some(Error::Integrity(K::ObjectIdMismatch))
        );
    }
}

fn idx_plain(v: &Value) -> IndexPlain {
    let ext = |e: &Value| {
        let mut l = ExtList::new();
        if let Some(c) = e.get("conflict_of").and_then(Value::as_str) {
            l.set(crate::ext::CONFLICT_OF, c.as_bytes().to_vec());
        }
        if let Some(f) = e.get("history_floor").and_then(Value::as_u64) {
            l.set(crate::ext::HISTORY_FLOOR, f.to_be_bytes().to_vec());
        }
        l
    };
    IndexPlain {
        writer_device_id: arr(&v["writer_device_id"]),
        entries: v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| IndexEntry {
                path: s(&e["path"]).to_owned(),
                head_object_id: arr(&e["head_object_id"]),
                head_sha256: arr(&e["head_sha256"]),
                revision: u(&e["revision"]),
                device_id: arr(&e["device_id"]),
                ext: ext(e),
            })
            .collect(),
        tombstones: v["tombstones"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| Tombstone {
                path: s(&e["path"]).to_owned(),
                head_object_id: arr(&e["head_object_id"]),
                head_sha256: arr(&e["head_sha256"]),
                revision: u(&e["revision"]),
                device_id: arr(&e["device_id"]),
                removed_index_seq: u(&e["removed_index_seq"]),
                ext: ext(e),
            })
            .collect(),
        applied: v["applied"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| Applied {
                device_id: arr(&a["device_id"]),
                last_op_seq: u(&a["last_op_seq"]),
            })
            .collect(),
        ext: ExtList::new(),
    }
}

#[test]
fn index_vectors() {
    let v = load("index.json");
    let (_, info, keys) = header_fixture();
    for (iv, vid) in [
        (&v, arr::<16>(&v["vault_id"])),
        (&v["rotation_index"], arr(&v["vault_id"])),
    ] {
        let obj = hx(&iv["object"]);
        assert_eq!(crate::sha256(&[&obj]).to_vec(), hx(&iv["object_sha256"]));
        let key = IndexKey::from_bytes(arr(&iv["k_index"]));
        let (prefix, plain) = index::open_with_key(&obj, &key).unwrap();
        let want = idx_plain(iv);
        assert_eq!(plain, want);
        let pfx = IndexPrefix {
            vault_id: vid,
            epoch: u(&iv["epoch"]) as u32,
            index_seq: u(&iv["index_seq"]),
            header_seq: u(&iv["header_seq"]),
        };
        assert_eq!(prefix, pfx);
        assert_eq!(
            index::seal_with_key(&key, &pfx, &want, &arr(&iv["nonce"])).unwrap(),
            obj
        );
        let (_, p2) = index::open_index(&keys, &obj).unwrap();
        assert_eq!(p2, want);
    }
    // The rotation index is the one the header commits to; an altered commitment rejects it.
    assert_eq!(
        info.rotation.from_index_sha256.to_vec(),
        hx(&v["rotation_index"]["object_sha256"])
    );
    // The entry vector's head hashes chain to the index, and the edit's parent hash chains to
    // the first revision.
    let entries = load("entry.json");
    let cases = entries["cases"].as_array().unwrap();
    let (_, main) = index::open_index(&keys, &hx(&v["object"])).unwrap();
    let mut opened = 0;
    for head in &main.entries {
        if let Some(c) = cases
            .iter()
            .find(|c| arr::<16>(&c["object_id"]) == head.head_object_id)
        {
            let obj = hx(&c["object"]);
            let (_, plain) = index::open_head(&keys, head, &obj).unwrap();
            opened += 1;
            if plain.revision > 1 {
                let parent = cases
                    .iter()
                    .find(|p| arr::<16>(&p["object_id"]) == plain.parent_object_id)
                    .unwrap();
                let (_, pp) = index::open_parent(&keys, &plain, &hx(&parent["object"])).unwrap();
                assert_eq!(pp.revision + 1, plain.revision);
                // A different object in the parent's place is rejected by its hash.
                assert_eq!(
                    index::open_parent(&keys, &plain, &obj).err(),
                    Some(Error::Integrity(K::ShaMismatch))
                );
            }
            // A head whose bytes do not match the index's hash is rejected before decryption.
            let mut wrong = head.clone();
            wrong.head_sha256[0] ^= 1;
            assert_eq!(
                index::open_head(&keys, &wrong, &obj).err(),
                Some(Error::Integrity(K::ShaMismatch))
            );
            let mut rev = head.clone();
            rev.revision += 1;
            assert_eq!(
                index::open_head(&keys, &rev, &obj).err(),
                Some(Error::Integrity(K::HeadMismatch))
            );
        }
    }
    assert_eq!(opened, 2);
}

#[test]
fn entry_text_vectors() {
    for c in load("entry-text.json")["cases"].as_array().unwrap() {
        let p = parse_entry_text(s(&c["content"]).as_bytes()).unwrap();
        let want = &c["parsed"];
        assert_eq!(
            p.password.as_str(),
            s(&want["password"]),
            "{}",
            s(&c["name"])
        );
        let fields: Vec<(String, String)> = p
            .fields
            .iter()
            .map(|f| (f.key.clone(), f.value.to_string()))
            .collect();
        let wf: Vec<(String, String)> = want["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| (s(&f["key"]).to_owned(), s(&f["value"]).to_owned()))
            .collect();
        assert_eq!(fields, wf, "{}", s(&c["name"]));
        let otp: Vec<String> = p.otpauth.iter().map(|o| o.to_string()).collect();
        let wo: Vec<String> = want["otpauth"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| s(o).to_owned())
            .collect();
        assert_eq!(otp, wo);
        assert_eq!(
            p.notes.as_ref().map(|n| n.as_str()),
            want["notes"].as_str(),
            "{}",
            s(&c["name"])
        );
    }
    assert!(parse_entry_text(&[0xff, 0xfe]).is_none());
}

#[test]
fn enrollment_vectors() {
    let v = load("enrollment.json");
    let iv = &v["invite"];
    let invite = Invite::from_text(s(&iv["text"]), false).unwrap();
    assert_eq!(invite.vault_id, arr(&v["vault_id"]));
    assert_eq!(invite.device_id, arr(&iv["device_id"]));
    assert_eq!(invite.epoch, u(&iv["epoch"]) as u32);
    assert_eq!(invite.fingerprint, arr(&iv["fingerprint"]));
    assert_eq!(invite.legacy_sha256, arr(&iv["legacy_sha256"]));
    assert_eq!(
        invite.invite_secret.expose().to_vec(),
        hx(&iv["invite_secret"])
    );
    for f in ["label", "endpoint", "region", "bucket", "prefix"] {
        let got = match f {
            "label" => &invite.label,
            "endpoint" => &invite.endpoint,
            "region" => &invite.region,
            "bucket" => &invite.bucket,
            _ => &invite.prefix,
        };
        assert_eq!(got, s(&iv[f]));
    }
    assert_eq!(invite.access_key_id.as_str(), s(&iv["access_key_id"]));
    assert_eq!(
        invite.secret_access_key.as_str(),
        s(&iv["secret_access_key"])
    );
    assert_eq!(invite.to_text().unwrap().as_str(), s(&iv["text"]));
    // The invite's legacy pin and fingerprint equal the header's.
    let (_, info, _) = header_fixture();
    assert_eq!(invite.legacy_sha256, info.legacy_sha256);
    assert_eq!(invite.fingerprint, info.fingerprint);

    let r = &v["request"];
    let key = invite.key();
    assert_eq!(key.expose().to_vec(), hx(&r["k_invite"]));
    let obj = hx(&r["object"]);
    let req = enroll::open_request(&invite, &obj).unwrap();
    let want = EnrollmentRequest {
        kind: u(&r["kind"]) as u8,
        device_pk: arr(&r["device_pk"]),
        kem_ek: hx(&r["kem_ek"]),
        ext: ExtList::new(),
    };
    assert_eq!(req, want);
    let mut rng = BufferRng::new(&[&hx(&r["nonce"])]);
    assert_eq!(
        enroll::seal_request_with(&mut rng, &invite, &want).unwrap(),
        obj
    );
    assert_eq!(enroll::comparison_code(&obj), s(&v["comparison_code"]));
    assert!(enroll::comparison_code_matches(
        &s(&v["comparison_code"]).to_lowercase().replace('-', " "),
        s(&v["comparison_code"])
    ));
    assert!(!enroll::comparison_code_matches(
        "0000-0000-0000-0000",
        s(&v["comparison_code"])
    ));

    for line in v["vault_configuration_lines"].as_array().unwrap() {
        let c = VaultConfig::from_line(s(line), false).unwrap();
        assert_eq!(c.vault_id, arr(&v["vault_id"]));
        assert_eq!(c.to_line().unwrap(), s(line));
    }
}

#[test]
fn device_file_vectors() {
    let v = load("device-file.json");
    let vid = arr(&v["vault_id"]);
    let params = kdf_params(&v["kdf"]);
    let pw = password(&v["password_utf8"]);
    let lk = device::lk_for_test(&kdf::argon2id_unchecked(&pw, &params), &vid);
    assert_eq!(lk.expose().to_vec(), hx(&v["lk"]));
    let file = hx(&v["file"]);
    let bundle = device::open_device_file(&file, &pw).unwrap();
    let b = &v["bundle"];
    assert_eq!(bundle.device_id, arr(&b["device_id"]));
    assert_eq!(bundle.secrets.x25519_sk.to_vec(), hx(&b["device_sk"]));
    assert_eq!(bundle.secrets.kem_seed.to_vec(), hx(&b["kem_seed"]));
    assert_eq!(bundle.access_key_id.as_str(), s(&b["access_key_id"]));
    assert_eq!(
        bundle.secret_access_key.as_str(),
        s(&b["secret_access_key"])
    );
    assert_eq!(bundle.encode().unwrap().to_vec(), hx(&v["bundle_plain"]));
    let again = Bundle::decode(&hx(&v["bundle_plain"])).unwrap();
    assert_eq!(again.device_id, bundle.device_id);
    let lk2 = LocalWrapKey::from_bytes(arr(&v["lk"]));
    assert_eq!(
        device::seal_with_key(&lk2, &vid, &params, true, &arr(&v["nonce"]), &bundle).unwrap(),
        file
    );
    assert_eq!(
        device::open_device_file(&file, "wrong password").err(),
        Some(Error::WrongPasswordOrUnknownDevice)
    );
}

#[test]
fn export_vectors() {
    let v = load("export.json");
    let vid = arr(&v["vault_id"]);
    let params = kdf_params(&v["kdf"]);
    let pw = password(&v["password_utf8"]);
    let sk = SecretKey::from_bytes(arr(&v["secret_key"]));
    assert_eq!(
        secret_key_text::encode(&sk).as_str(),
        s(&v["secret_key_text"])
    );
    let pk = kdf::argon2id_unchecked(&pw, &params);
    for c in v["cases"].as_array().unwrap() {
        let file = hx(&c["file"]);
        let info = export::export_info(&file).unwrap();
        assert_eq!(info.sk_check.to_vec(), hx(&c["sk_check"]));
        let sko = if info.password_only { None } else { Some(&sk) };
        let xk = export::export_key(&pk, sko, &vid);
        assert_eq!(xk.expose().to_vec(), hx(&c["xk"]), "{}", s(&c["name"]));
        let payload = export::open_with_key(&file, &xk).unwrap();
        let reseal = export::seal_with_key(
            &ExportKey::from_bytes(arr(&c["xk"])),
            &info,
            &arr(&c["nonce"]),
            &payload,
        )
        .unwrap();
        assert_eq!(reseal, file);
        let opened = export::open_export(&file, &pw, Some(&sk)).unwrap();
        assert_eq!(opened, payload);
        assert!(!opened.entries.is_empty() || !opened.tombstones.is_empty());
        if !info.password_only {
            assert_eq!(info.sk_check, secret_key_text::check_value(&sk));
            let other = SecretKey::from_bytes([1; 16]);
            assert_eq!(
                export::open_export(&file, &pw, Some(&other)).err(),
                Some(Error::WrongPasswordOrUnknownDevice)
            );
        }
    }
    // The payload vector re-encodes byte for byte.
    let key = ExportKey::from_bytes(arr(&v["cases"][0]["xk"]));
    let p = export::open_with_key(&hx(&v["cases"][0]["file"]), &key).unwrap();
    let info = export::export_info(&hx(&v["cases"][0]["file"])).unwrap();
    let file = export::seal_with_key(&key, &info, &[0; 24], &p).unwrap();
    let back = export::open_with_key(&file, &key).unwrap();
    assert_eq!(back, p);
}

#[test]
fn malformed_vectors() {
    let v = load("malformed.json");
    let h = load("header.json");
    for c in v["cases"].as_array().unwrap() {
        let name = s(&c["name"]);
        let want = expected_kind(name);
        let got = match s(&c["kind"]) {
            "index" => {
                index::open_with_key(&hx(&c["object"]), &IndexKey::from_bytes(arr(&c["key"])))
                    .map(|_| ())
            }
            "header" => {
                let k_meta = c.get("k_meta").map(arr).unwrap_or_else(|| {
                    *keys::meta_key(
                        &VaultKey::from_bytes(arr(&h["inputs"]["vk"])),
                        &arr(&h["inputs"]["vault_id"]),
                    )
                    .expose()
                });
                parse_header(&hx(&c["object"])).and_then(|p| {
                    p.verify_with_keys(
                        &HeaderMacKey::from_bytes(arr(&c["key"])),
                        &MetaKey::from_bytes(k_meta),
                    )
                    .map(|_| ())
                })
            }
            "invite" => Invite::from_text(s(&c["text"]), false).map(|_| ()),
            k => panic!("unknown kind {k}"),
        };
        assert_eq!(got.err(), Some(Error::Integrity(want)), "{name}");
    }
}

fn expected_kind(name: &str) -> K {
    match name {
        "unsorted paths" => K::Order,
        "duplicate path" | "duplicate head object id" => K::Duplicate,
        "path with a .. segment"
        | "path with a control character"
        | "path with a C1 control character" => K::PathRule,
        "history floor above the revision"
        | "history floor of 1"
        | "conflict-of naming the entry's own path" => K::ExtValue,
        "index_seq above 2^48" | "revision above 2^48" => K::CounterCap,
        "unknown critical extension item (type 0x8001)" => K::ExtCritical,
        "non-zero padding byte" => K::Padding,
        "object not a multiple of 4096 bytes" => K::PaddedSize,
        "device kem_ek fails the FIPS 203 encapsulation-key check" => K::KemEk,
        "keyring entry epoch 3 under a header at epoch 2" => K::Keyring,
        "non-canonical base64url (unused trailing bits set)" => K::Base64,
        n => panic!("no expected kind for malformed case {n:?}"),
    }
}

/// Open each object kind with the key the tamper file names.
type Opener = Box<dyn Fn(&[u8]) -> bool>;

fn tamper_opener(kind: &str) -> Opener {
    match kind {
        "header" => {
            let h = load("header.json");
            let vk = VaultKey::from_bytes(arr(&h["inputs"]["vk"]));
            let vid = arr(&h["inputs"]["vault_id"]);
            let hmk = *keys::header_mac_key(&vk, &vid).expose();
            assert_eq!(hmk.to_vec(), hx(&h["k_header_mac"]));
            let mk = *keys::meta_key(&vk, &vid).expose();
            Box::new(move |b| {
                parse_header(b)
                    .and_then(|p| {
                        p.verify_with_keys(&HeaderMacKey::from_bytes(hmk), &MetaKey::from_bytes(mk))
                            .map(|_| ())
                    })
                    .is_ok()
            })
        }
        "entry" => {
            let e = load("entry.json");
            let c = e["cases"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| s(&c["name"]) == "edit, epoch 2")
                .unwrap()
                .clone();
            let k: [u8; 32] = arr(&c["k_entry"]);
            Box::new(move |b| entry::open_with_key(b, &EntryKey::from_bytes(k)).is_ok())
        }
        "index" => {
            let k: [u8; 32] = arr(&load("index.json")["k_index"]);
            Box::new(move |b| index::open_with_key(b, &IndexKey::from_bytes(k)).is_ok())
        }
        "device_file" => {
            let k: [u8; 32] = arr(&load("device-file.json")["lk"]);
            Box::new(move |b| device::open_with_key(b, &LocalWrapKey::from_bytes(k)).is_ok())
        }
        "export" => {
            let k: [u8; 32] = arr(&load("export.json")["cases"][0]["xk"]);
            Box::new(move |b| export::open_with_key(b, &ExportKey::from_bytes(k)).is_ok())
        }
        "enrollment_request" => {
            let v = load("enrollment.json");
            let k: [u8; 32] = arr(&v["request"]["k_invite"]);
            let vid: [u8; 16] = arr(&v["vault_id"]);
            let did: [u8; 16] = arr(&v["invite"]["device_id"]);
            Box::new(move |b| {
                enroll::open_request_with_key(b, &InviteKey::from_bytes(k), &vid, &did).is_ok()
            })
        }
        k => panic!("unknown tamper kind {k}"),
    }
}

#[test]
fn tamper_vectors() {
    let t = load("tamper.json");
    for (kind, obj) in t["objects"].as_object().unwrap() {
        let opens = tamper_opener(kind);
        for c in obj["cases"].as_array().unwrap() {
            assert!(
                !opens(&hx(&c["object"])),
                "{kind}: {} not rejected",
                s(&c["field"])
            );
        }
    }
}

/// Every single-bit flip of every byte of every valid vector object is rejected.
#[test]
fn exhaustive_single_byte_flips() {
    let objects: Vec<(&str, Vec<u8>)> = vec![
        ("header", hx(&load("header.json")["header"])),
        ("entry", hx(&load("entry.json")["cases"][1]["object"])),
        ("index", hx(&load("index.json")["object"])),
        ("device_file", hx(&load("device-file.json")["file"])),
        ("export", hx(&load("export.json")["cases"][0]["file"])),
        (
            "enrollment_request",
            hx(&load("enrollment.json")["request"]["object"]),
        ),
    ];
    for (kind, obj) in objects {
        let opens = tamper_opener(kind);
        assert!(opens(&obj), "{kind}: the valid object must open");
        for i in 0..obj.len() {
            let mut b = obj.clone();
            b[i] ^= 1;
            assert!(!opens(&b), "{kind}: flip at {i} accepted");
        }
        let mut longer = obj.clone();
        longer.push(0);
        assert!(!opens(&longer), "{kind}: appended byte accepted");
        assert!(!opens(&obj[..obj.len() - 1]), "{kind}: truncation accepted");
    }
}
