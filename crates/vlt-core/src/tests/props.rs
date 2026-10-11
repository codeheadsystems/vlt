//! Property tests: round trips, tamper detection on random bytes, and encoder refusal of drafts
//! that break a decode rule.

use crate::codec::{Reader, Writer};
use crate::enroll::{Invite, VaultConfig};
use crate::entry::{self, EntryPlain, EntryPrefix};
use crate::error::Error;
use crate::export::{self, ExportInfo, ExportPayload, ExportRecord, ExportRevision};
use crate::ext::{ExtCtx, ExtItem, ExtList};
use crate::index::{self, Applied, IndexEntry, IndexPlain, IndexPrefix, Tombstone};
use crate::kdf::KdfParams;
use crate::secret::{EntryKey, ExportKey, IndexKey, InviteSecret, SecretKey};
use crate::secret_key_text;
use proptest::collection::{btree_map, btree_set, vec};
use proptest::prelude::*;
use zeroize::Zeroizing;

fn path() -> impl Strategy<Value = String> {
    "[A-Za-z0-9._é-]{1,8}(/[A-Za-z0-9 ü-]{1,8}){0,2}"
        .prop_filter("path rules", |p| crate::path::is_valid_path(p))
}

/// Unknown, non-critical extension items, sorted and unique.
fn ext_list() -> impl Strategy<Value = ExtList> {
    btree_map(0x0001u16..0x3fff, vec(any::<u8>(), 0..8), 0..3).prop_map(|m| ExtList {
        items: m
            .into_iter()
            .map(|(ty, value)| ExtItem { ty, value })
            .collect(),
    })
}

prop_compose! {
    fn index_plain()(
        paths in btree_set(path(), 0..6),
        tomb_paths in vec(path(), 0..3),
        seed in any::<[u8; 16]>(),
        revs in vec(2u64..1000, 6),
        ext in ext_list(),
        applied in btree_map(any::<[u8; 16]>(), 0u64..1 << 48, 0..3),
    ) -> IndexPlain {
        let entries: Vec<IndexEntry> = paths.into_iter().enumerate().map(|(i, path)| {
            let mut head = seed;
            head[0] = i as u8;
            let mut e = ExtList::new();
            if i % 2 == 0 {
                e.set(crate::ext::HISTORY_FLOOR, 2u64.to_be_bytes().to_vec());
            }
            IndexEntry { path, head_object_id: head, head_sha256: [i as u8; 32], revision: revs[i], device_id: seed, ext: e }
        }).collect();
        let mut tombstones: Vec<Tombstone> = tomb_paths.into_iter().enumerate().map(|(i, path)| Tombstone {
            path, head_object_id: seed, head_sha256: [1; 32], revision: 3, device_id: seed, removed_index_seq: i as u64 + 1, ext: ExtList::new(),
        }).collect();
        tombstones.sort_by(|a, b| (a.path.as_bytes(), a.removed_index_seq).cmp(&(b.path.as_bytes(), b.removed_index_seq)));
        IndexPlain {
            writer_device_id: seed,
            entries,
            tombstones,
            applied: applied.into_iter().map(|(device_id, last_op_seq)| Applied { device_id, last_op_seq }).collect(),
            ext,
        }
    }
}

prop_compose! {
    fn entry_plain()(
        first in any::<bool>(),
        revision in 2u64..1 << 48,
        parent in any::<[u8; 16]>().prop_filter("non-zero", |p| p != &[0; 16]),
        content in vec(any::<u8>(), 0..1500),
        created in any::<i64>(),
        device in any::<[u8; 16]>(),
        ext in ext_list(),
    ) -> EntryPlain {
        EntryPlain {
            revision: if first { 1 } else { revision },
            parent_object_id: if first { [0; 16] } else { parent },
            parent_sha256: if first { [0; 32] } else { [9; 32] },
            device_id: device,
            created_unix: created,
            content: Zeroizing::new(content),
            ext,
        }
    }
}

proptest! {
    #[test]
    fn ext_round_trip(l in ext_list()) {
        let mut w = Writer::new();
        l.encode(&mut w).unwrap();
        let bytes = w.into_vec();
        let mut r = Reader::new(&bytes);
        let back = ExtList::decode(&mut r, ExtCtx::Other).unwrap();
        r.finish().unwrap();
        prop_assert_eq!(&back, &l);
        // Re-encoding is byte for byte.
        let mut w2 = Writer::new();
        back.encode(&mut w2).unwrap();
        prop_assert_eq!(w2.into_vec(), bytes);
    }

    #[test]
    fn critical_unknown_rejected(ty in 0x8000u16..=0xffff) {
        let l = ExtList { items: vec![ExtItem { ty, value: vec![] }] };
        prop_assert!(l.check(ExtCtx::Other).is_err());
    }

    #[test]
    fn index_round_trip_and_tamper(p in index_plain(), key in any::<[u8; 32]>(), nonce in any::<[u8; 24]>(), seq in 1u64..1 << 48, at in any::<prop::sample::Index>(), mask in 1u8..=255) {
        let k = IndexKey::from_bytes(key);
        let pfx = IndexPrefix { vault_id: [3; 16], epoch: 2, index_seq: seq, header_seq: 5 };
        let obj = index::seal_with_key(&k, &pfx, &p, &nonce).unwrap();
        prop_assert_eq!(obj.len() % 4096, 0);
        let (pfx2, back) = index::open_with_key(&obj, &k).unwrap();
        prop_assert_eq!(pfx2, pfx);
        prop_assert!(back == p);
        let mut bad = obj.clone();
        let i = at.index(bad.len());
        bad[i] ^= mask;
        prop_assert!(index::open_with_key(&bad, &k).is_err());
    }

    #[test]
    fn index_encoder_refuses_rule_breaks(p in index_plain(), key in any::<[u8; 32]>()) {
        let k = IndexKey::from_bytes(key);
        let pfx = IndexPrefix { vault_id: [3; 16], epoch: 2, index_seq: 1, header_seq: 1 };
        if p.entries.len() >= 2 {
            let mut swapped = p.clone();
            swapped.entries.swap(0, 1);
            prop_assert!(matches!(index::seal_with_key(&k, &pfx, &swapped, &[0; 24]), Err(Error::InvalidInput(_))));
        }
        if let Some(first) = p.entries.first() {
            let mut dup = p.clone();
            dup.entries.push(first.clone());
            prop_assert!(index::seal_with_key(&k, &pfx, &dup, &[0; 24]).is_err());
            let mut cap = p.clone();
            cap.entries[0].revision = (1 << 48) + 1;
            prop_assert!(index::seal_with_key(&k, &pfx, &cap, &[0; 24]).is_err());
            let mut floor = p.clone();
            let above = floor.entries[0].revision + 1;
            floor.entries[0].ext.set(crate::ext::HISTORY_FLOOR, above.to_be_bytes().to_vec());
            prop_assert!(index::seal_with_key(&k, &pfx, &floor, &[0; 24]).is_err());
            let mut tomb_conflict = p.clone();
            tomb_conflict.tombstones.push(Tombstone {
                path: "z".into(), head_object_id: [0; 16], head_sha256: [0; 32], revision: 2, device_id: [0; 16], removed_index_seq: 99,
                ext: ExtList { items: vec![ExtItem { ty: crate::ext::CONFLICT_OF, value: b"a".to_vec() }] },
            });
            prop_assert!(index::seal_with_key(&k, &pfx, &tomb_conflict, &[0; 24]).is_err());
        }
        let cap = IndexPrefix { index_seq: (1 << 48) + 1, ..pfx };
        prop_assert!(index::seal_with_key(&k, &cap, &p, &[0; 24]).is_err());
    }

    #[test]
    fn entry_round_trip_and_tamper(p in entry_plain(), key in any::<[u8; 32]>(), nonce in any::<[u8; 24]>(), at in any::<prop::sample::Index>(), mask in 1u8..=255) {
        let k = EntryKey::from_bytes(key);
        let pfx = EntryPrefix { vault_id: [1; 16], epoch: 7, object_id: [2; 16] };
        let obj = entry::seal_with_key(&k, &pfx, &p, &nonce).unwrap();
        prop_assert_eq!(obj.len() % 512, 0);
        let minimal = (68 + 8 + 16 + 32 + 16 + 8 + 4 + p.content.len() + 2 + p.ext.items.iter().map(|i| 6 + i.value.len()).sum::<usize>() + 16).div_ceil(512) * 512;
        prop_assert_eq!(obj.len(), minimal);
        let (pfx2, back) = entry::open_with_key(&obj, &k).unwrap();
        prop_assert_eq!(pfx2, pfx);
        prop_assert!(back == p);
        let mut bad = obj.clone();
        let i = at.index(bad.len());
        bad[i] ^= mask;
        prop_assert!(entry::open_with_key(&bad, &k).is_err());
        let mut broken = p.clone();
        broken.parent_object_id = if p.revision == 1 { [1; 16] } else { [0; 16] };
        prop_assert!(entry::seal_with_key(&k, &pfx, &broken, &nonce).is_err());
    }

    #[test]
    fn export_round_trip(paths in btree_set(path(), 0..4), contents in vec(vec(any::<u8>(), 0..64), 3), key in any::<[u8; 32]>(), at in any::<prop::sample::Index>()) {
        let entries: Vec<ExportRecord> = paths.into_iter().map(|path| ExportRecord {
            path,
            revisions: contents.iter().enumerate().map(|(i, c)| ExportRevision { revision: 3 - i as u64, created_unix: i as i64, device_id: [i as u8; 16], content: Zeroizing::new(c.clone()) }).collect(),
        }).collect();
        let payload = ExportPayload { created_unix: 5, entries, tombstones: vec![], ext: ExtList::new() };
        let k = ExportKey::from_bytes(key);
        let info = ExportInfo { vault_id: [4; 16], kdf: KdfParams { m_kib: 65536, t: 3, p: 1, salt: [5; 16] }, test_kdf: false, password_only: false, sk_check: [1, 2, 3, 4] };
        let file = export::seal_with_key(&k, &info, &[6; 24], &payload).unwrap();
        prop_assert!(export::open_with_key(&file, &k).unwrap() == payload);
        let mut bad = file.clone();
        let i = at.index(bad.len());
        bad[i] ^= 0x80;
        prop_assert!(export::open_with_key(&bad, &k).is_err());
    }

    #[test]
    fn invite_round_trip(label in "[a-z0-9-]{1,32}", bucket in "[a-z0-9][a-z0-9.-]{1,20}[a-z0-9]", region in "[a-z0-9-]{1,32}", key in "[A-Z0-9]{20}", secret in "[A-Za-z0-9/+]{40}", s in any::<[u8; 32]>(), e in 1u32..1001) {
        let inv = Invite {
            vault_id: [1; 16], device_id: [2; 16], epoch: e, fingerprint: [3; 32], legacy_sha256: [4; 32],
            invite_secret: InviteSecret::from_bytes(s), label: label.clone(), endpoint: String::new(), region, bucket,
            prefix: "vlt/".into(), access_key_id: Zeroizing::new(key), secret_access_key: Zeroizing::new(secret), ext: ExtList::new(),
        };
        let text = inv.to_text().unwrap();
        let back = Invite::from_text(&text, false).unwrap();
        prop_assert_eq!(back.to_text().unwrap(), text);
        prop_assert_eq!(back.label, label);
        let cfg = VaultConfig { vault_id: [9; 16], region: back.region.clone(), bucket: back.bucket.clone(), prefix: "a/b/".into(), endpoint: "https://nas.example:9000".into() };
        prop_assert_eq!(VaultConfig::from_line(&cfg.to_line().unwrap(), false).unwrap(), cfg);
    }

    #[test]
    fn secret_key_text_tolerance(b in any::<[u8; 16]>(), lower in any::<bool>(), drop_dashes in any::<bool>()) {
        let sk = SecretKey::from_bytes(b);
        let mut t: String = secret_key_text::encode(&sk).to_string();
        if lower { t = t.to_lowercase(); }
        if drop_dashes { t = format!("VLT1-{}", t[5..].replace('-', " ")); }
        let t = format!("{}{}", &t[..5], t[5..].replace('0', "O").replace('1', "I"));
        let back = secret_key_text::decode(&t).unwrap();
        prop_assert_eq!(back.expose(), sk.expose());
    }

    #[test]
    fn secret_key_text_detects_one_change(b in any::<[u8; 16]>(), at in 5usize..44) {
        let sk = SecretKey::from_bytes(b);
        let t = secret_key_text::encode(&sk);
        let mut chars: Vec<char> = t.chars().collect();
        if chars[at] == '-' { return Ok(()); }
        chars[at] = if chars[at] == 'Z' { 'Y' } else { 'Z' };
        let changed: String = chars.into_iter().collect();
        prop_assert!(secret_key_text::decode(&changed).is_err());
    }
}
