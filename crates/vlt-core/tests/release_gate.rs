//! Runs against the library built without `cfg(test)`, as a release client would be: every vector
//! object that sets the `test_kdf` flag must be refused before any key derivation.

use vlt_core::{Error, IntegrityKind};

fn vector(name: &str, field: &str) -> Vec<u8> {
    let path = format!("{}/../../spec/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut cur = &v;
    for part in field.split('.') {
        cur = match part.parse::<usize>() {
            Ok(i) => &cur[i],
            Err(_) => &cur[part],
        };
    }
    hex::decode(cur.as_str().unwrap()).unwrap()
}

const REFUSED: Option<Error> = Some(Error::Integrity(IntegrityKind::TestKdfInRelease));

#[test]
fn header_with_test_kdf_is_refused() {
    assert_eq!(
        vlt_core::parse_header(&vector("header.json", "header")).err(),
        REFUSED
    );
}

#[test]
fn device_file_with_test_kdf_is_refused() {
    let f = vector("device-file.json", "file");
    assert_eq!(vlt_core::device::device_file_info(&f).err(), REFUSED);
    assert_eq!(vlt_core::device::open_device_file(&f, "any").err(), REFUSED);
}

#[test]
fn export_with_test_kdf_is_refused() {
    let f = vector("export.json", "cases.0.file");
    assert_eq!(vlt_core::export::export_info(&f).err(), REFUSED);
    assert_eq!(
        vlt_core::export::open_export(&f, "any", None).err(),
        REFUSED
    );
}

/// Error values carry only enums and integers, so their text cannot contain input. The in-crate
/// `errors_never_carry_secrets` test drives real failing paths with secret inputs.
#[test]
fn errors_carry_no_input_text() {
    let errors = [
        Error::Integrity(IntegrityKind::PathRule),
        Error::UnsupportedFormatVersion(2),
        Error::WrongPasswordOrUnknownDevice,
        Error::SecretKeyTypo,
        Error::InvalidInput(vlt_core::InputKind::Path),
        Error::Rng,
    ];
    for e in errors {
        let text = format!("{e} {e:?}");
        for secret in ["hunter2", "Email/example.com", "VLT1-"] {
            assert!(!text.contains(secret));
        }
    }
}

/// The gate must refuse only test parameters: an object at the real floor opens in a release-like
/// build, and parameters one step below the floor are refused before any hashing.
#[test]
fn floor_parameters_work_and_below_floor_is_refused() {
    use vlt_core::device::{Bundle, open_device_file, seal_device_file};
    use vlt_core::kdf::FLOOR;
    let (secrets, _) = vlt_core::keys::generate_device_keys().unwrap();
    let bundle = Bundle {
        device_id: [7; 16],
        secrets,
        access_key_id: zeroize::Zeroizing::new("AKID".into()),
        secret_access_key: zeroize::Zeroizing::new("secret".into()),
        ext: vlt_core::ext::ExtList::new(),
    };
    let pw = "correct horse battery staple";
    let file = seal_device_file(pw, &[1; 16], FLOOR.0, FLOOR.1, FLOOR.2, false, &bundle).unwrap();
    let back = open_device_file(&file, pw).unwrap();
    assert_eq!(back.device_id, [7; 16]);
    let below = seal_device_file(pw, &[1; 16], FLOOR.0 - 1, FLOOR.1, FLOOR.2, false, &bundle);
    assert_eq!(
        below.err(),
        Some(Error::Integrity(IntegrityKind::KdfParams))
    );
    let test_set = seal_device_file(pw, &[1; 16], 64, 1, 1, true, &bundle);
    assert_eq!(test_set.err(), REFUSED);
}

/// The compile_fail doctests in `secret.rs` must fail only for the missing `Debug` or `Display`,
/// so the same expressions must compile here without formatting.
#[test]
fn secret_type_paths_exist() {
    let _ = vlt_core::Auk::from_bytes([0u8; 32]);
    let _ = vlt_core::DeviceSecrets::from_bytes([0u8; 32], [0u8; 64]);
    let _ = vlt_core::secret::InviteSecret::from_bytes([0u8; 32]);
    let _ = vlt_core::secret::EntryKey::from_bytes([0u8; 32]);
    let _ = vlt_core::secret::IndexKey::from_bytes([0u8; 32]);
    let _ = vlt_core::secret::HeaderMacKey::from_bytes([0u8; 32]);
    let _ = vlt_core::secret::MetaKey::from_bytes([0u8; 32]);
    let _ = vlt_core::secret::MirrorKey::from_bytes([0u8; 32]);
    let _ = vlt_core::secret::LocalWrapKey::from_bytes([0u8; 32]);
    let _ = vlt_core::secret::ExportKey::from_bytes([0u8; 32]);
    let _ = vlt_core::secret::InviteKey::from_bytes([0u8; 32]);
    let _ = vlt_core::VaultKey::from_bytes([0u8; 32]);
    let _ = vlt_core::SecretKey::from_bytes([0u8; 16]);
    fn _types(
        _: &vlt_core::VaultKeys,
        _: &vlt_core::device::Bundle,
        _: &vlt_core::enroll::Invite,
        _: &vlt_core::header::HeaderDraft,
    ) {
    }
}
