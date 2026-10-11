//! The header object: parsing, unlock through the password or a device wrap, authentication,
//! strict metadata decoding, and building.
//!
//! Unlock follows the spec's order: [`parse_header`] checks the cleartext layout, a wrap opens the
//! vault key, and verification checks the MAC and decodes the metadata. The result splits into
//! [`HeaderInfo`], plain data with no secrets, and [`VaultKeys`], an opaque holder of every key
//! that never hands raw key bytes out.

use crate::FORMAT_VERSION;
use crate::codec::{Reader, Writer};
use crate::error::{Error, InputKind, IntegrityKind as K, Result, input, integrity};
use crate::ext::{ExtCtx, ExtList};
use crate::kdf::{KDF_BLOCK_LEN, KdfParams, TEST_KDF_ALLOWED, derive_auk};
use crate::keys::{entry_key, fingerprint, header_mac_key, index_key, meta_key, mirror_key};
use crate::limits::{COUNTER_CAP, DEVICES_MAX, EPOCH_MAX, HEADER_MAX, KEYRING_MAX, LEGACY_MAX};
use crate::path::is_valid_label;
use crate::prim::{hmac, hmac_verify, open, seal, sha256};
use crate::rng::{draw, os};
use crate::secret::{
    Auk, DeviceSecrets, EntryKey, HeaderMacKey, IndexKey, MetaKey, MirrorKey, SecretKey, VaultKey,
};
use crate::wrap::{
    DEVICE_RECORD_LEN, DeviceRecord, KEM_CT_LEN, KEM_EK_LEN, check_kem_ek, open_device_wrap,
    open_pw_wrap, seal_pw_wrap,
};
use rand_core::TryCryptoRng;

const MAGIC: &[u8; 4] = b"VLTH";
const FLAG_TEST_KDF: u16 = 1;
/// A legacy lineage: its vault ID and every vault key of it by epoch.
pub(crate) type Lineage = ([u8; 16], Vec<(u32, VaultKey)>);

/// Offset of the first device record.
const DEVICES_OFFSET: usize = 139;

/// Device information from the encrypted metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    /// Device ID; equals the matching device record's.
    pub device_id: [u8; 16],
    /// 1 CLI, 2 Android, 3 Firefox, 4 desktop.
    pub kind: u8,
    /// Label, unique within the vault.
    pub label: String,
    /// `header_seq` of the header that enrolled the device.
    pub enrolled_header_seq: u64,
    /// The enrolling device's wall clock, for display only.
    pub enrolled_unix: i64,
    /// The inviting device, the device itself (kit path), or zero (`vlt init`).
    pub enrolled_by: [u8; 16],
}

/// The rotation commitment: the index the last rotation started from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RotationCommitment {
    /// Epoch the last rotation left, or 0.
    pub from_epoch: u32,
    /// `index_seq` of that index, or 0.
    pub from_index_seq: u64,
    /// SHA-256 of that index object, or zeros.
    pub from_index_sha256: [u8; 32],
}

/// One enrolled device: its record in the header and its metadata entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderDevice {
    /// Public keys and the wrap of the vault key.
    pub record: DeviceRecord,
    /// Metadata.
    pub info: DeviceInfo,
}

/// A parsed header whose cleartext layout is valid. Nothing in it is authenticated yet.
#[derive(Debug, Clone)]
pub struct ParsedHeader {
    raw: Vec<u8>,
    /// Format version.
    pub format_version: u16,
    /// Whether the `test_kdf` flag is set.
    pub test_kdf: bool,
    /// Vault ID.
    pub vault_id: [u8; 16],
    /// Header sequence number.
    pub header_seq: u64,
    /// Current epoch.
    pub epoch: u32,
    /// KDF parameters of the password wrap.
    pub kdf: KdfParams,
    pub(crate) pw_nonce: [u8; 24],
    pub(crate) pw_ct: [u8; 48],
    /// Device records.
    pub records: Vec<DeviceRecord>,
    meta_nonce: [u8; 24],
    meta_ct_range: (usize, usize),
    mac_offset: usize,
}

/// Plain, authenticated header data. Holds no secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderInfo {
    /// Format version.
    pub format_version: u16,
    /// Whether the `test_kdf` flag is set.
    pub test_kdf: bool,
    /// Vault ID.
    pub vault_id: [u8; 16],
    /// Header sequence number.
    pub header_seq: u64,
    /// Current epoch.
    pub epoch: u32,
    /// KDF parameters.
    pub kdf: KdfParams,
    /// The device that wrote this header.
    pub writer_device_id: [u8; 16],
    /// Rotation commitment.
    pub rotation: RotationCommitment,
    /// Enrolled devices, sorted by device ID.
    pub devices: Vec<HeaderDevice>,
    /// Metadata extension list.
    pub ext: ExtList,
    /// Fingerprint of the current vault key.
    pub fingerprint: [u8; 32],
    /// The legacy pin, `SHA-256("vlt/v1/legacy" || legacy block)`.
    pub legacy_sha256: [u8; 32],
    /// Epochs present in each legacy lineage, by lineage vault ID.
    pub legacy_lineages: Vec<([u8; 16], u32)>,
    /// SHA-256 of the whole header object.
    pub header_sha256: [u8; 32],
}

/// Every key the header yields. Opaque: keys are used inside its methods and never returned as
/// bytes. The only deliberate exports are the secret key text for the emergency kit.
pub struct VaultKeys {
    vault_id: [u8; 16],
    epoch: u32,
    vk: VaultKey,
    secret_key: SecretKey,
    keyring: Vec<(u32, VaultKey)>,
    legacy: Vec<Lineage>,
    rotation: RotationCommitment,
}

impl VaultKeys {
    /// The vault ID these keys belong to.
    pub fn vault_id(&self) -> [u8; 16] {
        self.vault_id
    }

    /// The current epoch.
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// The emergency kit's text form of the current secret key.
    pub fn secret_key_text(&self) -> crate::secret::SecretString {
        crate::secret_key_text::encode(&self.secret_key)
    }

    fn vk_of(&self, vault_id: &[u8; 16], epoch: u32) -> Option<&VaultKey> {
        if vault_id == &self.vault_id {
            if epoch == self.epoch {
                return Some(&self.vk);
            }
            return self
                .keyring
                .iter()
                .find(|(e, _)| *e == epoch)
                .map(|(_, k)| k);
        }
        let (_, ring) = self.legacy.iter().find(|(v, _)| v == vault_id)?;
        ring.iter().find(|(e, _)| *e == epoch).map(|(_, k)| k)
    }

    /// `K_entry` for an entry object sealed under `(vault_id, epoch)`: the current lineage at an
    /// epoch up to the header's, or a legacy lineage.
    pub(crate) fn entry_key_for(&self, vault_id: &[u8; 16], epoch: u32) -> Result<EntryKey> {
        let vk = self
            .vk_of(vault_id, epoch)
            .ok_or(Error::Integrity(K::UnknownLineage))?;
        Ok(entry_key(vk, vault_id))
    }

    /// `K_index` for an index at `epoch`: only the header's epoch or the committed rotation epoch.
    pub(crate) fn index_key_for(&self, epoch: u32) -> Result<IndexKey> {
        let ok = epoch == self.epoch
            || (self.rotation.from_epoch != 0
                && epoch == self.rotation.from_epoch
                && epoch.checked_add(1) == Some(self.epoch));
        if !ok {
            return integrity(K::IndexEpoch);
        }
        let vk = self
            .vk_of(&self.vault_id, epoch)
            .ok_or(Error::Integrity(K::IndexEpoch))?;
        Ok(index_key(vk, &self.vault_id))
    }

    /// `K_entry` of the current epoch, for sealing.
    pub(crate) fn current_entry_key(&self) -> EntryKey {
        entry_key(&self.vk, &self.vault_id)
    }

    /// `K_index` of the current epoch, for sealing.
    pub(crate) fn current_index_key(&self) -> IndexKey {
        index_key(&self.vk, &self.vault_id)
    }

    /// `K_mirror` of the current epoch.
    pub(crate) fn mirror_key(&self) -> MirrorKey {
        mirror_key(&self.vk, &self.vault_id)
    }

    /// `K_mirror` of an epoch of the current lineage up to the current one, for opening a mirror
    /// `state` sealed before a rotation.
    pub(crate) fn mirror_key_for(&self, epoch: u32) -> Option<MirrorKey> {
        if epoch > self.epoch {
            return None;
        }
        self.vk_of(&self.vault_id, epoch)
            .map(|vk| mirror_key(vk, &self.vault_id))
    }

    /// The fingerprint of the vault key of `epoch` in the current lineage: the current epoch or
    /// one in the keyring. The header pin's chain of custody checks a new header through it.
    pub fn fingerprint_of(&self, epoch: u32) -> Option<[u8; 32]> {
        if epoch > self.epoch {
            return None;
        }
        self.vk_of(&self.vault_id, epoch)
            .map(|vk| fingerprint(vk, &self.vault_id))
    }

    /// The rotation commitment, for the index acceptance rule.
    pub(crate) fn rotation(&self) -> RotationCommitment {
        self.rotation
    }
}

/// Check a header's cleartext layout, before any key is used.
pub fn parse_header(bytes: &[u8]) -> Result<ParsedHeader> {
    if bytes.len() > HEADER_MAX {
        return integrity(K::SizeLimit);
    }
    let mut r = Reader::new(bytes);
    if &r.array::<4>()? != MAGIC {
        return integrity(K::BadMagic);
    }
    let format_version = r.u16()?;
    if format_version != FORMAT_VERSION {
        return Err(Error::UnsupportedFormatVersion(format_version));
    }
    let flags = r.u16()?;
    if flags & !FLAG_TEST_KDF != 0 {
        return integrity(K::UnknownFlags);
    }
    let test_kdf = flags & FLAG_TEST_KDF != 0;
    let vault_id = r.array()?;
    let header_seq = r.counter()?;
    let epoch = r.u32()?;
    if !(1..=EPOCH_MAX).contains(&epoch) {
        return integrity(K::Keyring);
    }
    let kdf = KdfParams::decode(&mut r)?;
    kdf.check(test_kdf, TEST_KDF_ALLOWED)?;
    let pw_nonce = r.array()?;
    let pw_ct = r.array()?;
    let device_count = r.u16()? as usize;
    if device_count > DEVICES_MAX {
        return integrity(K::SizeLimit);
    }
    debug_assert_eq!(r.pos(), DEVICES_OFFSET);
    let mut records: Vec<DeviceRecord> = Vec::with_capacity(device_count);
    for _ in 0..device_count {
        let rec = DeviceRecord {
            device_id: r.array()?,
            device_pk: r.array()?,
            kem_ek: r.take(KEM_EK_LEN)?.to_vec(),
            eph_pk: r.array()?,
            kem_ct: r.take(KEM_CT_LEN)?.to_vec(),
            nonce: r.array()?,
            ct: r.array()?,
        };
        if let Some(prev) = records.last()
            && prev.device_id >= rec.device_id
        {
            return integrity(if prev.device_id == rec.device_id {
                K::Duplicate
            } else {
                K::Order
            });
        }
        check_kem_ek(&rec.kem_ek)?;
        records.push(rec);
    }
    let meta_nonce = r.array()?;
    let meta_len = r.u32()? as usize;
    let start = r.pos();
    r.take(meta_len)?;
    let meta_ct_range = (start, start + meta_len);
    let mac_offset = r.pos();
    r.take(32)?;
    r.finish()?;
    Ok(ParsedHeader {
        raw: bytes.to_vec(),
        format_version,
        test_kdf,
        vault_id,
        header_seq,
        epoch,
        kdf,
        pw_nonce,
        pw_ct,
        records,
        meta_nonce,
        meta_ct_range,
        mac_offset,
    })
}

impl ParsedHeader {
    fn kdf_block(&self) -> [u8; KDF_BLOCK_LEN] {
        self.kdf.to_block()
    }

    /// Unlock with the master password and secret key.
    pub fn unlock_with_password(
        &self,
        password: &str,
        sk: &SecretKey,
    ) -> Result<(HeaderInfo, VaultKeys)> {
        let auk = derive_auk(password, sk, &self.kdf, self.test_kdf, &self.vault_id)?;
        self.unlock_with_auk(&auk)
    }

    /// Unlock with an account unlock key.
    pub fn unlock_with_auk(&self, auk: &Auk) -> Result<(HeaderInfo, VaultKeys)> {
        let vk = open_pw_wrap(
            auk,
            &self.vault_id,
            self.epoch,
            &self.kdf_block(),
            &self.pw_nonce,
            &self.pw_ct,
        )?;
        self.verify(vk)
    }

    /// Unlock with this device's wrap.
    pub fn unlock_with_device(
        &self,
        device_id: &[u8; 16],
        secrets: &DeviceSecrets,
    ) -> Result<(HeaderInfo, VaultKeys)> {
        let rec = self
            .records
            .iter()
            .find(|r| &r.device_id == device_id)
            .ok_or(Error::WrongPasswordOrUnknownDevice)?;
        let vk = open_device_wrap(rec, &self.vault_id, self.epoch, secrets)?;
        self.verify(vk)
    }

    /// Check the MAC and decode the metadata with the vault key a wrap yielded.
    pub fn verify(&self, vk: VaultKey) -> Result<(HeaderInfo, VaultKeys)> {
        let hmk = header_mac_key(&vk, &self.vault_id);
        let mk = meta_key(&vk, &self.vault_id);
        let meta = self.verify_with_keys(&hmk, &mk)?;
        let info = HeaderInfo {
            format_version: self.format_version,
            test_kdf: self.test_kdf,
            vault_id: self.vault_id,
            header_seq: self.header_seq,
            epoch: self.epoch,
            kdf: self.kdf,
            writer_device_id: meta.writer,
            rotation: meta.rotation,
            devices: self
                .records
                .iter()
                .cloned()
                .zip(meta.devices.iter().cloned())
                .map(|(record, info)| HeaderDevice { record, info })
                .collect(),
            ext: meta.ext.clone(),
            fingerprint: fingerprint(&vk, &self.vault_id),
            legacy_sha256: meta.legacy_sha256,
            legacy_lineages: meta
                .legacy
                .iter()
                .map(|(v, ring)| (*v, ring.len() as u32))
                .collect(),
            header_sha256: sha256(&[&self.raw]),
        };
        let keys = VaultKeys {
            vault_id: self.vault_id,
            epoch: self.epoch,
            vk,
            secret_key: meta.secret_key,
            keyring: meta.keyring,
            legacy: meta.legacy,
            rotation: meta.rotation,
        };
        Ok((info, keys))
    }

    /// MAC check and metadata decode with explicit subkeys; the vectors enter here.
    pub(crate) fn verify_with_keys(&self, hmk: &HeaderMacKey, mk: &MetaKey) -> Result<Meta> {
        hmac_verify(
            hmk.expose(),
            &self.raw[..self.mac_offset],
            &self.raw[self.mac_offset..],
        )?;
        let (a, b) = self.meta_ct_range;
        let plain = open(
            mk.expose(),
            &self.meta_nonce,
            &self.raw[a..b],
            &meta_ad(&self.vault_id, self.epoch),
        )?;
        let meta = Meta::decode(&plain)?;
        meta.validate(&self.vault_id, self.epoch, &self.records)?;
        Ok(meta)
    }
}

fn meta_ad(vault_id: &[u8; 16], epoch: u32) -> Vec<u8> {
    [b"vlt/v1/meta".as_slice(), vault_id, &epoch.to_be_bytes()].concat()
}

/// Decoded metadata. Crate-internal because it holds secrets.
pub(crate) struct Meta {
    pub(crate) writer: [u8; 16],
    pub(crate) secret_key: SecretKey,
    pub(crate) rotation: RotationCommitment,
    pub(crate) keyring: Vec<(u32, VaultKey)>,
    pub(crate) legacy: Vec<Lineage>,
    pub(crate) legacy_sha256: [u8; 32],
    pub(crate) devices: Vec<DeviceInfo>,
    pub(crate) ext: ExtList,
}

fn ring(r: &mut Reader<'_>, count: usize) -> Result<Vec<(u32, VaultKey)>> {
    let mut v = Vec::with_capacity(count.min(KEYRING_MAX));
    for _ in 0..count {
        v.push((r.u32()?, VaultKey::from_bytes(r.array()?)));
    }
    Ok(v)
}

fn encode_legacy(w: &mut Writer, legacy: &[Lineage]) {
    w.u16(legacy.len() as u16);
    for (vid, ring) in legacy {
        w.bytes(vid).u32(ring.len() as u32);
        for (e, k) in ring {
            w.u32(*e).bytes(k.expose());
        }
    }
}

pub(crate) fn legacy_sha256(block: &[u8]) -> [u8; 32] {
    sha256(&[b"vlt/v1/legacy", block])
}

impl Meta {
    pub(crate) fn decode(plain: &[u8]) -> Result<Meta> {
        let mut r = Reader::new(plain);
        let writer = r.array()?;
        let secret_key = SecretKey::from_bytes(r.array()?);
        let rotation = RotationCommitment {
            from_epoch: r.u32()?,
            from_index_seq: r.counter()?,
            from_index_sha256: r.array()?,
        };
        let kc = r.u32()? as usize;
        if kc > KEYRING_MAX {
            return integrity(K::Keyring);
        }
        let keyring = ring(&mut r, kc)?;
        let legacy_start = r.pos();
        let lc = r.u16()? as usize;
        if lc > LEGACY_MAX {
            return integrity(K::Legacy);
        }
        let mut legacy = Vec::with_capacity(lc);
        let mut total = kc;
        for _ in 0..lc {
            let vid: [u8; 16] = r.array()?;
            let c = r.u32()? as usize;
            if c > KEYRING_MAX - total {
                return integrity(K::Legacy);
            }
            total += c;
            legacy.push((vid, ring(&mut r, c)?));
        }
        let legacy_sha256 = legacy_sha256(&plain[legacy_start..r.pos()]);
        let dc = r.u16()? as usize;
        if dc > DEVICES_MAX {
            return integrity(K::DeviceInfoMismatch);
        }
        let mut devices = Vec::with_capacity(dc);
        for _ in 0..dc {
            devices.push(DeviceInfo {
                device_id: r.array()?,
                kind: r.u8()?,
                label: r.str16()?.to_owned(),
                enrolled_header_seq: r.counter()?,
                enrolled_unix: r.i64()?,
                enrolled_by: r.array()?,
            });
        }
        let ext = ExtList::decode(&mut r, ExtCtx::Other)?;
        r.finish()?;
        Ok(Meta {
            writer,
            secret_key,
            rotation,
            keyring,
            legacy,
            legacy_sha256,
            devices,
            ext,
        })
    }

    /// The rules shared by the decoder and the encoder.
    pub(crate) fn validate(
        &self,
        vault_id: &[u8; 16],
        epoch: u32,
        records: &[DeviceRecord],
    ) -> Result<()> {
        if self.keyring.len() != epoch as usize - 1
            || self
                .keyring
                .iter()
                .enumerate()
                .any(|(i, (e, _))| *e as usize != i + 1)
        {
            return integrity(K::Keyring);
        }
        if self.legacy.len() > LEGACY_MAX
            || self.legacy.windows(2).any(|w| w[0].0 >= w[1].0)
            || self.legacy.iter().any(|(v, ring)| {
                v == vault_id
                    || ring.is_empty()
                    || ring
                        .iter()
                        .enumerate()
                        .any(|(i, (e, _))| *e as usize != i + 1)
            })
        {
            return integrity(K::Legacy);
        }
        let total = self.keyring.len() + self.legacy.iter().map(|(_, r)| r.len()).sum::<usize>();
        if total > KEYRING_MAX {
            return integrity(K::Legacy);
        }
        if self.rotation.from_index_seq > COUNTER_CAP {
            return integrity(K::CounterCap);
        }
        let never_rotated = self.rotation.from_epoch == 0
            && self.rotation.from_index_seq == 0
            && self.rotation.from_index_sha256 == [0; 32];
        if !never_rotated && self.rotation.from_epoch.checked_add(1) != Some(epoch) {
            return integrity(K::Rotation);
        }
        if self.devices.len() != records.len()
            || self
                .devices
                .iter()
                .zip(records)
                .any(|(d, r)| d.device_id != r.device_id)
        {
            return integrity(K::DeviceInfoMismatch);
        }
        for (i, d) in self.devices.iter().enumerate() {
            if !(1..=4).contains(&d.kind) {
                return integrity(K::DeviceKind);
            }
            if !is_valid_label(&d.label) {
                return integrity(K::LabelRule);
            }
            if self.devices[..i].iter().any(|o| o.label == d.label) {
                return integrity(K::Duplicate);
            }
            if d.enrolled_header_seq > COUNTER_CAP {
                return integrity(K::CounterCap);
            }
        }
        self.ext.check(ExtCtx::Other)
    }

    pub(crate) fn encode(&self) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        let mut w = Writer::new();
        w.bytes(&self.writer).bytes(self.secret_key.expose());
        w.u32(self.rotation.from_epoch)
            .u64(self.rotation.from_index_seq)
            .bytes(&self.rotation.from_index_sha256);
        w.u32(self.keyring.len() as u32);
        for (e, k) in &self.keyring {
            w.u32(*e).bytes(k.expose());
        }
        encode_legacy(&mut w, &self.legacy);
        w.u16(self.devices.len() as u16);
        for d in &self.devices {
            w.bytes(&d.device_id).u8(d.kind);
            w.str16(d.label.as_bytes())?;
            w.u64(d.enrolled_header_seq)
                .i64(d.enrolled_unix)
                .bytes(&d.enrolled_by);
        }
        self.ext.encode(&mut w)?;
        Ok(w.into_secret())
    }
}

/// The password wrap fields of a header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordWrap {
    /// KDF parameters and salt.
    pub kdf: KdfParams,
    /// Whether the parameters are the test set.
    pub test_kdf: bool,
    /// Nonce.
    pub nonce: [u8; 24],
    /// Wrapped vault key and tag.
    pub ct: [u8; 48],
}

/// Everything needed to write a header. Rewrites start from [`HeaderDraft::from_verified`], so the
/// metadata extension list and the legacy lineages carry over exactly.
pub struct HeaderDraft {
    /// Format version to write; must equal [`FORMAT_VERSION`].
    pub format_version: u16,
    /// Vault ID.
    pub vault_id: [u8; 16],
    /// Header sequence number.
    pub header_seq: u64,
    /// Epoch of `vk`.
    pub epoch: u32,
    /// Writer device.
    pub writer_device_id: [u8; 16],
    /// Password wrap.
    pub password_wrap: PasswordWrap,
    /// Enrolled devices with their wraps.
    pub devices: Vec<HeaderDevice>,
    /// Rotation commitment.
    pub rotation: RotationCommitment,
    /// Metadata extension list.
    pub ext: ExtList,
    vk: VaultKey,
    secret_key: SecretKey,
    keyring: Vec<(u32, VaultKey)>,
    legacy: Vec<Lineage>,
}

impl HeaderDraft {
    /// A draft for a new vault at epoch 1 with no devices and no password wrap yet.
    pub fn new_vault(
        vault_id: [u8; 16],
        writer_device_id: [u8; 16],
        vk: VaultKey,
        secret_key: SecretKey,
    ) -> Self {
        HeaderDraft {
            format_version: FORMAT_VERSION,
            vault_id,
            header_seq: 1,
            epoch: 1,
            writer_device_id,
            password_wrap: PasswordWrap {
                kdf: KdfParams {
                    m_kib: 0,
                    t: 0,
                    p: 0,
                    salt: [0; 16],
                },
                test_kdf: false,
                nonce: [0; 24],
                ct: [0; 48],
            },
            devices: Vec::new(),
            rotation: RotationCommitment::default(),
            ext: ExtList::new(),
            vk,
            secret_key,
            keyring: Vec::new(),
            legacy: Vec::new(),
        }
    }

    /// A draft for rewriting a verified header: everything carries over, and `header_seq` is the
    /// next value. `parsed`, `info`, and `keys` must come from the same unlock.
    pub fn from_verified(
        parsed: &ParsedHeader,
        info: &HeaderInfo,
        keys: &VaultKeys,
    ) -> Result<Self> {
        if sha256(&[&parsed.raw]) != info.header_sha256
            || keys.vault_id != info.vault_id
            || keys.epoch != info.epoch
        {
            return input(InputKind::Keyring);
        }
        if info.header_seq >= COUNTER_CAP {
            return integrity(K::CounterCap);
        }
        Ok(HeaderDraft {
            format_version: info.format_version,
            vault_id: info.vault_id,
            header_seq: info.header_seq + 1,
            epoch: info.epoch,
            writer_device_id: info.writer_device_id,
            password_wrap: PasswordWrap {
                kdf: info.kdf,
                test_kdf: info.test_kdf,
                nonce: parsed.pw_nonce,
                ct: parsed.pw_ct,
            },
            devices: info.devices.clone(),
            rotation: info.rotation,
            ext: info.ext.clone(),
            vk: keys.vk.clone_secret(),
            secret_key: keys.secret_key.clone_secret(),
            keyring: keys
                .keyring
                .iter()
                .map(|(e, k)| (*e, k.clone_secret()))
                .collect(),
            legacy: keys
                .legacy
                .iter()
                .map(|(v, r)| (*v, r.iter().map(|(e, k)| (*e, k.clone_secret())).collect()))
                .collect(),
        })
    }

    /// Replace the password wrap with one under `auk`, which the caller derived from `kdf`. Draw
    /// order: nonce (24).
    pub(crate) fn set_password_wrap_with<R: TryCryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        auk: &Auk,
        kdf: KdfParams,
        test_kdf: bool,
    ) -> Result<()> {
        let nonce = draw(rng)?;
        let ct = seal_pw_wrap(
            auk,
            &self.vk,
            &self.vault_id,
            self.epoch,
            &kdf.to_block(),
            &nonce,
        );
        self.password_wrap = PasswordWrap {
            kdf,
            test_kdf,
            nonce,
            ct,
        };
        Ok(())
    }

    /// Set the password wrap from the master password and secret key, with a fresh salt.
    pub fn set_password(
        &mut self,
        password: &str,
        m_kib: u32,
        t: u32,
        p: u32,
        test_kdf: bool,
    ) -> Result<()> {
        let kdf = KdfParams {
            m_kib,
            t,
            p,
            salt: draw(&mut os())?,
        };
        let auk = derive_auk(password, &self.secret_key, &kdf, test_kdf, &self.vault_id)?;
        self.set_password_wrap_with(&mut os(), &auk, kdf, test_kdf)
    }

    /// Add a device, wrapping the draft's vault key to it.
    pub fn add_device(
        &mut self,
        info: DeviceInfo,
        device_pk: [u8; 32],
        kem_ek: &[u8],
    ) -> Result<()> {
        let record = crate::wrap::seal_device_wrap(
            &mut os(),
            &self.vk,
            &self.vault_id,
            self.epoch,
            &info.device_id,
            &device_pk,
            kem_ek,
        )?;
        self.devices.push(HeaderDevice { record, info });
        self.devices.sort_by_key(|d| d.record.device_id);
        Ok(())
    }

    /// Encode the header. Draw order: metadata nonce (24).
    pub(crate) fn encode_with<R: TryCryptoRng + ?Sized>(&self, rng: &mut R) -> Result<Vec<u8>> {
        if self.format_version != FORMAT_VERSION {
            return Err(Error::UnsupportedFormatVersion(self.format_version));
        }
        if self.header_seq > COUNTER_CAP {
            return integrity(K::CounterCap);
        }
        if !(1..=EPOCH_MAX).contains(&self.epoch) || self.devices.len() > DEVICES_MAX {
            return input(InputKind::Keyring);
        }
        self.password_wrap
            .kdf
            .check(self.password_wrap.test_kdf, TEST_KDF_ALLOWED)
            .map_err(|_| Error::InvalidInput(InputKind::KdfParams))?;
        let records: Vec<DeviceRecord> = self.devices.iter().map(|d| d.record.clone()).collect();
        if records.windows(2).any(|w| w[0].device_id >= w[1].device_id) {
            return input(InputKind::Order);
        }
        for r in &records {
            if r.kem_ek.len() != KEM_EK_LEN || r.kem_ct.len() != KEM_CT_LEN {
                return input(InputKind::Keyring);
            }
            check_kem_ek(&r.kem_ek).map_err(|_| Error::InvalidInput(InputKind::Keyring))?;
        }
        let meta = Meta {
            writer: self.writer_device_id,
            secret_key: self.secret_key.clone_secret(),
            rotation: self.rotation,
            keyring: self
                .keyring
                .iter()
                .map(|(e, k)| (*e, k.clone_secret()))
                .collect(),
            legacy: self
                .legacy
                .iter()
                .map(|(v, r)| (*v, r.iter().map(|(e, k)| (*e, k.clone_secret())).collect()))
                .collect(),
            legacy_sha256: [0; 32],
            devices: self.devices.iter().map(|d| d.info.clone()).collect(),
            ext: self.ext.clone(),
        };
        meta.validate(&self.vault_id, self.epoch, &records)?;
        let meta_plain = meta.encode()?;
        let meta_nonce: [u8; 24] = draw(rng)?;
        let mk = meta_key(&self.vk, &self.vault_id);
        let meta_ct = seal(
            mk.expose(),
            &meta_nonce,
            &meta_plain,
            &meta_ad(&self.vault_id, self.epoch),
        );

        let mut w = Writer::new();
        w.bytes(MAGIC).u16(self.format_version);
        w.u16(if self.password_wrap.test_kdf {
            FLAG_TEST_KDF
        } else {
            0
        });
        w.bytes(&self.vault_id).u64(self.header_seq).u32(self.epoch);
        w.bytes(&self.password_wrap.kdf.to_block())
            .bytes(&self.password_wrap.nonce)
            .bytes(&self.password_wrap.ct);
        w.u16(records.len() as u16);
        for r in &records {
            w.bytes(&r.device_id)
                .bytes(&r.device_pk)
                .bytes(&r.kem_ek)
                .bytes(&r.eph_pk);
            w.bytes(&r.kem_ct).bytes(&r.nonce).bytes(&r.ct);
        }
        w.bytes(&meta_nonce);
        w.bytes32(&meta_ct)?;
        let hmk = header_mac_key(&self.vk, &self.vault_id);
        let mac = hmac(hmk.expose(), w.as_slice());
        w.bytes(&mac);
        let out = w.into_vec();
        if out.len() > HEADER_MAX {
            return input(InputKind::TooLarge);
        }
        debug_assert_eq!(
            DEVICES_OFFSET + records.len() * DEVICE_RECORD_LEN + 24 + 4 + meta_ct.len() + 32,
            out.len()
        );
        Ok(out)
    }

    /// Encode the header with fresh randomness.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.encode_with(&mut os())
    }

    #[cfg(test)]
    pub(crate) fn from_parts(
        base: HeaderDraft,
        keyring: Vec<(u32, VaultKey)>,
        legacy: Vec<Lineage>,
    ) -> Self {
        HeaderDraft {
            keyring,
            legacy,
            ..base
        }
    }
}
