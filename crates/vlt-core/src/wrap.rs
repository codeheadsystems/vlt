//! The password wrap and the hybrid X25519 plus ML-KEM-768 device wrap.

use crate::error::{Error, IntegrityKind as K, Result, integrity};
use crate::kdf::KDF_BLOCK_LEN;
use crate::prim::{hkdf32, open, seal, sha256};
use crate::rng::draw;
use crate::secret::{Auk, DeviceSecrets, VaultKey};
use ml_kem::kem::Decapsulate;
use ml_kem::{DecapsulationKey, EncapsulationKey, MlKem768};
use rand_core::TryCryptoRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// ML-KEM-768 encapsulation key length.
pub const KEM_EK_LEN: usize = 1184;
/// ML-KEM-768 ciphertext length.
pub const KEM_CT_LEN: usize = 1088;
/// Length of one device record in the header.
pub const DEVICE_RECORD_LEN: usize = 16 + 32 + KEM_EK_LEN + 32 + KEM_CT_LEN + 24 + 48;

/// One device record: a device's public keys and its wrap of the current vault key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRecord {
    /// Device ID.
    pub device_id: [u8; 16],
    /// X25519 public key.
    pub device_pk: [u8; 32],
    /// ML-KEM-768 encapsulation key.
    pub kem_ek: Vec<u8>,
    /// Ephemeral X25519 public key.
    pub eph_pk: [u8; 32],
    /// ML-KEM-768 ciphertext.
    pub kem_ct: Vec<u8>,
    /// AEAD nonce.
    pub nonce: [u8; 24],
    /// Wrapped vault key and tag.
    pub ct: [u8; 48],
}

/// Check an ML-KEM-768 encapsulation key with the FIPS 203 encapsulation-key check.
pub(crate) fn check_kem_ek(kem_ek: &[u8]) -> Result<EncapsulationKey<MlKem768>> {
    let arr = kem_ek.try_into().or(integrity(K::KemEk))?;
    EncapsulationKey::<MlKem768>::new(arr).or(integrity(K::KemEk))
}

fn pw_wrap_ad(vault_id: &[u8; 16], epoch: u32, kdf_block: &[u8; KDF_BLOCK_LEN]) -> Vec<u8> {
    [
        b"vlt/v1/pw-wrap".as_slice(),
        vault_id,
        &epoch.to_be_bytes(),
        kdf_block,
    ]
    .concat()
}

pub(crate) fn seal_pw_wrap(
    auk: &Auk,
    vk: &VaultKey,
    vault_id: &[u8; 16],
    epoch: u32,
    kdf_block: &[u8; KDF_BLOCK_LEN],
    nonce: &[u8; 24],
) -> [u8; 48] {
    let ct = seal(
        auk.expose(),
        nonce,
        vk.expose(),
        &pw_wrap_ad(vault_id, epoch, kdf_block),
    );
    ct.try_into().expect("32-byte key plus 16-byte tag")
}

pub(crate) fn open_pw_wrap(
    auk: &Auk,
    vault_id: &[u8; 16],
    epoch: u32,
    kdf_block: &[u8; KDF_BLOCK_LEN],
    nonce: &[u8; 24],
    ct: &[u8; 48],
) -> Result<VaultKey> {
    let pt = open(
        auk.expose(),
        nonce,
        ct,
        &pw_wrap_ad(vault_id, epoch, kdf_block),
    )
    .map_err(|_| Error::WrongPasswordOrUnknownDevice)?;
    Ok(VaultKey::from_bytes(
        pt.as_slice().try_into().expect("32 bytes"),
    ))
}

fn device_wrap_ad(vault_id: &[u8; 16], epoch: u32, device_id: &[u8; 16]) -> Vec<u8> {
    [
        b"vlt/v1/device-wrap".as_slice(),
        vault_id,
        &epoch.to_be_bytes(),
        device_id,
    ]
    .concat()
}

fn dwk(
    ss_m: &[u8],
    ss_x: &[u8; 32],
    eph_pk: &[u8; 32],
    device_pk: &[u8; 32],
    kem_ek: &[u8],
    kem_ct: &[u8],
) -> Zeroizing<[u8; 32]> {
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(ss_m);
    ikm[32..].copy_from_slice(ss_x);
    let salt = [
        eph_pk.as_slice(),
        device_pk,
        &sha256(&[kem_ek]),
        &sha256(&[kem_ct]),
    ]
    .concat();
    hkdf32(ikm.as_ref(), &salt, b"vlt/v1/device-wrap")
}

/// Wrap `vk` to a device. Draw order: ephemeral X25519 private key (32), ML-KEM message (32),
/// nonce (24).
pub(crate) fn seal_device_wrap<R: TryCryptoRng + ?Sized>(
    rng: &mut R,
    vk: &VaultKey,
    vault_id: &[u8; 16],
    epoch: u32,
    device_id: &[u8; 16],
    device_pk: &[u8; 32],
    kem_ek: &[u8],
) -> Result<DeviceRecord> {
    let ek = check_kem_ek(kem_ek)?;
    let eph_sk = StaticSecret::from(draw::<32, _>(rng)?);
    let kem_m = Zeroizing::new(draw::<32, _>(rng)?);
    let nonce = draw::<24, _>(rng)?;
    let eph_pk = PublicKey::from(&eph_sk);
    let ss_x = eph_sk.diffie_hellman(&PublicKey::from(*device_pk));
    if !ss_x.was_contributory() {
        return integrity(K::LowOrderPoint);
    }
    let (kem_ct, ss_m) = ek.encapsulate_deterministic(&(*kem_m).into());
    let ss_m = Zeroizing::new(ss_m);
    let key = dwk(
        ss_m.as_slice(),
        ss_x.as_bytes(),
        eph_pk.as_bytes(),
        device_pk,
        kem_ek,
        kem_ct.as_slice(),
    );
    let ct = seal(
        &key,
        &nonce,
        vk.expose(),
        &device_wrap_ad(vault_id, epoch, device_id),
    );
    Ok(DeviceRecord {
        device_id: *device_id,
        device_pk: *device_pk,
        kem_ek: kem_ek.to_vec(),
        eph_pk: *eph_pk.as_bytes(),
        kem_ct: kem_ct.to_vec(),
        nonce,
        ct: ct.try_into().expect("48 bytes"),
    })
}

/// Open a device wrap with the device's private keys.
pub(crate) fn open_device_wrap(
    rec: &DeviceRecord,
    vault_id: &[u8; 16],
    epoch: u32,
    secrets: &DeviceSecrets,
) -> Result<VaultKey> {
    let sk = StaticSecret::from(secrets.x25519_sk);
    let ss_x = sk.diffie_hellman(&PublicKey::from(rec.eph_pk));
    if !ss_x.was_contributory() {
        return Err(Error::WrongPasswordOrUnknownDevice);
    }
    let dk = DecapsulationKey::<MlKem768>::from_seed(secrets.kem_seed.into());
    let ct = rec
        .kem_ct
        .as_slice()
        .try_into()
        .map_err(|_| Error::WrongPasswordOrUnknownDevice)?;
    let ss_m = Zeroizing::new(dk.decapsulate(ct));
    let key = dwk(
        ss_m.as_slice(),
        ss_x.as_bytes(),
        &rec.eph_pk,
        &rec.device_pk,
        &rec.kem_ek,
        &rec.kem_ct,
    );
    let pt = open(
        &key,
        &rec.nonce,
        &rec.ct,
        &device_wrap_ad(vault_id, epoch, &rec.device_id),
    )
    .map_err(|_| Error::WrongPasswordOrUnknownDevice)?;
    Ok(VaultKey::from_bytes(
        pt.as_slice().try_into().expect("32 bytes"),
    ))
}
