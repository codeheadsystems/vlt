//! Vault key subkeys, fingerprints, and device key generation.

use crate::error::Result;
use crate::prim::hkdf32;
use crate::rng::{draw, os};
use crate::secret::{
    DeviceSecrets, EntryKey, HeaderMacKey, IndexKey, MetaKey, MirrorKey, VaultKey,
};
use ml_kem::kem::KeyExport;
use ml_kem::{DecapsulationKey, MlKem768};
use rand_core::TryCryptoRng;
use x25519_dalek::{PublicKey, StaticSecret};

fn sub(vk: &VaultKey, vault_id: &[u8; 16], purpose: &str) -> zeroize::Zeroizing<[u8; 32]> {
    let mut info = Vec::with_capacity(7 + purpose.len());
    info.extend_from_slice(b"vlt/v1/");
    info.extend_from_slice(purpose.as_bytes());
    hkdf32(vk.expose(), vault_id, &info)
}

pub(crate) fn header_mac_key(vk: &VaultKey, vault_id: &[u8; 16]) -> HeaderMacKey {
    HeaderMacKey::from_zeroizing(sub(vk, vault_id, "header-mac"))
}
pub(crate) fn meta_key(vk: &VaultKey, vault_id: &[u8; 16]) -> MetaKey {
    MetaKey::from_zeroizing(sub(vk, vault_id, "meta"))
}
pub(crate) fn index_key(vk: &VaultKey, vault_id: &[u8; 16]) -> IndexKey {
    IndexKey::from_zeroizing(sub(vk, vault_id, "index"))
}
pub(crate) fn entry_key(vk: &VaultKey, vault_id: &[u8; 16]) -> EntryKey {
    EntryKey::from_zeroizing(sub(vk, vault_id, "entry"))
}
pub(crate) fn mirror_key(vk: &VaultKey, vault_id: &[u8; 16]) -> MirrorKey {
    MirrorKey::from_zeroizing(sub(vk, vault_id, "mirror"))
}

/// The public-safe fingerprint of a vault key, stored in pins.
pub fn fingerprint(vk: &VaultKey, vault_id: &[u8; 16]) -> [u8; 32] {
    *sub(vk, vault_id, "fingerprint")
}

/// A device's public keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevicePublic {
    /// X25519 public key.
    pub device_pk: [u8; 32],
    /// ML-KEM-768 encapsulation key, 1,184 bytes.
    pub kem_ek: Vec<u8>,
}

/// The public keys of a device's private keys.
pub fn device_public(secrets: &DeviceSecrets) -> DevicePublic {
    let pk = PublicKey::from(&StaticSecret::from(secrets.x25519_sk));
    let dk = DecapsulationKey::<MlKem768>::from_seed(secrets.kem_seed.into());
    DevicePublic {
        device_pk: *pk.as_bytes(),
        kem_ek: dk.encapsulation_key().to_bytes().to_vec(),
    }
}

/// Draw order: X25519 private key (32 bytes), then the ML-KEM seed (64 bytes).
pub(crate) fn generate_device_keys_with<R: TryCryptoRng + ?Sized>(
    rng: &mut R,
) -> Result<(DeviceSecrets, DevicePublic)> {
    let s = DeviceSecrets::from_bytes(draw(rng)?, draw(rng)?);
    let p = device_public(&s);
    Ok((s, p))
}

/// Generate a device's X25519 and ML-KEM-768 key pairs from the OS generator.
pub fn generate_device_keys() -> Result<(DeviceSecrets, DevicePublic)> {
    generate_device_keys_with(&mut os())
}

/// Generate a fresh vault key from the OS generator.
pub fn generate_vault_key() -> Result<VaultKey> {
    Ok(VaultKey::from_bytes(draw(&mut os())?))
}

/// Generate a fresh secret key from the OS generator.
pub fn generate_secret_key() -> Result<crate::secret::SecretKey> {
    Ok(crate::secret::SecretKey::from_bytes(draw(&mut os())?))
}

/// Generate a fresh invite secret from the OS generator.
pub fn generate_invite_secret() -> Result<crate::secret::InviteSecret> {
    Ok(crate::secret::InviteSecret::from_bytes(draw(&mut os())?))
}

/// Generate 16 random bytes for a vault, device, or object ID.
pub fn generate_id() -> Result<[u8; 16]> {
    draw(&mut os())
}
