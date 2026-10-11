//! Secret types. Each holds its bytes in a zeroizing buffer and implements neither `Debug` nor
//! `Display`, so a secret cannot reach a log or panic message through formatting.
//!
//! ```compile_fail
//! let k = vlt_core::VaultKey::from_bytes([0u8; 32]);
//! let _ = format!("{:?}", k);
//! ```
//!
//! ```compile_fail
//! let k = vlt_core::SecretKey::from_bytes([0u8; 16]);
//! let _ = format!("{}", k);
//! ```
//!
//! ```compile_fail
//! let k = vlt_core::Auk::from_bytes([0u8; 32]);
//! let _ = format!("{:?}", k);
//! ```
//!
//! ```compile_fail
//! let k = vlt_core::DeviceSecrets::from_bytes([0u8; 32], [0u8; 64]);
//! let _ = format!("{:?}", k);
//! ```
//!
//! ```compile_fail
//! let k = vlt_core::secret::InviteSecret::from_bytes([0u8; 32]);
//! let _ = format!("{:?}", k);
//! ```
//!
//! ```compile_fail
//! let k = vlt_core::secret::EntryKey::from_bytes([0u8; 32]);
//! let _ = format!("{:?}", k);
//! ```
//!
//! ```compile_fail
//! let k = vlt_core::secret::IndexKey::from_bytes([0u8; 32]);
//! let _ = format!("{:?}", k);
//! ```
//!
//! ```compile_fail
//! let k = vlt_core::secret::HeaderMacKey::from_bytes([0u8; 32]);
//! let _ = format!("{:?}", k);
//! ```
//!
//! ```compile_fail
//! let k = vlt_core::secret::MetaKey::from_bytes([0u8; 32]);
//! let _ = format!("{:?}", k);
//! ```
//!
//! ```compile_fail
//! let k = vlt_core::secret::MirrorKey::from_bytes([0u8; 32]);
//! let _ = format!("{:?}", k);
//! ```
//!
//! ```compile_fail
//! let k = vlt_core::secret::LocalWrapKey::from_bytes([0u8; 32]);
//! let _ = format!("{:?}", k);
//! ```
//!
//! ```compile_fail
//! let k = vlt_core::secret::ExportKey::from_bytes([0u8; 32]);
//! let _ = format!("{:?}", k);
//! ```
//!
//! ```compile_fail
//! let k = vlt_core::secret::InviteKey::from_bytes([0u8; 32]);
//! let _ = format!("{:?}", k);
//! ```
//!
//! ```compile_fail
//! let k = vlt_core::VaultKey::from_bytes([0u8; 32]);
//! let _ = format!("{}", k);
//! ```
//!
//! Types that hold secrets alongside other data have no `Debug` either:
//!
//! ```compile_fail
//! fn show(k: &vlt_core::VaultKeys) -> String { format!("{:?}", k) }
//! ```
//!
//! ```compile_fail
//! fn show(b: &vlt_core::device::Bundle) -> String { format!("{:?}", b) }
//! ```
//!
//! ```compile_fail
//! fn show(i: &vlt_core::enroll::Invite) -> String { format!("{:?}", i) }
//! ```
//!
//! ```compile_fail
//! fn show(d: &vlt_core::header::HeaderDraft) -> String { format!("{:?}", d) }
//! ```

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

macro_rules! secret_array {
    ($(#[$m:meta])* $name:ident, $n:expr) => {
        $(#[$m])*
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct $name([u8; $n]);

        impl $name {
            /// Wrap raw key bytes.
            pub fn from_bytes(b: [u8; $n]) -> Self {
                $name(b)
            }

            /// Take key bytes from a zeroizing buffer without an unzeroized copy.
            #[allow(dead_code)]
            pub(crate) fn from_zeroizing(z: Zeroizing<[u8; $n]>) -> Self {
                let mut s = $name([0u8; $n]);
                s.0.copy_from_slice(z.as_ref());
                s
            }

            #[allow(dead_code)]
            pub(crate) fn expose(&self) -> &[u8; $n] {
                &self.0
            }

            #[allow(dead_code)]
            pub(crate) fn clone_secret(&self) -> Self {
                $name(self.0)
            }
        }
    };
}

secret_array!(
    /// A vault key (VK) of one epoch.
    VaultKey, 32
);
secret_array!(
    /// The 16-byte secret key from the emergency kit.
    SecretKey, 16
);
secret_array!(
    /// The account unlock key, from the master password and the secret key.
    Auk, 32
);
secret_array!(
    /// The secret that an invite carries for its enrollment request.
    InviteSecret, 32
);

macro_rules! subkey {
    ($(#[$m:meta])* $name:ident) => {
        secret_array!($(#[$m])* $name, 32);
    };
}

subkey!(
    /// `K_header_mac`.
    HeaderMacKey
);
subkey!(
    /// `K_meta`.
    MetaKey
);
subkey!(
    /// `K_index`.
    IndexKey
);
subkey!(
    /// `K_entry`.
    EntryKey
);
subkey!(
    /// `K_mirror`.
    MirrorKey
);
subkey!(
    /// `K_invite`.
    InviteKey
);
subkey!(
    /// `LK`, the device file key.
    LocalWrapKey
);
subkey!(
    /// `XK`, the encrypted export key.
    ExportKey
);

/// A device's private keys: the X25519 private key and the 64-byte ML-KEM-768 seed `d || z`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DeviceSecrets {
    pub(crate) x25519_sk: [u8; 32],
    pub(crate) kem_seed: [u8; 64],
}

impl DeviceSecrets {
    /// Read private key bytes straight into a new value, so no unzeroized copy is left behind.
    pub(crate) fn from_slices(x25519_sk: &[u8], kem_seed: &[u8]) -> Self {
        let mut s = DeviceSecrets {
            x25519_sk: [0; 32],
            kem_seed: [0; 64],
        };
        s.x25519_sk.copy_from_slice(x25519_sk);
        s.kem_seed.copy_from_slice(kem_seed);
        s
    }

    /// Wrap raw private key bytes.
    pub fn from_bytes(x25519_sk: [u8; 32], kem_seed: [u8; 64]) -> Self {
        DeviceSecrets {
            x25519_sk,
            kem_seed,
        }
    }
}

/// A secret string, such as an S3 secret access key or a master password.
pub type SecretString = Zeroizing<String>;

/// Secret bytes, such as decrypted entry content.
pub type SecretBytes = Zeroizing<Vec<u8>>;
