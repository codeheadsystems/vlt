//! Size limits and caps from the spec's Size limits table and Conventions.

/// The highest value of any counter (`header_seq`, `index_seq`, `op_seq`, `revision`,
/// `removed_index_seq`, and the history floor).
pub const COUNTER_CAP: u64 = 1 << 48;
/// Header object, bytes.
pub const HEADER_MAX: usize = 128 * 1024;
/// Header `device_count`.
pub const DEVICES_MAX: usize = 32;
/// Keyring entries across the current keyring and every legacy lineage.
pub const KEYRING_MAX: usize = 1000;
/// Legacy lineages in one header.
pub const LEGACY_MAX: usize = 16;
/// The highest epoch a header can carry, given the keyring limit.
pub const EPOCH_MAX: u32 = KEYRING_MAX as u32 + 1;
/// Index object, bytes.
pub const INDEX_MAX: usize = 16 * 1024 * 1024;
/// Entry content, bytes.
pub const CONTENT_MAX: usize = 1024 * 1024;
/// Entry object, bytes.
pub const ENTRY_OBJECT_MAX: usize = CONTENT_MAX + 4 * 1024;
/// Path, bytes.
pub const PATH_MAX: usize = 1024;
/// Device label, characters.
pub const LABEL_MAX: usize = 32;
/// Extension list items.
pub const EXT_MAX: usize = 64;
/// Invite and enrollment request object, bytes.
pub const INVITE_MAX: usize = 4 * 1024;
/// Entry objects are padded to multiples of this.
pub const ENTRY_BLOCK: usize = 512;
/// Index objects are padded to multiples of this.
pub const INDEX_BLOCK: usize = 4096;
/// AEAD tag length.
pub const TAG_LEN: usize = 16;
