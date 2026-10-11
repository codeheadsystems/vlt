//! Extension lists and the two extension types format version 1 defines.

use crate::codec::{Reader, Writer};
use crate::error::{IntegrityKind as K, Result, integrity};
use crate::limits::{COUNTER_CAP, EXT_MAX};
use crate::path::is_valid_path;

/// Type bit 15: an unknown item with it set makes the structure unreadable.
pub const CRITICAL: u16 = 0x8000;
/// Type bit 14: an unknown item with it set survives a change to its record.
pub const COPY_SAFE: u16 = 0x4000;
/// Conflict-of: marks an index entry as a conflict copy and names its original path.
pub const CONFLICT_OF: u16 = 0x4001;
/// History floor: the oldest revision kept after a purge.
pub const HISTORY_FLOOR: u16 = 0x4002;

/// One extension item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtItem {
    /// The type, including its rule bits.
    pub ty: u16,
    /// The value, opaque for unknown types.
    pub value: Vec<u8>,
}

/// An extension list: at most 64 items, sorted by type, no duplicates.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExtList {
    /// The items, in ascending type order.
    pub items: Vec<ExtItem>,
}

/// Where an extension list sits, which decides the types known in it and how they are checked.
#[derive(Clone, Copy)]
pub(crate) enum ExtCtx<'a> {
    /// An index entry with its own path and revision.
    IndexEntry { path: &'a str, revision: u64 },
    /// An index tombstone with its own revision.
    Tombstone { revision: u64 },
    /// Any other structure; no types are known.
    Other,
}

impl ExtList {
    /// An empty list.
    pub fn new() -> Self {
        ExtList::default()
    }

    /// The conflict-of path, if present.
    pub fn conflict_of(&self) -> Option<&str> {
        self.get(CONFLICT_OF)
            .and_then(|v| core::str::from_utf8(v).ok())
    }

    /// The history floor, if present.
    pub fn history_floor(&self) -> Option<u64> {
        self.get(HISTORY_FLOOR)
            .and_then(|v| <[u8; 8]>::try_from(v).ok())
            .map(u64::from_be_bytes)
    }

    fn get(&self, ty: u16) -> Option<&[u8]> {
        self.items
            .iter()
            .find(|i| i.ty == ty)
            .map(|i| i.value.as_slice())
    }

    /// Set or replace an item, keeping the list sorted.
    pub fn set(&mut self, ty: u16, value: Vec<u8>) {
        match self.items.binary_search_by_key(&ty, |i| i.ty) {
            Ok(i) => self.items[i].value = value,
            Err(i) => self.items.insert(i, ExtItem { ty, value }),
        }
    }

    /// Remove an item.
    pub fn remove(&mut self, ty: u16) {
        self.items.retain(|i| i.ty != ty);
    }

    /// The list a writer keeps when it changes the record: known types and unknown copy-safe
    /// items stay; unknown items without the copy-safe bit are dropped.
    pub fn for_changed_record(&self) -> ExtList {
        let items = self
            .items
            .iter()
            .filter(|i| matches!(i.ty, CONFLICT_OF | HISTORY_FLOOR) || i.ty & COPY_SAFE != 0)
            .cloned()
            .collect();
        ExtList { items }
    }

    pub(crate) fn decode(r: &mut Reader<'_>, ctx: ExtCtx<'_>) -> Result<ExtList> {
        let count = r.u16()? as usize;
        if count > EXT_MAX {
            return integrity(K::ExtCount);
        }
        let mut items: Vec<ExtItem> = Vec::with_capacity(count);
        for _ in 0..count {
            let ty = r.u16()?;
            let value = r.bytes32(crate::limits::INDEX_MAX)?.to_vec();
            if let Some(prev) = items.last()
                && prev.ty >= ty
            {
                return integrity(if prev.ty == ty {
                    K::Duplicate
                } else {
                    K::Order
                });
            }
            items.push(ExtItem { ty, value });
        }
        let list = ExtList { items };
        list.check(ctx)?;
        Ok(list)
    }

    /// Check the list against its context: no unknown critical items, and valid values for the
    /// known types.
    pub(crate) fn check(&self, ctx: ExtCtx<'_>) -> Result<()> {
        if self.items.len() > EXT_MAX {
            return integrity(K::ExtCount);
        }
        if self.items.windows(2).any(|w| w[0].ty >= w[1].ty) {
            return integrity(K::Order);
        }
        for item in &self.items {
            let known = match (ctx, item.ty) {
                (ExtCtx::IndexEntry { path, .. }, CONFLICT_OF) => {
                    let ok = core::str::from_utf8(&item.value)
                        .is_ok_and(|v| is_valid_path(v) && v != path);
                    if !ok {
                        return integrity(K::ExtValue);
                    }
                    true
                }
                (ExtCtx::Tombstone { .. }, CONFLICT_OF) => return integrity(K::ExtValue),
                (
                    ExtCtx::IndexEntry { revision, .. } | ExtCtx::Tombstone { revision },
                    HISTORY_FLOOR,
                ) => {
                    let Ok(b) = <[u8; 8]>::try_from(item.value.as_slice()) else {
                        return integrity(K::ExtValue);
                    };
                    let floor = u64::from_be_bytes(b);
                    if floor <= 1 || floor > revision || floor > COUNTER_CAP {
                        return integrity(K::ExtValue);
                    }
                    true
                }
                _ => false,
            };
            if !known && item.ty & CRITICAL != 0 {
                return integrity(K::ExtCritical);
            }
        }
        Ok(())
    }

    pub(crate) fn encode(&self, w: &mut Writer) -> Result<()> {
        if self.items.len() > EXT_MAX {
            return Err(crate::error::Error::InvalidInput(
                crate::error::InputKind::Ext,
            ));
        }
        w.u16(self.items.len() as u16);
        for i in &self.items {
            w.u16(i.ty);
            w.bytes32(&i.value)?;
        }
        Ok(())
    }
}
