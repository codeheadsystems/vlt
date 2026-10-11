//! Mirror retention and history fill, from the spec's "Local mirror and write queue".
//!
//! Reachability starts at every live head, every tombstone head, and every queued object, and
//! follows parent links down to each record's history floor (with `mirror.history = heads`, only
//! the starting objects count). An object that stops being reachable is a candidate for a purge
//! check: the mirror deletes it at once only when the backend answers `404` for it, because only a
//! purge with admin credentials removes objects. Otherwise it is kept for 30 days after it became
//! unreachable, and objects displayed or published by this device in the last 30 days are kept
//! regardless, so a forged index cannot empty the mirrors that repair depends on.

use crate::error::{IntegrityKind as K, Result, integrity};
use crate::merge::MAX_WALK;
use crate::mirror_state::HistoryMode;
use crate::ops::Op;
use crate::vault::Vault;
use std::collections::{HashMap, HashSet};

/// How long an unreachable object stays in the mirror.
pub const KEEP_SECS: i64 = 30 * 86_400;

/// What the driver does to the mirror after [`Vault::refresh_retention`].
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RetentionPlan {
    /// Ask the backend whether each still exists; for those that are gone, call
    /// [`Vault::mark_purged`] and delete the mirror file, and for those that exist, call
    /// [`Vault::mark_present`]. An object left unanswered is listed again by the next refresh.
    pub check_gone: Vec<[u8; 16]>,
    /// Delete these mirror files; their bookkeeping is already dropped.
    pub delete: Vec<[u8; 16]>,
}

/// One history object to fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoryNeed {
    /// Object ID.
    pub object_id: [u8; 16],
    /// The SHA-256 its child records.
    pub sha256: [u8; 32],
    /// Its revision.
    pub revision: u64,
}

impl Vault {
    /// Starting objects of reachability, each with the history floor of its record.
    fn roots(&self) -> Vec<([u8; 16], u64)> {
        let mut roots: Vec<([u8; 16], u64)> = self
            .index
            .entries
            .iter()
            .map(|e| (e.head_object_id, e.ext.history_floor().unwrap_or(1)))
            .chain(
                self.index
                    .tombstones
                    .iter()
                    .map(|t| (t.head_object_id, t.ext.history_floor().unwrap_or(1))),
            )
            .collect();
        for op in &self.state.queue {
            if let Op::Put(p) = op {
                roots.push((p.object_id, 1));
            }
        }
        roots
    }

    fn reachable(&self) -> HashSet<[u8; 16]> {
        let mut out = HashSet::new();
        for (root, floor) in self.roots() {
            out.insert(root);
            if self.state.history == HistoryMode::Heads {
                continue;
            }
            let mut cur = root;
            for _ in 0..MAX_WALK {
                let Some(o) = self.state.object(&cur) else {
                    break;
                };
                if o.revision <= floor || o.parent == [0; 16] {
                    break;
                }
                cur = o.parent;
                out.insert(cur);
            }
        }
        out
    }

    /// Update reachability bookkeeping and plan what the mirror deletes. Unreachable objects are
    /// listed for a purge check until the backend has answered for them (through
    /// [`Vault::mark_purged`] or [`Vault::mark_present`]), so a check skipped or failed in one run
    /// is made in a later one. Objects this device wrote but never uploaded are never checked.
    /// Objects unreachable for 30 days, and not displayed or published by this device in that
    /// time, are dropped.
    pub fn refresh_retention(&mut self, now: i64) -> RetentionPlan {
        let reachable = self.reachable();
        let mut plan = RetentionPlan::default();
        let recent = |t: i64| t != 0 && now - t < KEEP_SECS;
        self.state.objects.retain_mut(|o| {
            if reachable.contains(&o.object_id) {
                o.unreachable_since = 0;
                o.gone_checked = false;
                return true;
            }
            if o.purged {
                return true;
            }
            if o.unreachable_since == 0 {
                o.unreachable_since = now;
            }
            let expired = now - o.unreachable_since >= KEEP_SECS;
            if expired && !recent(o.displayed_unix) && !recent(o.published_unix) {
                plan.delete.push(o.object_id);
                return false;
            }
            if !o.local_only && !o.gone_checked {
                plan.check_gone.push(o.object_id);
            }
            true
        });
        plan
    }

    /// Record an entry object found in the mirror's `e/` that the state does not know, such as the
    /// object of a write interrupted before its state was written. It is opened to check it and
    /// learn its parent, then kept as unreachable and local, so the 30-day rule removes it and no
    /// purge check is made for it. Returns whether it was recorded.
    pub fn record_stray(&mut self, object_id: &[u8; 16], bytes: &[u8], now: i64) -> Result<bool> {
        if self.state.object(object_id).is_some() {
            return Ok(false);
        }
        let sha = crate::prim::sha256(&[bytes]);
        let (_, plain) = self.open_object(object_id, &sha, bytes)?;
        let o = self.state.object_mut(
            object_id,
            plain.parent_object_id,
            plain.parent_sha256,
            plain.revision,
        );
        o.local_only = true;
        o.unreachable_since = now;
        Ok(true)
    }

    /// Record that the backend answered that an unreachable object still exists: it was not
    /// purged, and it is not checked again while it stays unreachable.
    pub fn mark_present(&mut self, object_id: &[u8; 16]) {
        if let Ok(i) = self
            .state
            .objects
            .binary_search_by(|o| o.object_id.cmp(object_id))
        {
            self.state.objects[i].gone_checked = true;
        }
    }

    /// Record that the backend answered `404` for an object: it was purged. The bookkeeping stays
    /// so the object is not fetched again; the driver deletes the mirror file.
    pub fn mark_purged(&mut self, object_id: &[u8; 16]) {
        if let Ok(i) = self
            .state
            .objects
            .binary_search_by(|o| o.object_id.cmp(object_id))
        {
            self.state.objects[i].purged = true;
        }
    }

    /// History objects that a `full` mirror lacks: for each chain from a live head or tombstone
    /// head, the first missing parent above the record's floor. Call again after feeding each
    /// batch to [`Vault::add_history`]; an empty list means the mirror is complete.
    pub fn history_missing(&self, limit: usize) -> Vec<HistoryNeed> {
        if self.state.history == HistoryMode::Heads {
            return Vec::new();
        }
        let mut out: HashMap<[u8; 16], HistoryNeed> = HashMap::new();
        for (root, floor) in self.roots() {
            let mut cur = root;
            for _ in 0..MAX_WALK {
                let Some(o) = self.state.object(&cur) else {
                    break;
                };
                if o.purged || o.revision <= floor || o.parent == [0; 16] {
                    break;
                }
                match self.state.object(&o.parent) {
                    Some(_) => cur = o.parent,
                    None => {
                        out.insert(
                            o.parent,
                            HistoryNeed {
                                object_id: o.parent,
                                sha256: o.parent_sha256,
                                revision: o.revision - 1,
                            },
                        );
                        break;
                    }
                }
            }
            if out.len() >= limit {
                break;
            }
        }
        let mut v: Vec<HistoryNeed> = out.into_values().collect();
        v.sort_by_key(|n| n.object_id);
        v.truncate(limit);
        v
    }

    /// Verify and record a fetched history object. `bytes` `None` means the backend answered
    /// `404`: the object was purged and is not requested again.
    pub fn add_history(&mut self, need: &HistoryNeed, bytes: Option<&[u8]>) -> Result<()> {
        let Some(bytes) = bytes else {
            self.state
                .object_mut(&need.object_id, [0; 16], [0; 32], need.revision)
                .purged = true;
            return Ok(());
        };
        let (_, plain) = self.open_object(&need.object_id, &need.sha256, bytes)?;
        if plain.revision != need.revision {
            return integrity(K::ParentRule);
        }
        self.state.object_mut(
            &need.object_id,
            plain.parent_object_id,
            plain.parent_sha256,
            plain.revision,
        );
        Ok(())
    }
}
