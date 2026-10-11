//! An unlocked vault: the accepted header and index, the keys, and the mirror state, with the
//! operations that read and queue changes. It does no I/O. The caller reads the mirror files and
//! hands their bytes in, and writes back what [`Vault::commit`] and the sync session return, in the
//! order the spec's "Local mirror and write queue" gives: entry objects, `header`, `index`, then
//! `state`.

use crate::entry::{EntryPlain, EntryPrefix, open_entry, seal_entry};
use crate::error::{Error, InputKind, IntegrityKind as K, Result, input, integrity};
use crate::ext::ExtList;
use crate::header::{HeaderInfo, VaultKeys, parse_header};
use crate::index::{IndexEntry, IndexPlain, IndexPrefix, index_prefix, open_index, seal_index};
use crate::keys::generate_id;
use crate::merge::{ChainView, Lookup, NoChain, ReplayCtx, ReplayOutcome, replay};
use crate::mirror_state::{HistoryMode, MirrorState, open_state, seal_state};
use crate::notice::ObjectKind;
use crate::ops::{MoveOp, Op, PutOp, RemoveOp, take_op_seq};
use crate::path::is_valid_path;
use crate::pins::{
    HeaderPin, IndexPin, IndexVerdict, check_header, check_index, check_index_writer,
};
use crate::prim::sha256;
use crate::secret::DeviceSecrets;
use zeroize::Zeroizing;

/// An unlocked vault.
pub struct Vault {
    pub(crate) device_id: [u8; 16],
    pub(crate) header_bytes: Vec<u8>,
    pub(crate) info: HeaderInfo,
    pub(crate) keys: VaultKeys,
    pub(crate) index_bytes: Vec<u8>,
    pub(crate) index_prefix: IndexPrefix,
    pub(crate) index: IndexPlain,
    pub(crate) state: MirrorState,
}

/// What [`Vault::put`] queued: the new entry object, which the caller writes to the mirror's
/// `e/<object_id hex>` before it writes the state from [`Vault::commit`].
pub struct Queued {
    /// The new object's ID.
    pub object_id: [u8; 16],
    /// The sealed object.
    pub object: Vec<u8>,
    /// The new revision number.
    pub revision: u64,
}

/// The device's labels, from the header, for conflict paths.
pub(crate) fn labels(info: &HeaderInfo) -> Vec<([u8; 16], String)> {
    info.devices
        .iter()
        .map(|d| (d.info.device_id, d.info.label.clone()))
        .collect()
}

/// A chain view over the mirror's bookkeeping, for the local view: anything the mirror lacks is
/// unavailable.
struct MirrorChain<'a>(&'a MirrorState);

impl ChainView for MirrorChain<'_> {
    fn lookup(&self, id: &[u8; 16]) -> Lookup {
        match self.0.object(id) {
            Some(o) if !o.purged => Lookup::Known {
                parent: o.parent,
                revision: o.revision,
            },
            _ => Lookup::Unavailable,
        }
    }
}

impl Vault {
    /// Create the first state of a new vault on the device that ran `vlt init`: the header is
    /// accepted as is, and an empty index at `index_seq` 1 is built. Both are recorded as this
    /// device's own before they are written. Returns the vault and the index bytes; the caller
    /// writes the header and the index (through the capability probe), records their etags with
    /// [`Vault::set_etags`], and writes the mirror.
    pub fn create(
        device_id: [u8; 16],
        secrets: &DeviceSecrets,
        header: &[u8],
        history: HistoryMode,
        now: i64,
    ) -> Result<(Vault, Vec<u8>)> {
        let parsed = parse_header(header)?;
        let (info, keys) = parsed.unlock_with_device(&device_id, secrets)?;
        let plain = IndexPlain {
            writer_device_id: device_id,
            ..IndexPlain::default()
        };
        let index_bytes = seal_index(&keys, 1, info.header_seq, &plain)?;
        let prefix = index_prefix(&index_bytes)?;
        let index_sha = sha256(&[&index_bytes]);
        let mut state = MirrorState::new(device_id, HeaderPin::from_header(&info), history);
        state.own.headers_from = info.header_seq;
        state.own.indexes_from = 1;
        state
            .own
            .record(ObjectKind::Header, info.header_seq, info.header_sha256, now);
        state.own.record(ObjectKind::Index, 1, index_sha, now);
        state.index_pin = Some(IndexPin::from_index(&prefix, index_sha));
        Ok((
            Vault {
                device_id,
                header_bytes: header.to_vec(),
                info,
                keys,
                index_bytes: index_bytes.clone(),
                index_prefix: prefix,
                index: plain,
                state,
            },
            index_bytes,
        ))
    }

    /// Build a new mirror for this device from the bucket's header and index, after enrollment.
    /// `pin` is the pin from an invite; `None` on the kit path, where the password wrap is the
    /// trust anchor and the caller has checked the header against the kit's `vault_id`. The
    /// index pins start from this index. Head objects are fetched by the first sync.
    #[allow(clippy::too_many_arguments)]
    pub fn join(
        device_id: [u8; 16],
        secrets: &DeviceSecrets,
        header: &[u8],
        header_etag: Option<String>,
        pin: Option<&HeaderPin>,
        index: &[u8],
        index_etag: Option<String>,
        history: HistoryMode,
    ) -> Result<Vault> {
        let parsed = parse_header(header)?;
        let (info, keys) = parsed.unlock_with_device(&device_id, secrets)?;
        let own = crate::pins::OwnRecords::default();
        if let Some(pin) = pin {
            check_header(pin, &info, &keys, &own, &device_id)?;
        }
        let mut state = MirrorState::new(device_id, HeaderPin::from_header(&info), history);
        let prefix = index_prefix(index)?;
        let sha = sha256(&[index]);
        if check_index(None, &info, &prefix, &sha)? != IndexVerdict::Accept {
            return integrity(K::IndexEpoch);
        }
        let (prefix, plain) = open_index(&keys, index)?;
        state.index_pin = Some(IndexPin::from_index(&prefix, sha));
        state.own.indexes_from = prefix.index_seq.saturating_add(1);
        let applied = plain
            .applied
            .iter()
            .find(|a| a.device_id == device_id)
            .map_or(0, |a| a.last_op_seq);
        crate::ops::raise_op_seq(
            &mut state.next_op_seq,
            &mut [],
            applied,
            plain.writer_device_id,
        )?;
        state.header_etag = header_etag;
        state.index_etag = index_etag;
        Ok(Vault {
            device_id,
            header_bytes: header.to_vec(),
            info,
            keys,
            index_bytes: index.to_vec(),
            index_prefix: prefix,
            index: plain,
            state,
        })
    }

    /// Open a vault from its mirror files. A `header` or `index` file whose SHA-256 differs from
    /// the pins in `state` is the remnant of an interrupted write: it is checked against the pins
    /// as a newly fetched object and accepted only if it passes.
    pub fn open(
        device_id: [u8; 16],
        secrets: &DeviceSecrets,
        header: &[u8],
        index: &[u8],
        state: &[u8],
    ) -> Result<Vault> {
        let parsed = parse_header(header)?;
        let (info, keys) = parsed.unlock_with_device(&device_id, secrets)?;
        let (mut state, _sealed_epoch) = open_state(&keys, state)?;
        if state.device_id != device_id {
            return integrity(K::MirrorMismatch);
        }
        if info.header_sha256 != state.header_pin.header_sha256 {
            let notices = check_header(&state.header_pin, &info, &keys, &state.own, &device_id)?;
            for n in notices {
                state.push_notice(n, 0);
            }
            state.header_pin = HeaderPin::from_header(&info);
        }
        let prefix = index_prefix(index)?;
        let sha = sha256(&[index]);
        if state.index_pin.map(|p| p.index_sha256) != Some(sha) {
            match check_index(state.index_pin.as_ref(), &info, &prefix, &sha)? {
                IndexVerdict::Accept => {}
                _ => return integrity(K::MirrorMismatch),
            }
        }
        let (prefix, plain) = open_index(&keys, index)?;
        if state.index_pin.map(|p| p.index_sha256) != Some(sha) {
            let notices = check_index_writer(
                state.index_pin.as_ref(),
                &info,
                &prefix,
                &sha,
                &plain.writer_device_id,
                &state.own,
                &device_id,
            )?;
            for n in notices {
                state.push_notice(n, 0);
            }
            if state.index_pin.is_none() {
                state.own.indexes_from = state
                    .own
                    .indexes_from
                    .max(prefix.index_seq.saturating_add(1));
            }
            state.index_pin = Some(IndexPin::from_index(&prefix, sha));
            state.index_etag = None;
        }
        // The mirror's index may be one an interrupted sync accepted but whose state was never
        // written: adopt its applied value now, as the sync would have.
        let applied = plain
            .applied
            .iter()
            .find(|a| a.device_id == device_id)
            .map_or(0, |a| a.last_op_seq);
        if let Some(n) = state.adopt_applied(applied, plain.writer_device_id, 0)? {
            state.push_notice(n, 0);
        }
        Ok(Vault {
            device_id,
            header_bytes: header.to_vec(),
            info,
            keys,
            index_bytes: index.to_vec(),
            index_prefix: prefix,
            index: plain,
            state,
        })
    }

    /// This device's ID.
    pub fn device_id(&self) -> [u8; 16] {
        self.device_id
    }

    /// The accepted header's plain data.
    pub fn header(&self) -> &HeaderInfo {
        &self.info
    }

    /// The keys of the accepted header.
    pub fn keys(&self) -> &VaultKeys {
        &self.keys
    }

    /// The accepted index, without queued changes.
    pub fn index(&self) -> &IndexPlain {
        &self.index
    }

    /// The accepted index's cleartext prefix.
    pub fn index_prefix(&self) -> &IndexPrefix {
        &self.index_prefix
    }

    /// The mirror state.
    pub fn state(&self) -> &MirrorState {
        &self.state
    }

    /// The mirror state, for bookkeeping such as marking notices read.
    pub fn state_mut(&mut self) -> &mut MirrorState {
        &mut self.state
    }

    /// Record the backend's etags for the header and index this vault holds.
    pub fn set_etags(&mut self, header: Option<String>, index: Option<String>) {
        self.state.header_etag = header;
        self.state.index_etag = index;
    }

    /// The bytes of the accepted header, for the mirror's `header` file.
    pub fn header_bytes(&self) -> &[u8] {
        &self.header_bytes
    }

    /// The bytes of the accepted index, for the mirror's `index` file.
    pub fn index_bytes(&self) -> &[u8] {
        &self.index_bytes
    }

    /// The sealed state, for the mirror's `state` file. Written last.
    pub fn commit(&self) -> Result<Vec<u8>> {
        seal_state(&self.keys, &self.state)
    }

    /// The index as this device sees it: the accepted index with the write queue replayed on it,
    /// using only what the mirror holds. Reads use this view, so queued writes are visible.
    pub fn view(&self) -> Result<IndexPlain> {
        if self.state.queue.is_empty() {
            return Ok(self.index.clone());
        }
        let labels = labels(&self.info);
        let ctx = ReplayCtx {
            device_id: self.device_id,
            labels: &labels,
            new_index_seq: self.index_prefix.index_seq.saturating_add(1),
        };
        match replay(
            &self.index,
            &self.state.queue,
            &ctx,
            &MirrorChain(&self.state),
        )? {
            ReplayOutcome::Done(r) => Ok(r.index),
            // The mirror view never answers `Missing`, so this cannot happen; fall back to a view
            // that treats every walk as incomplete.
            ReplayOutcome::Need(_) => match replay(&self.index, &self.state.queue, &ctx, &NoChain)?
            {
                ReplayOutcome::Done(r) => Ok(r.index),
                ReplayOutcome::Need(_) => integrity(K::MirrorMismatch),
            },
        }
    }

    /// Open an entry object of the view or the index, checking it against the entry.
    pub fn open_entry_of(
        &self,
        e: &IndexEntry,
        object: &[u8],
    ) -> Result<(EntryPrefix, EntryPlain)> {
        crate::index::open_head(&self.keys, e, object)
    }

    /// Open an object by ID and expected hash, for history walks.
    pub fn open_object(
        &self,
        object_id: &[u8; 16],
        sha256: &[u8; 32],
        object: &[u8],
    ) -> Result<(EntryPrefix, EntryPlain)> {
        open_entry(&self.keys, object_id, sha256, object)
    }

    /// Record that the user displayed an object, which keeps it in a `heads` mirror.
    pub fn mark_displayed(&mut self, object_id: &[u8; 16], now: i64) {
        if let Ok(i) = self
            .state
            .objects
            .binary_search_by(|o| o.object_id.cmp(object_id))
        {
            self.state.objects[i].displayed_unix = now;
        }
    }

    fn check_path(path: &str) -> Result<()> {
        if !is_valid_path(path) {
            return input(InputKind::Path);
        }
        Ok(())
    }

    /// Queue a new revision of `path`. With `parent` `None` it is a new entry (revision 1, also
    /// used by `vlt cp`); otherwise `parent` is the head the user edited, which must be the head
    /// of an entry in [`Vault::view`]. `ext` is the new plaintext's extension list: empty for a
    /// new entry, and for an edit the parent's list as [`ExtList::for_changed_record`] keeps it.
    pub fn put(
        &mut self,
        path: &str,
        content: &[u8],
        parent: Option<[u8; 16]>,
        ext: ExtList,
        now: i64,
    ) -> Result<Queued> {
        Self::check_path(path)?;
        let (revision, parent_id, parent_sha) = match parent {
            None => (1, [0; 16], [0; 32]),
            Some(h) => {
                let view = self.view()?;
                let e = view
                    .entries
                    .iter()
                    .find(|e| e.head_object_id == h)
                    .ok_or(Error::InvalidInput(InputKind::NotFound))?;
                let r = e
                    .revision
                    .checked_add(1)
                    .filter(|r| *r <= crate::limits::COUNTER_CAP)
                    .ok_or(Error::Integrity(K::CounterCap))?;
                (r, h, e.head_sha256)
            }
        };
        let plain = EntryPlain {
            revision,
            parent_object_id: parent_id,
            parent_sha256: parent_sha,
            device_id: self.device_id,
            created_unix: now,
            content: Zeroizing::new(content.to_vec()),
            ext,
        };
        let object_id = generate_id()?;
        let object = seal_entry(&self.keys, &object_id, &plain)?;
        let object_sha256 = sha256(&[&object]);
        let mut next = self.state.next_op_seq;
        let op_seq = take_op_seq(&mut next)?;
        self.state.next_op_seq = next;
        self.state.queue.push(Op::Put(PutOp {
            op_seq,
            path: path.to_owned(),
            object_id,
            object_sha256,
            revision,
            parent_object_id: parent_id,
            device_id: self.device_id,
            entry_vault_id: self.keys.vault_id(),
            entry_epoch: self.keys.epoch(),
            uploaded: false,
        }));
        let meta = self
            .state
            .object_mut(&object_id, parent_id, parent_sha, revision);
        meta.published_unix = 0;
        meta.local_only = true;
        Ok(Queued {
            object_id,
            object,
            revision,
        })
    }

    /// Queue the removal of `path` as the view shows it.
    pub fn remove(&mut self, path: &str) -> Result<()> {
        let view = self.view()?;
        let e = find(&view, path)?;
        let mut next = self.state.next_op_seq;
        let op_seq = take_op_seq(&mut next)?;
        self.state.next_op_seq = next;
        self.state.queue.push(Op::Remove(RemoveOp {
            op_seq,
            path: path.to_owned(),
            expected_head: e.head_object_id,
        }));
        Ok(())
    }

    /// Queue a move of `from` to `to`, which must be free in the view.
    pub fn rename(&mut self, from: &str, to: &str) -> Result<()> {
        Self::check_path(to)?;
        let view = self.view()?;
        let e = find(&view, from)?;
        if find(&view, to).is_ok() {
            return input(InputKind::PathTaken);
        }
        let mut next = self.state.next_op_seq;
        let op_seq = take_op_seq(&mut next)?;
        self.state.next_op_seq = next;
        self.state.queue.push(Op::Move(MoveOp {
            op_seq,
            from: from.to_owned(),
            to: to.to_owned(),
            expected_head: e.head_object_id,
        }));
        Ok(())
    }
}

/// The entry at `path` in an index.
pub fn find<'a>(index: &'a IndexPlain, path: &str) -> Result<&'a IndexEntry> {
    index
        .entries
        .binary_search_by(|e| e.path.as_bytes().cmp(path.as_bytes()))
        .map(|i| &index.entries[i])
        .map_err(|_| Error::InvalidInput(InputKind::NotFound))
}
