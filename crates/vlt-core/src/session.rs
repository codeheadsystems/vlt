//! The sans-I/O sync and publish state machine, from the spec's "Sync policy" and "Local mirror and
//! write queue".
//!
//! A [`SyncSession`] tells its caller what to fetch, write, or wait for through [`Action`]s and
//! takes the results back as [`Response`]s. Every decision about the vault lives here; a driver
//! only executes actions, supplies the clock and jitter, and may run a batch of object requests in
//! parallel. Every platform therefore implements one small executor over the same vocabulary.
//!
//! Changes reach the [`Vault`] only through [`Action::Commit`]: the driver writes the commit's files
//! to the mirror in order (entry objects, `header`, `index`, then `state`) and answers
//! [`Response::Committed`], and only then does the session apply them to the vault. An integrity
//! error ends the session with nothing applied that was not already committed.

use crate::entry::{EntryPlain, open_entry, seal_entry};
use crate::error::{Error, IntegrityKind as K, Result, integrity};
use crate::header::{HeaderInfo, VaultKeys};
use crate::index::{
    IndexEntry, IndexPlain, IndexPrefix, index_prefix, open_head, open_index, seal_index,
};
use crate::keys::generate_id;
use crate::limits::COUNTER_CAP;
use crate::merge::{ChainView, Lookup, ReplayCtx, ReplayOutcome, ReportItem, replay};
use crate::mirror_state::{MirrorState, PublishFailure, seal_state};
use crate::notice::{Notice, ObjectKind};
use crate::ops::Op;
use crate::pins::{
    HeaderPin, IndexPin, IndexVerdict, check_header, check_index, check_index_writer,
};
use crate::prim::sha256;
use crate::vault::{Vault, labels};
use std::collections::{HashMap, HashSet};

/// Index `PUT` attempts before a publish gives up.
pub const PUBLISH_ATTEMPTS: u32 = 8;

/// Where to look for entry objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The mirror's `e/` first, then the backend.
    MirrorThenBackend,
    /// The backend only, bypassing the mirror.
    Backend,
}

/// Files to write to the mirror, in field order, `state` last.
pub struct Commit {
    /// Entry objects for `e/<object_id hex>`.
    pub objects: Vec<([u8; 16], Vec<u8>)>,
    /// A new `header` file.
    pub header: Option<Vec<u8>>,
    /// A new `index` file.
    pub index: Option<Vec<u8>>,
    /// The new `state` file, written last.
    pub state: Vec<u8>,
}

/// What the driver does next.
pub enum Action {
    /// `GET <prefix>index`, conditional on the etag when one is given.
    GetIndex {
        /// `If-None-Match` value.
        if_none_match: Option<String>,
    },
    /// `GET <prefix>header`, conditional on the etag when one is given.
    GetHeader {
        /// `If-None-Match` value.
        if_none_match: Option<String>,
    },
    /// Unlock this header with the device's private keys (`parse_header` then
    /// `unlock_with_device`) and answer [`Response::Unlocked`] or [`Response::UnlockFailed`].
    /// The session never sees device secrets.
    Unlock {
        /// The header bytes.
        header: Vec<u8>,
    },
    /// Obtain these entry objects; answer [`Response::Objects`] with one result per ID.
    GetObjects {
        /// Object IDs.
        ids: Vec<[u8; 16]>,
        /// Where to look.
        source: Source,
    },
    /// `PUT` each object with `If-None-Match: *`; answer [`Response::Stored`].
    PutObjects {
        /// Object IDs and bytes.
        objects: Vec<([u8; 16], Vec<u8>)>,
    },
    /// `PUT <prefix>index` with `If-Match`; answer [`Response::IndexStored`].
    PutIndex {
        /// The sealed index.
        index: Vec<u8>,
        /// `If-Match` value.
        if_match: String,
    },
    /// Wait before retrying a publish: jittered backoff from 100 ms, doubling per attempt. Answer
    /// [`Response::Waited`].
    Backoff {
        /// The attempt that failed, from 1.
        attempt: u32,
    },
    /// Write these mirror files; answer [`Response::Committed`].
    Commit(Commit),
    /// The session is over.
    Done(SyncReport),
}

/// The result of a `GET` of the header or index.
pub enum Fetched {
    /// The object and its etag.
    Found {
        /// Bytes.
        bytes: Vec<u8>,
        /// Etag.
        etag: String,
    },
    /// `304`.
    NotModified,
    /// `404`.
    NotFound,
}

/// The result of one conditional `PUT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stored {
    /// Written; the new etag.
    Written {
        /// Etag.
        etag: String,
    },
    /// `412`.
    PreconditionFailed,
}

/// The result of obtaining one entry object.
pub enum ObjectFetch {
    /// Found.
    Found {
        /// Bytes.
        bytes: Vec<u8>,
        /// Whether it came from the mirror (and so need not be written there).
        from_mirror: bool,
    },
    /// The backend answered `404`.
    NotFound,
    /// Not obtainable now (offline).
    Unavailable,
}

/// A backend failure the driver reports instead of a result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// Connection failure, DNS failure, or timeout.
    Offline,
    /// An HTTP error response. The message names the S3 error code and object key, never content.
    Http {
        /// HTTP status.
        status: u16,
        /// Message for the user.
        message: String,
    },
}

/// The answer to an [`Action`].
pub enum Response {
    /// For [`Action::GetIndex`].
    Index(Fetched),
    /// For [`Action::GetHeader`].
    Header(Fetched),
    /// For [`Action::Unlock`].
    Unlocked(Box<(HeaderInfo, VaultKeys)>),
    /// For [`Action::Unlock`]: no wrap opened, so this device was revoked, the vault was rekeyed,
    /// or the header was tampered with.
    UnlockFailed,
    /// For [`Action::GetObjects`].
    Objects(Vec<([u8; 16], ObjectFetch)>),
    /// For [`Action::PutObjects`].
    Stored(Vec<([u8; 16], Stored)>),
    /// For [`Action::PutIndex`].
    IndexStored(Stored),
    /// For [`Action::Backoff`].
    Waited,
    /// For [`Action::Commit`].
    Committed,
    /// For any request to the backend that failed.
    Failed(Failure),
}

/// What one sync did. Its `Debug` output names report items without their paths.
#[derive(Debug, Default)]
pub struct SyncReport {
    /// A newer header was accepted.
    pub header_changed: bool,
    /// A newer index was accepted.
    pub index_changed: bool,
    /// Entry objects fetched from the backend.
    pub fetched: usize,
    /// Indexes this device published.
    pub published: u32,
    /// Conflicts and dropped or reported operations.
    pub items: Vec<ReportItem>,
    /// New notices.
    pub notices: Vec<Notice>,
    /// The bucket's index is an unmatched rotation index.
    pub rotation_pending: bool,
    /// The backend could not be reached.
    pub offline: bool,
    /// A backend failure that ended the session.
    pub failure: Option<Failure>,
    /// An error recorded after the session committed its state, such as
    /// [`Error::PublishContention`].
    pub error: Option<Error>,
}

/// Options for one sync.
#[derive(Debug, Clone, Copy)]
pub struct SyncOptions {
    /// Publish the write queue.
    pub publish: bool,
    /// Also fetch the header conditionally, as `vlt sync` does.
    pub check_header: bool,
    /// The current time, seconds.
    pub now: i64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum After {
    Sync,
    Reseal,
    WriteAhead,
    Published { more: bool },
    Finish,
}

enum Phase {
    Idle,
    WaitIndex {
        publishing: bool,
    },
    WaitHeader {
        stash: Option<(Vec<u8>, String)>,
        publishing: bool,
    },
    WaitUnlock {
        header: Vec<u8>,
        etag: Option<String>,
        stash: Option<(Vec<u8>, String)>,
        publishing: bool,
    },
    WaitHeads,
    WaitReseal,
    WaitUploadBytes,
    WaitPut {
        ours: HashMap<[u8; 16], Vec<u8>>,
    },
    WaitCompare {
        ours: HashMap<[u8; 16], Vec<u8>>,
    },
    WaitChain {
        id: [u8; 16],
        expect: Expect,
    },
    WaitIndexPut,
    WaitBackoff,
    WaitCommit {
        then: After,
    },
    Over,
}

#[derive(Clone, Copy)]
struct Expect {
    sha256: [u8; 32],
    revision: u64,
    device: Option<[u8; 16]>,
}

struct InFlight {
    bytes: Vec<u8>,
    index: IndexPlain,
    deferred: usize,
    items: Vec<ReportItem>,
}

/// Verified chain links: object ID to parent ID, parent SHA-256, and revision.
type Links = HashMap<[u8; 16], ([u8; 16], [u8; 32], u64)>;

/// Chain links known to this session: the mirror's bookkeeping plus objects verified during it.
struct SessionChain<'a> {
    state: &'a MirrorState,
    extra: &'a Links,
    unavailable: &'a HashSet<[u8; 16]>,
}

impl ChainView for SessionChain<'_> {
    fn lookup(&self, id: &[u8; 16]) -> Lookup {
        if let Some((parent, _, revision)) = self.extra.get(id) {
            return Lookup::Known {
                parent: *parent,
                revision: *revision,
            };
        }
        if self.unavailable.contains(id) {
            return Lookup::Unavailable;
        }
        match self.state.object(id) {
            Some(o) if !o.purged => Lookup::Known {
                parent: o.parent,
                revision: o.revision,
            },
            Some(_) => Lookup::Unavailable,
            None => Lookup::Missing,
        }
    }
}

/// One sync, with publication of the write queue when asked.
pub struct SyncSession<'a> {
    vault: &'a mut Vault,
    opts: SyncOptions,
    st: MirrorState,
    pend_header: Option<(Vec<u8>, HeaderInfo, VaultKeys)>,
    pend_index: Option<(Vec<u8>, IndexPrefix, IndexPlain)>,
    new_objects: Vec<([u8; 16], Vec<u8>)>,
    report: SyncReport,
    phase: Phase,
    header_fetched: bool,
    remote_fresh: bool,
    attempts: u32,
    extra: Links,
    unavailable: HashSet<[u8; 16]>,
    inflight: Option<InFlight>,
}

macro_rules! keys {
    ($s:expr) => {
        match &$s.pend_header {
            Some(h) => &h.2,
            None => &$s.vault.keys,
        }
    };
}

macro_rules! info {
    ($s:expr) => {
        match &$s.pend_header {
            Some(h) => &h.1,
            None => &$s.vault.info,
        }
    };
}

macro_rules! index {
    ($s:expr) => {
        match &$s.pend_index {
            Some(i) => (&i.1, &i.2),
            None => (&$s.vault.index_prefix, &$s.vault.index),
        }
    };
}

impl Vault {
    /// Start one sync of this vault.
    pub fn sync(&mut self, opts: SyncOptions) -> SyncSession<'_> {
        let st = self.state.clone();
        SyncSession {
            vault: self,
            opts,
            st,
            pend_header: None,
            pend_index: None,
            new_objects: Vec::new(),
            report: SyncReport::default(),
            phase: Phase::Idle,
            header_fetched: false,
            remote_fresh: false,
            attempts: 0,
            extra: HashMap::new(),
            unavailable: HashSet::new(),
            inflight: None,
        }
    }
}

/// This device's applied value in an index.
fn applied_of(index: &IndexPlain, device: &[u8; 16]) -> u64 {
    index
        .applied
        .iter()
        .find(|a| &a.device_id == device)
        .map_or(0, |a| a.last_op_seq)
}

fn device_of(e: &IndexEntry) -> [u8; 16] {
    e.device_id
}

impl SyncSession<'_> {
    /// The first action.
    pub fn start(&mut self) -> Result<Action> {
        if !matches!(self.phase, Phase::Idle) {
            return integrity(K::MirrorMismatch);
        }
        self.phase = Phase::WaitIndex { publishing: false };
        Ok(Action::GetIndex {
            if_none_match: self.st.index_etag.clone(),
        })
    }

    /// Feed the answer to the last action and get the next one.
    pub fn feed(&mut self, resp: Response) -> Result<Action> {
        let phase = core::mem::replace(&mut self.phase, Phase::Over);
        if let Response::Failed(f) = resp {
            return self.fail(f);
        }
        match (phase, resp) {
            (Phase::WaitIndex { publishing }, Response::Index(f)) => match f {
                Fetched::NotFound => integrity(K::ObjectMissing),
                Fetched::NotModified => {
                    self.remote_fresh = true;
                    if publishing {
                        self.publish_replay()
                    } else {
                        self.after_index()
                    }
                }
                Fetched::Found { bytes, etag } => self.handle_index(bytes, etag, false, publishing),
            },
            (Phase::WaitHeader { stash, publishing }, Response::Header(f)) => {
                self.header_fetched = true;
                match f {
                    Fetched::NotFound => integrity(K::ObjectMissing),
                    Fetched::NotModified => self.header_unchanged(stash, publishing),
                    Fetched::Found { bytes, etag } => {
                        if sha256(&[&bytes]) == info!(self).header_sha256 {
                            self.st.header_etag = Some(etag);
                            return self.header_unchanged(stash, publishing);
                        }
                        let header = bytes.clone();
                        self.phase = Phase::WaitUnlock {
                            header: bytes,
                            etag: Some(etag),
                            stash,
                            publishing,
                        };
                        Ok(Action::Unlock { header })
                    }
                }
            }
            (
                Phase::WaitUnlock {
                    header,
                    etag,
                    stash,
                    publishing,
                },
                resp,
            ) => {
                let (info, keys) = match resp {
                    Response::Unlocked(b) => *b,
                    Response::UnlockFailed => return Err(Error::WrongPasswordOrUnknownDevice),
                    _ => return integrity(K::MirrorMismatch),
                };
                self.accept_header(header, etag, info, keys)?;
                if publishing {
                    // A new header may carry a new epoch or lineage: start publishing over,
                    // re-sealing what needs it, and fetch the index afresh.
                    self.remote_fresh = false;
                    return self.publish_begin();
                }
                match stash {
                    Some((b, e)) => self.handle_index(b, e, true, false),
                    None => self.after_index(),
                }
            }
            (Phase::WaitHeads, Response::Objects(rs)) => {
                self.take_heads(rs)?;
                self.commit(After::Sync)
            }
            (Phase::WaitReseal, Response::Objects(rs)) => self.reseal(rs),
            (Phase::WaitUploadBytes, Response::Objects(rs)) => self.upload(rs),
            (Phase::WaitPut { ours }, Response::Stored(rs)) => self.after_put(ours, rs),
            (Phase::WaitCompare { ours }, Response::Objects(rs)) => {
                for (id, r) in rs {
                    match &r {
                        ObjectFetch::Unavailable => return self.fail(Failure::Offline),
                        ObjectFetch::Found { bytes, .. } if Some(bytes) == ours.get(&id) => {}
                        _ => return integrity(K::ObjectMismatch),
                    }
                    self.mark_uploaded(&id);
                }
                self.publish_fetch_index()
            }
            (Phase::WaitChain { id, expect }, Response::Objects(rs)) => {
                self.take_chain(id, expect, rs)?;
                self.publish_replay()
            }
            (Phase::WaitIndexPut, Response::IndexStored(s)) => self.after_index_put(s),
            (Phase::WaitBackoff, Response::Waited) => self.publish_fetch_index(),
            (Phase::WaitCommit { then }, Response::Committed) => {
                self.apply();
                self.after_commit(then)
            }
            _ => integrity(K::MirrorMismatch),
        }
    }

    fn header_unchanged(
        &mut self,
        stash: Option<(Vec<u8>, String)>,
        publishing: bool,
    ) -> Result<Action> {
        if stash.is_some() {
            // The index names a header newer than the one in the bucket.
            return integrity(K::IndexHeaderSeq);
        }
        if publishing {
            return self.publish_begin();
        }
        self.after_index()
    }

    fn accept_header(
        &mut self,
        bytes: Vec<u8>,
        etag: Option<String>,
        info: HeaderInfo,
        keys: VaultKeys,
    ) -> Result<()> {
        if sha256(&[&bytes]) != info.header_sha256 || keys.vault_id() != info.vault_id {
            return integrity(K::MirrorMismatch);
        }
        let notices = check_header(
            &self.st.header_pin,
            &info,
            &keys,
            &self.st.own,
            &self.vault.device_id,
        )?;
        for n in notices {
            self.notice(n);
        }
        self.st.header_pin = HeaderPin::from_header(&info);
        self.st.header_etag = etag;
        self.pend_header = Some((bytes, info, keys));
        // The index this session holds was checked against the old header.
        self.remote_fresh = false;
        self.report.header_changed = true;
        Ok(())
    }

    fn notice(&mut self, n: Notice) {
        self.st.push_notice(n.clone(), self.opts.now);
        self.report.notices.push(n);
    }

    fn handle_index(
        &mut self,
        bytes: Vec<u8>,
        etag: String,
        header_refreshed: bool,
        publishing: bool,
    ) -> Result<Action> {
        let prefix = index_prefix(&bytes)?;
        let sha = sha256(&[&bytes]);
        let verdict = check_index(self.st.index_pin.as_ref(), info!(self), &prefix, &sha)?;
        match verdict {
            IndexVerdict::NeedHeader => {
                if header_refreshed {
                    return integrity(K::IndexHeaderSeq);
                }
                self.phase = Phase::WaitHeader {
                    stash: Some((bytes, etag)),
                    publishing,
                };
                return Ok(Action::GetHeader {
                    if_none_match: None,
                });
            }
            IndexVerdict::Unchanged => {
                self.st.index_etag = Some(etag);
                self.st.rotation_pending = false;
                let me = self.vault.device_id;
                let (_, idx) = index!(self);
                let (applied, writer) = (applied_of(idx, &me), idx.writer_device_id);
                if let Some(n) = self.st.adopt_applied(applied, writer, self.opts.now)? {
                    self.notice(n);
                }
            }
            IndexVerdict::RotationPending => {
                self.st.rotation_pending = true;
                self.report.rotation_pending = true;
                self.remote_fresh = false;
                if publishing {
                    return self.commit(After::Finish);
                }
                return self.after_index();
            }
            IndexVerdict::Accept => {
                let (p, plain) = open_index(keys!(self), &bytes)?;
                if p != prefix {
                    return integrity(K::MirrorMismatch);
                }
                let me = self.vault.device_id;
                let notices = check_index_writer(
                    self.st.index_pin.as_ref(),
                    info!(self),
                    &prefix,
                    &sha,
                    &plain.writer_device_id,
                    &self.st.own,
                    &me,
                )?;
                for n in notices {
                    self.notice(n);
                }
                if let Some(n) = self.st.adopt_applied(
                    applied_of(&plain, &me),
                    plain.writer_device_id,
                    self.opts.now,
                )? {
                    self.notice(n);
                }
                if self.st.index_pin.is_none() {
                    self.st.own.indexes_from = self
                        .st
                        .own
                        .indexes_from
                        .max(prefix.index_seq.saturating_add(1));
                }
                self.st.index_pin = Some(IndexPin::from_index(&prefix, sha));
                self.st.index_etag = Some(etag);
                self.st.rotation_pending = false;
                self.pend_index = Some((bytes, prefix, plain));
                self.report.index_changed = true;
            }
        }
        self.remote_fresh = true;
        if publishing {
            self.publish_replay()
        } else {
            self.after_index()
        }
    }

    fn after_index(&mut self) -> Result<Action> {
        if self.opts.check_header && !self.header_fetched {
            self.phase = Phase::WaitHeader {
                stash: None,
                publishing: false,
            };
            return Ok(Action::GetHeader {
                if_none_match: self.st.header_etag.clone(),
            });
        }
        let (_, idx) = index!(self);
        let mut ids: Vec<[u8; 16]> = idx
            .entries
            .iter()
            .map(|e| e.head_object_id)
            .chain(idx.tombstones.iter().map(|t| t.head_object_id))
            .filter(|id| self.st.object(id).is_none())
            .collect();
        ids.sort();
        ids.dedup();
        if ids.is_empty() {
            return self.commit(After::Sync);
        }
        self.phase = Phase::WaitHeads;
        Ok(Action::GetObjects {
            ids,
            source: Source::MirrorThenBackend,
        })
    }

    fn take_heads(&mut self, rs: Vec<([u8; 16], ObjectFetch)>) -> Result<()> {
        for (id, r) in rs {
            let (_, idx) = index!(self);
            let live = idx.entries.iter().find(|e| e.head_object_id == id).cloned();
            let tomb = idx
                .tombstones
                .iter()
                .find(|t| t.head_object_id == id)
                .map(|t| (t.head_sha256, t.revision, t.device_id));
            match r {
                ObjectFetch::Found { bytes, from_mirror } => {
                    let plain = match (&live, tomb) {
                        (Some(e), _) => open_head(keys!(self), e, &bytes)?.1,
                        (None, Some((sha, rev, dev))) => {
                            let (_, p) = open_entry(keys!(self), &id, &sha, &bytes)?;
                            if p.revision != rev || p.device_id != dev {
                                return integrity(K::HeadMismatch);
                            }
                            p
                        }
                        (None, None) => return integrity(K::MirrorMismatch),
                    };
                    self.record(&id, &plain);
                    if !from_mirror {
                        self.new_objects.push((id, bytes));
                        self.report.fetched += 1;
                    }
                }
                ObjectFetch::NotFound => {
                    if live.is_some() {
                        return integrity(K::HeadMissing);
                    }
                    if let Some((_, rev, _)) = tomb {
                        self.st.object_mut(&id, [0; 16], [0; 32], rev).purged = true;
                    }
                }
                ObjectFetch::Unavailable => self.report.offline = true,
            }
        }
        Ok(())
    }

    fn record(&mut self, id: &[u8; 16], plain: &EntryPlain) {
        self.st.object_mut(
            id,
            plain.parent_object_id,
            plain.parent_sha256,
            plain.revision,
        );
    }

    fn commit(&mut self, then: After) -> Result<Action> {
        if then == After::Sync && !self.report.offline {
            self.st.last_sync_unix = Some(self.opts.now);
        }
        let state = seal_state(keys!(self), &self.st)?;
        let commit = Commit {
            objects: self.new_objects.clone(),
            header: self.pend_header.as_ref().map(|h| h.0.clone()),
            index: self.pend_index.as_ref().map(|i| i.0.clone()),
            state,
        };
        self.phase = Phase::WaitCommit { then };
        Ok(Action::Commit(commit))
    }

    fn apply(&mut self) {
        if let Some((b, i, k)) = self.pend_header.take() {
            self.vault.header_bytes = b;
            self.vault.info = i;
            self.vault.keys = k;
        }
        if let Some((b, p, plain)) = self.pend_index.take() {
            self.vault.index_bytes = b;
            self.vault.index_prefix = p;
            self.vault.index = plain;
        }
        self.vault.state = self.st.clone();
        self.new_objects.clear();
    }

    fn after_commit(&mut self, then: After) -> Result<Action> {
        match then {
            After::Sync => {
                let publish = self.opts.publish
                    && !self.st.queue.is_empty()
                    && !self.st.rotation_pending
                    && !self.report.offline;
                if publish {
                    self.publish_begin()
                } else {
                    self.done()
                }
            }
            After::Reseal => self.upload_begin(),
            After::WriteAhead => {
                let Some(f) = &self.inflight else {
                    return integrity(K::MirrorMismatch);
                };
                let Some(etag) = self.st.index_etag.clone() else {
                    return integrity(K::MirrorMismatch);
                };
                let index = f.bytes.clone();
                self.phase = Phase::WaitIndexPut;
                Ok(Action::PutIndex {
                    index,
                    if_match: etag,
                })
            }
            After::Published { more } => {
                if more && !self.st.queue.is_empty() {
                    self.upload_begin()
                } else {
                    self.done()
                }
            }
            After::Finish => self.done(),
        }
    }

    fn done(&mut self) -> Result<Action> {
        self.phase = Phase::Over;
        self.report.rotation_pending = self.st.rotation_pending;
        Ok(Action::Done(core::mem::take(&mut self.report)))
    }

    fn fail(&mut self, f: Failure) -> Result<Action> {
        let publishing = self.inflight.is_some() || self.attempts > 0;
        match &f {
            Failure::Offline => self.report.offline = true,
            Failure::Http { message, .. } => {
                if publishing || self.opts.publish && !self.st.queue.is_empty() {
                    self.st.last_publish_error = Some(PublishFailure {
                        exit_code: 7,
                        message: message.clone(),
                        unix: self.opts.now,
                    });
                }
            }
        }
        self.report.failure = Some(f);
        self.inflight = None;
        self.commit(After::Finish)
    }

    // Publishing.

    fn publish_begin(&mut self) -> Result<Action> {
        // A header change that no index announced yet (a rotation interrupted between its header
        // and index writes) must be seen before anything is sealed.
        if !self.header_fetched {
            self.phase = Phase::WaitHeader {
                stash: None,
                publishing: true,
            };
            return Ok(Action::GetHeader {
                if_none_match: self.st.header_etag.clone(),
            });
        }
        let (vid, epoch) = (keys!(self).vault_id(), keys!(self).epoch());
        let needs = self.st.queue.iter().any(|op| match op {
            Op::Put(p) => (p.entry_vault_id, p.entry_epoch) != (vid, epoch),
            _ => false,
        });
        if !needs {
            return self.upload_begin();
        }
        let ids = self
            .st
            .queue
            .iter()
            .filter_map(|op| match op {
                Op::Put(p) => Some(p.object_id),
                _ => None,
            })
            .collect();
        self.phase = Phase::WaitReseal;
        Ok(Action::GetObjects {
            ids,
            source: Source::MirrorThenBackend,
        })
    }

    /// Publishing step 1: re-seal every queued object sealed under another `(vault_id, epoch)`,
    /// or whose parent was re-sealed, under fresh object IDs, and rewrite later operations.
    fn reseal(&mut self, rs: Vec<([u8; 16], ObjectFetch)>) -> Result<Action> {
        let bytes: HashMap<[u8; 16], Vec<u8>> = rs
            .into_iter()
            .filter_map(|(id, r)| match r {
                ObjectFetch::Found { bytes, .. } => Some((id, bytes)),
                _ => None,
            })
            .collect();
        let (vid, epoch) = (keys!(self).vault_id(), keys!(self).epoch());
        let mut renames: HashMap<[u8; 16], ([u8; 16], [u8; 32])> = HashMap::new();
        let mut queue = core::mem::take(&mut self.st.queue);
        for op in &mut queue {
            match op {
                Op::Put(p) => {
                    let renamed_parent = renames.get(&p.parent_object_id).copied();
                    if (p.entry_vault_id, p.entry_epoch) == (vid, epoch) && renamed_parent.is_none()
                    {
                        continue;
                    }
                    let b = bytes
                        .get(&p.object_id)
                        .ok_or(Error::Integrity(K::MirrorMismatch))?;
                    let (_, mut plain) =
                        open_entry(keys!(self), &p.object_id, &p.object_sha256, b)?;
                    if let Some((nid, nsha)) = renamed_parent {
                        plain.parent_object_id = nid;
                        plain.parent_sha256 = nsha;
                        p.parent_object_id = nid;
                    }
                    let new_id = generate_id()?;
                    let sealed = seal_entry(keys!(self), &new_id, &plain)?;
                    let new_sha = sha256(&[&sealed]);
                    renames.insert(p.object_id, (new_id, new_sha));
                    p.object_id = new_id;
                    p.object_sha256 = new_sha;
                    p.entry_vault_id = vid;
                    p.entry_epoch = epoch;
                    p.uploaded = false;
                    self.st
                        .object_mut(
                            &new_id,
                            plain.parent_object_id,
                            plain.parent_sha256,
                            plain.revision,
                        )
                        .local_only = true;
                    self.new_objects.push((new_id, sealed));
                }
                Op::Remove(r) => {
                    if let Some((n, _)) = renames.get(&r.expected_head) {
                        r.expected_head = *n;
                    }
                }
                Op::Move(m) => {
                    if let Some((n, _)) = renames.get(&m.expected_head) {
                        m.expected_head = *n;
                    }
                }
            }
        }
        self.st.queue = queue;
        self.commit(After::Reseal)
    }

    fn upload_begin(&mut self) -> Result<Action> {
        let ids: Vec<[u8; 16]> = self
            .st
            .queue
            .iter()
            .filter_map(|op| match op {
                Op::Put(p) if !p.uploaded => Some(p.object_id),
                _ => None,
            })
            .collect();
        if ids.is_empty() {
            return self.publish_fetch_index();
        }
        self.phase = Phase::WaitUploadBytes;
        Ok(Action::GetObjects {
            ids,
            source: Source::MirrorThenBackend,
        })
    }

    /// Publishing step 2: `PUT` every queued object that is not known to be uploaded.
    fn upload(&mut self, rs: Vec<([u8; 16], ObjectFetch)>) -> Result<Action> {
        let mut ours = HashMap::new();
        for (id, r) in rs {
            let ObjectFetch::Found { bytes, .. } = r else {
                return integrity(K::MirrorMismatch);
            };
            let sha = self.st.queue.iter().find_map(|op| match op {
                Op::Put(p) if p.object_id == id => Some(p.object_sha256),
                _ => None,
            });
            if sha != Some(sha256(&[&bytes])) {
                return integrity(K::MirrorMismatch);
            }
            ours.insert(id, bytes);
        }
        let objects = ours.iter().map(|(k, v)| (*k, v.clone())).collect();
        self.phase = Phase::WaitPut { ours };
        Ok(Action::PutObjects { objects })
    }

    fn mark_uploaded(&mut self, id: &[u8; 16]) {
        for op in &mut self.st.queue {
            if let Op::Put(p) = op
                && &p.object_id == id
            {
                p.uploaded = true;
            }
        }
        if let Ok(i) = self.st.objects.binary_search_by(|o| o.object_id.cmp(id)) {
            self.st.objects[i].local_only = false;
        }
    }

    fn after_put(
        &mut self,
        mut ours: HashMap<[u8; 16], Vec<u8>>,
        rs: Vec<([u8; 16], Stored)>,
    ) -> Result<Action> {
        let mut compare = Vec::new();
        for (id, s) in rs {
            match s {
                Stored::Written { .. } => {
                    self.mark_uploaded(&id);
                    ours.remove(&id);
                }
                Stored::PreconditionFailed => compare.push(id),
            }
        }
        if compare.is_empty() {
            return self.publish_fetch_index();
        }
        ours.retain(|k, _| compare.contains(k));
        self.phase = Phase::WaitCompare { ours };
        Ok(Action::GetObjects {
            ids: compare,
            source: Source::Backend,
        })
    }

    /// Publishing step 3: the index to replay on, fetched unless this session already holds it.
    fn publish_fetch_index(&mut self) -> Result<Action> {
        if self.remote_fresh && self.st.index_etag.is_some() {
            return self.publish_replay();
        }
        self.phase = Phase::WaitIndex { publishing: true };
        Ok(Action::GetIndex {
            if_none_match: None,
        })
    }

    fn expect_for(&self, id: &[u8; 16]) -> Option<Expect> {
        let (_, idx) = index!(self);
        if let Some(e) = idx.entries.iter().find(|e| &e.head_object_id == id) {
            return Some(Expect {
                sha256: e.head_sha256,
                revision: e.revision,
                device: Some(device_of(e)),
            });
        }
        if let Some(t) = idx.tombstones.iter().find(|t| &t.head_object_id == id) {
            return Some(Expect {
                sha256: t.head_sha256,
                revision: t.revision,
                device: Some(t.device_id),
            });
        }
        let child = self
            .extra
            .values()
            .find(|(p, _, _)| p == id)
            .map(|(_, sha, rev)| (*sha, *rev))
            .or_else(|| {
                self.st
                    .objects
                    .iter()
                    .find(|o| &o.parent == id && !o.purged)
                    .map(|o| (o.parent_sha256, o.revision))
            })?;
        Some(Expect {
            sha256: child.0,
            revision: child.1.checked_sub(1)?,
            device: None,
        })
    }

    fn take_chain(
        &mut self,
        id: [u8; 16],
        expect: Expect,
        rs: Vec<([u8; 16], ObjectFetch)>,
    ) -> Result<()> {
        let r = rs.into_iter().find(|(i, _)| i == &id).map(|(_, r)| r);
        match r {
            Some(ObjectFetch::Found { bytes, from_mirror }) => {
                let (_, plain) = open_entry(keys!(self), &id, &expect.sha256, &bytes)?;
                if plain.revision != expect.revision
                    || expect.device.is_some_and(|d| d != plain.device_id)
                {
                    return integrity(K::ParentRule);
                }
                self.extra.insert(
                    id,
                    (plain.parent_object_id, plain.parent_sha256, plain.revision),
                );
                self.record(&id, &plain);
                if !from_mirror {
                    self.new_objects.push((id, bytes));
                }
            }
            _ => {
                self.unavailable.insert(id);
            }
        }
        Ok(())
    }

    /// Publishing steps 3 and 4: replay the queue on the remote index, record the new index as
    /// this device's own, and commit before the conditional `PUT`.
    fn publish_replay(&mut self) -> Result<Action> {
        loop {
            let (prefix, remote) = index!(self);
            let new_seq = prefix
                .index_seq
                .checked_add(1)
                .filter(|s| *s <= COUNTER_CAP)
                .ok_or(Error::Integrity(K::CounterCap))?;
            let labels = labels(info!(self));
            let ctx = ReplayCtx {
                device_id: self.vault.device_id,
                labels: &labels,
                new_index_seq: new_seq,
            };
            let view = SessionChain {
                state: &self.st,
                extra: &self.extra,
                unavailable: &self.unavailable,
            };
            match replay(remote, &self.st.queue, &ctx, &view)? {
                ReplayOutcome::Need(id) => match self.expect_for(&id) {
                    Some(expect) => {
                        self.phase = Phase::WaitChain { id, expect };
                        return Ok(Action::GetObjects {
                            ids: vec![id],
                            source: Source::MirrorThenBackend,
                        });
                    }
                    None => {
                        self.unavailable.insert(id);
                    }
                },
                ReplayOutcome::Done(res) => {
                    let header_seq = info!(self).header_seq;
                    let bytes = seal_index(keys!(self), new_seq, header_seq, &res.index)?;
                    let sha = sha256(&[&bytes]);
                    self.st
                        .own
                        .record(ObjectKind::Index, new_seq, sha, self.opts.now);
                    self.inflight = Some(InFlight {
                        bytes,
                        index: res.index,
                        deferred: res.deferred,
                        items: res.report,
                    });
                    return self.commit(After::WriteAhead);
                }
            }
        }
    }

    fn after_index_put(&mut self, s: Stored) -> Result<Action> {
        let Some(f) = self.inflight.take() else {
            return integrity(K::MirrorMismatch);
        };
        match s {
            Stored::Written { etag } => {
                let prefix = index_prefix(&f.bytes)?;
                let sha = sha256(&[&f.bytes]);
                self.st.index_pin = Some(IndexPin::from_index(&prefix, sha));
                self.st.index_etag = Some(etag);
                let me = self.vault.device_id;
                self.st
                    .adopt_applied(applied_of(&f.index, &me), me, self.opts.now)?;
                self.st.last_publish_error = None;
                self.st.own.prune(self.opts.now);
                self.report.published += 1;
                self.report.items.extend(f.items);
                self.pend_index = Some((f.bytes, prefix, f.index));
                self.remote_fresh = true;
                self.commit(After::Published {
                    more: f.deferred > 0,
                })
            }
            Stored::PreconditionFailed => {
                self.attempts += 1;
                self.remote_fresh = false;
                if self.attempts >= PUBLISH_ATTEMPTS {
                    self.st.last_publish_error = Some(PublishFailure {
                        exit_code: 7,
                        message: Error::PublishContention.to_string(),
                        unix: self.opts.now,
                    });
                    self.report.error = Some(Error::PublishContention);
                    return self.commit(After::Finish);
                }
                self.phase = Phase::WaitBackoff;
                Ok(Action::Backoff {
                    attempt: self.attempts,
                })
            }
        }
    }
}
