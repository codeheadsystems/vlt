//! The driver: executes `vlt-core`'s sync session against a [`Backend`] and a [`Mirror`].
//!
//! The driver makes no decision about the vault. It runs each [`Action`] the session returns,
//! supplies the clock and jitter for backoff, fetches batches of objects up to 16 at a time, and
//! hands device-key unlocking back to its caller, so device secrets never reach the session. Every
//! branch on vault semantics lives in `vlt-core`, which the Android and Firefox drivers share.

use crate::backend::{Backend, Etag, Get, Put};
use crate::error::StoreError;
use crate::mirror::Mirror;
use std::time::Duration;
use vlt_core::header::{HeaderInfo, VaultKeys};
use vlt_core::limits::{ENTRY_OBJECT_MAX, HEADER_MAX, INDEX_MAX};
use vlt_core::session::{
    Action, Failure, Fetched, ObjectFetch, Response, Source, Stored, SyncOptions, SyncReport,
};
use vlt_core::vault::Vault;

/// Opens a header with this device's private keys.
pub type Unlock<'a> = dyn Fn(&[u8]) -> vlt_core::Result<(HeaderInfo, VaultKeys)> + 'a;

/// Objects fetched or written in parallel.
pub const PARALLEL: usize = 16;

/// Why a sync stopped without a report.
#[derive(Debug)]
pub enum DriveError {
    /// The vault refused: an integrity error, a revoked device, or a counter at its cap.
    Core(vlt_core::Error),
    /// The mirror could not be written; nothing after the failed file was written.
    Mirror(StoreError),
}

impl core::fmt::Display for DriveError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DriveError::Core(e) => write!(f, "{e}"),
            DriveError::Mirror(e) => write!(f, "mirror: {e}"),
        }
    }
}

impl std::error::Error for DriveError {}

impl From<vlt_core::Error> for DriveError {
    fn from(e: vlt_core::Error) -> Self {
        DriveError::Core(e)
    }
}

/// Driver settings.
#[derive(Debug, Clone, Copy)]
pub struct DriverOptions {
    /// First publish backoff; doubled per attempt, with full jitter.
    pub backoff_base: Duration,
}

impl Default for DriverOptions {
    fn default() -> Self {
        DriverOptions {
            backoff_base: Duration::from_millis(100),
        }
    }
}

fn failure(e: &StoreError) -> Failure {
    if e.is_offline() {
        Failure::Offline
    } else {
        Failure::Http {
            status: e.status().unwrap_or(0),
            message: e.to_string(),
        }
    }
}

/// A body over the spec's size limit is an integrity error, not a backend failure.
fn get(
    backend: &dyn Backend,
    key: &str,
    inm: Option<String>,
    max: usize,
) -> Result<Fetched, Result<Failure, DriveError>> {
    match backend.get(key, inm.map(Etag).as_ref(), max) {
        Ok(Get::Found { bytes, etag }) => Ok(Fetched::Found {
            bytes,
            etag: etag.0,
        }),
        Ok(Get::NotModified) => Ok(Fetched::NotModified),
        Ok(Get::NotFound) => Ok(Fetched::NotFound),
        Err(StoreError::TooLarge { .. }) => Err(Err(DriveError::Core(vlt_core::Error::Integrity(
            vlt_core::IntegrityKind::SizeLimit,
        )))),
        Err(e) => Err(Ok(failure(&e))),
    }
}

fn object_key(id: &[u8; 16]) -> String {
    format!("e/{}", hex::encode(id))
}

fn fetch_one(
    backend: &dyn Backend,
    mirror: &Mirror,
    id: &[u8; 16],
    source: Source,
) -> Result<Result<ObjectFetch, Failure>, DriveError> {
    if source == Source::MirrorThenBackend
        && let Some(b) = mirror.object(id).map_err(DriveError::Mirror)?
    {
        return Ok(Ok(ObjectFetch::Found {
            bytes: b,
            from_mirror: true,
        }));
    }
    match backend.get(&object_key(id), None, ENTRY_OBJECT_MAX) {
        Ok(Get::Found { bytes, .. }) => Ok(Ok(ObjectFetch::Found {
            bytes,
            from_mirror: false,
        })),
        Ok(Get::NotFound) => Ok(Ok(ObjectFetch::NotFound)),
        Ok(Get::NotModified) => Ok(Ok(ObjectFetch::Unavailable)),
        Err(StoreError::TooLarge { .. }) => Err(DriveError::Core(vlt_core::Error::Integrity(
            vlt_core::IntegrityKind::SizeLimit,
        ))),
        Err(e) if e.is_offline() => Ok(Ok(ObjectFetch::Unavailable)),
        Err(e) => Ok(Err(failure(&e))),
    }
}

/// Run `f` over `items` with up to [`PARALLEL`] threads, keeping order.
fn parallel<T: Sync, R: Send>(items: &[T], f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    if items.len() <= 1 {
        return items.iter().map(&f).collect();
    }
    let chunk = items.len().div_ceil(PARALLEL);
    std::thread::scope(|s| {
        let handles: Vec<_> = items
            .chunks(chunk)
            .map(|c| s.spawn(|| c.iter().map(&f).collect::<Vec<R>>()))
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("driver worker panicked"))
            .collect()
    })
}

fn jitter(max: Duration) -> Duration {
    let mut b = [0u8; 8];
    if getrandom::fill(&mut b).is_err() {
        return max;
    }
    let n = u64::from_le_bytes(b);
    let ms = max.as_millis() as u64;
    Duration::from_millis(if ms == 0 { 0 } else { n % (ms + 1) })
}

/// Run one sync to completion. `unlock` opens a header with this device's private keys
/// (`parse_header` then `unlock_with_device`); it is the only place device secrets are used.
pub fn sync_once(
    vault: &mut Vault,
    opts: SyncOptions,
    backend: &dyn Backend,
    mirror: &Mirror,
    unlock: &Unlock<'_>,
    dopts: DriverOptions,
) -> Result<SyncReport, DriveError> {
    let mut s = vault.sync(opts);
    let mut action = s.start()?;
    loop {
        let resp = match action {
            Action::Done(r) => return Ok(r),
            Action::GetIndex { if_none_match } => {
                match get(backend, "index", if_none_match, INDEX_MAX) {
                    Ok(f) => Response::Index(f),
                    Err(Ok(f)) => Response::Failed(f),
                    Err(Err(e)) => return Err(e),
                }
            }
            Action::GetHeader { if_none_match } => {
                match get(backend, "header", if_none_match, HEADER_MAX) {
                    Ok(f) => Response::Header(f),
                    Err(Ok(f)) => Response::Failed(f),
                    Err(Err(e)) => return Err(e),
                }
            }
            Action::Unlock { header } => match unlock(&header) {
                Ok(x) => Response::Unlocked(Box::new(x)),
                Err(vlt_core::Error::WrongPasswordOrUnknownDevice) => Response::UnlockFailed,
                Err(e) => return Err(e.into()),
            },
            Action::GetObjects { ids, source } => {
                let rs = parallel(&ids, |id| fetch_one(backend, mirror, id, source));
                let mut out = Vec::with_capacity(ids.len());
                let mut failed = None;
                for (id, r) in ids.into_iter().zip(rs) {
                    match r? {
                        Ok(f) => out.push((id, f)),
                        Err(f) => {
                            failed.get_or_insert(f);
                        }
                    }
                }
                match failed {
                    Some(f) => Response::Failed(f),
                    None => Response::Objects(out),
                }
            }
            Action::PutObjects { objects } => {
                let rs = parallel(&objects, |(id, b)| backend.create(&object_key(id), b));
                let mut out = Vec::with_capacity(objects.len());
                let mut failed = None;
                for ((id, _), r) in objects.iter().zip(rs) {
                    match r {
                        Ok(Put::Written { etag }) => {
                            out.push((*id, Stored::Written { etag: etag.0 }))
                        }
                        Ok(Put::PreconditionFailed) => out.push((*id, Stored::PreconditionFailed)),
                        Err(e) => {
                            failed.get_or_insert(failure(&e));
                        }
                    }
                }
                match failed {
                    Some(f) => Response::Failed(f),
                    None => Response::Stored(out),
                }
            }
            Action::PutIndex { index, if_match } => {
                match backend.replace("index", &index, &Etag(if_match)) {
                    Ok(Put::Written { etag }) => {
                        Response::IndexStored(Stored::Written { etag: etag.0 })
                    }
                    Ok(Put::PreconditionFailed) => {
                        Response::IndexStored(Stored::PreconditionFailed)
                    }
                    Err(e) => Response::Failed(failure(&e)),
                }
            }
            Action::Backoff { attempt } => {
                let max = dopts
                    .backoff_base
                    .saturating_mul(1u32 << attempt.saturating_sub(1).min(10));
                std::thread::sleep(jitter(max));
                Response::Waited
            }
            Action::Commit(c) => {
                mirror.apply(&c).map_err(DriveError::Mirror)?;
                Response::Committed
            }
        };
        action = s.feed(resp)?;
    }
}

/// After a sync: update retention bookkeeping, confirm purges with the backend, delete what the
/// mirror no longer keeps, and write the state.
///
/// `store_ok` is the caller's proof that the backend was healthy in this run: set it only from a
/// [`SyncReport`] with no `failure` that is not `offline`. Without it, purge checks wait for a later
/// run, because a `404` from a misbehaving backend must not delete history. For the same reason, if
/// any check in this run fails, no `404` from this run is trusted.
pub fn prune(
    vault: &mut Vault,
    backend: &dyn Backend,
    mirror: &Mirror,
    now: i64,
    store_ok: bool,
) -> Result<(), DriveError> {
    // Files no state records (a write interrupted before its state) join retention as local,
    // unreachable objects. A file that does not open as this vault's object is left alone.
    for id in mirror.object_ids().map_err(DriveError::Mirror)? {
        if vault.state().object(&id).is_none()
            && let Some(bytes) = mirror.object(&id).map_err(DriveError::Mirror)?
        {
            let _ = vault.record_stray(&id, &bytes, now);
        }
    }
    let plan = vault.refresh_retention(now);
    if store_ok && !plan.check_gone.is_empty() {
        let rs = parallel(&plan.check_gone, |id| backend.exists(&object_key(id)));
        let trust_gone = rs.iter().all(Result::is_ok);
        for (id, r) in plan.check_gone.iter().zip(rs) {
            match r {
                Ok(true) => vault.mark_present(id),
                Ok(false) if trust_gone => {
                    vault.mark_purged(id);
                    mirror.delete_object(id).map_err(DriveError::Mirror)?;
                }
                Ok(false) | Err(_) => {}
            }
        }
    }
    let state = vault.commit()?;
    mirror.write_state(&state).map_err(DriveError::Mirror)?;
    for id in &plan.delete {
        mirror.delete_object(id).map_err(DriveError::Mirror)?;
    }
    Ok(())
}

/// Fill a `full` mirror's history, in batches of `batch` objects, until it is complete or the
/// backend is unreachable. Returns how many objects were fetched.
pub fn fill_history(
    vault: &mut Vault,
    backend: &dyn Backend,
    mirror: &Mirror,
    batch: usize,
) -> Result<usize, DriveError> {
    let mut fetched = 0;
    loop {
        let need = vault.history_missing(batch);
        if need.is_empty() {
            return Ok(fetched);
        }
        let rs = parallel(&need, |n| {
            backend.get(&object_key(&n.object_id), None, ENTRY_OBJECT_MAX)
        });
        let mut objects = Vec::new();
        for (n, r) in need.iter().zip(rs) {
            match r {
                Ok(Get::Found { bytes, .. }) => {
                    vault.add_history(n, Some(&bytes))?;
                    objects.push((n.object_id, bytes));
                    fetched += 1;
                }
                Ok(Get::NotFound) => vault.add_history(n, None)?,
                Ok(Get::NotModified) => {}
                Err(StoreError::TooLarge { .. }) => {
                    return Err(
                        vlt_core::Error::Integrity(vlt_core::IntegrityKind::SizeLimit).into(),
                    );
                }
                Err(_) => {
                    let state = vault.commit()?;
                    mirror
                        .apply(&vlt_core::session::Commit {
                            objects,
                            header: None,
                            index: None,
                            state,
                        })
                        .map_err(DriveError::Mirror)?;
                    return Ok(fetched);
                }
            }
        }
        let state = vault.commit()?;
        mirror
            .apply(&vlt_core::session::Commit {
                objects,
                header: None,
                index: None,
                state,
            })
            .map_err(DriveError::Mirror)?;
    }
}
