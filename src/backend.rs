//! Where the atoms' state lives: a [`Backend`] the host chooses.
//!
//! # Why the state is held here, and not composed over `ikigai-store` or `urn:file:`
//!
//! The obvious design is the ledger's: author every read and write as a sub-request to a
//! store's named graph (or to the host's file workspace through `urn:file:*`), and own no
//! bytes. It does not work for scripts, and the reason is the kernel's own rule: **a
//! sub-request carries the caller's capability unchanged** (`Invocation::issue`). Whatever
//! this crate writes on a caller's behalf, the caller must hold the grant to write
//! directly — and here the record IS the authority:
//!
//! - every **publisher** would hold write over the graph (or file) that stores a script's
//!   granted-at-publish snapshot, so a publisher could rewrite their own snapshot through
//!   `urn:iki:store:graph-update` and have their script run with grants they never held.
//!   That is exactly the elevation this crate exists to rule out.
//! - every **runner** records a run, so every runner — the anonymous principal included,
//!   for a public script — would hold store write. An unauthenticated door holding write
//!   over the run log can forge the log.
//!
//! So the atoms hold their own state, behind this trait, and nothing but this crate's
//! endpoints write it. No caller needs a storage grant, and no storage grant reaches an
//! authority record. The golden threads are still the kernel's: a Sink or Delete to
//! `urn:script:{name}` cuts the thread named after it, and every derived read hangs from
//! that thread.
//!
//! # Out-of-band edits are survivable
//!
//! [`DirBackend`] keeps plain files a person can read and edit, and assumes an editor got
//! there first:
//!
//! - a head is replaced by compare-and-set against the head the writer READ, so a hand
//!   edit in between is a typed `Conflict`, never a lost update;
//! - a version file is checked against the digest it is named by on every read, so an
//!   edited version is refused by name ("edited out of band") and every other version and
//!   script still works;
//! - a malformed head fails that script alone, with the file named; the catalog lists it
//!   as broken rather than failing whole.
//!
//! What it cannot do is SEE an edit: a read the kernel cached before the edit is served
//! until the host cuts `urn:script:{name}` (a watcher on the directory, or
//! `sink urn:kernel:cut urn:script:{name}`), the same contract every file-backed resource
//! has. A hand edit is the host operator's act — the same trust as the ceiling files in
//! the config home — and the run-time intersection with the stored snapshot and the
//! host's ceiling still holds whatever the files say.

use std::collections::BTreeMap;
use std::sync::Mutex;

use ikigai_core::{Error, Result};

use crate::model::{Head, Run, Version};

mod dir;

pub use dir::DirBackend;

/// Where a host keeps its scripts. Every method is called from inside an endpoint, so an
/// implementation must not block for long; both built-ins are synchronous and local.
pub trait Backend: Send + Sync {
    /// The head of `name`, or `None` when no such script exists.
    fn head(&self, name: &str) -> Result<Option<Head>>;

    /// Replace the head of `name` with `new`, **if** it is still `expected` (`None`: if no
    /// head exists yet). Otherwise a typed `Conflict`: someone got there first.
    fn swap_head(&self, name: &str, expected: Option<&Head>, new: &Head) -> Result<()>;

    /// Store a version under `name`. Idempotent: a version is its content.
    fn put_version(&self, name: &str, version: &Version) -> Result<()>;

    /// The version `digest` of `name`, or `None`. An implementation verifies the content
    /// against the digest and refuses a mismatch.
    fn version(&self, name: &str, digest: &str) -> Result<Option<Version>>;

    /// Every script name that has a head, sorted.
    fn names(&self) -> Result<Vec<String>>;

    /// Record a run that is starting, under a fresh id (the `id` field is ignored), and
    /// return the id.
    fn start_run(&self, name: &str, run: &Run) -> Result<u64>;

    /// Replace the record of a run already started.
    fn finish_run(&self, name: &str, run: &Run) -> Result<()>;

    /// Run `id` of `name`, or `None`.
    fn run(&self, name: &str, id: u64) -> Result<Option<Run>>;

    /// The run of `name` with the highest id, or `None`.
    fn last_run(&self, name: &str) -> Result<Option<Run>>;
}

fn conflict(name: &str) -> Error {
    Error::Conflict(format!(
        "urn:script:{name} changed while this write was being prepared (another writer, \
         or an edit out of band); read it again and retry"
    ))
}

/// Every script in memory: for tests, and for hosts whose scripts are configuration that
/// is published again at every start.
#[derive(Default)]
pub struct MemoryBackend {
    scripts: Mutex<BTreeMap<String, Entry>>,
}

#[derive(Default)]
struct Entry {
    head: Option<Head>,
    versions: BTreeMap<String, Version>,
    runs: BTreeMap<u64, Run>,
}

impl MemoryBackend {
    /// An empty backend.
    pub fn new() -> MemoryBackend {
        MemoryBackend::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Entry>> {
        // A panic while holding the lock leaves plain data behind, never a half-written
        // invariant (every mutation is a single insert), so a poisoned lock is still good.
        self.scripts.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl Backend for MemoryBackend {
    fn head(&self, name: &str) -> Result<Option<Head>> {
        Ok(self.lock().get(name).and_then(|e| e.head.clone()))
    }

    fn swap_head(&self, name: &str, expected: Option<&Head>, new: &Head) -> Result<()> {
        let mut scripts = self.lock();
        let entry = scripts.entry(name.to_string()).or_default();
        if entry.head.as_ref() != expected {
            return Err(conflict(name));
        }
        entry.head = Some(new.clone());
        Ok(())
    }

    fn put_version(&self, name: &str, version: &Version) -> Result<()> {
        self.lock()
            .entry(name.to_string())
            .or_default()
            .versions
            .insert(version.digest(), version.clone());
        Ok(())
    }

    fn version(&self, name: &str, digest: &str) -> Result<Option<Version>> {
        Ok(self
            .lock()
            .get(name)
            .and_then(|e| e.versions.get(digest).cloned()))
    }

    fn names(&self) -> Result<Vec<String>> {
        Ok(self
            .lock()
            .iter()
            .filter(|(_, e)| e.head.is_some())
            .map(|(n, _)| n.clone())
            .collect())
    }

    fn start_run(&self, name: &str, run: &Run) -> Result<u64> {
        let mut scripts = self.lock();
        let runs = &mut scripts.entry(name.to_string()).or_default().runs;
        let id = runs.keys().next_back().map_or(1, |last| last + 1);
        runs.insert(id, Run { id, ..run.clone() });
        Ok(id)
    }

    fn finish_run(&self, name: &str, run: &Run) -> Result<()> {
        self.lock()
            .entry(name.to_string())
            .or_default()
            .runs
            .insert(run.id, run.clone());
        Ok(())
    }

    fn run(&self, name: &str, id: u64) -> Result<Option<Run>> {
        Ok(self.lock().get(name).and_then(|e| e.runs.get(&id).cloned()))
    }

    fn last_run(&self, name: &str) -> Result<Option<Run>> {
        Ok(self
            .lock()
            .get(name)
            .and_then(|e| e.runs.values().next_back().cloned()))
    }
}
