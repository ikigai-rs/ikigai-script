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
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use ikigai_core::{Error, Result};
use serde::{Deserialize, Serialize};

use crate::model::{Head, Language, Run, Version, SCHEMA};

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

/// Every script as plain files under one directory the host chooses:
///
/// ```text
/// <root>/<name>/head.json               the head (compare-and-set on every write)
/// <root>/<name>/versions/<hex>.json     one immutable version, named by its sha256
/// <root>/<name>/runs/<id>.json          one run record
/// ```
///
/// **One host process per directory**, the rule `ikigai-store` states for RocksDB: writes
/// are serialized by a lock in this process, and a second process writing the same
/// directory would race it. People editing files by hand are expected and survivable; see
/// the [module documentation](self).
pub struct DirBackend {
    root: PathBuf,
    write: Mutex<()>,
}

/// A version as it is written to disk.
#[derive(Serialize, Deserialize)]
struct VersionFile {
    schema: u32,
    language: Language,
    requires: std::collections::BTreeSet<String>,
    source: String,
}

impl DirBackend {
    /// Open (creating it if needed) the directory `root`.
    pub fn open(root: impl Into<PathBuf>) -> Result<DirBackend> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(|e| io_error(&root, "create", &e))?;
        Ok(DirBackend {
            root,
            write: Mutex::new(()),
        })
    }

    /// The directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn dir(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    fn head_path(&self, name: &str) -> PathBuf {
        self.dir(name).join("head.json")
    }

    fn version_path(&self, name: &str, digest: &str) -> Result<PathBuf> {
        let hex = digest
            .strip_prefix("sha256:")
            .filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or_else(|| Error::InvalidArgument {
                name: "digest".to_string(),
                detail: format!("`{digest}` is not `sha256:` and 64 hex digits"),
            })?;
        Ok(self
            .dir(name)
            .join("versions")
            .join(format!("{}.json", hex.to_ascii_lowercase())))
    }

    fn run_path(&self, name: &str, id: u64) -> PathBuf {
        self.dir(name).join("runs").join(format!("{id}.json"))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.write.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn read_head(&self, name: &str) -> Result<Option<Head>> {
        let path = self.head_path(name);
        match read_json::<Head>(&path)? {
            Some(head) if head.name != name => Err(Error::Endpoint(format!(
                "{} names the script `{}`, not `{name}` (edited or moved out of band)",
                path.display(),
                head.name
            ))),
            other => Ok(other),
        }
    }

    /// The highest run id on disk for `name` (0 when none).
    fn last_run_id(&self, name: &str) -> Result<u64> {
        let dir = self.dir(name).join("runs");
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(io_error(&dir, "list", &e)),
        };
        let mut last = 0;
        for entry in entries {
            let entry = entry.map_err(|e| io_error(&dir, "list", &e))?;
            let file = entry.file_name();
            if let Some(id) = file
                .to_str()
                .and_then(|f| f.strip_suffix(".json"))
                .and_then(|stem| stem.parse::<u64>().ok())
            {
                last = last.max(id);
            }
        }
        Ok(last)
    }
}

impl Backend for DirBackend {
    fn head(&self, name: &str) -> Result<Option<Head>> {
        self.read_head(name)
    }

    fn swap_head(&self, name: &str, expected: Option<&Head>, new: &Head) -> Result<()> {
        let _guard = self.lock();
        // Read again under the lock: whatever is on disk NOW is what an editor left.
        let current = match self.read_head(name) {
            Ok(current) => current,
            // A head someone broke by hand cannot match what the writer read.
            Err(_) if expected.is_some() => return Err(conflict(name)),
            Err(e) => return Err(e),
        };
        if current.as_ref() != expected {
            return Err(conflict(name));
        }
        write_json(&self.head_path(name), new)
    }

    fn put_version(&self, name: &str, version: &Version) -> Result<()> {
        let path = self.version_path(name, &version.digest())?;
        let _guard = self.lock();
        // Rewritten even when present: a version file someone damaged by hand is repaired
        // by publishing the same content again, which is the natural thing to try.
        write_json(
            &path,
            &VersionFile {
                schema: SCHEMA,
                language: version.language,
                requires: version.requires.clone(),
                source: version.source.clone(),
            },
        )
    }

    fn version(&self, name: &str, digest: &str) -> Result<Option<Version>> {
        let path = self.version_path(name, digest)?;
        let Some(file) = read_json::<VersionFile>(&path)? else {
            return Ok(None);
        };
        let version = Version {
            language: file.language,
            requires: file.requires,
            source: file.source,
        };
        if version.digest() != digest.to_ascii_lowercase() {
            return Err(Error::Endpoint(format!(
                "{} does not match the digest it is named by (edited out of band); this \
                 version cannot be trusted. Publish the content again to restore it",
                path.display()
            )));
        }
        Ok(Some(version))
    }

    fn names(&self) -> Result<Vec<String>> {
        let entries = fs::read_dir(&self.root).map_err(|e| io_error(&self.root, "list", &e))?;
        let mut names = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| io_error(&self.root, "list", &e))?;
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            // Anything that is not a script directory (a stray file, an editor's backup)
            // is not a script; it is skipped, not an error.
            if crate::name::validate(&name).is_ok() && self.head_path(&name).is_file() {
                names.push(name);
            }
        }
        names.sort();
        Ok(names)
    }

    fn start_run(&self, name: &str, run: &Run) -> Result<u64> {
        let _guard = self.lock();
        let mut id = self.last_run_id(name)? + 1;
        loop {
            let path = self.run_path(name, id);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|e| io_error(parent, "create", &e))?;
            }
            let bytes = to_json(&Run { id, ..run.clone() })?;
            // `create_new`: an id is taken by whoever creates its file first, so a record
            // written by hand (or by another process, against the rule) is never
            // overwritten; the next id is tried instead.
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut file) => {
                    file.write_all(&bytes)
                        .map_err(|e| io_error(&path, "write", &e))?;
                    return Ok(id);
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => id += 1,
                Err(e) => return Err(io_error(&path, "create", &e)),
            }
        }
    }

    fn finish_run(&self, name: &str, run: &Run) -> Result<()> {
        let _guard = self.lock();
        write_json(&self.run_path(name, run.id), run)
    }

    fn run(&self, name: &str, id: u64) -> Result<Option<Run>> {
        read_json(&self.run_path(name, id))
    }

    fn last_run(&self, name: &str) -> Result<Option<Run>> {
        match self.last_run_id(name)? {
            0 => Ok(None),
            id => self.run(name, id),
        }
    }
}

fn io_error(path: &Path, what: &str, e: &std::io::Error) -> Error {
    Error::Unavailable(format!("could not {what} {}: {e}", path.display()))
}

fn to_json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|e| Error::Endpoint(format!("could not serialize a record: {e}")))?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Read and parse `path`; `None` when it does not exist. A file that does not parse is an
/// error naming the file, never a silent absence.
fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<T>> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io_error(path, "read", &e)),
    };
    serde_json::from_slice(&bytes).map(Some).map_err(|e| {
        Error::Endpoint(format!(
            "{} is not a record this crate wrote (edited out of band?): {e}",
            path.display()
        ))
    })
}

/// Write `value` to `path` atomically: a sibling temporary file, then a rename, so a
/// reader (or a crash) never sees half a record.
fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::Endpoint(format!("{} has no parent directory", path.display())))?;
    fs::create_dir_all(parent).map_err(|e| io_error(parent, "create", &e))?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, to_json(value)?).map_err(|e| io_error(&tmp, "write", &e))?;
    fs::rename(&tmp, path).map_err(|e| io_error(path, "replace", &e))
}
