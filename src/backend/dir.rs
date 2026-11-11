//! The file backend: every script as plain files under a directory the host chooses.
//!
//! This is the one place the crate touches a disk, and it does so only because a host chose
//! [`DirBackend`] and handed it a directory. Nothing else in the crate opens a path. The
//! reason the atoms keep their own state at all, rather than composing over `urn:file:*` or a
//! store graph, is in the [parent module's documentation](super).
//!
//! Hypothesis H (ledger #2384) names this module as one exception, here at the top, so a new
//! file operation anywhere else in the crate is still a violation the gate reports.
// ambient: fs: the host-chosen file backend; it touches only the directory the host passed to DirBackend::open
#![allow(clippy::disallowed_methods)]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use ikigai_core::{Error, Result};
use serde::{Deserialize, Serialize};

use super::{conflict, Backend};
use crate::model::{Head, Language, Run, Version, SCHEMA};

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
/// the [module documentation](super).
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
    /// Absent when the version declares no budget, so a file written before `budget` existed
    /// reads as it did, and one that declares none is written as it was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    budget: Option<u64>,
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
            .filter(|h| {
                h.len() == 64
                    && h.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
            .ok_or_else(|| Error::InvalidArgument {
                name: "digest".to_string(),
                detail: format!(
                    "`{digest}` is not a version digest for urn:script:{name}; \
                     use `sha256:` and 64 lowercase hex digits"
                ),
            })?;
        Ok(self.dir(name).join("versions").join(format!("{hex}.json")))
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
                .and_then(crate::name::run_id)
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
                budget: version.budget,
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
            budget: file.budget,
            source: file.source,
        };
        if version.digest() != digest {
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
            // Publish a complete file only if the id is still free. A hand-written
            // record that arrives after last_run_id wins without being overwritten.
            if write_new_json(&path, &Run { id, ..run.clone() })? {
                return Ok(id);
            }
            id += 1;
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

/// Publish a complete record without replacing an existing destination. The hard link
/// makes checking absence and publishing one atomic operation; a plain rename could
/// overwrite a record that appeared while the temporary file was being written.
fn write_new_json<T: Serialize>(path: &Path, value: &T) -> Result<bool> {
    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    let bytes = to_json(value)?;
    let (tmp, mut file) = loop {
        let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let tmp = path.with_extension(format!("json.{}.{serial}.tmp", std::process::id()));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
        {
            Ok(file) => break (tmp, file),
            // A stale temporary file from a stopped host is never reused.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(io_error(&tmp, "create", &e)),
        }
    };
    let result = (|| {
        file.write_all(&bytes)
            .map_err(|e| io_error(&tmp, "write", &e))?;
        drop(file);
        match fs::hard_link(&tmp, path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(e) => Err(io_error(path, "create", &e)),
        }
    })();
    // A crash can leave this non-record temporary file behind, but readers ignore it.
    let _ = fs::remove_file(tmp);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publishing_a_new_record_does_not_replace_an_occupied_destination() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("occupied-run-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("1.json");
        fs::write(&path, "an editor's record").unwrap();
        assert!(!write_new_json(&path, &"new record").unwrap());
        assert_eq!(fs::read_to_string(&path).unwrap(), "an editor's record");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        fs::remove_dir_all(root).unwrap();
    }
}
