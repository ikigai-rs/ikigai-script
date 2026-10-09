//! What the atoms hold: a script's head, its immutable versions, and its runs.
//!
//! These are also the machine faces (`as=application/json`): one serde shape for the disk
//! and the wire, carrying `"schema": 1` so a consumer can tell a future shape apart.

use std::collections::BTreeSet;

use ikigai_core::{Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::authority::CAP_LISP;

/// The version of every JSON shape this crate writes.
pub const SCHEMA: u32 = 1;

/// The languages a script can be written in. Lisp only in this phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    /// Steel Scheme, evaluated by `ikigai-lisp` at `urn:lisp:eval`.
    Lisp,
}

impl Language {
    /// Every language, in the order `language=` offers them.
    pub const ALL: [Language; 1] = [Language::Lisp];

    /// The word `language=` takes and every face shows.
    pub fn as_str(self) -> &'static str {
        match self {
            Language::Lisp => "lisp",
        }
    }

    /// Parse `language=`.
    pub fn parse(text: &str) -> Result<Language> {
        match text.trim() {
            "lisp" => Ok(Language::Lisp),
            other => Err(Error::InvalidArgument {
                name: "language".to_string(),
                detail: format!("`{other}` is not a script language here; only `lisp`"),
            }),
        }
    }

    /// The evaluator a run issues its sub-request to: the language is a resource, so this
    /// crate links no interpreter.
    pub fn evaluator(self) -> &'static str {
        match self {
            Language::Lisp => "urn:lisp:eval",
        }
    }

    /// The capability the evaluator requires. Every script in this language declares it
    /// implicitly: evaluating code is itself authority, so a publisher who may not run
    /// Lisp may not publish Lisp for others to run.
    pub fn capability(self) -> &'static str {
        match self {
            Language::Lisp => CAP_LISP,
        }
    }
}

/// A script's lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    /// Saved, not runnable: readable by holders of the script's read grant only.
    Draft,
    /// Runnable.
    Published,
    /// Retired by a Delete: still readable, versions still fetchable, never runnable.
    Retired,
}

impl State {
    /// The word every face shows.
    pub fn as_str(self) -> &'static str {
        match self {
            State::Draft => "draft",
            State::Published => "published",
            State::Retired => "retired",
        }
    }
}

/// One immutable version: the content a digest names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version {
    /// Its language.
    pub language: Language,
    /// The capability it declares it needs, its language's included.
    pub requires: BTreeSet<String>,
    /// The source text.
    pub source: String,
}

impl Version {
    /// The bytes the digest is taken over:
    ///
    /// ```text
    /// ikigai-script/1\n
    /// language <language>\n
    /// requires <scope>\n        (one line per scope, sorted)
    /// \n
    /// <source>
    /// ```
    ///
    /// A scope contains no whitespace and the source comes last, so the framing is
    /// unambiguous without escaping anything.
    pub fn canonical(&self) -> Vec<u8> {
        let mut out = format!("ikigai-script/1\nlanguage {}\n", self.language.as_str());
        for scope in &self.requires {
            out.push_str("requires ");
            out.push_str(scope);
            out.push('\n');
        }
        out.push('\n');
        out.push_str(&self.source);
        out.into_bytes()
    }

    /// The version's name: `sha256:` and 64 lowercase hex digits over [`canonical`].
    ///
    /// ```
    /// use ikigai_script::model::{Language, Version};
    /// let v = Version {
    ///     language: Language::Lisp,
    ///     requires: ["urn:cap:lisp".to_string()].into_iter().collect(),
    ///     source: "(+ 1 2)".to_string(),
    /// };
    /// let digest = v.digest();
    /// assert!(digest.starts_with("sha256:"));
    /// assert_eq!(digest.len(), "sha256:".len() + 64);
    /// assert!(digest["sha256:".len()..].bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    /// // Content-addressed: the same content is the same version.
    /// assert_eq!(digest, v.clone().digest());
    /// ```
    ///
    /// [`canonical`]: Version::canonical
    pub fn digest(&self) -> String {
        let hash = Sha256::digest(self.canonical());
        let mut out = String::with_capacity(7 + 64);
        out.push_str("sha256:");
        for byte in hash {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    /// The JSON face of this version under `name`.
    pub fn document(&self, name: &str) -> VersionDocument {
        let digest = self.digest();
        VersionDocument {
            schema: SCHEMA,
            iri: crate::name::version_iri(name, &digest),
            script: crate::name::script_iri(name),
            version: digest,
            language: self.language,
            requires: self.requires.clone(),
            source: self.source.clone(),
        }
    }
}

/// A version's JSON face.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionDocument {
    /// [`SCHEMA`].
    pub schema: u32,
    /// `urn:script:{name}:version:{digest}`.
    pub iri: String,
    /// `urn:script:{name}`.
    pub script: String,
    /// `sha256:…`.
    pub version: String,
    /// Its language.
    pub language: Language,
    /// What it declares it needs.
    pub requires: BTreeSet<String>,
    /// The source text.
    pub source: String,
}

/// One change to a script's head: what its history is made of.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// `publish`, `draft` or `retire`.
    pub action: String,
    /// The version the head pointed at afterwards.
    pub version: String,
    /// The state afterwards.
    pub state: State,
    /// Whether it was public afterwards.
    pub public: bool,
    /// Who, as the host stamped it.
    pub principal: String,
    /// When, in milliseconds since the epoch, from the kernel's clock (`None` on a
    /// clockless kernel).
    pub at: Option<u64>,
}

/// A script's head: the mutable atom `urn:script:{name}` names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Head {
    /// [`SCHEMA`].
    pub schema: u32,
    /// The script's name.
    pub name: String,
    /// The version it points at.
    pub version: String,
    /// Its state.
    pub state: State,
    /// Whether it is public: runnable by holders of
    /// [`CAP_RUN_PUBLIC`](crate::authority::CAP_RUN_PUBLIC) and readable by holders of
    /// [`CAP_READ_PUBLIC`](crate::authority::CAP_READ_PUBLIC), once published.
    pub public: bool,
    /// The part of the version's `requires` its publisher held when they published it.
    pub granted: BTreeSet<String>,
    /// Every exclusion the publisher's capability carried then.
    pub exclusions: BTreeSet<String>,
    /// Who published the version the head points at.
    pub publisher: String,
    /// When the head last changed.
    pub updated: Option<u64>,
    /// Every change, oldest first.
    pub history: Vec<Event>,
}

/// How a run ended.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", tag = "status")]
pub enum Outcome {
    /// Not finished. A run that stays here after its host stopped was abandoned.
    Running,
    /// Finished with an answer.
    Ok,
    /// Finished with an error.
    Failed {
        /// The error's kind: `denied`, `not-found`, `conflict`, `invalid-argument`,
        /// `timeout`, `unavailable`, `endpoint`, …
        kind: String,
        /// The error, as text.
        message: String,
    },
}

/// The longest result a run record keeps; a longer one is cut there and marked.
pub const MAX_RECORDED_RESULT: usize = 64 * 1024;

/// One run: the atom `urn:script:{name}:run:{id}` names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Run {
    /// [`SCHEMA`].
    pub schema: u32,
    /// The script.
    pub name: String,
    /// Its number, unique per script, in order of starting.
    pub id: u64,
    /// The version that ran.
    pub version: String,
    /// Who ran it, as the host stamped it — never caller-supplied.
    pub principal: String,
    /// The capability the run executed under, exactly: grants and exclusions.
    pub capability: BTreeSet<String>,
    /// When it started, from the kernel's clock.
    pub started: Option<u64>,
    /// When it ended.
    pub ended: Option<u64>,
    /// How it ended.
    pub outcome: Outcome,
    /// What it answered, as text, up to [`MAX_RECORDED_RESULT`] bytes.
    pub result: Option<String>,
    /// Whether `result` was cut.
    pub truncated: bool,
    /// The trace span the host's tracer gave the run's request, when the host traced it:
    /// the key into the host's trace, which holds every verb the script issued.
    pub trace_span: Option<u64>,
}

impl Run {
    /// Its IRI.
    pub fn iri(&self) -> String {
        crate::name::run_iri(&self.name, self.id)
    }

    /// The plain face: one fact per line.
    pub fn render(&self) -> String {
        let outcome = match &self.outcome {
            Outcome::Running => "running".to_string(),
            Outcome::Ok => "ok".to_string(),
            Outcome::Failed { kind, message } => format!("failed ({kind}): {message}"),
        };
        let mut text = format!(
            "{}\n  script:     {}\n  version:    {}\n  principal:  {}\n  started:    {}\n  \
             ended:      {}\n  outcome:    {outcome}\n  capability: {}\n",
            self.iri(),
            crate::name::script_iri(&self.name),
            self.version,
            self.principal,
            when(self.started),
            when(self.ended),
            if self.capability.is_empty() {
                "(none)".to_string()
            } else {
                self.capability
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(" ")
            },
        );
        if let Some(span) = self.trace_span {
            text.push_str(&format!("  trace span: {span}\n"));
        }
        if let Some(result) = &self.result {
            text.push_str(&format!(
                "  result{}:\n{result}\n",
                if self.truncated { " (truncated)" } else { "" }
            ));
        }
        text
    }
}

/// A timestamp for the plain faces: `xsd:dateTime` in UTC, or a note that the kernel had
/// no clock.
///
/// ```
/// use ikigai_script::model::when;
/// assert_eq!(when(Some(1_789_430_400_000)), "2026-09-15T00:00:00.000Z");
/// assert_eq!(when(Some(0)), "1970-01-01T00:00:00.000Z");
/// assert_eq!(when(None), "unstamped (the kernel has no clock)");
/// ```
pub fn when(millis: Option<u64>) -> String {
    let Some(millis) = millis else {
        return "unstamped (the kernel has no clock)".to_string();
    };
    let secs = millis / 1000;
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Howard Hinnant's civil-from-days, over days since 1970-01-01.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        millis % 1000
    )
}

/// Cut `text` to at most `max` bytes on a character boundary; whether it was cut.
pub(crate) fn truncate(mut text: String, max: usize) -> (String, bool) {
    if text.len() <= max {
        return (text, false);
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    (text, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_and_language_are_part_of_the_content() {
        let a = Version {
            language: Language::Lisp,
            requires: BTreeSet::new(),
            source: "(+ 1 2)".to_string(),
        };
        let mut b = a.clone();
        b.requires.insert("urn:cap:lisp".to_string());
        assert_ne!(a.digest(), b.digest());
    }

    #[test]
    fn truncation_respects_characters() {
        let (text, cut) = truncate("héllo".to_string(), 2);
        assert_eq!((text.as_str(), cut), ("h", true));
        let (text, cut) = truncate("abc".to_string(), 3);
        assert_eq!((text.as_str(), cut), ("abc", false));
    }
}
