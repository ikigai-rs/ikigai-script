//! Script names and the IRIs built from them.
//!
//! A script is named by one segment, `urn:script:{name}`, and everything about it hangs
//! below that name: `…:version:{digest}`, `…:compiled`, `…:result`, `…:runs` and
//! `…:run:{id}`. The name is a segment of the IRI rather than an argument so that a
//! capability can bind to it (`urn:cap:script:run:{name}`), which is the same reason
//! `ikigai-ledger` names its ledgers.
//!
//! ```
//! use ikigai_script::name;
//!
//! assert_eq!(name::script_iri("nightly"), "urn:script:nightly");
//! assert_eq!(
//!     name::version_iri("nightly", "sha256:ab"),
//!     "urn:script:nightly:version:sha256:ab"
//! );
//! assert_eq!(name::run_iri("nightly", 7), "urn:script:nightly:run:7");
//! assert!(name::validate("nightly-report_2").is_ok());
//! assert!(name::validate("Nightly").is_err()); // lowercase only
//! assert!(name::validate("a:b").is_err()); // one segment
//! assert!(name::validate("eval").is_err()); // reserved: `urn:script:eval` is the paste box
//! ```

use ikigai_core::{Error, Invocation, Result};

/// Every script IRI starts here.
pub const PREFIX: &str = "urn:script:";

/// The ad hoc door: run supplied code under the caller's own authority.
pub const EVAL_IRI: &str = "urn:script:eval";

/// The catalog: what is registered, its state, head version and last run.
///
/// ★ Not `urn:host:scripts`. `urn:host:*` is the HOST's namespace (`urn:host:info`,
/// `urn:host:identity`, `urn:host:arrangement` in ikigai-cli), and a library binding
/// into it would collide with whatever host mounts it. A host that wants the design's
/// `urn:host:scripts` aliases it to this name.
pub const CATALOG_IRI: &str = "urn:script:catalog";

/// Names a script may not take, because a resource already answers there or because
/// the name means something to the capability grammar.
///
/// - `eval` and `catalog` are [`EVAL_IRI`] and [`CATALOG_IRI`].
/// - `public` is the parameter of [`crate::authority::CAP_RUN_PUBLIC`] and
///   [`crate::authority::CAP_READ_PUBLIC`]: a script called `public` would have its
///   per-script grant spelled exactly like the grant a host gives its anonymous
///   principal.
/// - `outcome` and `principal` begin IRIs this crate mints and nothing resolves:
///   [`crate::graph::OUTCOME_OK`] (`urn:script:outcome:ok`) and the principals
///   [`crate::authority::UNSTAMPED`] and [`crate::authority::ANONYMOUS`]
///   (`urn:script:principal:…`). Everything below `urn:script:{name}:` is that script's,
///   so a script called `principal` would own, by the naming rule, an IRI that names
///   who ran it (ledger #1076).
///
/// ⚠ A script already stored under a name reserved later is unreachable, not migrated:
/// every door refuses its name as `InvalidArgument`, [`crate::DirBackend`] leaves it out of
/// the catalog, and its files stay where they were. Rename its entries in the backend to
/// get it back.
///
/// ```
/// use ikigai_script::{authority, graph, name};
///
/// // Every IRI this crate mints directly under `urn:script:` starts with a reserved name,
/// // so no script can be named into one.
/// for minted in [
///     name::EVAL_IRI,
///     name::CATALOG_IRI,
///     graph::OUTCOME_OK,
///     graph::OUTCOME_FAILED,
///     authority::UNSTAMPED,
///     authority::ANONYMOUS,
/// ] {
///     let first = minted[name::PREFIX.len()..].split(':').next().unwrap();
///     assert!(name::RESERVED.contains(&first), "{minted}");
///     assert!(name::validate(first).is_err(), "{minted}");
/// }
/// ```
pub const RESERVED: [&str; 5] = ["eval", "catalog", "public", "outcome", "principal"];

/// The longest name.
pub const MAX_NAME: usize = 64;

/// Check a script name: `[a-z0-9][a-z0-9_-]*`, at most [`MAX_NAME`] bytes, not
/// [`RESERVED`].
///
/// One segment and lowercase so that a name is the same string in an IRI, in a
/// capability scope, on a file system that folds case, and in a URL path.
pub fn validate(name: &str) -> Result<()> {
    let bad = |detail: String| Error::InvalidArgument {
        name: "name".to_string(),
        detail,
    };
    if name.is_empty() {
        return Err(bad("a script name cannot be empty".to_string()));
    }
    if name.len() > MAX_NAME {
        return Err(bad(format!(
            "`{name}` is {} bytes; a script name is at most {MAX_NAME}",
            name.len()
        )));
    }
    let mut chars = name.chars();
    let first_ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    let rest_ok =
        chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    if !first_ok || !rest_ok {
        return Err(bad(format!(
            "`{name}` is not a script name: one segment of lowercase letters, digits, `-` \
             and `_`, starting with a letter or digit"
        )));
    }
    if RESERVED.contains(&name) {
        return Err(bad(format!(
            "`{name}` is reserved ({}); choose another name",
            RESERVED.join(", ")
        )));
    }
    Ok(())
}

/// `urn:script:{name}`: the script itself (the head).
pub fn script_iri(name: &str) -> String {
    format!("{PREFIX}{name}")
}

/// `urn:script:{name}:version:{digest}`: one immutable version.
pub fn version_iri(name: &str, digest: &str) -> String {
    format!("{PREFIX}{name}:version:{digest}")
}

/// `urn:script:{name}:run:{id}`: one recorded run.
pub fn run_iri(name: &str, id: u64) -> String {
    format!("{PREFIX}{name}:run:{id}")
}

/// `urn:script:{name}:{part}`: `compiled`, `result` or `runs`.
pub fn part_iri(name: &str, part: &str) -> String {
    format!("{PREFIX}{name}:{part}")
}

/// The golden thread a host cuts when it changes the ceiling it allows `{name}`
/// (`<config home>/script-authority/{name}`): `urn:script:{name}:authority`.
///
/// Every `…:result` hangs from it, because a cached answer computed under the old
/// ceiling must not outlive the ceiling. The library cannot see the host's file change,
/// so cutting this thread is the host's half of the contract (a watcher on the config
/// home, or `sink urn:kernel:cut urn:script:{name}:authority`).
pub fn authority_thread(name: &str) -> String {
    format!("{PREFIX}{name}:authority")
}

/// The `name` a grammar captured, checked. Every templated resource here captures it.
pub(crate) fn from_bindings(inv: &Invocation<'_>) -> Result<String> {
    let name = inv.bindings.get("name").ok_or_else(|| {
        Error::Endpoint(
            "no `name` captured: this endpoint is bound under `urn:script:{name}` and was \
             invoked without the grammar's capture"
                .to_string(),
        )
    })?;
    validate(name)?;
    Ok(name.to_string())
}
