//! The three authorities, never merged — and the one computation that decides what a run
//! may touch.
//!
//! 1. **Publish or change**: `urn:cap:script:write:{name}`, and `urn:cap:script:delete:{name}`
//!    to retire.
//! 2. **Run**: `urn:cap:script:run:{name}`. A **public** script is also runnable by any
//!    holder of [`CAP_RUN_PUBLIC`], which is the grant a host gives its anonymous
//!    principal.
//! 3. **Runs as**: what [`effective`] computes, applied to the runner's own capability by
//!    attenuation. Never minted.
//!
//! Reading a script without running it is a fourth scope, `urn:cap:script:read:{name}`
//! (or [`CAP_READ_PUBLIC`] for a public, published script): source code is not the same
//! sensitivity as running it, the same split `ikigai-ledger` draws between read and write.
//!
//! Each of the four is held for ONE script (`urn:cap:script:{act}:{name}`) or for a
//! NAMESPACE of them (`urn:cap:script:{act}:{namespace}-*`, [`cap_namespace`]: every name
//! that begins `{namespace}-`), and an exclusion (`…:{act}:-{name}`, `…:{act}:-{prefix}*`)
//! takes a script back out. [`holds`] is the one place that rule lives.
//!
//! # Runs as: the least of four
//!
//! A run executes under
//!
//! ```text
//! runner.attenuate( { s in declared : s in granted-at-publish and ceiling.allows(s) }
//!                   + the publisher's exclusions + the ceiling's exclusions )
//! ```
//!
//! - **declared**: what the script says it needs (`requires=` at publish), plus the
//!   capability its LANGUAGE needs (`urn:cap:lisp` for Lisp), because evaluating code is
//!   itself authority.
//! - **granted at publish**: the part of `declared` the publisher held when they published.
//!   **A publish that declares a scope the publisher does not hold is REFUSED** with a typed
//!   `Denied` naming the scopes. Narrowing silently instead would store a script whose
//!   `requires` says one thing and whose runs get another, and the manifold would lie.
//!   The snapshot is still stored and still intersected, so a hand edit of ONE record (a
//!   version's `requires`, say, in a [`crate::DirBackend`] file) cannot widen a run past
//!   the other. Editing both is the host operator's act — the same trust as the ceiling
//!   files — and the ceiling bounds every run whatever the records say.
//! - **the host's ceiling** for this script ([`Ceiling`], from the host's
//!   `<config home>/script-authority/{name}`): the host decides, never the script.
//! - **the runner's own capability**: [`Capability::attenuate`] keeps a grant only when the
//!   runner holds it, so a run never exceeds the intersection of runner and script.
//!
//! **Exclusions travel.** A publisher who holds `urn:cap:fs:read:/root` together with the
//! exclusion `urn:cap:fs:read:-/root/secret` could not read the secret, so neither can the
//! script, whoever runs it: every exclusion the publisher held is stored with the version's
//! grant and handed to `attenuate`, which keeps a requested exclusion (it only narrows).
//! The ceiling's exclusions travel the same way.
//!
//! ```
//! use ikigai_core::Capability;
//! use ikigai_script::authority::{effective, Ceiling};
//! use std::collections::BTreeSet;
//!
//! let set = |xs: &[&str]| xs.iter().map(|s| s.to_string()).collect::<BTreeSet<_>>();
//! let declared = set(&["urn:cap:lisp", "urn:cap:net:example.com", "urn:cap:mail:send"]);
//! let granted = declared.clone(); // the publisher held all three
//! let exclusions = set(&["urn:cap:net:-example.com/admin"]);
//! // The host lets this script run Lisp and reach the network, but not send mail.
//! let ceiling = Ceiling::scoped(["urn:cap:lisp", "urn:cap:net:*"]);
//!
//! let request = effective(&declared, &granted, &exclusions, &ceiling);
//! assert_eq!(
//!     request,
//!     set(&["urn:cap:lisp", "urn:cap:net:-example.com/admin", "urn:cap:net:example.com"])
//! );
//!
//! // A runner who holds Lisp and mail, but not the network: the run gets Lisp, and the
//! // exclusion still rides along (it only narrows).
//! let runner = Capability::scoped(["urn:cap:lisp", "urn:cap:mail:send", "urn:cap:script:run:x"]);
//! let runs_as = runner.attenuate(request);
//! assert!(runs_as.allows("urn:cap:lisp"));
//! assert!(!runs_as.allows("urn:cap:mail:send")); // the ceiling withheld it
//! assert!(!runs_as.allows("urn:cap:net:example.com")); // the runner never held it
//! assert!(!runs_as.allows("urn:cap:script:run:x")); // nothing undeclared survives
//! ```

use std::collections::BTreeSet;
use std::sync::Arc;

use ikigai_core::{is_deny_scope, Capability, Error, Result};

/// Reading a script, as declared: "holds some script read grant". A held grant names one
/// script ([`cap_read`]) or a namespace ([`cap_namespace`]), checked inside by [`holds`].
pub const CAP_READ: &str = "urn:cap:script:read:*";
/// Publishing or replacing a script, as declared. Exact form: [`cap_write`].
pub const CAP_WRITE: &str = "urn:cap:script:write:*";
/// Retiring a script, as declared. Exact form: [`cap_delete`].
pub const CAP_DELETE: &str = "urn:cap:script:delete:*";
/// Running a script, as declared. Exact form: [`cap_run`], or [`CAP_RUN_PUBLIC`] for a
/// public script.
pub const CAP_RUN: &str = "urn:cap:script:run:*";
/// Any script grant at all: the compiled form is readable by a reader OR a runner, and a
/// `requires` is a conjunction, so it declares the family and checks the exact pair inside.
pub const CAP_ANY: &str = "urn:cap:script:*";

/// Run any script marked **public** (and published). The grant a host gives its anonymous
/// principal: it is how "a public script grants the run capability to the anonymous
/// principal" is spelled, since a host's anonymous grant cannot enumerate scripts that do
/// not exist yet. Withhold it and nothing runs anonymously.
pub const CAP_RUN_PUBLIC: &str = "urn:cap:script:run:public";
/// Read the source of any script marked public (and published).
pub const CAP_READ_PUBLIC: &str = "urn:cap:script:read:public";

/// The capability `urn:lisp:eval` requires, and so every Lisp script declares implicitly
/// (see [`crate::model::Language::capability`]). Spelled here rather than imported:
/// the library does not link `ikigai-lisp`.
pub const CAP_LISP: &str = "urn:cap:lisp";

/// The exact grant to read `{name}`.
pub fn cap_read(name: &str) -> String {
    format!("urn:cap:script:read:{name}")
}

/// The exact grant to publish or replace `{name}`.
pub fn cap_write(name: &str) -> String {
    format!("urn:cap:script:write:{name}")
}

/// The exact grant to retire `{name}`.
pub fn cap_delete(name: &str) -> String {
    format!("urn:cap:script:delete:{name}")
}

/// The exact grant to run `{name}`.
pub fn cap_run(name: &str) -> String {
    format!("urn:cap:script:run:{name}")
}

/// What a script grant authorizes: the `{act}` in `urn:cap:script:{act}:{name}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Act {
    /// Read the source and head record without running it.
    Read,
    /// Publish, replace or draft it.
    Write,
    /// Retire it.
    Delete,
    /// Run it, as a read or for effects.
    Run,
}

impl Act {
    /// Every act.
    pub const ALL: [Act; 4] = [Act::Read, Act::Write, Act::Delete, Act::Run];

    /// The word in the scope.
    pub fn as_str(self) -> &'static str {
        match self {
            Act::Read => "read",
            Act::Write => "write",
            Act::Delete => "delete",
            Act::Run => "run",
        }
    }

    /// `urn:cap:script:{act}:`, the prefix every grant of this act starts with.
    fn prefix(self) -> String {
        format!("urn:cap:script:{}:", self.as_str())
    }
}

/// The exact grant to `act` on `{name}`: [`cap_read`], [`cap_write`], [`cap_delete`] or
/// [`cap_run`].
pub fn cap(act: Act, name: &str) -> String {
    format!("{}{name}", act.prefix())
}

/// The grant to `act` on every script in a NAMESPACE: `urn:cap:script:{act}:{namespace}-*`
/// (ledger #1174).
///
/// A namespace is a name prefix that ends at a `-`: the grant for `team` covers `team-report`
/// and `team-a-report`, never `teammate` or `team` itself. The `{namespace}` is spelled like
/// a script name (lowercase letters, digits, `-` and `_`, starting with a letter or digit),
/// so it can be nested: `team-a` is a namespace inside `team`.
///
/// ★ **The parameter goes last, and the wildcard only at its end.** Core has no infix
/// wildcard (`urn:cap:script:*:team` is not a form anything matches), and the act stays
/// spelled out, so a namespace grant to RUN never publishes and a grant to READ never runs.
/// There is no "every script" grant below root: `urn:cap:script:{act}:*` grants nothing,
/// because it is spelled exactly like the FAMILY each act's door declares
/// ([`CAP_WRITE`], …), the "holds some script grant" presence test, and a held string that
/// means "everything" in one reading and "something" in the other is the confusion a grant
/// must not carry.
///
/// An exclusion names a script (`urn:cap:script:{act}:-{name}`) or a namespace
/// (`urn:cap:script:{act}:-{namespace}-*`) and always wins, over an exact grant too.
///
/// ```
/// use ikigai_core::Capability;
/// use ikigai_script::authority::{cap_namespace, holds, Act};
///
/// let grant = cap_namespace(Act::Write, "team").unwrap();
/// assert_eq!(grant, "urn:cap:script:write:team-*");
/// let alice = Capability::scoped([grant.as_str(), "urn:cap:script:write:-team-payroll"]);
/// assert!(holds(&alice, Act::Write, "team-report"));
/// assert!(holds(&alice, Act::Write, "team-a-report")); // nested
/// assert!(!holds(&alice, Act::Write, "teammate")); // not in the namespace
/// assert!(!holds(&alice, Act::Write, "team")); // the namespace is not a script
/// assert!(!holds(&alice, Act::Write, "team-payroll")); // excluded
/// assert!(!holds(&alice, Act::Run, "team-report")); // another act
/// // Not a namespace: the wildcard must follow a `-`, and there is no "every script".
/// assert!(cap_namespace(Act::Write, "").is_err());
/// assert!(cap_namespace(Act::Write, "Team").is_err());
/// assert!(!holds(&Capability::scoped(["urn:cap:script:write:team*"]), Act::Write, "teammate"));
/// assert!(!holds(&Capability::scoped(["urn:cap:script:write:*"]), Act::Write, "anything"));
/// ```
pub fn cap_namespace(act: Act, namespace: &str) -> Result<String> {
    if !is_namespace(namespace) {
        return Err(Error::InvalidArgument {
            name: "namespace".to_string(),
            detail: format!(
                "`{namespace}` is not a namespace: one or more `-`-separated words of lowercase \
                 letters, digits, `-` and `_`, starting with a letter or digit, at most {} bytes",
                crate::name::MAX_NAME - 1
            ),
        });
    }
    Ok(format!("{}{namespace}-*", act.prefix()))
}

/// Whether `namespace` is spelled like a script name (and leaves room for one more byte).
fn is_namespace(namespace: &str) -> bool {
    let mut chars = namespace.chars();
    namespace.len() < crate::name::MAX_NAME
        && chars
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

/// Whether `capability` may `act` on the script `name`: it holds the exact grant
/// ([`cap`]) or a namespace grant covering the name ([`cap_namespace`]), and no exclusion
/// it holds names the script or a namespace it is in ([`excluded`]). Root holds every grant
/// and no exclusion.
///
/// This is the whole rule, and every door of this crate checks it; a host or module asking
/// "may this caller read script X?" (to filter what it shows, say) asks it here rather than
/// with `Capability::allows`, which matches a held scope exactly and so would miss a
/// namespace grant.
pub fn holds(capability: &Capability, act: Act, name: &str) -> bool {
    let Some(held) = capability.scopes() else {
        return true;
    };
    if excluded(capability, act, name) {
        return false;
    }
    if capability.allows(&cap(act, name)) {
        return true;
    }
    let prefix = act.prefix();
    held.iter()
        .filter_map(|scope| scope.strip_prefix(prefix.as_str()))
        .filter_map(|rule| rule.strip_suffix('*'))
        .any(|covered| {
            covered
                .strip_suffix('-')
                .is_some_and(|namespace| is_namespace(namespace) && name.starts_with(covered))
        })
}

/// Whether an exclusion `capability` holds names the script `name` for `act`: the script
/// itself (`urn:cap:script:{act}:-{name}`) or any prefix of its name
/// (`urn:cap:script:{act}:-{prefix}*`).
///
/// Read liberally where a grant is read strictly: an exclusion only ever narrows, so any
/// `-…*` it spells is honored as a prefix (`-*` excludes every script), while a grant must
/// be a well-formed namespace to grant anything.
pub fn excluded(capability: &Capability, act: Act, name: &str) -> bool {
    let Some(held) = capability.scopes() else {
        return false;
    };
    let prefix = act.prefix();
    held.iter()
        .filter_map(|scope| scope.strip_prefix(prefix.as_str()))
        .filter_map(|rule| rule.strip_prefix('-'))
        .any(|rule| match rule.strip_suffix('*') {
            Some(covered) => name.starts_with(covered),
            None => rule == name,
        })
}

/// The run gate a script's OWN contract declares (a published query's or plan's
/// `…:result` and `…:runs`), as the kernel's floor can check it before the endpoint runs.
///
/// The floor matches a declared scope exactly, or a declared `prefix*` as "holds some grant
/// starting with `prefix`", and a description cannot depend on who asks. So a name with no
/// `-` (which no namespace grant can cover) declares its exact run grant, and a name in a
/// namespace declares its TOP-LEVEL namespace as a family: `team-a-report` declares
/// `urn:cap:script:run:team-*`, which a holder of `run:team-a-report`, `run:team-a-*` or
/// `run:team-*` satisfies. The exact rule ([`holds`]) is checked inside, so the cost is
/// only that the script's entry is offered to a holder of another grant in the same
/// top-level namespace, who is refused when they call it.
///
/// ```
/// use ikigai_script::authority::run_floor;
/// assert_eq!(run_floor("nightly"), "urn:cap:script:run:nightly");
/// assert_eq!(run_floor("team-a-report"), "urn:cap:script:run:team-*");
/// ```
pub fn run_floor(name: &str) -> String {
    match name.split_once('-') {
        Some((top, _)) => format!("{}{top}-*", Act::Run.prefix()),
        None => cap_run(name),
    }
}

/// What is recorded as the principal when the request's capability names none: root (the
/// host's own authority, which holds every principal and names none), a door that minted no
/// `urn:cap:principal:` scope, or a capability carrying several (which names nobody). Honest
/// rather than useful, so a host that never identifies its callers cannot have its records
/// claim an identity nobody checked. The value records written before 0.2.0 carry for a host
/// that stamped nothing, kept so old and new records agree.
pub const UNSTAMPED: &str = "urn:script:principal:unstamped";

/// What a door conventionally mints (`Capability::with_principal`) for a caller it cannot
/// identify. Many callers share it, so it is nobody's identity: see [`is_identity`].
pub const ANONYMOUS: &str = "urn:script:principal:anonymous";

/// Who a request comes from: the principal its CAPABILITY names, minted by the host's door
/// (`urn:cap:principal:<iri>`, ikigai-core 0.1.93), or [`UNSTAMPED`] when it names none.
///
/// The library records it on every publish and every run. It is never an argument: a caller
/// cannot name itself, and narrowing a capability can never add or change a principal, so a
/// sub-request issued on someone's behalf carries their name or none.
///
/// ```
/// use ikigai_core::Capability;
/// use ikigai_script::authority::{principal_of, UNSTAMPED};
///
/// let door = Capability::scoped(["urn:cap:script:run:job"]);
/// let alice = door.with_principal("urn:example:person:alice").unwrap();
/// assert_eq!(principal_of(&alice), "urn:example:person:alice");
/// assert_eq!(principal_of(&door), UNSTAMPED);
/// // Root is the host's own authority, not a party's.
/// assert_eq!(principal_of(&Capability::root()), UNSTAMPED);
/// ```
pub fn principal_of(capability: &Capability) -> String {
    capability.principal().unwrap_or(UNSTAMPED).to_string()
}

/// Whether a recorded principal names SOMEONE: anything but [`UNSTAMPED`] and
/// [`ANONYMOUS`], which stand for many different callers at once.
///
/// It decides who may see a draft. A draft is visible only to its author until it is
/// published, and the author is the principal recorded when the draft was written; two
/// callers minted [`ANONYMOUS`] are not one person, and a capability naming no principal
/// cannot be told apart from any other. So a draft written under either is nobody's: only
/// root sees it until it is published. A door that cannot identify a caller mints
/// [`ANONYMOUS`] (or nothing) rather than inventing a shared name.
///
/// ```
/// use ikigai_script::authority::{is_identity, ANONYMOUS, UNSTAMPED};
/// assert!(is_identity("urn:example:person:brian"));
/// assert!(!is_identity(ANONYMOUS));
/// assert!(!is_identity(UNSTAMPED));
/// assert!(!is_identity(""));
/// ```
pub fn is_identity(principal: &str) -> bool {
    !principal.trim().is_empty() && principal != UNSTAMPED && principal != ANONYMOUS
}

/// The host's ceiling for one script: the most it will let that script's runs touch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ceiling {
    /// The host imposes nothing beyond what the script declared and its publisher held.
    Unbounded,
    /// Exactly these scopes. A grant ending in `*` admits every scope under that prefix
    /// (`urn:cap:net:*`); a deny-shaped scope ([`is_deny_scope`]) is an exclusion every run
    /// of the script carries.
    Scopes(BTreeSet<String>),
}

impl Ceiling {
    /// No ceiling: [`Ceiling::Unbounded`].
    pub fn unbounded() -> Ceiling {
        Ceiling::Unbounded
    }

    /// The empty ceiling: the script may touch nothing, not even its language, so it cannot
    /// run. The answer for a script the host has no file for, when the host fails closed.
    pub fn nothing() -> Ceiling {
        Ceiling::Scopes(BTreeSet::new())
    }

    /// Exactly these scopes.
    pub fn scoped<I, S>(scopes: I) -> Ceiling
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Ceiling::Scopes(scopes.into_iter().map(Into::into).collect())
    }

    /// Parse the text of a ceiling file (`<config home>/script-authority/{name}`): one
    /// `urn:cap:` scope per line, `#` to the end of a line is a comment, blank lines are
    /// ignored. A lone `*` line means [`Ceiling::Unbounded`].
    ///
    /// ```
    /// use ikigai_script::authority::Ceiling;
    /// let ceiling = Ceiling::parse(
    ///     "# the nightly report\nurn:cap:lisp\nurn:cap:net:*   # any host\n\
    ///      urn:cap:net:-internal.example\n",
    /// )
    /// .unwrap();
    /// assert!(ceiling.allows("urn:cap:lisp"));
    /// assert!(ceiling.allows("urn:cap:net:example.com"));
    /// assert!(!ceiling.allows("urn:cap:mail:send"));
    /// assert_eq!(ceiling.exclusions(), vec!["urn:cap:net:-internal.example".to_string()]);
    /// assert_eq!(Ceiling::parse("*\n").unwrap(), Ceiling::Unbounded);
    /// assert!(Ceiling::parse("lisp\n").is_err()); // not a capability scope
    /// ```
    pub fn parse(text: &str) -> Result<Ceiling> {
        let mut scopes = BTreeSet::new();
        for (number, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if line == "*" {
                return Ok(Ceiling::Unbounded);
            }
            if !line.starts_with("urn:cap:") || line.split_whitespace().count() != 1 {
                return Err(Error::InvalidArgument {
                    name: "ceiling".to_string(),
                    detail: format!(
                        "line {}: `{line}` is not one `urn:cap:` scope (or `*` for no ceiling)",
                        number + 1
                    ),
                });
            }
            scopes.insert(line.to_string());
        }
        Ok(Ceiling::Scopes(scopes))
    }

    /// Whether the ceiling admits the grant `scope`: held exactly, or under a held
    /// `prefix*` family. An exclusion is never admitted as a grant.
    pub fn allows(&self, scope: &str) -> bool {
        match self {
            Ceiling::Unbounded => !is_deny_scope(scope),
            Ceiling::Scopes(held) => {
                !is_deny_scope(scope)
                    && held.iter().any(|h| match h.strip_suffix('*') {
                        Some(prefix) => scope.starts_with(prefix),
                        None => h == scope,
                    })
            }
        }
    }

    /// The exclusions the ceiling carries, which every run of the script carries too.
    pub fn exclusions(&self) -> Vec<String> {
        match self {
            Ceiling::Unbounded => Vec::new(),
            Ceiling::Scopes(held) => held.iter().filter(|s| is_deny_scope(s)).cloned().collect(),
        }
    }
}

/// How the host answers "what is the ceiling for this script?" — called on every run, so a
/// changed ceiling takes effect at the next one (and a cached result is cut by
/// [`crate::name::authority_thread`]).
///
/// ```
/// use ikigai_script::authority::{Ceiling, CeilingPolicy};
/// use std::sync::Arc;
/// // A host reading `<config home>/script-authority/{name}`, failing closed when the file
/// // is missing or unreadable:
/// let dir = std::path::PathBuf::from("/etc/my-host/script-authority");
/// let policy: CeilingPolicy = Arc::new(move |name| {
///     std::fs::read_to_string(dir.join(name))
///         .ok()
///         .and_then(|text| Ceiling::parse(&text).ok())
///         .unwrap_or_else(Ceiling::nothing)
/// });
/// # let _ = policy;
/// ```
pub type CeilingPolicy = Arc<dyn Fn(&str) -> Ceiling + Send + Sync>;

/// A ceiling policy that answers the same ceiling for every script.
pub fn same_for_all(ceiling: Ceiling) -> CeilingPolicy {
    Arc::new(move |_| ceiling.clone())
}

/// Parse `requires=`: whitespace-separated `urn:cap:` grants.
///
/// Refused: anything not under `urn:cap:`, a family wildcard (`*`: a script states the
/// grants it needs, and attenuation keeps grants by exact name, so a wildcard would keep
/// nothing), and an exclusion (it is not something a script can need; exclusions come
/// from the publisher and the host).
pub fn parse_requires(text: &str) -> Result<BTreeSet<String>> {
    let mut scopes = BTreeSet::new();
    for scope in text.split_whitespace() {
        let detail = if !scope.starts_with("urn:cap:") {
            Some("is not a `urn:cap:` scope")
        } else if scope.ends_with('*') {
            Some(
                "is a family wildcard; a script declares the exact grants it needs, \
                 because a run keeps grants by exact name",
            )
        } else if is_deny_scope(scope) {
            Some("is an exclusion; a script declares what it needs, not what it may not touch")
        } else {
            None
        };
        if let Some(detail) = detail {
            return Err(Error::InvalidArgument {
                name: "requires".to_string(),
                detail: format!("`{scope}` {detail}"),
            });
        }
        scopes.insert(scope.to_string());
    }
    Ok(scopes)
}

/// What the publisher held of a script's declared scopes, taken at publish time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    /// The declared scopes the publisher held: all of them, since a publish declaring more
    /// is refused. For a declared FAMILY (`prefix*`, which only a SPARQL script's derived
    /// authority carries: [`crate::sparql::CAP_READ_GRAPH`]), the publisher's own grants
    /// under it, each one, or the family itself when the publisher was root.
    pub granted: BTreeSet<String>,
    /// Every exclusion the publisher's capability carried, which every run carries too.
    pub exclusions: BTreeSet<String>,
}

/// A declared family (`prefix*`): its prefix.
fn family(scope: &str) -> Option<&str> {
    scope.strip_suffix('*')
}

/// Take the publisher's grant for `declared`, or refuse with a typed `Denied` naming what
/// they do not hold. **No elevation**: a script never runs with more than its publisher
/// held.
///
/// A declared family (`prefix*`) is held when the publisher holds some grant under it,
/// the kernel's own reading of a family in a `requires`; what is taken is every such
/// grant, so a run's union is never wider than its publisher's.
pub fn grant_at_publish(publisher: &Capability, declared: &BTreeSet<String>) -> Result<Grant> {
    let held_under = |prefix: &str| -> Vec<String> {
        publisher
            .scopes()
            .map(|held| {
                held.iter()
                    .filter(|s| s.starts_with(prefix) && !is_deny_scope(s))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    };
    let mut granted = BTreeSet::new();
    let mut missing: Vec<&str> = Vec::new();
    for scope in declared {
        match family(scope) {
            Some(_) if publisher.is_root() => {
                granted.insert(scope.clone());
            }
            Some(prefix) => {
                let held = held_under(prefix);
                if held.is_empty() {
                    missing.push(scope);
                }
                granted.extend(held);
            }
            None if publisher.allows(scope) => {
                granted.insert(scope.clone());
            }
            None => missing.push(scope),
        }
    }
    if !missing.is_empty() {
        return Err(Error::Denied(format!(
            "a script cannot be given more than its publisher holds, and this capability \
             does not hold {} — declare less, or publish under a capability that holds it",
            missing.join(", ")
        )));
    }
    let exclusions = publisher
        .scopes()
        .map(|held| held.iter().filter(|s| is_deny_scope(s)).cloned().collect())
        .unwrap_or_default();
    Ok(Grant {
        granted,
        exclusions,
    })
}

/// The scopes a run asks to keep: `{ s in declared : s in granted and ceiling.allows(s) }`
/// plus the publisher's and the ceiling's exclusions. The run's capability is the runner's
/// own [`Capability::attenuate`]d to this set — see the module documentation.
///
/// A declared family keeps the publisher's grants under it that the ceiling allows; when
/// the publisher was root it keeps the family itself, a marker the SPARQL run expands
/// into exact grants (each checked against the ceiling and the runner) before anything
/// is attenuated, because attenuation keeps grants by exact name.
pub fn effective(
    declared: &BTreeSet<String>,
    granted: &BTreeSet<String>,
    exclusions: &BTreeSet<String>,
    ceiling: &Ceiling,
) -> BTreeSet<String> {
    let mut keep: BTreeSet<String> = BTreeSet::new();
    for scope in declared {
        match family(scope) {
            Some(_) if granted.contains(scope) => {
                keep.insert(scope.clone());
            }
            Some(prefix) => keep.extend(
                granted
                    .iter()
                    .filter(|g| g.starts_with(prefix) && ceiling.allows(g))
                    .cloned(),
            ),
            None if granted.contains(scope) && ceiling.allows(scope) => {
                keep.insert(scope.clone());
            }
            None => {}
        }
    }
    keep.extend(exclusions.iter().filter(|s| is_deny_scope(s)).cloned());
    keep.extend(ceiling.exclusions());
    keep
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(xs: &[&str]) -> BTreeSet<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_publisher_cannot_declare_what_they_do_not_hold() {
        let publisher = Capability::scoped(["urn:cap:lisp", "urn:cap:script:write:x"]);
        let err =
            grant_at_publish(&publisher, &set(&["urn:cap:lisp", "urn:cap:mail:send"])).unwrap_err();
        assert!(
            matches!(&err, Error::Denied(m) if m.contains("urn:cap:mail:send") && !m.contains("urn:cap:lisp,")),
            "{err:?}"
        );
    }

    #[test]
    fn the_publishers_exclusions_are_taken_with_the_grant() {
        let publisher = Capability::scoped([
            "urn:cap:lisp",
            "urn:cap:fs:read:/root",
            "urn:cap:fs:read:-/root/secret",
        ]);
        let grant =
            grant_at_publish(&publisher, &set(&["urn:cap:lisp", "urn:cap:fs:read:/root"])).unwrap();
        assert_eq!(grant.exclusions, set(&["urn:cap:fs:read:-/root/secret"]));
        // Root holds no exclusions and every grant.
        let grant = grant_at_publish(&Capability::root(), &set(&["urn:cap:anything"])).unwrap();
        assert!(grant.exclusions.is_empty());
    }

    #[test]
    fn a_hand_widened_grant_still_cannot_exceed_the_stored_snapshot() {
        // declared names mail, but the snapshot (what the publisher held) does not.
        let request = effective(
            &set(&["urn:cap:lisp", "urn:cap:mail:send"]),
            &set(&["urn:cap:lisp"]),
            &BTreeSet::new(),
            &Ceiling::Unbounded,
        );
        assert_eq!(request, set(&["urn:cap:lisp"]));
    }

    #[test]
    fn a_family_takes_the_publishers_grants_under_it() {
        let family = "urn:cap:store:read:graph:*";
        let publisher = Capability::scoped([
            "urn:cap:store:read:graph:urn:a",
            "urn:cap:store:read:graph:urn:b",
            "urn:cap:other",
        ]);
        let grant = grant_at_publish(&publisher, &set(&[family])).unwrap();
        assert_eq!(
            grant.granted,
            set(&[
                "urn:cap:store:read:graph:urn:a",
                "urn:cap:store:read:graph:urn:b"
            ])
        );
        // Holding nothing under it is holding nothing it declares.
        assert!(grant_at_publish(&Capability::scoped(["urn:cap:other"]), &set(&[family])).is_err());
        // Root keeps the family, as a marker for the run to expand.
        let root = grant_at_publish(&Capability::root(), &set(&[family])).unwrap();
        assert_eq!(root.granted, set(&[family]));
        // The ceiling narrows the members.
        let keep = effective(
            &set(&[family]),
            &grant.granted,
            &BTreeSet::new(),
            &Ceiling::scoped(["urn:cap:store:read:graph:urn:a"]),
        );
        assert_eq!(keep, set(&["urn:cap:store:read:graph:urn:a"]));
    }

    #[test]
    fn requires_refuses_wildcards_exclusions_and_strangers() {
        assert!(parse_requires("urn:cap:net:*").is_err());
        assert!(parse_requires("urn:cap:fs:read:-/x").is_err());
        assert!(parse_requires("lisp").is_err());
        assert_eq!(
            parse_requires(" urn:cap:a\n urn:cap:b urn:cap:a ").unwrap(),
            set(&["urn:cap:a", "urn:cap:b"])
        );
    }

    #[test]
    fn a_ceiling_never_admits_an_exclusion_as_a_grant() {
        assert!(!Ceiling::Unbounded.allows("urn:cap:net:-x"));
        assert!(!Ceiling::scoped(["urn:cap:net:*"]).allows("urn:cap:net:-x"));
        assert!(!Ceiling::nothing().allows("urn:cap:lisp"));
    }
}
