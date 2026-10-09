//! The resources, as endpoints.
//!
//! Only two of them hold state — the script (its head and versions) and a run — and they
//! hold it through the host's [`Backend`]. Everything else is composed: `…:result` and
//! `…:runs` read `…:compiled` through the kernel and hand the program to the language's
//! evaluator as a sub-request; `urn:script:eval` saves a draft by sinking to the script
//! like any other writer.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ikigai_core::{
    ActionSpec, ArgRef, ArgSpec, Description, Endpoint, EndpointSpace, Error, Exact, Invocation,
    Iri, ReprType, Representation, Request, Resolution, Result, Scope, Space, SpaceEntry, Topology,
    UriTemplate, Verb,
};
use serde::{Deserialize, Serialize};

use crate::authority::{
    self, cap_delete, cap_read, cap_run, cap_write, Ceiling, CeilingPolicy, PrincipalStamper,
    CAP_ANY, CAP_DELETE, CAP_LISP, CAP_READ, CAP_READ_PUBLIC, CAP_RUN, CAP_RUN_PUBLIC, CAP_WRITE,
};
use crate::backend::Backend;
use crate::model::{
    self, Event, Head, Language, Outcome, Run, State, Version, MAX_RECORDED_RESULT, SCHEMA,
};
use crate::name::{self, CATALOG_IRI, EVAL_IRI};
use crate::sparql::{self, Analysis, Form, Parameter, SparqlDoor, Value, CAP_READ_GRAPH};

const PLAIN: &str = "text/plain";
const JSON: &str = "application/json";
const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";
const XSD_BOOLEAN: &str = "http://www.w3.org/2001/XMLSchema#boolean";
const XSD_INTEGER: &str = "http://www.w3.org/2001/XMLSchema#integer";
/// The faces of a read: the source (or a summary) for people, the record for machines.
const READ_FACES: [&str; 2] = [PLAIN, JSON];

/// What a host decides when it mounts scripts: where they live, the ceiling it allows each
/// one, and who a request comes from. Built with [`SpaceConfig::new`] and handed to
/// [`space`].
///
/// There is no default backend and no default ceiling, on purpose: both are the host's
/// decision, and a library that guessed either would be guessing about authority.
#[derive(Clone)]
#[non_exhaustive]
pub struct SpaceConfig {
    backend: Arc<dyn Backend>,
    ceiling: CeilingPolicy,
    principal: PrincipalStamper,
    sparql: Option<SparqlDoor>,
    on_change: Option<ChangeHook>,
    /// Each published SPARQL script's own endpoints (its contract), built once per head and
    /// dropped by every publish or retire through this crate. `None`: the template's.
    described: Arc<Mutex<HashMap<String, Option<PerScript>>>>,
}

/// What a host runs when a script's head changes through this crate: see
/// [`SpaceConfig::on_change`].
pub type ChangeHook = Arc<dyn Fn(&str) + Send + Sync>;

impl SpaceConfig {
    /// Scripts kept in `backend`, each run under the ceiling `ceiling` answers for it.
    pub fn new(backend: Arc<dyn Backend>, ceiling: CeilingPolicy) -> SpaceConfig {
        SpaceConfig {
            backend,
            ceiling,
            principal: authority::unstamped(),
            sparql: None,
            on_change: None,
            described: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// How the principal recorded on every publish and run is decided: by the HOST, from
    /// the invocation. The default records [`authority::UNSTAMPED`].
    pub fn principal(mut self, stamper: PrincipalStamper) -> SpaceConfig {
        self.principal = stamper;
        self
    }

    /// Accept SPARQL scripts, evaluated through `door` (the store's graph-scoped doors).
    /// Without it, publishing `language=sparql` is refused: which store a query runs
    /// against is the host's decision, as the evaluator a Lisp script reaches is.
    pub fn sparql(mut self, door: SparqlDoor) -> SpaceConfig {
        self.sparql = Some(door);
        self
    }

    /// Run `hook` with the script's name after every publish or retire through this crate.
    ///
    /// ★ **Wire it to `kernel.cut(ikigai_core::BINDINGS_THREAD)`.** A published SPARQL
    /// script is its own entry in the catalog and the action manifold (`…:result` and
    /// `…:runs` with ITS parameters as arguments), and the kernel caches every description
    /// and Meta answer under `urn:kernel:bindings`, which it cannot know a publish changed.
    /// The library holds no kernel and an endpoint may not cut that thread without
    /// `urn:cap:kernel:cut`, so the host, which holds both, makes the cut. Unwired, a new
    /// query is runnable at once but the catalog, MCP and the engine's argument routing
    /// describe the old set until something else cuts the thread.
    pub fn on_change(mut self, hook: ChangeHook) -> SpaceConfig {
        self.on_change = Some(hook);
        self
    }

    /// A script's head changed through this crate: forget its contract, tell the host.
    fn changed(&self, name: &str) {
        self.described
            .lock()
            .expect("the described-script memo")
            .remove(name);
        if let Some(hook) = &self.on_change {
            hook(name);
        }
    }
}

/// Bind every script resource.
///
/// ⚠ **Bind order is resolution order** (`EndpointSpace` takes the first grammar that
/// matches), and `urn:script:{name}`'s template captures the rest of an IRI, so the two
/// exact names go first and the bare script last. A name cannot contain `:`, so
/// `urn:script:x:compiled` can only be the compiled form of `x`.
pub fn space(config: SpaceConfig) -> ScriptSpace {
    let shared = Arc::new(config);
    let template = |t: &str| UriTemplate::parse(t).expect("a constant template");
    let inner = EndpointSpace::new()
        .bind(Exact::new(EVAL_IRI), EvalEndpoint)
        .bind(
            Exact::new(CATALOG_IRI),
            CatalogEndpoint {
                shared: Arc::clone(&shared),
            },
        )
        .bind(
            template("urn:script:{name}:version:{digest}"),
            VersionEndpoint {
                shared: Arc::clone(&shared),
            },
        )
        .bind(
            template("urn:script:{name}:run:{id}"),
            RunEndpoint {
                shared: Arc::clone(&shared),
            },
        )
        .bind(
            template("urn:script:{name}:compiled"),
            CompiledEndpoint {
                shared: Arc::clone(&shared),
            },
        )
        .bind(
            template("urn:script:{name}:result"),
            ResultEndpoint {
                shared: Arc::clone(&shared),
            },
        )
        .bind(
            template("urn:script:{name}:runs"),
            RunsEndpoint {
                shared: Arc::clone(&shared),
            },
        )
        .bind(
            template("urn:script:{name}"),
            ScriptEndpoint {
                shared: Arc::clone(&shared),
            },
        );
    ScriptSpace { inner, shared }
}

// ---------------------------------------------------------------------------------------
// Gates
// ---------------------------------------------------------------------------------------

fn holds(inv: &Invocation<'_>, scope: &str) -> bool {
    inv.capability.allows(scope)
}

/// Public and published: what the `…:public` grants reach.
fn is_public(head: &Head) -> bool {
    head.public && head.state == State::Published
}

/// The head of `name`, if the caller may read it.
///
/// ★ No existence oracle: a caller without the script's own read grant is told `Denied`
/// whether the script exists or not, unless it is public and they hold
/// [`CAP_READ_PUBLIC`]. Only a caller who may read it learns that it is absent.
fn readable_head(inv: &Invocation<'_>, shared: &SpaceConfig, name: &str) -> Result<Option<Head>> {
    gated_head(inv, shared, name, &[cap_read(name)], &[CAP_READ_PUBLIC])
}

/// The head of `name` if the caller holds one of `exact`, or the script is public and they
/// hold one of `public`. Otherwise `Denied`, naming both.
fn gated_head(
    inv: &Invocation<'_>,
    shared: &SpaceConfig,
    name: &str,
    exact: &[String],
    public: &[&str],
) -> Result<Option<Head>> {
    if exact.iter().any(|s| holds(inv, s)) {
        return shared.backend.head(name);
    }
    if let Ok(Some(head)) = shared.backend.head(name) {
        if is_public(&head) && public.iter().any(|s| holds(inv, s)) {
            return Ok(Some(head));
        }
    }
    Err(Error::Denied(format!(
        "this capability holds none of {} — nor, for a public script, {}. A script grant \
         names exactly one script",
        exact.join(", "),
        public.join(", ")
    )))
}

fn require(inv: &Invocation<'_>, scope: &str, doing: &str) -> Result<()> {
    if holds(inv, scope) {
        Ok(())
    } else {
        Err(Error::Denied(format!(
            "{doing} needs `{scope}`, which this capability does not hold. A script grant \
             names exactly one script"
        )))
    }
}

fn found(head: Option<Head>, name: &str) -> Result<Head> {
    head.ok_or_else(|| Error::NotFound(format!("no script is published at urn:script:{name}")))
}

fn head_version(shared: &SpaceConfig, head: &Head) -> Result<Version> {
    shared
        .backend
        .version(&head.name, &head.version)?
        .ok_or_else(|| {
            Error::Endpoint(format!(
                "urn:script:{} points at version {}, which its backend does not hold",
                head.name, head.version
            ))
        })
}

// ---------------------------------------------------------------------------------------
// Arguments and faces
// ---------------------------------------------------------------------------------------

/// An optional inline argument; present-but-not-UTF-8 is an error, absent is `None`.
fn optional<'a>(inv: &'a Invocation<'_>, name: &str) -> Result<Option<&'a str>> {
    match inv.inline_str(name) {
        Ok(value) => Ok(Some(value)),
        Err(Error::MissingArgument(_)) => Ok(None),
        Err(other) => Err(other),
    }
}

fn parse_bool(name: &str, text: &str) -> Result<bool> {
    match text.trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(Error::InvalidArgument {
            name: name.to_string(),
            detail: format!("`{other}` is not `true` or `false`"),
        }),
    }
}

/// Which face was asked for. One this resource cannot serve is refused, never substituted.
fn wanted_face(inv: &Invocation<'_>) -> Result<&'static str> {
    match optional(inv, "as")? {
        None => Ok(PLAIN),
        Some(asked) => {
            let bare = asked.split(';').next().unwrap_or(asked).trim();
            READ_FACES
                .iter()
                .find(|face| **face == bare)
                .copied()
                .ok_or_else(|| Error::InvalidArgument {
                    name: "as".to_string(),
                    detail: format!(
                        "`{asked}` is not a face this resource serves; one of {}",
                        READ_FACES.join(", ")
                    ),
                })
        }
    }
}

fn plain(text: impl Into<String>) -> Representation {
    Representation::new(
        ReprType::new(PLAIN).with_param("charset", "utf-8"),
        text.into().into_bytes(),
    )
}

fn json<T: Serialize>(value: &T) -> Result<Representation> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|e| Error::Endpoint(format!("could not serialize a record: {e}")))?;
    bytes.push(b'\n');
    Ok(Representation::new(ReprType::new(JSON), bytes))
}

fn iri(text: &str) -> Result<Iri> {
    Iri::parse(text).map_err(|e| Error::Endpoint(format!("`{text}` is not an IRI: {e}")))
}

fn inline(text: &str) -> ArgRef {
    ArgRef::Inline(text.as_bytes().to_vec())
}

fn name_arg() -> ArgSpec {
    ArgSpec::new("name")
        .summary(
            "The script's name: one segment of lowercase letters, digits, `-` and `_` \
             (`eval`, `catalog` and `public` are reserved).",
        )
        .class(XSD_STRING)
        .binding()
}

fn as_arg() -> ArgSpec {
    ArgSpec::new("as")
        .summary(
            "The face: `text/plain` (for people) or `application/json` (the versioned \
             record, `\"schema\": 1`). Any other is refused, never substituted.",
        )
        .class(XSD_STRING)
        .one_of(READ_FACES)
        .default_value(PLAIN)
        .optional()
}

fn data_arg(arg: &str, summary: &str) -> ArgSpec {
    ArgSpec::new(arg)
        .summary(summary)
        .class(XSD_STRING)
        .optional()
}

// ---------------------------------------------------------------------------------------
// urn:script:{name} — the script (the head), and publishing
// ---------------------------------------------------------------------------------------

/// The script's JSON face: its head, flattened, with the version it points at.
#[derive(Serialize)]
struct ScriptDocument<'a> {
    iri: String,
    #[serde(flatten)]
    head: &'a Head,
    #[serde(rename = "versionIri")]
    version_iri: String,
    language: Language,
    requires: &'a BTreeSet<String>,
    source: &'a str,
}

struct ScriptEndpoint {
    shared: Arc<SpaceConfig>,
}

#[async_trait]
impl Endpoint for ScriptEndpoint {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        let name = name::from_bindings(inv)?;
        let shared = &self.shared;
        match inv.request.verb {
            Verb::Exists => {
                let exists = readable_head(inv, shared, &name)?.is_some();
                Ok(plain(if exists { "true\n" } else { "false\n" }).cacheable())
            }
            Verb::Source => {
                let want = wanted_face(inv)?;
                let head = found(readable_head(inv, shared, &name)?, &name)?;
                let version = head_version(shared, &head)?;
                let repr = if want == JSON {
                    json(&ScriptDocument {
                        iri: name::script_iri(&name),
                        head: &head,
                        version_iri: name::version_iri(&name, &head.version),
                        language: version.language,
                        requires: &version.requires,
                        source: &version.source,
                    })?
                } else {
                    plain(version.source)
                };
                Ok(repr.cacheable())
            }
            Verb::Sink => publish(inv, shared, &name),
            Verb::Delete => retire(inv, shared, &name),
            other => Err(unsupported("script", other)),
        }
    }

    fn name(&self) -> &str {
        "script"
    }

    fn describe(&self) -> Description {
        Description::new("script")
            .title("A script")
            .summary(
                "A script as a resource: fetch its source without running it, publish or \
                 replace it (every write is a new content-addressed version), or retire it.",
            )
            .verb(Verb::Meta)
            .action(
                ActionSpec::new(Verb::Source)
                    .summary(
                        "The script, WITHOUT running it: its source (`text/plain`), or its head \
                         record (`application/json`): state, public flag, version, what it \
                         declares and what its publisher held. Needs \
                         `urn:cap:script:read:{name}`, or `urn:cap:script:read:public` for a \
                         public published script.",
                    )
                    .input(name_arg())
                    .input(as_arg())
                    .output(PLAIN)
                    .output(JSON)
                    .requires(CAP_READ),
            )
            .action(
                ActionSpec::new(Verb::Exists)
                    .summary("Whether the script exists (to a caller who may read it).")
                    .input(name_arg())
                    .output(PLAIN)
                    .requires(CAP_READ),
            )
            .action(
                ActionSpec::new(Verb::Sink)
                    .summary(
                        "Publish or replace the script; answers the new version's IRI. The \
                         declared `requires` (plus the language's own capability) must all \
                         be held by the publisher, or the publish is refused: a script never \
                         runs with more than its publisher held. Needs \
                         `urn:cap:script:write:{name}`.",
                    )
                    .input(name_arg())
                    .input(
                        ArgSpec::new("content")
                            .summary("The source text.")
                            .class(XSD_STRING),
                    )
                    .input(
                        ArgSpec::new("language")
                            .summary(
                                "The script's language: `lisp`, or `sparql` (a query or \
                                 update, when the host mounts a SPARQL door).",
                            )
                            .class(XSD_STRING)
                            .one_of(Language::ALL.map(Language::as_str))
                            .default_value("lisp")
                            .optional(),
                    )
                    .input(
                        ArgSpec::new("requires")
                            .summary(
                                "Whitespace-separated `urn:cap:` grants the script needs to \
                                 run. Lisp: the language's capability is added; exact grants \
                                 only, no wildcards, no exclusions. SPARQL: DERIVED from the \
                                 graphs the text names, so omit it; one that says anything \
                                 else is refused, naming the derived set.",
                            )
                            .class(XSD_STRING)
                            .optional(),
                    )
                    .input(
                        ArgSpec::new("public")
                            .summary(
                                "Whether holders of `urn:cap:script:run:public` (a host's \
                                 anonymous principal) may run it and holders of \
                                 `urn:cap:script:read:public` read it.",
                            )
                            .class(XSD_BOOLEAN)
                            .one_of(["true", "false"])
                            .default_value("false")
                            .optional(),
                    )
                    .input(
                        ArgSpec::new("state")
                            .summary(
                                "`published` (runnable) or `draft` (saved, not runnable). \
                                 To retire, Delete.",
                            )
                            .class(XSD_STRING)
                            .one_of(["published", "draft"])
                            .default_value("published")
                            .optional(),
                    )
                    .input(
                        ArgSpec::new("if-version")
                            .summary(
                                "Write only if the head is still this version (`none`: only \
                                 if the script does not exist yet); otherwise `Conflict`.",
                            )
                            .class(XSD_STRING)
                            .optional(),
                    )
                    .output(PLAIN)
                    .requires(CAP_WRITE),
            )
            .action(
                ActionSpec::new(Verb::Delete)
                    .summary(
                        "Retire the script: it stays readable and its versions fetchable, but \
                         it never runs again until republished. Needs \
                         `urn:cap:script:delete:{name}`.",
                    )
                    .input(name_arg())
                    .output(PLAIN)
                    .requires(CAP_DELETE),
            )
    }
}

fn publish(inv: &Invocation<'_>, shared: &SpaceConfig, name: &str) -> Result<Representation> {
    require(inv, &cap_write(name), "publishing a script")?;
    let source = inv.inline_str("content")?;
    let language = optional(inv, "language")?
        .map(Language::parse)
        .transpose()?
        .unwrap_or(Language::Lisp);
    let requires = match language {
        Language::Lisp => {
            let mut requires = optional(inv, "requires")?
                .map(authority::parse_requires)
                .transpose()?
                .unwrap_or_default();
            requires.insert(CAP_LISP.to_string());
            requires
        }
        Language::Sparql => derived_requires(inv, shared, source)?,
    };
    let public = optional(inv, "public")?
        .map(|v| parse_bool("public", v))
        .transpose()?
        .unwrap_or(false);
    let state = match optional(inv, "state")?.map(str::trim) {
        None | Some("published") => State::Published,
        Some("draft") => State::Draft,
        Some(other) => {
            return Err(Error::InvalidArgument {
                name: "state".to_string(),
                detail: format!(
                    "`{other}` is not `published` or `draft`; to retire a script, Delete it"
                ),
            })
        }
    };
    // ★ No elevation: refused here, before anything is written, if the publisher does not
    // hold every scope the script declares.
    let grant = authority::grant_at_publish(inv.capability, &requires)?;

    let version = Version {
        language,
        requires,
        source: source.to_string(),
    };
    let digest = version.digest();
    let current = shared.backend.head(name)?;
    if let Some(expected) = optional(inv, "if-version")? {
        let at = current.as_ref().map_or("none", |h| h.version.as_str());
        if at != expected.trim() {
            return Err(Error::Conflict(format!(
                "urn:script:{name} is at {at}, not {}; read it again and retry",
                expected.trim()
            )));
        }
    }
    shared.backend.put_version(name, &version)?;

    let principal = (shared.principal)(inv);
    let at = inv.now().map(|t| t.as_millis());
    let mut history = current
        .as_ref()
        .map(|h| h.history.clone())
        .unwrap_or_default();
    history.push(Event {
        action: if state == State::Draft {
            "draft"
        } else {
            "publish"
        }
        .to_string(),
        version: digest.clone(),
        state,
        public,
        principal: principal.clone(),
        at,
    });
    let head = Head {
        schema: SCHEMA,
        name: name.to_string(),
        version: digest.clone(),
        state,
        public,
        granted: grant.granted,
        exclusions: grant.exclusions,
        publisher: principal,
        updated: at,
        history,
    };
    shared.backend.swap_head(name, current.as_ref(), &head)?;
    shared.changed(name);
    Ok(plain(format!("{}\n", name::version_iri(name, &digest))))
}

/// A SPARQL script's authority: DERIVED from the graphs its text names, never declared.
/// A `requires=` is accepted only when it says exactly the same thing, and refused naming
/// the derived set when it does not, so an author can neither under- nor over-declare.
fn derived_requires(
    inv: &Invocation<'_>,
    shared: &SpaceConfig,
    source: &str,
) -> Result<BTreeSet<String>> {
    let door = door(shared).map_err(|_| Error::InvalidArgument {
        name: "language".to_string(),
        detail: "this host takes no SPARQL scripts: it mounts no SPARQL door".to_string(),
    })?;
    let derived = sparql::analyze(source, door)?.requires();
    if let Some(said) = optional(inv, "requires")? {
        let said: BTreeSet<String> = said.split_whitespace().map(str::to_string).collect();
        if said != derived {
            return Err(Error::InvalidArgument {
                name: "requires".to_string(),
                detail: format!(
                    "a SPARQL script's authority is derived from the graphs its text names, \
                     not declared, and this one derives {}; the `requires` given says {}. \
                     Omit `requires`",
                    listed(&derived),
                    listed(&said)
                ),
            });
        }
    }
    Ok(derived)
}

fn listed(scopes: &BTreeSet<String>) -> String {
    if scopes.is_empty() {
        "nothing".to_string()
    } else {
        scopes.iter().cloned().collect::<Vec<_>>().join(" ")
    }
}

fn door(shared: &SpaceConfig) -> Result<&SparqlDoor> {
    shared.sparql.as_ref().ok_or_else(|| {
        Error::Endpoint(
            "this host mounts no SPARQL door (`SpaceConfig::sparql`), so it cannot run a \
             SPARQL script"
                .to_string(),
        )
    })
}

fn retire(inv: &Invocation<'_>, shared: &SpaceConfig, name: &str) -> Result<Representation> {
    require(inv, &cap_delete(name), "retiring a script")?;
    let current = found(shared.backend.head(name)?, name)?;
    let iri = name::script_iri(name);
    if current.state == State::Retired {
        return Ok(plain(format!("{iri} was already retired\n")));
    }
    let at = inv.now().map(|t| t.as_millis());
    let mut head = current.clone();
    head.state = State::Retired;
    head.updated = at;
    head.history.push(Event {
        action: "retire".to_string(),
        version: current.version.clone(),
        state: State::Retired,
        public: current.public,
        principal: (shared.principal)(inv),
        at,
    });
    shared.backend.swap_head(name, Some(&current), &head)?;
    shared.changed(name);
    Ok(plain(format!("retired {iri}\n")))
}

// ---------------------------------------------------------------------------------------
// urn:script:{name}:version:{digest}
// ---------------------------------------------------------------------------------------

struct VersionEndpoint {
    shared: Arc<SpaceConfig>,
}

#[async_trait]
impl Endpoint for VersionEndpoint {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        let name = name::from_bindings(inv)?;
        let digest = inv
            .bindings
            .get("digest")
            .ok_or_else(|| Error::Endpoint("no `digest` captured".to_string()))?
            .to_string();
        readable_head(inv, &self.shared, &name)?;
        let version = self.shared.backend.version(&name, &digest);
        match inv.request.verb {
            Verb::Exists => {
                let exists = match version {
                    Ok(v) => v.is_some(),
                    Err(Error::InvalidArgument { .. }) => false,
                    Err(other) => return Err(other),
                };
                Ok(plain(if exists { "true\n" } else { "false\n" }).cacheable())
            }
            Verb::Source => {
                let want = wanted_face(inv)?;
                let version = version?.ok_or_else(|| {
                    Error::NotFound(format!("urn:script:{name} has no version {digest}"))
                })?;
                let repr = if want == JSON {
                    json(&version.document(&name))?
                } else {
                    plain(version.source)
                };
                Ok(repr.cacheable())
            }
            other => Err(unsupported("script-version", other)),
        }
    }

    fn name(&self) -> &str {
        "script-version"
    }

    fn describe(&self) -> Description {
        let digest = || {
            ArgSpec::new("digest")
                .summary("The version's digest: `sha256:` and 64 hex digits over its content.")
                .class(XSD_STRING)
                .binding()
        };
        Description::new("script-version")
            .title("One version of a script")
            .summary(
                "An immutable version, named by the sha256 of its content (language, declared \
                 capability, source). Republishing moves the head; every version stays \
                 fetchable here.",
            )
            .verb(Verb::Meta)
            .action(
                ActionSpec::new(Verb::Source)
                    .summary(
                        "The version's source (`text/plain`) or its record (`application/json`).",
                    )
                    .input(name_arg())
                    .input(digest())
                    .input(as_arg())
                    .output(PLAIN)
                    .output(JSON)
                    .requires(CAP_READ),
            )
            .action(
                ActionSpec::new(Verb::Exists)
                    .summary("Whether the script has this version.")
                    .input(name_arg())
                    .input(digest())
                    .output(PLAIN)
                    .requires(CAP_READ),
            )
    }
}

// ---------------------------------------------------------------------------------------
// urn:script:{name}:compiled — the prepared form
// ---------------------------------------------------------------------------------------

/// The compiled form: everything a run needs, in one cacheable resource hung from the
/// script's thread. For Lisp the "compilation" is preparation — the evaluator offers no
/// separate compile step to cache — so this is the program and the authority it runs
/// under, bound to the version they came from. For SPARQL it adds what the parsed text
/// says: its form, its parameters and the graphs it names ([`Analysis`]).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Prepared {
    /// [`SCHEMA`].
    pub schema: u32,
    /// The script.
    pub name: String,
    /// `urn:script:{name}:compiled`.
    pub iri: String,
    /// The version prepared.
    pub version: String,
    /// Its language.
    pub language: Language,
    /// The door a run issues to: `urn:lisp:eval`, or the host's SPARQL door for this form.
    pub evaluator: String,
    /// The program.
    pub program: String,
    /// What it declares (for SPARQL: what its text derives).
    pub requires: BTreeSet<String>,
    /// What its publisher held of that.
    pub granted: BTreeSet<String>,
    /// The publisher's exclusions.
    pub exclusions: BTreeSet<String>,
    /// Whether it is public.
    pub public: bool,
    /// Its state.
    pub state: State,
    /// For a SPARQL script: its form, parameters and graphs, read from the parsed text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sparql: Option<Analysis>,
}

struct CompiledEndpoint {
    shared: Arc<SpaceConfig>,
}

#[async_trait]
impl Endpoint for CompiledEndpoint {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        if inv.request.verb != Verb::Source {
            return Err(unsupported("script-compiled", inv.request.verb));
        }
        let name = name::from_bindings(inv)?;
        // Readable by a reader or a runner: a run reads its program here.
        let head = found(
            gated_head(
                inv,
                &self.shared,
                &name,
                &[cap_read(&name), cap_run(&name)],
                &[CAP_READ_PUBLIC, CAP_RUN_PUBLIC],
            )?,
            &name,
        )?;
        let version = head_version(&self.shared, &head)?;
        let (evaluator, analysis) = match version.language {
            Language::Lisp => (LISP_EVAL.to_string(), None),
            Language::Sparql => {
                let door = door(&self.shared)?;
                let analysis = sparql::analyze(&version.source, door)?;
                (door.query_iri(analysis.form), Some(analysis))
            }
        };
        let prepared = Prepared {
            schema: SCHEMA,
            iri: name::part_iri(&name, "compiled"),
            version: head.version.clone(),
            language: version.language,
            evaluator,
            program: version.source,
            requires: version.requires,
            granted: head.granted,
            exclusions: head.exclusions,
            public: head.public,
            state: head.state,
            sparql: analysis,
            name: name.clone(),
        };
        // ★ Hung from the SCRIPT's thread, which every publish and retire cuts (the kernel
        // cuts the thread named after a Sink's or Delete's target). Without it a cached
        // compiled form would outlive the version it was prepared from.
        Ok(json(&prepared)?
            .cacheable()
            .depends_on(name::script_iri(&name)))
    }

    fn name(&self) -> &str {
        "script-compiled"
    }

    fn describe(&self) -> Description {
        Description::new("script-compiled")
            .title("A script's compiled form")
            .summary(
                "The head version prepared for its evaluator, with the authority it runs \
                 under (and, for SPARQL, its form, parameters and graphs): cached, and cut \
                 whenever the script is republished or retired. Readable by a holder of the \
                 script's read OR run grant (a run reads its program here).",
            )
            .verb(Verb::Meta)
            .action(
                ActionSpec::new(Verb::Source)
                    .summary("The prepared form, as JSON.")
                    .input(name_arg())
                    .output(JSON)
                    .requires(CAP_ANY),
            )
    }
}

// ---------------------------------------------------------------------------------------
// Running: …:result (a read) and …:runs (a write)
// ---------------------------------------------------------------------------------------

const LISP_EVAL: &str = "urn:lisp:eval";

/// Read the compiled form through the kernel, check the run gate and the state, and
/// compute what the run may keep of the runner's capability (and under which ceiling).
async fn prepare_run(
    inv: &Invocation<'_>,
    shared: &SpaceConfig,
    name: &str,
) -> Result<(Prepared, BTreeSet<String>, Ceiling)> {
    // Composed, not reached into: the run is a reader of its own compiled form, so the
    // compiled form's thread (and the script's, through it) lands on the result.
    let compiled = inv
        .issue(Request::new(
            Verb::Source,
            iri(&name::part_iri(name, "compiled"))?,
        ))
        .await?;
    let prepared: Prepared = serde_json::from_slice(&compiled.bytes).map_err(|e| {
        Error::Endpoint(format!(
            "urn:script:{name}:compiled did not answer a prepared form: {e}"
        ))
    })?;
    if prepared.name != name {
        return Err(Error::Endpoint(format!(
            "urn:script:{name}:compiled answered for `{}`",
            prepared.name
        )));
    }
    let public = prepared.public && prepared.state == State::Published;
    let may_run = holds(inv, &cap_run(name)) || (public && holds(inv, CAP_RUN_PUBLIC));
    if !may_run {
        return Err(Error::Denied(format!(
            "running urn:script:{name} needs `{}`{}",
            cap_run(name),
            if prepared.public {
                format!(" (or `{CAP_RUN_PUBLIC}`, since it is public)")
            } else {
                " — it is not public".to_string()
            }
        )));
    }
    match prepared.state {
        State::Published => {}
        State::Draft => {
            return Err(Error::Conflict(format!(
                "urn:script:{name} is a draft; publish it (`state=published`) to run it, or \
                 try the code at urn:script:eval"
            )))
        }
        State::Retired => {
            return Err(Error::Conflict(format!(
                "urn:script:{name} is retired; publish it again to run it"
            )))
        }
    }
    let ceiling = (shared.ceiling)(name);
    let keep = authority::effective(
        &prepared.requires,
        &prepared.granted,
        &prepared.exclusions,
        &ceiling,
    );
    Ok((prepared, keep, ceiling))
}

/// The Lisp evaluator sub-request: `in` is the program, `data` what it reads with `(input)`.
fn lisp_request(program: &str, data: Option<&str>) -> Result<Request> {
    let mut request = Request::new(Verb::Source, iri(LISP_EVAL)?).with_arg("in", inline(program));
    if let Some(data) = data {
        request = request.with_arg("data", inline(data));
    }
    Ok(request)
}

/// `run_args`: the description of the run's input, shared by both run doors.
const DATA_SUMMARY: &str = "Optional data the script reads with `(input)` — data, never code.";

/// Which door a run came through.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Door {
    /// `…:result`: a read, answered with the script's value.
    Result,
    /// `…:runs`: a write, recorded.
    Runs,
}

/// What a run issues, and exactly the scopes it issues it under (before the runner's own
/// capability is attenuated to them).
struct Planned {
    request: Request,
    keep: BTreeSet<String>,
}

/// The run's sub-request, for whichever language the script is in.
async fn plan(
    inv: &Invocation<'_>,
    shared: &SpaceConfig,
    prepared: &Prepared,
    keep: BTreeSet<String>,
    ceiling: &Ceiling,
    through: Door,
) -> Result<Planned> {
    match prepared.language {
        Language::Lisp => {
            let data = optional(
                inv,
                match through {
                    Door::Result => "data",
                    Door::Runs => "content",
                },
            )?;
            Ok(Planned {
                request: lisp_request(&prepared.program, data)?,
                keep,
            })
        }
        Language::Sparql => plan_sparql(inv, shared, prepared, keep, ceiling, through).await,
    }
}

/// A SPARQL run: bind the parameters into the parsed query, work out its dataset and the
/// exact store grants it needs, and address the host's store door for its form.
///
/// ★ **The dataset is never wider than the authority.** The graphs the text fixes need
/// their grants in the run's capability (the store refuses the whole read, naming the
/// grant, when one is missing). A graph only the run decides (`GRAPH ?g`, or a parameter
/// naming a graph) is admitted only under the derived family, and only when the
/// publisher held it (or was root), the host's ceiling allows it AND the runner holds it:
/// that set is "the caller's readable union", computed here per run and never more.
async fn plan_sparql(
    inv: &Invocation<'_>,
    shared: &SpaceConfig,
    prepared: &Prepared,
    mut keep: BTreeSet<String>,
    ceiling: &Ceiling,
    through: Door,
) -> Result<Planned> {
    let name = &prepared.name;
    let door = door(shared)?;
    let analysis = prepared.sparql.as_ref().ok_or_else(|| {
        Error::Endpoint(format!(
            "urn:script:{name}:compiled carries no SPARQL analysis"
        ))
    })?;
    if through == Door::Result && !analysis.form.is_read() {
        return Err(Error::InvalidArgument {
            name: "name".to_string(),
            detail: format!(
                "urn:script:{name} is a SPARQL UPDATE, which is a write: run it with a Sink to \
                 urn:script:{name}:runs"
            ),
        });
    }
    let values = parameter_values(inv, name, &analysis.parameters, through)?;
    let face = sparql_face(inv, analysis.form)?;
    let bound = sparql::bind(&prepared.program, door, &values)?;

    let runner = inv.capability;
    // The root publisher's marker: expanded below into exact grants, never attenuated as
    // it stands (attenuation keeps grants by exact name).
    let root_marker = keep.remove(CAP_READ_GRAPH);
    let family = prepared.requires.contains(CAP_READ_GRAPH);
    let by_family = |scope: &str, keep: &BTreeSet<String>| {
        family
            && runner.allows(scope)
            && if root_marker {
                ceiling.allows(scope)
            } else {
                keep.contains(scope)
            }
    };

    if bound.form == Form::Update {
        // An update's one graph is fixed by its text (a parameter cannot name it), so its
        // grants are exactly the derived ones, already in `keep`.
        let graph = bound.graphs.iter().next().cloned().ok_or_else(|| {
            Error::Endpoint(format!("urn:script:{name} names no graph to update"))
        })?;
        for scope in &prepared.requires {
            may_use(name, &graph, scope, &keep, runner)?;
        }
        let request = Request::new(Verb::Sink, iri(&door.query_iri(Form::Update))?)
            .with_arg("content", inline(&bound.text))
            .with_arg("graph", inline(&graph));
        return Ok(Planned { request, keep });
    }

    let mut extra = BTreeSet::new();
    for graph in &bound.graphs {
        let scope = sparql::cap_read_graph(graph);
        if !keep.contains(&scope) && by_family(&scope, &keep) {
            extra.insert(scope);
        }
    }
    let mut dataset = bound.graphs.clone();
    if bound.any_graph {
        if !family {
            return Err(Error::Endpoint(format!(
                "urn:script:{name} reads a variable graph but its record derives no \
                 `{CAP_READ_GRAPH}`; republish it"
            )));
        }
        let under = |scopes: &mut dyn Iterator<Item = &String>| -> BTreeSet<String> {
            scopes
                .filter_map(|s| s.strip_prefix(sparql::READ_GRAPH_PREFIX))
                .filter(|g| !g.starts_with('-') && !g.ends_with('*'))
                .map(str::to_string)
                .collect()
        };
        let candidates = if !root_marker {
            under(&mut keep.iter())
        } else if let Some(held) = runner.scopes() {
            under(&mut held.iter())
        } else {
            // Root ran a script a root published: the readable union is every graph the
            // store holds, listed by the store itself under the broad read the runner holds.
            let listing = inv
                .issue_attenuated(
                    Request::new(Verb::Source, iri(&door.graphs_iri())?),
                    [sparql::CAP_STORE_READ.to_string()],
                )
                .await?;
            String::from_utf8_lossy(&listing.bytes)
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect()
        };
        for graph in candidates {
            let scope = sparql::cap_read_graph(&graph);
            if keep.contains(&scope) && runner.allows(&scope) || by_family(&scope, &keep) {
                extra.insert(scope);
                dataset.insert(graph);
            }
        }
    }
    if dataset.is_empty() {
        return Err(Error::Denied(format!(
            "urn:script:{name} reads the caller's readable graphs, and this run may read none: \
             it needs `{}` grants the publisher held, the host allows and the runner holds",
            sparql::READ_GRAPH_PREFIX
        )));
    }
    keep.extend(extra);
    for graph in &dataset {
        may_use(name, graph, &sparql::cap_read_graph(graph), &keep, runner)?;
    }
    let graphs = dataset.into_iter().collect::<Vec<_>>().join(" ");
    let request = Request::new(Verb::Source, iri(&door.query_iri(bound.form))?)
        .with_arg("query", inline(&bound.text))
        .with_arg("graph", inline(&graphs))
        .with_arg("as", inline(face));
    Ok(Planned { request, keep })
}

/// Refused HERE, naming the exact grant and who withheld it, rather than by the store's
/// door: the kernel's floor there sees only the family a run holds, so its refusal would
/// name `urn:cap:store:read:graph:*` and not the graph.
fn may_use(
    name: &str,
    graph: &str,
    scope: &str,
    keep: &BTreeSet<String>,
    runner: &ikigai_core::Capability,
) -> Result<()> {
    if !runner.allows(scope) {
        return Err(Error::Denied(format!(
            "running urn:script:{name} reads or writes <{graph}>, which needs `{scope}`, and the \
             runner does not hold it"
        )));
    }
    if !keep.contains(scope) {
        return Err(Error::Denied(format!(
            "running urn:script:{name} reads or writes <{graph}>, which needs `{scope}`, and \
             this script may not have it: its publisher did not hold it, or the host's ceiling \
             for it does not allow it"
        )));
    }
    Ok(())
}

/// The face a SPARQL run answers in: `as=`, one its form can serve, or the form's default.
/// Refused, never substituted.
fn sparql_face(inv: &Invocation<'_>, form: Form) -> Result<&'static str> {
    let faces = form.faces();
    match optional(inv, "as")? {
        None => Ok(faces[0]),
        Some(asked) => {
            let bare = asked.split(';').next().unwrap_or(asked).trim();
            faces
                .iter()
                .find(|f| **f == bare)
                .copied()
                .ok_or_else(|| Error::InvalidArgument {
                    name: "as".to_string(),
                    detail: format!(
                        "`{asked}` is not a face a SPARQL {} answers in; one of {}",
                        form.as_str().to_uppercase(),
                        faces.join(", ")
                    ),
                })
        }
    }
}

/// The run's parameter values, each checked against its declared type.
///
/// Named arguments, or (through `…:runs`) a JSON object piped as `content`. A missing
/// required parameter is `MissingArgument`; a value that is not of its type, a parameter
/// given both ways, and an argument the script does not declare are `InvalidArgument`: a
/// binding the query does not mention is refused, never ignored, so a filter you thought
/// was applied can never silently not be.
fn parameter_values(
    inv: &Invocation<'_>,
    name: &str,
    parameters: &[Parameter],
    through: Door,
) -> Result<BTreeMap<String, Value>> {
    let declared = || {
        if parameters.is_empty() {
            "it declares none".to_string()
        } else {
            format!(
                "its parameters are {}",
                parameters
                    .iter()
                    .map(|p| p.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
    };
    for arg in inv.request.args.keys() {
        let known = arg == "as"
            || (through == Door::Runs && arg == "content")
            || parameters.iter().any(|p| &p.name == arg);
        if !known {
            return Err(Error::InvalidArgument {
                name: arg.clone(),
                detail: format!("is not a parameter of urn:script:{name}; {}", declared()),
            });
        }
    }
    let mut piped: BTreeMap<String, String> = BTreeMap::new();
    if through == Door::Runs {
        // An empty body is no parameters: a bare `sink …:runs` sends one.
        if let Some(content) = optional(inv, "content")?.filter(|c| !c.trim().is_empty()) {
            let object: serde_json::Map<String, serde_json::Value> = serde_json::from_str(content)
                .map_err(|e| Error::InvalidArgument {
                    name: "content".to_string(),
                    detail: format!(
                        "a SPARQL script's piped content is its parameters as one JSON object \
                         ({e})"
                    ),
                })?;
            for (key, value) in object {
                let lexical = match value {
                    serde_json::Value::String(s) => s,
                    serde_json::Value::Number(n) => n.to_string(),
                    serde_json::Value::Bool(b) => b.to_string(),
                    other => {
                        return Err(Error::InvalidArgument {
                            name: "content".to_string(),
                            detail: format!(
                                "`{key}` is {other}; a parameter's value is a string, a number \
                                 or a boolean"
                            ),
                        })
                    }
                };
                piped.insert(key, lexical);
            }
        }
    }
    let mut values = BTreeMap::new();
    for parameter in parameters {
        let named = optional(inv, &parameter.name)?;
        let lexical = match (named, piped.remove(&parameter.name)) {
            (Some(_), Some(_)) => {
                return Err(Error::InvalidArgument {
                    name: parameter.name.clone(),
                    detail: "is given both by name and in the piped content".to_string(),
                })
            }
            (Some(value), None) => Some(value.to_string()),
            (None, Some(value)) => Some(value),
            (None, None) => parameter.default.clone(),
        };
        match lexical {
            Some(lexical) => {
                values.insert(parameter.name.clone(), parameter.value(&lexical)?);
            }
            None if parameter.required => {
                return Err(Error::MissingArgument(parameter.name.clone()));
            }
            None => {}
        }
    }
    if let Some(stray) = piped.keys().next() {
        return Err(Error::InvalidArgument {
            name: "content".to_string(),
            detail: format!(
                "`{stray}` is not a parameter of urn:script:{name}; {}",
                declared()
            ),
        });
    }
    Ok(values)
}

struct ResultEndpoint {
    shared: Arc<SpaceConfig>,
}

#[async_trait]
impl Endpoint for ResultEndpoint {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        if inv.request.verb != Verb::Source {
            return Err(unsupported("script-result", inv.request.verb));
        }
        let name = name::from_bindings(inv)?;
        let (prepared, keep, ceiling) = prepare_run(inv, &self.shared, &name).await?;
        let planned = plan(inv, &self.shared, &prepared, keep, &ceiling, Door::Result).await?;
        // ★ The ONLY authority a run gets: the runner's own capability, narrowed. There is
        // no form that widens, so a script cannot reach past its runner whatever it says.
        let answer = inv.issue_attenuated(planned.request, planned.keep).await?;
        // Cacheable as far as this endpoint is concerned; the kernel folds in the
        // evaluator's expiry (a Lisp program is uncacheable unless it opts in with
        // `(cacheable …)`; a query is as cacheable as the store's answer, which hangs from
        // the store's write threads) and the compiled form's threads. The authority thread
        // is the host's to cut when it changes this script's ceiling.
        Ok(Representation::new(answer.repr_type, answer.bytes)
            .cacheable()
            .depends_on(name::authority_thread(&name)))
    }

    fn name(&self) -> &str {
        "script-result"
    }

    fn describe(&self) -> Description {
        Description::new("script-result")
            .title("A script's result")
            .summary(
                "Run the script as a READ and answer its value. It runs under the runner's \
                 capability narrowed to what the script declares, its publisher held and \
                 the host allows it — never more. Cacheable exactly as far as the script's \
                 own sub-requests are (a Lisp program opts in with `(cacheable …)`), and \
                 recomputed when the script is republished. No run record: a cached answer \
                 runs nothing; record a run with `…:runs`. A published SPARQL script is \
                 its own entry, with its parameters as arguments.",
            )
            .verb(Verb::Meta)
            .action(
                ActionSpec::new(Verb::Source)
                    .summary("The script's answer.")
                    .input(name_arg())
                    .input(data_arg("data", DATA_SUMMARY))
                    .output(PLAIN)
                    .requires(CAP_RUN)
                    .requires(CAP_LISP),
            )
    }
}

struct RunsEndpoint {
    shared: Arc<SpaceConfig>,
}

#[async_trait]
impl Endpoint for RunsEndpoint {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        if inv.request.verb != Verb::Sink {
            return Err(unsupported("script-runs", inv.request.verb));
        }
        let name = name::from_bindings(inv)?;
        let shared = &self.shared;
        let (prepared, keep, ceiling) = prepare_run(inv, shared, &name).await?;
        // A caller's mistake (a missing or ill-typed parameter) is refused here, before a
        // run is recorded: nothing ran.
        let planned = plan(inv, shared, &prepared, keep, &ceiling, Door::Runs).await?;
        let runs_as = inv.capability.attenuate(planned.keep.iter().cloned());
        let mut run = Run {
            schema: SCHEMA,
            name: name.clone(),
            id: 0,
            version: prepared.version.clone(),
            principal: (shared.principal)(inv),
            capability: runs_as.scopes().cloned().unwrap_or_default(),
            started: inv.now().map(|t| t.as_millis()),
            ended: None,
            outcome: Outcome::Running,
            result: None,
            truncated: false,
            trace_span: inv.trace_span(),
        };
        run.id = shared.backend.start_run(&name, &run)?;
        let answer = inv.issue_attenuated(planned.request, planned.keep).await;
        run.ended = inv.now().map(|t| t.as_millis());
        match answer {
            Ok(repr) => {
                let (text, truncated) = model::truncate(
                    String::from_utf8_lossy(&repr.bytes).into_owned(),
                    MAX_RECORDED_RESULT,
                );
                run.outcome = Outcome::Ok;
                run.result = Some(text);
                run.truncated = truncated;
                shared.backend.finish_run(&name, &run)?;
                Ok(plain(format!("{}\n", run.iri())))
            }
            Err(error) => {
                run.outcome = Outcome::Failed {
                    kind: kind(&error).to_string(),
                    message: error.to_string(),
                };
                shared.backend.finish_run(&name, &run)?;
                Err(annotate(error, &run.iri()))
            }
        }
    }

    fn name(&self) -> &str {
        "script-runs"
    }

    fn describe(&self) -> Description {
        Description::new("script-runs")
            .title("A script's runs")
            .summary(
                "Run the script for its EFFECTS and record the run: who (as the host \
                 stamped it), which version, under exactly what capability, when, and the \
                 outcome. Answers the run's IRI; a run that fails is recorded too, and its \
                 error names the record. A published SPARQL script is its own entry, with \
                 its parameters as arguments.",
            )
            .verb(Verb::Meta)
            .action(
                ActionSpec::new(Verb::Sink)
                    .summary("Run the script and record the run.")
                    .input(name_arg())
                    .input(data_arg("content", DATA_SUMMARY))
                    .output(PLAIN)
                    .requires(CAP_RUN)
                    .requires(CAP_LISP),
            )
    }
}

// ---------------------------------------------------------------------------------------
// A published SPARQL script's own contract, and the space that offers it
// ---------------------------------------------------------------------------------------

/// A SPARQL script's own endpoints, `…:result` and `…:runs`, each the template's endpoint
/// behind the script's OWN description.
#[derive(Clone)]
struct PerScript {
    result: Arc<dyn Endpoint>,
    runs: Arc<dyn Endpoint>,
    /// Whether its `…:result` is a read it offers (a query, not an update).
    reads: bool,
    /// Whether it is published, and so listed in the catalog. A draft or a retired script
    /// still answers under its own contract (its run is refused for its state, not for a
    /// language capability it never needed), but is not offered.
    listed: bool,
}

/// The template's endpoint, behind one script's contract.
///
/// ★ **Why a script is its own entry.** A description is the contract the engine routes
/// arguments by, selection matches on, MCP projects and the Emacs aliases are generated
/// from, and the kernel answers it per ENDPOINT, never per IRI. A query's parameters are
/// real arguments only if they are in a description, so each published query gets one.
/// It is built once per head (the kernel memoizes floors by this allocation) and dropped
/// by the next publish or retire.
struct Described {
    inner: Arc<dyn Endpoint>,
    id: String,
    description: Description,
}

#[async_trait]
impl Endpoint for Described {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        self.inner.invoke(inv).await
    }

    fn name(&self) -> &str {
        &self.id
    }

    fn describe(&self) -> Description {
        self.description.clone()
    }
}

/// The script resources as a space: [`space`]'s bindings, plus each published SPARQL
/// script as its own `…:result` and `…:runs` entry, carrying its parameters.
pub struct ScriptSpace {
    inner: EndpointSpace,
    shared: Arc<SpaceConfig>,
}

impl ScriptSpace {
    /// The script's own endpoints, when it is a SPARQL script this host can run.
    fn per_script(&self, name: &str) -> Option<PerScript> {
        let shared = &self.shared;
        if let Some(known) = shared
            .described
            .lock()
            .expect("the described-script memo")
            .get(name)
        {
            return known.clone();
        }
        let built = self.build(name);
        shared
            .described
            .lock()
            .expect("the described-script memo")
            .insert(name.to_string(), built.clone());
        built
    }

    fn build(&self, name: &str) -> Option<PerScript> {
        let shared = &self.shared;
        let door = shared.sparql.as_ref()?;
        let head = shared.backend.head(name).ok()??;
        let version = shared.backend.version(name, &head.version).ok()??;
        if version.language != Language::Sparql {
            return None;
        }
        let analysis = sparql::analyze(&version.source, door).ok()?;
        let about = about(&version.source);
        // The run gate, as the kernel can check it before the endpoint is entered: the
        // script's own grant, or for a public one the family (its own grant OR the
        // public one, which `requires` cannot say any other way: it is all-of).
        let gate = if head.public {
            CAP_RUN.to_string()
        } else {
            cap_run(name)
        };
        let params = |mut spec: ActionSpec| {
            for p in &analysis.parameters {
                let mut arg = ArgSpec::new(p.name.clone())
                    .summary(
                        p.summary
                            .clone()
                            .unwrap_or_else(|| format!("The value of ?{} in the query.", p.name)),
                    )
                    .class(p.kind.iri().to_string());
                if let Some(default) = &p.default {
                    arg = arg.default_value(default.clone()).optional();
                } else if !p.required {
                    arg = arg.optional();
                }
                spec = spec.input(arg);
            }
            spec = spec.requires(gate.clone());
            for scope in &version.requires {
                spec = spec.requires(scope.clone());
            }
            spec
        };
        let form = analysis.form;
        let faces = form.faces();
        let as_arg = || {
            ArgSpec::new("as")
                .summary(format!(
                    "The face: one of {}. Any other is refused, never substituted.",
                    faces.join(", ")
                ))
                .class(XSD_STRING)
                .one_of(faces.iter().copied())
                .default_value(faces[0])
                .optional()
        };
        let id = format!("script-{name}-result");
        let description = if form.is_read() {
            let mut spec = params(ActionSpec::new(Verb::Source))
                .summary(format!("Run the query {name} and answer its result."))
                .input(as_arg());
            for face in faces {
                spec = spec.output(*face);
            }
            Description::new(id.clone())
                .title(format!("{name}: a SPARQL {}", form.as_str().to_uppercase()))
                .summary(format!(
                    "{about}Runs as a READ under the runner's capability narrowed to the \
                     graphs the query names; cached as the store's answer is, and \
                     recomputed after a write to the store or a republish."
                ))
                .verb(Verb::Meta)
                .action(spec)
        } else {
            // An update is never a read: no action is offered here, and a Source that
            // arrives anyway is refused by the run, naming `…:runs`.
            Description::new(id.clone())
                .title(format!("{name}: a SPARQL UPDATE (run it at …:runs)"))
                .summary(format!(
                    "{about}A write: run it with a Sink to urn:script:{name}:runs."
                ))
                .verb(Verb::Meta)
        };
        let result = Arc::new(Described {
            inner: Arc::new(ResultEndpoint {
                shared: Arc::clone(shared),
            }),
            description,
            id,
        }) as Arc<dyn Endpoint>;
        let id = format!("script-{name}-runs");
        let mut spec = params(ActionSpec::new(Verb::Sink))
            .summary(format!(
                "Run {name} for its effects and record the run; answers the run's IRI."
            ))
            .input(
                ArgSpec::new("content")
                    .summary(
                        "The parameters as one JSON object, for a pipe (a parameter given \
                         both here and by name is refused).",
                    )
                    .class(XSD_STRING)
                    .optional(),
            )
            .output(PLAIN);
        if form.is_read() {
            spec = spec.input(as_arg());
        }
        let runs = Arc::new(Described {
            inner: Arc::new(RunsEndpoint {
                shared: Arc::clone(shared),
            }),
            description: Description::new(id.clone())
                .title(format!("{name}: runs"))
                .summary(format!(
                    "{about}Each run is recorded: who, which version, under exactly what \
                     capability, when, and the outcome."
                ))
                .verb(Verb::Meta)
                .action(spec),
            id,
        }) as Arc<dyn Endpoint>;
        Some(PerScript {
            result,
            runs,
            reads: form.is_read(),
            listed: head.state == State::Published,
        })
    }
}

/// A script's own words for the catalog: its leading comment lines that declare nothing.
fn about(source: &str) -> String {
    let mut lines = Vec::new();
    for line in source.lines() {
        let trimmed = line.trim();
        let Some(body) = trimmed.strip_prefix('#') else {
            if trimmed.is_empty() {
                continue;
            }
            break;
        };
        let body = body.trim();
        if !body.is_empty() && !body.starts_with("@param") {
            lines.push(body);
        }
    }
    if lines.is_empty() {
        String::new()
    } else {
        format!("{} ", lines.join(" "))
    }
}

impl Space for ScriptSpace {
    fn resolve(&self, request: &Request, scope: &Scope) -> Resolution {
        let resolution = self.inner.resolve(request, scope);
        let (name, part) = match &resolution {
            Resolution::Hit(hit) => {
                let part = match hit.endpoint.name() {
                    "script-result" => Door::Result,
                    "script-runs" => Door::Runs,
                    _ => return resolution,
                };
                match hit.bindings.get("name") {
                    Some(name) if name::validate(name).is_ok() => (name.to_string(), part),
                    _ => return resolution,
                }
            }
            Resolution::Miss => return resolution,
        };
        match self.per_script(&name) {
            Some(per) => resolution.map_endpoint(|_| match part {
                Door::Result => per.result,
                Door::Runs => per.runs,
            }),
            None => resolution,
        }
    }

    fn entries(&self) -> Option<Vec<SpaceEntry>> {
        let mut entries = self.inner.entries().unwrap_or_default();
        for name in self.shared.backend.names().unwrap_or_default() {
            let Some(per) = self.per_script(&name).filter(|per| per.listed) else {
                continue;
            };
            if per.reads {
                entries.push(SpaceEntry::new(
                    name::part_iri(&name, "result"),
                    per.result.name(),
                ));
            }
            entries.push(SpaceEntry::new(
                name::part_iri(&name, "runs"),
                per.runs.name(),
            ));
        }
        Some(entries)
    }

    fn id(&self) -> Option<Iri> {
        self.inner.id()
    }

    fn topology(&self) -> Topology {
        self.inner.topology()
    }
}

/// An error's kind, as a run record spells it.
fn kind(error: &Error) -> &'static str {
    match error {
        Error::Unresolved(_) => "unresolved",
        Error::MissingArgument(_) => "missing-argument",
        Error::InvalidArgument { .. } => "invalid-argument",
        Error::Endpoint(_) => "endpoint",
        Error::Denied(_) => "denied",
        Error::NotFound(_) => "not-found",
        Error::Conflict(_) => "conflict",
        Error::Timeout(_) => "timeout",
        Error::Unavailable(_) => "unavailable",
        _ => "other",
    }
}

/// The same error, of the same type, naming the run record it was written to.
fn annotate(error: Error, run: &str) -> Error {
    let note = |message: String| format!("{message} (run recorded at {run})");
    match error {
        Error::Endpoint(m) => Error::Endpoint(note(m)),
        Error::Denied(m) => Error::Denied(note(m)),
        Error::NotFound(m) => Error::NotFound(note(m)),
        Error::Conflict(m) => Error::Conflict(note(m)),
        Error::Timeout(m) => Error::Timeout(note(m)),
        Error::Unavailable(m) => Error::Unavailable(note(m)),
        Error::InvalidArgument { name, detail } => Error::InvalidArgument {
            name,
            detail: note(detail),
        },
        other => other,
    }
}

// ---------------------------------------------------------------------------------------
// urn:script:{name}:run:{id}
// ---------------------------------------------------------------------------------------

struct RunEndpoint {
    shared: Arc<SpaceConfig>,
}

#[async_trait]
impl Endpoint for RunEndpoint {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        let name = name::from_bindings(inv)?;
        // A run record says who ran what: readable by the script's readers and its named
        // runners, never through the public grants.
        if !holds(inv, &cap_read(&name)) && !holds(inv, &cap_run(&name)) {
            return Err(Error::Denied(format!(
                "a run record of urn:script:{name} needs `{}` or `{}`",
                cap_read(&name),
                cap_run(&name)
            )));
        }
        let id_text = inv
            .bindings
            .get("id")
            .ok_or_else(|| Error::Endpoint("no `id` captured".to_string()))?;
        let id = id_text.parse::<u64>().map_err(|_| Error::InvalidArgument {
            name: "id".to_string(),
            detail: format!("`{id_text}` is not a run number"),
        });
        let run = match id {
            Ok(id) => self.shared.backend.run(&name, id)?,
            Err(_) if inv.request.verb == Verb::Exists => None,
            Err(e) => return Err(e),
        };
        match inv.request.verb {
            Verb::Exists => Ok(plain(if run.is_some() { "true\n" } else { "false\n" })),
            Verb::Source => {
                let want = wanted_face(inv)?;
                let run = run.ok_or_else(|| {
                    Error::NotFound(format!("urn:script:{name} has no run {id_text}"))
                })?;
                let finished = run.outcome != Outcome::Running;
                let repr = if want == JSON {
                    json(&run)?
                } else {
                    plain(run.render())
                };
                // A finished run never changes again; one still running will.
                Ok(if finished { repr.cacheable() } else { repr })
            }
            other => Err(unsupported("script-run", other)),
        }
    }

    fn name(&self) -> &str {
        "script-run"
    }

    fn describe(&self) -> Description {
        let id = || {
            ArgSpec::new("id")
                .summary("The run's number, unique per script.")
                .class(XSD_INTEGER)
                .binding()
        };
        Description::new("script-run")
            .title("One run of a script")
            .summary(
                "A recorded run: principal, version, capability, start and end, outcome, the \
                 result (up to 64 KiB) and the host's trace span when it traced. Needs the \
                 script's read or run grant.",
            )
            .verb(Verb::Meta)
            .action(
                ActionSpec::new(Verb::Source)
                    .summary("The run record.")
                    .input(name_arg())
                    .input(id())
                    .input(as_arg())
                    .output(PLAIN)
                    .output(JSON)
                    .requires(CAP_ANY),
            )
            .action(
                ActionSpec::new(Verb::Exists)
                    .summary("Whether the run exists.")
                    .input(name_arg())
                    .input(id())
                    .output(PLAIN)
                    .requires(CAP_ANY),
            )
    }
}

// ---------------------------------------------------------------------------------------
// urn:script:eval — the paste box
// ---------------------------------------------------------------------------------------

struct EvalEndpoint;

#[async_trait]
impl Endpoint for EvalEndpoint {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        if inv.request.verb != Verb::Sink {
            return Err(unsupported("script-eval", inv.request.verb));
        }
        let code = inv.inline_str("content")?;
        let language_text = optional(inv, "language")?;
        let language = language_text
            .map(Language::parse)
            .transpose()?
            .unwrap_or(Language::Lisp);
        if language == Language::Sparql {
            return Err(Error::InvalidArgument {
                name: "language".to_string(),
                detail: "SPARQL through urn:script:eval is the SPARQL Protocol face (ledger \
                         #955), not in this version: publish the query as a script and read \
                         its `…:result`"
                    .to_string(),
            });
        }
        if let Some(save) = optional(inv, "save")? {
            let save = save.trim();
            name::validate(save)?;
            // Saved the way any writer saves: a Sink to the script, under the caller's own
            // capability (so it needs `urn:cap:script:write:{save}`), which cuts the script's
            // thread like every other write.
            let mut request = Request::new(Verb::Sink, iri(&name::script_iri(save))?)
                .with_arg("content", inline(code))
                .with_arg("language", inline(language.as_str()))
                .with_arg("state", inline("draft"));
            if let Some(requires) = optional(inv, "requires")? {
                request = request.with_arg("requires", inline(requires));
            }
            inv.issue(request).await?;
        }
        // ★ The caller's OWN capability, unchanged: `issue`, not `issue_attenuated`, and
        // nothing that could add to it exists.
        let answer = inv
            .issue(lisp_request(code, optional(inv, "data")?)?)
            .await?;
        Ok(Representation::new(answer.repr_type, answer.bytes))
    }

    fn name(&self) -> &str {
        "script-eval"
    }

    fn describe(&self) -> Description {
        Description::new("script-eval")
            .title("Run code you supply")
            .summary(
                "Run typed or pasted code as an anonymous script under the caller's OWN \
                 capability and nothing more; answers its value. `save=` keeps it as a draft \
                 of that script (which needs that script's write grant).",
            )
            .verb(Verb::Meta)
            .action(
                ActionSpec::new(Verb::Sink)
                    .summary("Run the code.")
                    .input(
                        ArgSpec::new("content")
                            .summary("The code (piped).")
                            .class(XSD_STRING),
                    )
                    .input(
                        ArgSpec::new("language")
                            .summary(
                                "The code's language: `lisp` (SPARQL here is the Protocol \
                                 face, not in this version).",
                            )
                            .class(XSD_STRING)
                            .one_of(Language::ALL.map(Language::as_str))
                            .default_value("lisp")
                            .optional(),
                    )
                    .input(data_arg("data", DATA_SUMMARY))
                    .input(
                        ArgSpec::new("save")
                            .summary(
                                "A script name: also keep the code as a draft at \
                                 `urn:script:{save}`. Needs `urn:cap:script:write:{save}`.",
                            )
                            .class(XSD_STRING)
                            .optional(),
                    )
                    .input(
                        ArgSpec::new("requires")
                            .summary("With `save=`: the draft's declared capability.")
                            .class(XSD_STRING)
                            .optional(),
                    )
                    .output(PLAIN)
                    .requires(CAP_LISP),
            )
    }
}

// ---------------------------------------------------------------------------------------
// urn:script:catalog
// ---------------------------------------------------------------------------------------

/// One row of the catalog.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogEntry {
    /// The script.
    pub name: String,
    /// `urn:script:{name}`.
    pub iri: String,
    /// Its state, when its head could be read.
    pub state: Option<State>,
    /// Whether it is public.
    pub public: Option<bool>,
    /// Its head version.
    pub version: Option<String>,
    /// Its latest run.
    #[serde(rename = "lastRun")]
    pub last_run: Option<LastRun>,
    /// Why its head could not be read, when it could not.
    pub error: Option<String>,
}

/// A catalog row's latest run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastRun {
    /// `urn:script:{name}:run:{id}`.
    pub iri: String,
    /// `running`, `ok` or `failed`.
    pub status: String,
    /// When it ended.
    pub ended: Option<u64>,
}

/// The catalog's JSON face.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Catalog {
    /// [`SCHEMA`].
    pub schema: u32,
    /// Every script the caller may read, by name.
    pub scripts: Vec<CatalogEntry>,
}

struct CatalogEndpoint {
    shared: Arc<SpaceConfig>,
}

#[async_trait]
impl Endpoint for CatalogEndpoint {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        if inv.request.verb != Verb::Source {
            return Err(unsupported("script-catalog", inv.request.verb));
        }
        let want = wanted_face(inv)?;
        let backend = &self.shared.backend;
        let mut scripts = Vec::new();
        for name in backend.names()? {
            let own = holds(inv, &cap_read(&name));
            let mut entry = CatalogEntry {
                iri: name::script_iri(&name),
                name: name.clone(),
                state: None,
                public: None,
                version: None,
                last_run: None,
                error: None,
            };
            match backend.head(&name) {
                // A broken head is shown to whoever may read the script, so the dashboard
                // says what is wrong instead of losing the row (or the whole list).
                Err(e) if own => entry.error = Some(e.to_string()),
                Ok(Some(head)) if own || (is_public(&head) && holds(inv, CAP_READ_PUBLIC)) => {
                    entry.state = Some(head.state);
                    entry.public = Some(head.public);
                    entry.version = Some(head.version);
                    entry.last_run = backend.last_run(&name).ok().flatten().map(|run| LastRun {
                        iri: run.iri(),
                        status: match run.outcome {
                            Outcome::Running => "running",
                            Outcome::Ok => "ok",
                            Outcome::Failed { .. } => "failed",
                        }
                        .to_string(),
                        ended: run.ended,
                    });
                }
                _ => continue,
            }
            scripts.push(entry);
        }
        if want == JSON {
            // Live: a run that fails is recorded without a write through any name the
            // catalog could hang from, so this list is never cached.
            return json(&Catalog {
                schema: SCHEMA,
                scripts,
            });
        }
        let mut text = String::new();
        for entry in &scripts {
            match (&entry.error, entry.state) {
                (Some(error), _) => text.push_str(&format!("{}  BROKEN: {error}\n", entry.iri)),
                (None, Some(state)) => {
                    let version = entry.version.as_deref().unwrap_or("");
                    text.push_str(&format!(
                        "{}  {}{}  {}",
                        entry.iri,
                        state.as_str(),
                        if entry.public == Some(true) {
                            " public"
                        } else {
                            ""
                        },
                        &version[..version.len().min(19)],
                    ));
                    if let Some(run) = &entry.last_run {
                        text.push_str(&format!(
                            "  last run {} {} {}",
                            run.iri,
                            run.status,
                            model::when(run.ended)
                        ));
                    }
                    text.push('\n');
                }
                _ => {}
            }
        }
        if scripts.is_empty() {
            text.push_str("no scripts this capability may read\n");
        }
        Ok(plain(text))
    }

    fn name(&self) -> &str {
        "script-catalog"
    }

    fn describe(&self) -> Description {
        Description::new("script-catalog")
            .title("Scripts")
            .summary(
                "Every script the caller may read: state, public flag, head version and last \
                 run. Live (never cached). A host that wants `urn:host:scripts` aliases it \
                 here.",
            )
            .verb(Verb::Meta)
            .action(
                ActionSpec::new(Verb::Source)
                    .summary("The catalog.")
                    .input(as_arg())
                    .output(PLAIN)
                    .output(JSON)
                    .requires(CAP_READ),
            )
    }
}

fn unsupported(id: &str, verb: Verb) -> Error {
    Error::Endpoint(format!("{id} does not answer {verb:?}"))
}
