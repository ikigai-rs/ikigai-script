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
    self, cap, cap_run, principal_of, Act, Ceiling, CeilingPolicy, CAP_ANY, CAP_DELETE, CAP_LISP,
    CAP_READ, CAP_READ_PUBLIC, CAP_RUN, CAP_RUN_PUBLIC, CAP_WRITE,
};
use crate::backend::Backend;
use crate::model::{
    self, Event, Head, Language, Outcome, Run, State, Version, MAX_RECORDED_RESULT, SCHEMA,
};
use crate::name::{self, CATALOG_IRI, EVAL_IRI};
use crate::plan;
use crate::sparql::{self, Analysis, Form, Parameter, SparqlDoor, Value, CAP_READ_GRAPH};

const PLAIN: &str = "text/plain";
const JSON: &str = "application/json";
const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";
const XSD_BOOLEAN: &str = "http://www.w3.org/2001/XMLSchema#boolean";
const XSD_INTEGER: &str = "http://www.w3.org/2001/XMLSchema#integer";
const TURTLE: &str = "text/turtle";
/// The faces of a read: the source (or a summary) for people, the record for machines.
const READ_FACES: [&str; 2] = [PLAIN, JSON];
/// The faces of the catalog and a run record: those, and the graph (see [`crate::graph`]).
const RECORD_FACES: [&str; 3] = [PLAIN, JSON, TURTLE];

/// What a host decides when it mounts scripts: where they live and the ceiling it allows each
/// one. Built with [`SpaceConfig::new`] and handed to [`space`].
///
/// Who a request comes from is not configured here: it is the principal the request's
/// capability names (`urn:cap:principal:<iri>`), which the host's door mints with
/// `Capability::with_principal` (see [`authority::principal_of`]).
///
/// There is no default backend and no default ceiling, on purpose: both are the host's
/// decision, and a library that guessed either would be guessing about authority.
#[derive(Clone)]
#[non_exhaustive]
pub struct SpaceConfig {
    backend: Arc<dyn Backend>,
    ceiling: CeilingPolicy,
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
            sparql: None,
            on_change: None,
            described: Arc::new(Mutex::new(HashMap::new())),
        }
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

/// Whether the caller may `act` on `name`: its exact grant or a namespace grant, and no
/// exclusion naming it ([`authority::holds`]).
fn may(inv: &Invocation<'_>, act: Act, name: &str) -> bool {
    authority::holds(inv.capability, act, name)
}

/// Whether the caller reaches a PUBLIC script through `public` (a `…:public` grant), unless
/// an exclusion it holds names the script.
fn may_public(inv: &Invocation<'_>, act: Act, public: &str, name: &str) -> bool {
    holds(inv, public) && !authority::excluded(inv.capability, act, name)
}

/// How a refusal says what a script grant can name.
const GRANT_FORMS: &str = "A script grant names one script (`urn:cap:script:{act}:{name}`) or a \
     namespace of them (`urn:cap:script:{act}:{namespace}-*`)";

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
    gated_head(inv, shared, name, &[(Act::Read, CAP_READ_PUBLIC)])
}

/// The head of `name` if the caller may do one of `acts` to it ([`may`]), or the script is
/// public and they hold that act's public grant. Otherwise `Denied`, naming both.
fn gated_head(
    inv: &Invocation<'_>,
    shared: &SpaceConfig,
    name: &str,
    acts: &[(Act, &str)],
) -> Result<Option<Head>> {
    if acts.iter().any(|(act, _)| may(inv, *act, name)) {
        return shared.backend.head(name);
    }
    if let Ok(Some(head)) = shared.backend.head(name) {
        if is_public(&head)
            && acts
                .iter()
                .any(|(act, public)| may_public(inv, *act, public, name))
        {
            return Ok(Some(head));
        }
    }
    Err(Error::Denied(format!(
        "this capability holds none of {} — nor, for a public script, {}. {GRANT_FORMS}, and \
         an exclusion (`…:-{{name}}`) takes one back out",
        acts.iter()
            .map(|(act, _)| cap(*act, name))
            .collect::<Vec<_>>()
            .join(", "),
        acts.iter()
            .map(|(_, public)| *public)
            .collect::<Vec<_>>()
            .join(", ")
    )))
}

fn require(inv: &Invocation<'_>, act: Act, name: &str, doing: &str) -> Result<()> {
    if may(inv, act, name) {
        Ok(())
    } else {
        Err(Error::Denied(format!(
            "{doing} needs `{}`, which this capability does not hold. {GRANT_FORMS}, and an \
             exclusion (`…:-{{name}}`) takes one back out",
            cap(act, name)
        )))
    }
}

fn found(head: Option<Head>, name: &str) -> Result<Head> {
    head.ok_or_else(|| Error::NotFound(format!("no script is published at urn:script:{name}")))
}

// ---------------------------------------------------------------------------------------
// Drafts: a version never published is its author's alone
// ---------------------------------------------------------------------------------------

/// Who may see one version of a script, beyond the read (or run) grant that gates it.
///
/// ★ **A draft is visible only to its author until it is published.** The author is the
/// principal recorded when the draft was written, the principal the writer's CAPABILITY
/// named ([`authority::principal_of`]), and the reader is its author when their capability
/// `acts_as` that principal. Never an argument, so no caller can name itself the author.
/// This only ever NARROWS what a grant reaches: seeing a draft needs the grant AND
/// authorship, so it can give no one more than their capability.
///
/// Every answer is CACHEABLE, whatever the sight (ledger #1077). It is a function of the
/// capability and the script's state alone: the kernel keys its cache on the capability,
/// which carries the principal, so alice's cached draft is never bob's answer even when the
/// rest of their capabilities are the same; and every answer hangs from the script's
/// thread, which a publish or retire cuts. Before 0.2.0 the principal came from a host
/// stamper the cache key could not see, and these answers could not be cached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sight {
    /// Published content, the caller's own draft, or a root caller.
    Visible,
    /// A version never published, and the caller is not its author: absent, told exactly
    /// as a name nobody wrote is (`NotFound`, `false`), so its existence does not leak.
    Hidden,
}

/// Whether `digest` was ever published under this head: the head published at it, or any
/// change in its history did. Once published, always: history only grows.
fn ever_published(head: &Head, digest: &str) -> bool {
    (head.version == digest && head.state == State::Published)
        || head
            .history
            .iter()
            .any(|event| event.action == "publish" && event.version == digest)
}

/// What the caller may see of version `digest` of `head`'s script.
///
/// Root sees everything: it is the host's own authority, not a principal's, and holds the
/// backend the draft is stored in (`acts_as` is true for root, and root also sees a draft
/// whose author is nobody's identity).
fn sight(inv: &Invocation<'_>, head: &Head, digest: &str) -> Sight {
    if ever_published(head, digest) || inv.capability.is_root() {
        return Sight::Visible;
    }
    let wrote_it = |author: &str| authority::is_identity(author) && inv.capability.acts_as(author);
    let mine = (head.version == digest && wrote_it(&head.publisher))
        || head
            .history
            .iter()
            .any(|e| e.action == "draft" && e.version == digest && wrote_it(&e.principal));
    if mine {
        Sight::Visible
    } else {
        Sight::Hidden
    }
}

/// `found`'s NotFound for a name the caller may read but cannot see: the same words as for
/// a name nobody wrote, plus, for a capability naming no principal (which says nothing
/// about any one name), why that caller can see no draft at all.
fn absent(inv: &Invocation<'_>, name: &str) -> Error {
    let mut message = format!("no script is published at urn:script:{name}");
    if inv.capability.principal().is_none() && !inv.capability.is_root() {
        message.push_str(
            " (this request's capability names no principal (`urn:cap:principal:…`, minted \
             by the host's door), so it cannot be shown to be a draft's author: a draft is \
             visible to its author and root alone until it is published)",
        );
    }
    Error::NotFound(message)
}

/// The head of `name`, from a gate's answer, if the caller may also SEE the version it
/// points at.
fn seen_head(inv: &Invocation<'_>, name: &str, gated: Option<Head>) -> Result<Head> {
    let Some(head) = gated else {
        return Err(absent(inv, name));
    };
    match sight(inv, &head, &head.version) {
        Sight::Hidden => Err(absent(inv, name)),
        Sight::Visible => Ok(head),
    }
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

/// Which face was asked for: [`READ_FACES`]. One this resource cannot serve is refused,
/// never substituted.
fn wanted_face(inv: &Invocation<'_>) -> Result<&'static str> {
    face_of(inv, &READ_FACES)
}

/// Which of `faces` was asked for (the first when none was).
fn face_of(inv: &Invocation<'_>, faces: &[&'static str]) -> Result<&'static str> {
    match optional(inv, "as")? {
        None => Ok(faces[0]),
        Some(asked) => {
            let bare = asked.split(';').next().unwrap_or(asked).trim();
            faces
                .iter()
                .find(|face| **face == bare)
                .copied()
                .ok_or_else(|| Error::InvalidArgument {
                    name: "as".to_string(),
                    detail: format!(
                        "`{asked}` is not a face this resource serves; one of {}",
                        faces.join(", ")
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
             (`eval`, `catalog`, `public`, `outcome` and `principal` are reserved).",
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

/// `as` for a record with a graph face.
fn record_as_arg() -> ArgSpec {
    ArgSpec::new("as")
        .summary(
            "The face: `text/plain` (for people), `application/json` (the versioned record, \
             `\"schema\": 1`) or `text/turtle` (the graph: PROV-O and the shared \
             vocabulary, no blank nodes). Any other is refused, never substituted.",
        )
        .class(XSD_STRING)
        .one_of(RECORD_FACES)
        .default_value(PLAIN)
        .optional()
}

fn turtle(graph: crate::graph::Graph) -> Result<Representation> {
    let bytes = graph
        .turtle()
        .map_err(|e| Error::Endpoint(format!("could not write the graph face: {e}")))?;
    Ok(Representation::new(
        ReprType::new(TURTLE).with_param("charset", "utf-8"),
        bytes,
    ))
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
                let exists = match readable_head(inv, shared, &name)? {
                    None => false,
                    Some(head) => sight(inv, &head, &head.version) == Sight::Visible,
                };
                Ok(plain(if exists { "true\n" } else { "false\n" }).cacheable())
            }
            Verb::Source => {
                let want = wanted_face(inv)?;
                let head = seen_head(inv, &name, readable_head(inv, shared, &name)?)?;
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
            Verb::Sink => publish(inv, shared, &name).await,
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
                                "The script's language: `lisp`, `sparql` (a query or update, \
                                 when the host mounts a SPARQL door), or `plan` (an \
                                 ik:Process graph, when the host binds the plan doors).",
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
                                 graphs the text names; a plan: DERIVED from its steps' \
                                 contracts. For both, omit it: one that says anything else \
                                 is refused, naming the derived set.",
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
                                "`published` (runnable) or `draft` (saved, not runnable, \
                                 and visible only to its author until published). To \
                                 retire, Delete.",
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

async fn publish(inv: &Invocation<'_>, shared: &SpaceConfig, name: &str) -> Result<Representation> {
    require(inv, Act::Write, name, "publishing a script")?;
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
        Language::Plan => {
            // Validated by the host's validator first, so a malformed plan is refused
            // naming the shape it broke; then read for what this crate decides itself;
            // then its authority derived from its steps' contracts.
            plan::check_bound(source)?;
            plan::validate(inv, source).await?;
            plan::analyze(source)?;
            plan::derive(inv, source, optional(inv, "requires")?).await?
        }
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

    let principal = principal_of(inv.capability);
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
    require(inv, Act::Delete, name, "retiring a script")?;
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
        principal: principal_of(inv.capability),
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
        // ★ Hung from the SCRIPT's thread, which every publish and retire cuts, and named
        // FIRST, so every answer below carries it: a success (ledger #1076) and a NotFound
        // alike (ledger #1079). Everything this answer says is the script's state, not the
        // version's: whether that content has been written under the name (a version named
        // by its content can be asked for before anyone publishes it), whether the caller may
        // see it (a draft is its author's until it is published), and whether the caller may
        // read the name at all (a public script's version stops being readable through the
        // public grant when it is retired). The kernel hangs an answer from its OWN name,
        // which no write here ever targets, so without this a cached `false`, or a cached
        // fallback over a NotFound, outlived the publish that ended the absence. Caching the
        // negative is kept, not dropped: it is a backend read per ask, and an uncacheable
        // `Exists` would make every composite over it uncacheable. The kernel carries the
        // thread on a miss only (NotFound, Unresolved); a refusal stays never-cached.
        inv.depends_on(name::script_iri(&name));
        let head = readable_head(inv, &self.shared, &name)?;
        let version = self.shared.backend.version(&name, &digest);
        // A version that exists is seen as its head's history says: one never published is
        // its author's alone. One with no head at all (a write that lost its race) was never
        // published either.
        let seen = match (&version, &head) {
            (Ok(Some(_)), Some(head)) => sight(inv, head, &digest),
            (Ok(Some(_)), None) if !inv.capability.is_root() => Sight::Hidden,
            _ => Sight::Visible,
        };
        let no_such = || Error::NotFound(format!("urn:script:{name} has no version {digest}"));
        match inv.request.verb {
            Verb::Exists => {
                let exists = match version {
                    Ok(v) => v.is_some() && seen != Sight::Hidden,
                    Err(Error::InvalidArgument { .. }) => false,
                    Err(other) => return Err(other),
                };
                Ok(plain(if exists { "true\n" } else { "false\n" }).cacheable())
            }
            Verb::Source => {
                let want = wanted_face(inv)?;
                let version = version?.ok_or_else(no_such)?;
                if seen == Sight::Hidden {
                    return Err(no_such());
                }
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
    /// For a plan: its process, its steps' verbs (read or write) and its parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<plan::Analysis>,
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
        // ★ Hung from the SCRIPT's thread, which every publish and retire cuts (the kernel
        // cuts the thread named after a Sink's or Delete's target), and named FIRST so a
        // NotFound carries it as well as a success (ledger #1079): without it a cached
        // compiled form would outlive the version it was prepared from, and a cached fallback
        // over "nothing is published here" (or "this draft is not yours") would outlive the
        // publish that ended it. A run as a read reaches this form by sub-request, so its
        // answers, and its misses, inherit the thread.
        inv.depends_on(name::script_iri(&name));
        // Readable by a reader or a runner: a run reads its program here. A draft's program
        // is its author's alone, so a run of someone else's draft finds nothing to run.
        let gated = gated_head(
            inv,
            &self.shared,
            &name,
            &[(Act::Read, CAP_READ_PUBLIC), (Act::Run, CAP_RUN_PUBLIC)],
        )?;
        let head = seen_head(inv, &name, gated)?;
        let version = head_version(&self.shared, &head)?;
        let (evaluator, analysis, plan_analysis) = match version.language {
            Language::Lisp => (LISP_EVAL.to_string(), None, None),
            Language::Sparql => {
                let door = door(&self.shared)?;
                let analysis = sparql::analyze(&version.source, door)?;
                (door.query_iri(analysis.form), Some(analysis), None)
            }
            Language::Plan => (
                plan::EVAL.to_string(),
                None,
                Some(plan::analyze(&version.source)?),
            ),
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
            plan: plan_analysis,
            name: name.clone(),
        };
        Ok(json(&prepared)?.cacheable())
    }

    fn name(&self) -> &str {
        "script-compiled"
    }

    fn describe(&self) -> Description {
        Description::new("script-compiled")
            .title("A script's compiled form")
            .summary(
                "The head version prepared for its evaluator, with the authority it runs \
                 under (and, for SPARQL, its form, parameters and graphs; for a plan, its \
                 steps' verbs and its parameters): cached, and cut \
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
    let may_run =
        may(inv, Act::Run, name) || (public && may_public(inv, Act::Run, CAP_RUN_PUBLIC, name));
    if !may_run {
        return Err(Error::Denied(format!(
            "running urn:script:{name} needs `{}` or a namespace grant covering it{}. \
             {GRANT_FORMS}, and an exclusion (`…:-{{name}}`) takes one back out",
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
    /// What a refusal of this run should also say: why the run held only family markers
    /// (ledger #1220). Set only for a plan run that keeps one.
    note: Option<String>,
}

/// A run's refusal, with the run's [`Planned::note`] said after it when there is one.
fn explain(note: Option<&str>, error: Error) -> Error {
    match (note, error) {
        (Some(note), Error::Denied(message)) => Error::Denied(format!("{message}. {note}")),
        (_, error) => error,
    }
}

/// The run's sub-request, for whichever language the script is in.
async fn prepare_request(
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
                note: None,
            })
        }
        Language::Sparql => plan_sparql(inv, shared, prepared, keep, ceiling, through).await,
        Language::Plan => plan_eval_request(inv, prepared, keep, ceiling, through),
    }
}

/// A plan run: refuse a write through the read door, take the plan's parameters, turn a
/// root publisher's derived families into exact grants, and address `urn:plan:eval`.
///
/// The plan's steps then run as `urn:plan:eval`'s sub-requests under exactly the narrowed
/// capability, and each meets its own target's floor there: a step the run may not take is
/// refused by the kernel at that step, typed, and arrives here unchanged.
fn plan_eval_request(
    inv: &Invocation<'_>,
    prepared: &Prepared,
    keep: BTreeSet<String>,
    ceiling: &Ceiling,
    through: Door,
) -> Result<Planned> {
    let name = &prepared.name;
    let analysis = prepared.plan.as_ref().ok_or_else(|| {
        Error::Endpoint(format!(
            "urn:script:{name}:compiled carries no plan analysis"
        ))
    })?;
    if through == Door::Result && analysis.mutates() {
        let writers: Vec<String> = analysis
            .steps
            .iter()
            .filter(|s| s.mutates())
            .map(|s| format!("<{}> ({} <{}>)", s.iri, s.verb, s.resolves))
            .collect();
        return Err(Error::InvalidArgument {
            name: "name".to_string(),
            detail: format!(
                "urn:script:{name} is a plan that writes ({}), so it is not a read: run it with \
                 a Sink to urn:script:{name}:runs",
                writers.join(", ")
            ),
        });
    }
    let declared: Vec<(&str, bool)> = analysis
        .parameters
        .iter()
        .map(|p| (p.name.as_str(), p.must_be_given()))
        .collect();
    let values = given_parameters(inv, name, &declared, through)?;
    let face = optional(inv, "as")?;
    let keep = plan::expand_families(keep, inv.capability, ceiling);
    let markers = plan::markers(&keep);
    let note = (!markers.is_empty()).then(|| {
        format!(
            "urn:script:{name} ran holding {} only as a family: a family held is not a grant, \
             so a step whose module checks an exact token under it is refused. Neither the \
             runner nor the host's ceiling for this script names a member (a step's contract \
             declares the family, never the member, and root holds no list to pick one from). \
             Run it under a capability that holds the exact grants, or have the host's \
             ceiling for urn:script:{name} name them",
            markers
                .iter()
                .map(|m| format!("`{m}`"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    });
    Ok(Planned {
        request: plan::eval_request(&prepared.program, &values, face),
        keep,
        note,
    })
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
        return Ok(Planned {
            request,
            keep,
            note: None,
        });
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
    Ok(Planned {
        request,
        keep,
        note: None,
    })
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
/// What was given is [`given_parameters`]'s; a parameter not given takes its default, and
/// one with neither stays unbound.
fn parameter_values(
    inv: &Invocation<'_>,
    name: &str,
    parameters: &[Parameter],
    through: Door,
) -> Result<BTreeMap<String, Value>> {
    let declared: Vec<(&str, bool)> = parameters
        .iter()
        .map(|p| (p.name.as_str(), p.required && p.default.is_none()))
        .collect();
    let mut given = given_parameters(inv, name, &declared, through)?;
    let mut values = BTreeMap::new();
    for parameter in parameters {
        if let Some(lexical) = given
            .remove(&parameter.name)
            .or_else(|| parameter.default.clone())
        {
            values.insert(parameter.name.clone(), parameter.value(&lexical)?);
        }
    }
    Ok(values)
}

/// The argument names a TRANSPORT owns, which a run never reads as a script's parameters
/// (ledger #1173).
///
/// `ikigai-web` stamps a write with its provenance, `received`, `client` and `principal`,
/// read off the connection, and with the body's `content-type`; `ikigai-quic` stamps
/// `principal` on every verb. Each is the door's statement about the request, never the
/// caller's, and none is an input to a script: who a request is from reaches a run in its
/// CAPABILITY (`Capability::with_principal`, read with [`authority::principal_of`]), which
/// is what every run and publish records.
///
/// So the doors of this crate ignore these names wherever a script's parameters are read
/// (`…:result` and `…:runs`, for a query and a plan), instead of refusing them as arguments
/// the script does not declare — which made every run for effects through the HTTP door a
/// `400` — and no script may declare a parameter by one of them (refused at publish; see
/// [`sparql::RESERVED_PARAMETERS`] and [`plan::RESERVED_PARAMETERS`]). A value a CALLER
/// supplies under one of them (where a door passes it through) is ignored the same way, so
/// it can neither reach a script nor stand in for the principal.
///
/// ```
/// use ikigai_script::TRANSPORT_ARGUMENTS;
/// for owned in TRANSPORT_ARGUMENTS {
///     assert!(ikigai_script::sparql::RESERVED_PARAMETERS.contains(&owned), "{owned}");
///     assert!(ikigai_script::plan::RESERVED_PARAMETERS.contains(&owned), "{owned}");
/// }
/// ```
pub const TRANSPORT_ARGUMENTS: [&str; 4] = ["received", "client", "principal", "content-type"];

/// The parameters a run was GIVEN, as text, for a script that declares `declared` (each
/// parameter's name, and whether a run must give it).
///
/// Named arguments, or (through `…:runs`) a JSON object piped as `content`. A missing
/// parameter a run must give is `MissingArgument`; a parameter given both ways and an
/// argument the script does not declare are `InvalidArgument`: a binding the script does not
/// mention is refused, never ignored, so a filter you thought was applied can never silently
/// not be. Refused here, before a run is recorded: nothing ran.
///
/// The one exception is [`TRANSPORT_ARGUMENTS`]: a door's own stamps, ignored, never bound.
/// `declared` never holds one: the parameters are read again from the source each time the
/// compiled form is prepared, and that read refuses a reserved name, so a script stored
/// before they were reserved that declares one fails there, naming it, and never runs with
/// the parameter silently unbound.
fn given_parameters(
    inv: &Invocation<'_>,
    name: &str,
    declared: &[(&str, bool)],
    through: Door,
) -> Result<BTreeMap<String, String>> {
    let listed = || {
        if declared.is_empty() {
            "it declares none".to_string()
        } else {
            format!(
                "its parameters are {}",
                declared
                    .iter()
                    .map(|(p, _)| *p)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
    };
    for arg in inv.request.args.keys() {
        let known = arg == "as"
            || TRANSPORT_ARGUMENTS.contains(&arg.as_str())
            || (through == Door::Runs && arg == "content")
            || declared.iter().any(|(p, _)| p == arg);
        if !known {
            return Err(Error::InvalidArgument {
                name: arg.clone(),
                detail: format!("is not a parameter of urn:script:{name}; {}", listed()),
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
                        "a script's piped content is its parameters as one JSON object ({e})"
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
    let mut given = BTreeMap::new();
    for (parameter, must) in declared {
        let named = optional(inv, parameter)?;
        let lexical = match (named, piped.remove(*parameter)) {
            (Some(_), Some(_)) => {
                return Err(Error::InvalidArgument {
                    name: parameter.to_string(),
                    detail: "is given both by name and in the piped content".to_string(),
                })
            }
            (Some(value), None) => Some(value.to_string()),
            (None, Some(value)) => Some(value),
            (None, None) => None,
        };
        match lexical {
            Some(lexical) => {
                given.insert(parameter.to_string(), lexical);
            }
            None if *must => return Err(Error::MissingArgument(parameter.to_string())),
            None => {}
        }
    }
    if let Some(stray) = piped.keys().next() {
        return Err(Error::InvalidArgument {
            name: "content".to_string(),
            detail: format!(
                "`{stray}` is not a parameter of urn:script:{name}; {}",
                listed()
            ),
        });
    }
    Ok(given)
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
        let planned =
            prepare_request(inv, &self.shared, &prepared, keep, &ceiling, Door::Result).await?;
        // ★ The ONLY authority a run gets: the runner's own capability, narrowed. There is
        // no form that widens, so a script cannot reach past its runner whatever it says.
        let Planned {
            request,
            keep,
            note,
        } = planned;
        let answer = inv
            .issue_attenuated(request, keep)
            .await
            .map_err(|e| explain(note.as_deref(), e))?;
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
        let planned = prepare_request(inv, shared, &prepared, keep, &ceiling, Door::Runs).await?;
        let runs_as = inv.capability.attenuate(planned.keep.iter().cloned());
        let mut run = Run {
            schema: SCHEMA,
            name: name.clone(),
            id: 0,
            version: prepared.version.clone(),
            principal: principal_of(inv.capability),
            capability: runs_as.scopes().cloned().unwrap_or_default(),
            started: inv.now().map(|t| t.as_millis()),
            ended: None,
            outcome: Outcome::Running,
            result: None,
            truncated: false,
            trace_span: inv.trace_span(),
        };
        run.id = shared.backend.start_run(&name, &run)?;
        let Planned {
            request,
            keep,
            note,
        } = planned;
        let answer = inv
            .issue_attenuated(request, keep)
            .await
            .map_err(|e| explain(note.as_deref(), e));
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
                "Run the script for its EFFECTS and record the run: who (the principal \
                 the capability names), which version, under exactly what capability, when, and the \
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

/// A SPARQL script's or a plan's own endpoints, `…:result` and `…:runs`, each the
/// template's endpoint behind the script's OWN description.
#[derive(Clone)]
struct PerScript {
    result: Arc<dyn Endpoint>,
    runs: Arc<dyn Endpoint>,
    /// Whether its `…:result` is a read it offers (a query, not an update).
    reads: bool,
    /// Whether it is published, and so listed in the catalog. A draft of content that was
    /// published before, or a retired script, still answers under its own contract (its run
    /// is refused for its state, not for a language capability it never needed), but is not
    /// offered. A draft never published has no contract of its own (see `build`).
    listed: bool,
}

/// The template's endpoint, behind one script's contract.
///
/// ★ **Why a script is its own entry.** A description is the contract the engine routes
/// arguments by, selection matches on, MCP projects and the Emacs aliases are generated
/// from, and the kernel answers it per ENDPOINT, never per IRI. A query's or a plan's
/// parameters are real arguments only if they are in a description, so each gets one. And
/// the template's `requires` is Lisp's (`urn:cap:lisp`): a query or a plan behind it would be
/// refused at the floor for a language grant it never needs, so a plan with no parameters
/// still gets its own.
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
/// script and plan as its own `…:result` and `…:runs` entry, carrying its parameters.
pub struct ScriptSpace {
    inner: EndpointSpace,
    shared: Arc<SpaceConfig>,
}

impl ScriptSpace {
    /// The script's own endpoints, when it is a SPARQL script this host can run or a plan.
    ///
    /// A Lisp script has none (the template's contract IS its contract), but finding that
    /// out costs one head and version read per name, remembered until the next publish.
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
        // ⚠ Remember only scripts that exist: a name nobody published is a miss every
        // time, never an entry, so resolving arbitrary names cannot grow this map.
        if built.is_some() || matches!(shared.backend.head(name), Ok(Some(_))) {
            shared
                .described
                .lock()
                .expect("the described-script memo")
                .insert(name.to_string(), built.clone());
        }
        built
    }

    fn build(&self, name: &str) -> Option<PerScript> {
        let shared = &self.shared;
        let head = shared.backend.head(name).ok()??;
        // ★ A draft never published wears the TEMPLATE's contract. Meta is answered from the
        // description to anyone who can reach the door (the kernel's, before any endpoint
        // runs, so it cannot ask who is calling), and a script's own contract is made of its
        // text: its parameters, its leading comment, the graphs it names. Its own entry would
        // publish all three, and that the draft exists. Its run is still refused (for its
        // state, to its author; as absent, to everyone else), now at the template's floor.
        if !ever_published(&head, &head.version) {
            return None;
        }
        let version = shared.backend.version(name, &head.version).ok()??;
        match version.language {
            Language::Lisp => None,
            Language::Sparql => self.build_sparql(name, &head, &version),
            Language::Plan => self.build_plan(name, &head, &version),
        }
    }

    /// A per-script endpoint: the template's, behind `description`.
    fn described(
        &self,
        inner: Arc<dyn Endpoint>,
        id: String,
        description: Description,
    ) -> Arc<dyn Endpoint> {
        Arc::new(Described {
            inner,
            id,
            description,
        }) as Arc<dyn Endpoint>
    }

    fn result_endpoint(&self) -> Arc<dyn Endpoint> {
        Arc::new(ResultEndpoint {
            shared: Arc::clone(&self.shared),
        })
    }

    fn runs_endpoint(&self) -> Arc<dyn Endpoint> {
        Arc::new(RunsEndpoint {
            shared: Arc::clone(&self.shared),
        })
    }

    fn build_sparql(&self, name: &str, head: &Head, version: &Version) -> Option<PerScript> {
        let door = self.shared.sparql.as_ref()?;
        let analysis = sparql::analyze(&version.source, door).ok()?;
        let about = about(&version.source);
        let inputs: Vec<ArgSpec> = analysis
            .parameters
            .iter()
            .map(|p| {
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
                arg
            })
            .collect();
        let params = |spec: ActionSpec| contracted(spec, &inputs, name, head, version);
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
        let result = self.described(self.result_endpoint(), id, description);
        let id = format!("script-{name}-runs");
        let mut spec = params(ActionSpec::new(Verb::Sink))
            .summary(format!(
                "Run {name} for its effects and record the run; answers the run's IRI."
            ))
            .input(piped_parameters_arg())
            .output(PLAIN);
        if form.is_read() {
            spec = spec.input(as_arg());
        }
        let runs = self.described(
            self.runs_endpoint(),
            id.clone(),
            Description::new(id)
                .title(format!("{name}: runs"))
                .summary(format!(
                    "{about}Each run is recorded: who, which version, under exactly what \
                     capability, when, and the outcome."
                ))
                .verb(Verb::Meta)
                .action(spec),
        );
        Some(PerScript {
            result,
            runs,
            reads: form.is_read(),
            listed: head.state == State::Published,
        })
    }

    /// A plan's own contract: its declared parameters as arguments, and the capability
    /// derived from its steps as what the floor checks.
    fn build_plan(&self, name: &str, head: &Head, version: &Version) -> Option<PerScript> {
        let analysis = plan::analyze(&version.source).ok()?;
        let about = about(&version.source);
        let inputs: Vec<ArgSpec> = analysis
            .parameters
            .iter()
            .map(|p| {
                let mut arg = ArgSpec::new(p.name.clone())
                    .summary(
                        p.summary
                            .clone()
                            .unwrap_or_else(|| format!("The plan's parameter `{}`.", p.name)),
                    )
                    .class(p.class.clone().unwrap_or_else(|| XSD_STRING.to_string()));
                if let Some(default) = &p.default {
                    arg = arg.default_value(default.clone()).optional();
                } else if !p.required {
                    arg = arg.optional();
                }
                arg
            })
            .collect();
        let params = |spec: ActionSpec| contracted(spec, &inputs, name, head, version);
        // A plan's answer is its result step's own representation, so no list of faces can
        // be declared in advance: `as` is passed to the evaluator, which transrepts or
        // refuses.
        let as_arg = || {
            ArgSpec::new("as")
                .summary(
                    "The face of the plan's result: when its result step served another \
                     media type it is transrepted, and refused when nothing converts it.",
                )
                .class(XSD_STRING)
                .optional()
        };
        let reads = !analysis.mutates();
        let id = format!("script-{name}-result");
        let description = if reads {
            Description::new(id.clone())
                .title(format!("{name}: a plan"))
                .summary(format!(
                    "{about}Runs as a READ (every step reads) under the runner's capability \
                     narrowed to what the plan's steps require; as cacheable as its least \
                     cacheable step, and recomputed after a republish."
                ))
                .verb(Verb::Meta)
                .action(
                    params(ActionSpec::new(Verb::Source))
                        .summary(format!("Run the plan {name} and answer its result."))
                        .input(as_arg())
                        .output(PLAIN),
                )
        } else {
            // A plan with a Sink or Delete step is never a read: no action is offered here,
            // and a Source that arrives anyway is refused by the run, naming `…:runs`.
            Description::new(id.clone())
                .title(format!("{name}: a plan that writes (run it at …:runs)"))
                .summary(format!(
                    "{about}A write: run it with a Sink to urn:script:{name}:runs."
                ))
                .verb(Verb::Meta)
        };
        let result = self.described(self.result_endpoint(), id, description);
        let id = format!("script-{name}-runs");
        let runs = self.described(
            self.runs_endpoint(),
            id.clone(),
            Description::new(id)
                .title(format!("{name}: runs"))
                .summary(format!(
                    "{about}Each run is recorded: who, which version, under exactly what \
                     capability, when, and the outcome."
                ))
                .verb(Verb::Meta)
                .action(
                    params(ActionSpec::new(Verb::Sink))
                        .summary(format!(
                            "Run the plan {name} and record the run; answers the run's IRI."
                        ))
                        .input(piped_parameters_arg())
                        .input(as_arg())
                        .output(PLAIN),
                ),
        );
        Some(PerScript {
            result,
            runs,
            reads,
            listed: head.state == State::Published,
        })
    }
}

/// `spec` with a script's own `inputs`, the run gate and every scope its version requires.
///
/// The run gate, as the kernel can check it before the endpoint is entered: the script's own
/// grant, or the family of its top-level namespace when it is in one, so a namespace grant
/// is not refused at the floor ([`authority::run_floor`]); for a public one, the family of
/// every run grant (its own grant OR the public one, which `requires` cannot say any other
/// way: it is all-of). The exact rule is checked inside, by [`prepare_run`].
fn contracted(
    mut spec: ActionSpec,
    inputs: &[ArgSpec],
    name: &str,
    head: &Head,
    version: &Version,
) -> ActionSpec {
    for input in inputs {
        spec = spec.input(input.clone());
    }
    spec = spec.requires(if head.public {
        CAP_RUN.to_string()
    } else {
        authority::run_floor(name)
    });
    for scope in &version.requires {
        spec = spec.requires(scope.clone());
    }
    spec
}

/// `…:runs`' piped body, for a script with parameters.
fn piped_parameters_arg() -> ArgSpec {
    ArgSpec::new("content")
        .summary(
            "The parameters as one JSON object, for a pipe (a parameter given both here and \
             by name is refused).",
        )
        .class(XSD_STRING)
        .optional()
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
        // ★ Hung from the script's RUNS thread, which every run cuts (the kernel cuts the
        // thread named after a Sink's target, `urn:script:{name}:runs`), and named FIRST so a
        // NotFound carries it as well as a success (ledger #1079's shape): whether run `{id}`
        // exists is the state a run writes, never anything written through this record's own
        // name, so without it a cached fallback over "no run {id}" outlived the run that
        // recorded it. A FAILED run is recorded too, and cuts it as well: the kernel cuts a
        // Sink's target whenever the endpoint ran (ikigai-core 0.1.95; pinned in
        // `tests/lifecycle.rs`).
        inv.depends_on(name::part_iri(&name, "runs"));
        // A run record says who ran what: readable by the script's readers and its named
        // runners, never through the public grants.
        if !may(inv, Act::Read, &name) && !may(inv, Act::Run, &name) {
            return Err(Error::Denied(format!(
                "a run record of urn:script:{name} needs `{}` or `{}`. {GRANT_FORMS}",
                cap(Act::Read, &name),
                cap(Act::Run, &name)
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
                let want = face_of(inv, &RECORD_FACES)?;
                let run = run.ok_or_else(|| {
                    Error::NotFound(format!("urn:script:{name} has no run {id_text}"))
                })?;
                let finished = run.outcome != Outcome::Running;
                let repr = match want {
                    JSON => json(&run)?,
                    TURTLE => {
                        let mut graph = crate::graph::Graph::default();
                        graph.record(&run);
                        turtle(graph)?
                    }
                    _ => plain(run.render()),
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
                    .summary("The run record, as text, JSON, or a PROV-O graph (Turtle).")
                    .input(name_arg())
                    .input(id())
                    .input(record_as_arg())
                    .output(PLAIN)
                    .output(JSON)
                    .output(TURTLE)
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
        if language == Language::Plan {
            // Not a second door onto the same thing: the host's evaluator already runs a
            // supplied plan under the caller's own capability, which is all this door adds.
            return Err(Error::InvalidArgument {
                name: "language".to_string(),
                detail: format!(
                    "a plan supplied ad hoc runs at {} (`in` = the plan), under the caller's \
                     own capability; to keep it, publish it as a script",
                    plan::EVAL
                ),
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
                                "The code's language: `lisp`, the one this door runs, so the \
                                 one its `requires` (`urn:cap:lisp`) is for. A plan runs at \
                                 urn:plan:eval, which declares no language capability; SPARQL \
                                 here is the Protocol face, not in this version.",
                            )
                            .class(XSD_STRING)
                            // ★ Only what this door runs (ledger #1174): offering `sparql` and
                            // `plan` here advertised values it always refuses, under a floor
                            // (`urn:cap:lisp`) that only Lisp needs.
                            .one_of([Language::Lisp.as_str()])
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
        let want = face_of(inv, &RECORD_FACES)?;
        let backend = &self.shared.backend;
        let mut scripts = Vec::new();
        // Each row's last run in full, for the graph face (a catalog row keeps less).
        let mut last_runs = Vec::new();
        for name in backend.names()? {
            let own = may(inv, Act::Read, &name);
            let mut entry = CatalogEntry {
                iri: name::script_iri(&name),
                name: name.clone(),
                state: None,
                public: None,
                version: None,
                last_run: None,
                error: None,
            };
            let mut last = None;
            match backend.head(&name) {
                // A broken head is shown to whoever may read the script, so the dashboard
                // says what is wrong instead of losing the row (or the whole list).
                Err(e) if own => entry.error = Some(e.to_string()),
                // Someone else's draft is not listed: to this caller it does not exist.
                Ok(Some(head)) if sight(inv, &head, &head.version) == Sight::Hidden => continue,
                Ok(Some(head))
                    if own
                        || (is_public(&head)
                            && may_public(inv, Act::Read, CAP_READ_PUBLIC, &name)) =>
                {
                    entry.state = Some(head.state);
                    entry.public = Some(head.public);
                    entry.version = Some(head.version);
                    last = backend.last_run(&name).ok().flatten();
                    entry.last_run = last.as_ref().map(|run| LastRun {
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
            last_runs.push(last);
            scripts.push(entry);
        }
        if want == TURTLE {
            let mut graph = crate::graph::Graph::default();
            for (entry, last) in scripts.iter().zip(&last_runs) {
                graph.script(&entry.name, entry.version.as_deref(), last.as_ref());
            }
            return turtle(graph);
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
                    .summary("The catalog, as text, JSON, or a graph (Turtle).")
                    .input(record_as_arg())
                    .output(PLAIN)
                    .output(JSON)
                    .output(TURTLE)
                    .requires(CAP_READ),
            )
    }
}

fn unsupported(id: &str, verb: Verb) -> Error {
    Error::Endpoint(format!("{id} does not answer {verb:?}"))
}
