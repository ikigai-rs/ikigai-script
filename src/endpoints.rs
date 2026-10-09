//! The resources, as endpoints.
//!
//! Only two of them hold state — the script (its head and versions) and a run — and they
//! hold it through the host's [`Backend`]. Everything else is composed: `…:result` and
//! `…:runs` read `…:compiled` through the kernel and hand the program to the language's
//! evaluator as a sub-request; `urn:script:eval` saves a draft by sinking to the script
//! like any other writer.

use std::collections::BTreeSet;
use std::sync::Arc;

use async_trait::async_trait;
use ikigai_core::{
    ActionSpec, ArgRef, ArgSpec, Description, Endpoint, EndpointSpace, Error, Exact, Invocation,
    Iri, ReprType, Representation, Request, Result, UriTemplate, Verb,
};
use serde::{Deserialize, Serialize};

use crate::authority::{
    self, cap_delete, cap_read, cap_run, cap_write, CeilingPolicy, PrincipalStamper, CAP_ANY,
    CAP_DELETE, CAP_LISP, CAP_READ, CAP_READ_PUBLIC, CAP_RUN, CAP_RUN_PUBLIC, CAP_WRITE,
};
use crate::backend::Backend;
use crate::model::{
    self, Event, Head, Language, Outcome, Run, State, Version, MAX_RECORDED_RESULT, SCHEMA,
};
use crate::name::{self, CATALOG_IRI, EVAL_IRI};

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
}

impl SpaceConfig {
    /// Scripts kept in `backend`, each run under the ceiling `ceiling` answers for it.
    pub fn new(backend: Arc<dyn Backend>, ceiling: CeilingPolicy) -> SpaceConfig {
        SpaceConfig {
            backend,
            ceiling,
            principal: authority::unstamped(),
        }
    }

    /// How the principal recorded on every publish and run is decided: by the HOST, from
    /// the invocation. The default records [`authority::UNSTAMPED`].
    pub fn principal(mut self, stamper: PrincipalStamper) -> SpaceConfig {
        self.principal = stamper;
        self
    }
}

/// Bind every script resource.
///
/// ⚠ **Bind order is resolution order** (`EndpointSpace` takes the first grammar that
/// matches), and `urn:script:{name}`'s template captures the rest of an IRI, so the two
/// exact names go first and the bare script last. A name cannot contain `:`, so
/// `urn:script:x:compiled` can only be the compiled form of `x`.
pub fn space(config: SpaceConfig) -> EndpointSpace {
    let shared = Arc::new(config);
    let template = |t: &str| UriTemplate::parse(t).expect("a constant template");
    EndpointSpace::new()
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
        .bind(template("urn:script:{name}"), ScriptEndpoint { shared })
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
                            .summary("The script's language. Lisp only in this version.")
                            .class(XSD_STRING)
                            .one_of(Language::ALL.map(Language::as_str))
                            .default_value("lisp")
                            .optional(),
                    )
                    .input(
                        ArgSpec::new("requires")
                            .summary(
                                "Whitespace-separated `urn:cap:` grants the script needs to \
                                 run. The language's capability is added. Exact grants \
                                 only: no wildcards, no exclusions.",
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
    let mut requires = optional(inv, "requires")?
        .map(authority::parse_requires)
        .transpose()?
        .unwrap_or_default();
    requires.insert(language.capability().to_string());
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
    Ok(plain(format!("{}\n", name::version_iri(name, &digest))))
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
/// under, bound to the version they came from.
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
    /// The evaluator a run issues to.
    pub evaluator: String,
    /// The program.
    pub program: String,
    /// What it declares.
    pub requires: BTreeSet<String>,
    /// What its publisher held of that.
    pub granted: BTreeSet<String>,
    /// The publisher's exclusions.
    pub exclusions: BTreeSet<String>,
    /// Whether it is public.
    pub public: bool,
    /// Its state.
    pub state: State,
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
        let prepared = Prepared {
            schema: SCHEMA,
            iri: name::part_iri(&name, "compiled"),
            version: head.version.clone(),
            language: version.language,
            evaluator: version.language.evaluator().to_string(),
            program: version.source,
            requires: version.requires,
            granted: head.granted,
            exclusions: head.exclusions,
            public: head.public,
            state: head.state,
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
                 under: cached, and cut whenever the script is republished or retired. \
                 Readable by a holder of the script's read OR run grant (a run reads its \
                 program here).",
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

/// Read the compiled form through the kernel, check the run gate and the state, and
/// compute what the run may keep of the runner's capability.
async fn prepare_run(
    inv: &Invocation<'_>,
    shared: &SpaceConfig,
    name: &str,
) -> Result<(Prepared, BTreeSet<String>)> {
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
    Ok((prepared, keep))
}

/// The evaluator sub-request: `in` is the program, `data` what it reads with `(input)`.
fn eval_request(language: Language, program: &str, data: Option<&str>) -> Result<Request> {
    let mut request =
        Request::new(Verb::Source, iri(language.evaluator())?).with_arg("in", inline(program));
    if let Some(data) = data {
        request = request.with_arg("data", inline(data));
    }
    Ok(request)
}

/// `run_args`: the description of the run's input, shared by both run doors.
const DATA_SUMMARY: &str = "Optional data the script reads with `(input)` — data, never code.";

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
        let (prepared, keep) = prepare_run(inv, &self.shared, &name).await?;
        let request = eval_request(prepared.language, &prepared.program, optional(inv, "data")?)?;
        // ★ The ONLY authority a run gets: the runner's own capability, narrowed. There is
        // no form that widens, so a script cannot reach past its runner whatever it says.
        let answer = inv.issue_attenuated(request, keep).await?;
        // Cacheable as far as this endpoint is concerned; the kernel folds in the
        // evaluator's expiry (uncacheable unless the program opts in with `(cacheable …)`)
        // and the compiled form's threads. The authority thread is the host's to cut when
        // it changes this script's ceiling.
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
                 runs nothing; record a run with `…:runs`.",
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
        let (prepared, keep) = prepare_run(inv, shared, &name).await?;
        let request = eval_request(
            prepared.language,
            &prepared.program,
            optional(inv, "content")?,
        )?;
        let runs_as = inv.capability.attenuate(keep.iter().cloned());
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
        let answer = inv.issue_attenuated(request, keep).await;
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
                 error names the record.",
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
            .issue(eval_request(language, code, optional(inv, "data")?)?)
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
                            .summary("The code's language. Lisp only in this version.")
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
