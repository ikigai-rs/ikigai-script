//! The fixture every suite shares: a kernel with the script space, the real Lisp
//! evaluator (counted), a few probe endpoints, and a clock.
//!
//! The evaluator is `ikigai-lisp`'s, bound exactly as a host binds it, behind a counter:
//! whether a read RAN the script or was served from the cache is the question the caching
//! tests ask, and the number of evaluations answers it without reading the kernel's
//! internals.

#![allow(dead_code)] // each suite uses a different subset of these helpers

pub mod plan;

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use futures::executor::block_on;
use ikigai_core::{
    ArgRef, AsyncFnEndpoint, Capability, Clock, Description, Endpoint, EndpointSpace, Error, Exact,
    Fallback, FnEndpoint, Invocation, Iri, Kernel, ReprType, Representation, Request, Result,
    Space, Time, Verb,
};
use ikigai_script::authority::{Ceiling, CeilingPolicy};
use ikigai_script::{Backend, MemoryBackend, ScriptSpace, SpaceConfig};

/// A clock that advances one second per reading, from 2026-09-15T00:00:00Z.
pub struct TickingClock(AtomicU64);

impl Default for TickingClock {
    fn default() -> Self {
        TickingClock(AtomicU64::new(1_789_430_400_000))
    }
}

impl Clock for TickingClock {
    fn now(&self) -> Time {
        Time::from_millis(self.0.fetch_add(1_000, Ordering::SeqCst))
    }
}

/// `urn:lisp:eval`, counted.
pub struct Counted<E> {
    inner: E,
    pub calls: Arc<AtomicUsize>,
}

#[async_trait]
impl<E: Endpoint> Endpoint for Counted<E> {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.invoke(inv).await
    }
    fn name(&self) -> &str {
        self.inner.name()
    }
    fn describe(&self) -> Description {
        self.inner.describe()
    }
}

/// The scope a probe needs to be written: `urn:test:vault` refuses everyone else.
pub const CAP_VAULT: &str = "urn:cap:test:vault";

/// The probes a script reaches:
///
/// - `urn:test:whoami` answers the capability it was resolved under, one scope per line
///   (`root` for root): what a run REALLY held, observed from the far side.
/// - `urn:test:vault` is a Sink that declares (so the kernel enforces) [`CAP_VAULT`].
/// - `urn:test:fallback?of=<iri>` is a COMPOSITE that reads `of` and, when it is NotFound,
///   answers `fallback`, cacheably: the shape the field guide's first invalidation trap is
///   about, so a test can ask whether a write that ends the absence reaches the fallback.
fn probes() -> EndpointSpace {
    let whoami = FnEndpoint::new("whoami", |inv: &Invocation<'_>| {
        let text = match inv.capability.scopes() {
            None => "root".to_string(),
            Some(scopes) => scopes.iter().cloned().collect::<Vec<_>>().join("\n"),
        };
        // Cacheable, so a program that opts in can be cached over it: the cache keys on
        // the capability, so a run under a different capability is a different entry.
        Ok(Representation::new(ReprType::new("text/plain"), text.into_bytes()).cacheable())
    })
    .with_description(
        Description::new("whoami")
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .output("text/plain"),
    );
    let vault = FnEndpoint::new("vault", |_inv: &Invocation<'_>| {
        Ok(Representation::new(
            ReprType::new("text/plain"),
            b"stored".to_vec(),
        ))
    })
    .with_description(
        Description::new("vault")
            .verb(Verb::Sink)
            .verb(Verb::Meta)
            .requires(CAP_VAULT)
            .output("text/plain"),
    );
    let fallback = AsyncFnEndpoint::new("fallback", |inv| {
        Box::pin(async move {
            let of = Iri::parse(inv.inline_str("of")?)
                .map_err(|e| Error::Endpoint(format!("`of` is not an IRI: {e}")))?;
            match inv.source(&of).await {
                Ok(found) => Ok(found.cacheable()),
                Err(Error::NotFound(_)) => Ok(Representation::new(
                    ReprType::new("text/plain"),
                    b"fallback".to_vec(),
                )
                .cacheable()),
                Err(other) => Err(other),
            }
        })
    })
    .with_description(
        Description::new("fallback")
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .output("text/plain"),
    );
    EndpointSpace::new()
        .bind(Exact::new("urn:test:whoami"), whoami)
        .bind(Exact::new("urn:test:vault"), vault)
        .bind(Exact::new("urn:test:fallback"), fallback)
}

/// A test host: its kernel, its backend, and the evaluator's counter.
pub struct Host {
    pub kernel: Kernel,
    pub backend: Arc<dyn Backend>,
    /// The script space this host's kernel binds: the SAME value, so the conformance suite
    /// can declare it host-named (`Suite::host_named_space`) and check the space it walks.
    pub space: Arc<ScriptSpace>,
    pub evals: Arc<AtomicUsize>,
}

impl Host {
    /// How many times the evaluator has run.
    pub fn evals(&self) -> usize {
        self.evals.load(Ordering::SeqCst)
    }
}

/// A host over `backend`, with every script's ceiling answered by `ceiling`. Who a request
/// comes from is the principal its capability names (`Capability::with_principal`).
pub fn host_with(backend: Arc<dyn Backend>, ceiling: CeilingPolicy) -> Host {
    let evals = Arc::new(AtomicUsize::new(0));
    let config = SpaceConfig::new(Arc::clone(&backend), ceiling);
    let lisp = EndpointSpace::new().bind(
        Exact::new("urn:lisp:eval"),
        Counted {
            inner: ikigai_lisp::eval(),
            calls: Arc::clone(&evals),
        },
    );
    let space = Arc::new(ikigai_script::space(config));
    let root = Fallback::new(vec![
        Arc::clone(&space) as Arc<dyn Space>,
        Arc::new(lisp) as Arc<dyn Space>,
        Arc::new(probes()) as Arc<dyn Space>,
    ]);
    let kernel = Kernel::with_meta_renderer(Arc::new(root), Arc::new(ikigai_vocab::TurtleRenderer))
        .with_clock(Arc::new(TickingClock::default()));
    Host {
        kernel,
        backend,
        space,
        evals,
    }
}

/// A host keeping scripts in memory, with no ceiling.
pub fn host() -> Host {
    host_with(
        Arc::new(MemoryBackend::new()),
        ikigai_script::authority::same_for_all(Ceiling::unbounded()),
    )
}

pub fn request(verb: Verb, iri: &str, args: &[(&str, &str)]) -> Request {
    args.iter().fold(
        Request::new(verb, Iri::parse(iri).expect("a test IRI")),
        |request, (name, value)| request.with_arg(*name, ArgRef::Inline(value.as_bytes().to_vec())),
    )
}

/// Resolve under `capability` and hand back the body as text.
pub fn call(
    kernel: &Kernel,
    capability: &Capability,
    verb: Verb,
    iri: &str,
    args: &[(&str, &str)],
) -> std::result::Result<String, Error> {
    block_on(kernel.issue(request(verb, iri, args), capability))
        .map(|repr| String::from_utf8_lossy(&repr.bytes).into_owned())
}

/// Resolve under root, expecting success.
pub fn ok(kernel: &Kernel, verb: Verb, iri: &str, args: &[(&str, &str)]) -> String {
    call(kernel, &Capability::root(), verb, iri, args)
        .unwrap_or_else(|e| panic!("{verb:?} {iri} {args:?} failed: {e}"))
}

/// Publish `source` at `urn:script:{name}` under root with extra `args`; the version IRI.
pub fn publish(kernel: &Kernel, name: &str, source: &str, args: &[(&str, &str)]) -> String {
    let mut all = vec![("content", source)];
    all.extend_from_slice(args);
    ok(kernel, Verb::Sink, &format!("urn:script:{name}"), &all)
        .trim()
        .to_string()
}

/// A scoped capability.
pub fn cap(scopes: &[&str]) -> Capability {
    Capability::scoped(scopes.iter().copied())
}

/// Assert `result` is a typed `Denied`, and return its message.
pub fn denied(result: std::result::Result<String, Error>) -> String {
    match result {
        Err(Error::Denied(message)) => message,
        other => panic!("expected a typed Denied, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------
// SPARQL: a host with the store, bound as a host binds it
// ---------------------------------------------------------------------------------------

/// An endpoint behind a counter: how many times the store EVALUATED something is the
/// question the caching tests ask.
pub struct CountedDyn {
    inner: Arc<dyn Endpoint>,
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl Endpoint for CountedDyn {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.invoke(inv).await
    }
    fn name(&self) -> &str {
        self.inner.name()
    }
    fn describe(&self) -> Description {
        self.inner.describe()
    }
}

/// `ikigai-store`'s space, with every evaluation of a graph-scoped QUERY counted.
pub struct CountingStore {
    inner: EndpointSpace,
    queries: Arc<AtomicUsize>,
}

impl Space for CountingStore {
    fn resolve(&self, request: &Request, scope: &ikigai_core::Scope) -> ikigai_core::Resolution {
        let resolution = self.inner.resolve(request, scope);
        let target = request.target.as_str();
        if target.starts_with("urn:iki:store:graph-") && target != "urn:iki:store:graph-update" {
            let calls = Arc::clone(&self.queries);
            resolution.map_endpoint(|inner| Arc::new(CountedDyn { inner, calls }))
        } else {
            resolution
        }
    }
    fn entries(&self) -> Option<Vec<ikigai_core::SpaceEntry>> {
        self.inner.entries()
    }
}

/// A host whose scripts may be SPARQL, run against an in-memory `ikigai-store`.
pub struct SparqlHost {
    pub kernel: Arc<Kernel>,
    pub backend: Arc<dyn Backend>,
    /// The script space this host's kernel binds: the SAME value, so the conformance suite
    /// can declare it host-named (`Suite::host_named_space`) and check the space it walks.
    pub space: Arc<ScriptSpace>,
    queries: Arc<AtomicUsize>,
    /// Every name the space reported changed, in order.
    pub changed: Arc<std::sync::Mutex<Vec<String>>>,
}

impl SparqlHost {
    /// How many times the store has evaluated a query for a script.
    pub fn queries(&self) -> usize {
        self.queries.load(Ordering::SeqCst)
    }
}

/// A SPARQL host: scripts (with `door`), the store, Lisp, and the probes. The space's
/// change hook is wired as a host wires it: to a cut of `urn:kernel:bindings`.
pub fn sparql_host_with(
    door: ikigai_script::sparql::SparqlDoor,
    ceiling: CeilingPolicy,
) -> SparqlHost {
    let backend: Arc<dyn Backend> = Arc::new(MemoryBackend::new());
    let kernel_cell: Arc<std::sync::OnceLock<std::sync::Weak<Kernel>>> =
        Arc::new(std::sync::OnceLock::new());
    let changed = Arc::new(std::sync::Mutex::new(Vec::new()));
    let hook: ikigai_script::endpoints::ChangeHook = {
        let cell = Arc::clone(&kernel_cell);
        let changed = Arc::clone(&changed);
        Arc::new(move |name: &str| {
            changed.lock().unwrap().push(name.to_string());
            if let Some(kernel) = cell.get().and_then(std::sync::Weak::upgrade) {
                kernel.cut(ikigai_core::BINDINGS_THREAD);
            }
        })
    };
    let config = SpaceConfig::new(Arc::clone(&backend), ceiling)
        .sparql(door)
        .on_change(hook);
    let queries = Arc::new(AtomicUsize::new(0));
    let store = CountingStore {
        inner: ikigai_store::space(ikigai_store::DurableStore::in_memory().expect("a store")),
        queries: Arc::clone(&queries),
    };
    let lisp = EndpointSpace::new().bind(Exact::new("urn:lisp:eval"), ikigai_lisp::eval());
    let space = Arc::new(ikigai_script::space(config));
    let root = Fallback::new(vec![
        Arc::clone(&space) as Arc<dyn Space>,
        Arc::new(store) as Arc<dyn Space>,
        Arc::new(lisp) as Arc<dyn Space>,
        Arc::new(probes()) as Arc<dyn Space>,
    ]);
    let kernel = Arc::new(
        Kernel::with_meta_renderer(Arc::new(root), Arc::new(ikigai_vocab::TurtleRenderer))
            .with_clock(Arc::new(TickingClock::default())),
    );
    kernel_cell
        .set(Arc::downgrade(&kernel))
        .unwrap_or_else(|_| unreachable!("set once"));
    SparqlHost {
        kernel,
        backend,
        space,
        queries,
        changed,
    }
}

/// A SPARQL host over `urn:iki:store:`, no ceiling.
pub fn sparql_host() -> SparqlHost {
    sparql_host_with(
        ikigai_script::sparql::SparqlDoor::store(),
        ikigai_script::authority::same_for_all(Ceiling::unbounded()),
    )
}

/// Write `update` straight to the store under root: the host's own data, not a script.
pub fn seed(kernel: &Kernel, update: &str) {
    ok(
        kernel,
        Verb::Sink,
        "urn:iki:store:update",
        &[("content", update)],
    );
}

// ---------------------------------------------------------------------------------------
// Plans: a host with the plan doors (a test double of part A's contract, or the engine's), and
// probes
// ---------------------------------------------------------------------------------------

/// The scope `urn:test:greet` declares (so the kernel enforces it).
pub const CAP_GREET: &str = "urn:cap:test:greet";
/// The family `urn:test:host` declares: "holds some `urn:cap:test:net:<host>`". It checks
/// the exact `urn:cap:test:net:<host>` for its `host` argument itself, as `ikigai-http`
/// checks a host rule.
pub const CAP_NET: &str = "urn:cap:test:net:*";

/// The probes a plan's steps reach, beside [`probes`]:
///
/// - `urn:test:greet` (Source, requires [`CAP_GREET`]): `hello, {who}`, cacheable.
/// - `urn:test:host` (Source, requires the family [`CAP_NET`]): `reached {host}`, refused
///   unless the capability holds `urn:cap:test:net:{host}` exactly.
/// - `urn:test:held` (Source, requires nothing): `urn:test:whoami`'s answer, taking a fed
///   value as `in` and ignoring it.
fn plan_probes() -> EndpointSpace {
    let greet = FnEndpoint::new("greet", |inv: &Invocation<'_>| {
        let who = inv.inline_str("who").unwrap_or("nobody");
        Ok(Representation::new(
            ReprType::new("text/plain"),
            format!("hello, {who}").into_bytes(),
        )
        .cacheable())
    })
    .with_description(
        Description::new("greet")
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .requires(CAP_GREET)
            .output("text/plain"),
    );
    let host = FnEndpoint::new("host", |inv: &Invocation<'_>| {
        let host = inv.inline_str("host")?;
        let exact = format!("urn:cap:test:net:{host}");
        if !inv.capability.allows(&exact) {
            return Err(Error::Denied(format!("reaching {host} needs `{exact}`")));
        }
        Ok(Representation::new(
            ReprType::new("text/plain"),
            format!("reached {host}").into_bytes(),
        ))
    })
    .with_description(
        Description::new("host")
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .requires(CAP_NET)
            .output("text/plain"),
    );
    // `urn:test:whoami` with ONE declared input, so a plan step can be FED (`ik:pipeFrom`) and
    // its answer therefore depends on the step before it: the engine runs and derives only
    // the steps its result depends on, so a step left dangling never runs there.
    let held = FnEndpoint::new("held", |inv: &Invocation<'_>| {
        let text = match inv.capability.scopes() {
            None => "root".to_string(),
            Some(scopes) => scopes.iter().cloned().collect::<Vec<_>>().join("\n"),
        };
        Ok(Representation::new(ReprType::new("text/plain"), text.into_bytes()).cacheable())
    })
    .with_description(
        Description::new("held")
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .input(
                ikigai_core::ArgSpec::new("in")
                    .summary("A value fed from an earlier step; ignored.")
                    .class("http://www.w3.org/2001/XMLSchema#string")
                    .optional(),
            )
            .output("text/plain"),
    );
    EndpointSpace::new()
        .bind(Exact::new("urn:test:greet"), greet)
        .bind(Exact::new("urn:test:host"), host)
        .bind(Exact::new("urn:test:held"), held)
}

/// A host whose scripts may be plans: scripts, the plan doors (the double or the engine's,
/// [`Doors`]; `urn:plan:eval` counted), Lisp, and the probes. The change hook is wired as a host wires it.
pub struct PlanHost {
    pub kernel: Arc<Kernel>,
    pub backend: Arc<dyn Backend>,
    /// The script space this host's kernel binds: the SAME value, so the conformance suite
    /// can declare it host-named (`Suite::host_named_space`) and check the space it walks.
    pub space: Arc<ScriptSpace>,
    evals: Arc<AtomicUsize>,
}

impl PlanHost {
    /// How many times `urn:plan:eval` has run.
    pub fn evals(&self) -> usize {
        self.evals.load(Ordering::SeqCst)
    }
}

/// Which plan doors a [`PlanHost`] binds (ledger #1222): the DOUBLE in [`plan`], which states
/// the contract this crate relies on, or the ENGINE's real ones
/// (`ikigai_engine::plan_space::space()`, validating through `ikigai_shacl::space()`), which is
/// what a host binds. Every plan suite runs its cases against both ([`both`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Doors {
    Double,
    Engine,
}

/// The engine's plan doors with the SHACL validator they compose, `urn:plan:eval` counted.
struct EngineDoors {
    inner: Fallback,
    calls: Arc<AtomicUsize>,
}

impl EngineDoors {
    fn new(calls: Arc<AtomicUsize>) -> Self {
        EngineDoors {
            inner: Fallback::new(vec![
                Arc::new(ikigai_engine::plan_space::space()) as Arc<dyn Space>,
                Arc::new(ikigai_shacl::space()) as Arc<dyn Space>,
            ]),
            calls,
        }
    }
}

impl Space for EngineDoors {
    fn resolve(&self, request: &Request, scope: &ikigai_core::Scope) -> ikigai_core::Resolution {
        let resolution = self.inner.resolve(request, scope);
        if request.target.as_str() == ikigai_engine::plan_space::EVAL {
            let calls = Arc::clone(&self.calls);
            resolution.map_endpoint(|inner| Arc::new(CountedDyn { inner, calls }))
        } else {
            resolution
        }
    }
    fn entries(&self) -> Option<Vec<ikigai_core::SpaceEntry>> {
        self.inner.entries()
    }
}

/// Run `case` against both kinds of plan doors, naming the doors in any failure.
pub fn both(case: impl Fn(Doors)) {
    for doors in [Doors::Double, Doors::Engine] {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| case(doors)));
        if let Err(panic) = outcome {
            eprintln!("the case above failed against the {doors:?} plan doors");
            std::panic::resume_unwind(panic);
        }
    }
}

pub fn plan_host_with(ceiling: CeilingPolicy) -> PlanHost {
    plan_host_over(ceiling, Vec::new())
}

/// [`plan_host_with`] on the given doors.
pub fn plan_host_on(doors: Doors, ceiling: CeilingPolicy) -> PlanHost {
    plan_host_on_over(doors, ceiling, Vec::new())
}

/// [`plan_host_with`], with `extra` spaces bound behind the probes (a store and a module whose
/// resources a plan's steps reach, as a host binds them).
pub fn plan_host_over(ceiling: CeilingPolicy, extra: Vec<Arc<dyn Space>>) -> PlanHost {
    plan_host_on_over(Doors::Double, ceiling, extra)
}

/// [`plan_host_over`] on the given doors.
pub fn plan_host_on_over(
    doors: Doors,
    ceiling: CeilingPolicy,
    extra: Vec<Arc<dyn Space>>,
) -> PlanHost {
    let backend: Arc<dyn Backend> = Arc::new(MemoryBackend::new());
    let kernel_cell: Arc<std::sync::OnceLock<std::sync::Weak<Kernel>>> =
        Arc::new(std::sync::OnceLock::new());
    let hook: ikigai_script::endpoints::ChangeHook = {
        let cell = Arc::clone(&kernel_cell);
        Arc::new(move |_name: &str| {
            if let Some(kernel) = cell.get().and_then(std::sync::Weak::upgrade) {
                kernel.cut(ikigai_core::BINDINGS_THREAD);
            }
        })
    };
    let config = SpaceConfig::new(Arc::clone(&backend), ceiling).on_change(hook);
    let evals = Arc::new(AtomicUsize::new(0));
    let lisp = EndpointSpace::new().bind(Exact::new("urn:lisp:eval"), ikigai_lisp::eval());
    let space = Arc::new(ikigai_script::space(config));
    let root = Fallback::new(
        [
            Arc::clone(&space) as Arc<dyn Space>,
            match doors {
                Doors::Double => Arc::new(plan::doors(Arc::clone(&evals))) as Arc<dyn Space>,
                Doors::Engine => Arc::new(EngineDoors::new(Arc::clone(&evals))) as Arc<dyn Space>,
            },
            Arc::new(lisp) as Arc<dyn Space>,
            Arc::new(probes()) as Arc<dyn Space>,
            Arc::new(plan_probes()) as Arc<dyn Space>,
        ]
        .into_iter()
        .chain(extra)
        .collect(),
    );
    let kernel = Arc::new(
        Kernel::with_meta_renderer(Arc::new(root), Arc::new(ikigai_vocab::TurtleRenderer))
            .with_clock(Arc::new(TickingClock::default())),
    );
    kernel_cell
        .set(Arc::downgrade(&kernel))
        .unwrap_or_else(|_| unreachable!("set once"));
    PlanHost {
        kernel,
        backend,
        space,
        evals,
    }
}

/// A plan host with no ceiling.
pub fn plan_host() -> PlanHost {
    plan_host_with(ikigai_script::authority::same_for_all(Ceiling::unbounded()))
}

/// [`plan_host`] on the given doors.
pub fn plan_host_of(doors: Doors) -> PlanHost {
    plan_host_on(
        doors,
        ikigai_script::authority::same_for_all(Ceiling::unbounded()),
    )
}
