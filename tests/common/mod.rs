//! The fixture every suite shares: a kernel with the script space, the real Lisp
//! evaluator (counted), a few probe endpoints, and a clock.
//!
//! The evaluator is `ikigai-lisp`'s, bound exactly as a host binds it, behind a counter:
//! whether a read RAN the script or was served from the cache is the question the caching
//! tests ask, and the number of evaluations answers it without reading the kernel's
//! internals.

#![allow(dead_code)] // each suite uses a different subset of these helpers

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use futures::executor::block_on;
use ikigai_core::{
    ArgRef, Capability, Clock, Description, Endpoint, EndpointSpace, Error, Exact, Fallback,
    FnEndpoint, Invocation, Iri, Kernel, ReprType, Representation, Request, Result, Space, Time,
    Verb,
};
use ikigai_script::authority::{Ceiling, CeilingPolicy, PrincipalStamper};
use ikigai_script::{Backend, MemoryBackend, SpaceConfig};

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
    EndpointSpace::new()
        .bind(Exact::new("urn:test:whoami"), whoami)
        .bind(Exact::new("urn:test:vault"), vault)
}

/// A test host: its kernel, its backend, and the evaluator's counter.
pub struct Host {
    pub kernel: Kernel,
    pub backend: Arc<dyn Backend>,
    pub evals: Arc<AtomicUsize>,
}

impl Host {
    /// How many times the evaluator has run.
    pub fn evals(&self) -> usize {
        self.evals.load(Ordering::SeqCst)
    }
}

/// A host over `backend`, with every script's ceiling answered by `ceiling` and every
/// request's principal by `principal`.
pub fn host_with(
    backend: Arc<dyn Backend>,
    ceiling: CeilingPolicy,
    principal: Option<PrincipalStamper>,
) -> Host {
    let evals = Arc::new(AtomicUsize::new(0));
    let mut config = SpaceConfig::new(Arc::clone(&backend), ceiling);
    if let Some(principal) = principal {
        config = config.principal(principal);
    }
    let lisp = EndpointSpace::new().bind(
        Exact::new("urn:lisp:eval"),
        Counted {
            inner: ikigai_lisp::eval(),
            calls: Arc::clone(&evals),
        },
    );
    let root = Fallback::new(vec![
        Arc::new(ikigai_script::space(config)) as Arc<dyn Space>,
        Arc::new(lisp) as Arc<dyn Space>,
        Arc::new(probes()) as Arc<dyn Space>,
    ]);
    let kernel = Kernel::with_meta_renderer(Arc::new(root), Arc::new(ikigai_vocab::TurtleRenderer))
        .with_clock(Arc::new(TickingClock::default()));
    Host {
        kernel,
        backend,
        evals,
    }
}

/// A host keeping scripts in memory, with no ceiling.
pub fn host() -> Host {
    host_with(
        Arc::new(MemoryBackend::new()),
        ikigai_script::authority::same_for_all(Ceiling::unbounded()),
        None,
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
    principal: Option<PrincipalStamper>,
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
    let mut config = SpaceConfig::new(Arc::clone(&backend), ceiling)
        .sparql(door)
        .on_change(hook);
    if let Some(principal) = principal {
        config = config.principal(principal);
    }
    let queries = Arc::new(AtomicUsize::new(0));
    let store = CountingStore {
        inner: ikigai_store::space(ikigai_store::DurableStore::in_memory().expect("a store")),
        queries: Arc::clone(&queries),
    };
    let lisp = EndpointSpace::new().bind(Exact::new("urn:lisp:eval"), ikigai_lisp::eval());
    let root = Fallback::new(vec![
        Arc::new(ikigai_script::space(config)) as Arc<dyn Space>,
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
        queries,
        changed,
    }
}

/// A SPARQL host over `urn:iki:store:`, no ceiling, unstamped.
pub fn sparql_host() -> SparqlHost {
    sparql_host_with(
        ikigai_script::sparql::SparqlDoor::store(),
        ikigai_script::authority::same_for_all(Ceiling::unbounded()),
        None,
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
