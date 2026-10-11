# ikigai-script

**Scripts as resources in any ikigai host.** Write a few lines of Lisp, or a SPARQL
query, publish them at a name, and every door the host already has (REST, the REPL, MCP,
a timer, an admin panel) can fetch them, run them, and see who ran what, under exactly
what authority. No second API, no second permission system: a script is a resource like
any other, and running it is a read or a write like any other.

```text
urn:script:{name}                    Source Exists Sink Delete  the script: fetch WITHOUT running, publish, retire
urn:script:{name}:version:{digest}   Source Exists              one immutable, content-addressed version
urn:script:{name}:compiled           Source                     the head prepared for its evaluator (cached)
urn:script:{name}:result             Source                     run it as a READ: its answer
urn:script:{name}:runs               Sink                       run it for EFFECTS: answers the run's IRI
urn:script:{name}:run:{id}           Source Exists              one recorded run
urn:script:eval                      Sink                       run supplied code under the caller's own authority
urn:script:catalog                   Source                     every script the caller may read
```

A published SPARQL query or plan is also its OWN entry in the host's catalog:
`urn:script:{name}:result` and `…:runs` with its declared parameters as their arguments (see
"Queries as scripts" and "Plans as scripts").

**Which language?** When assembling anything, prefer **a query, then a plan, then Lisp.** A
query and a plan both derive their authority from what they name and are checked before they
run; Lisp declares its authority and can do anything its capability allows, in any order. Use
Lisp for control flow a plan cannot express, and preferably as one step inside a plan.

## Why resources

Because then every modality is a door, not a feature. `ikigai-web` already maps HTTP
methods onto verbs, so the REST surface is this table projected: `GET urn:script:x` fetches
the source without running it, `PUT` publishes, `DELETE` retires, `GET …:result` runs it as
a read, `POST …:runs` runs it for its effects. An agent sees a published script in its
manifold under its own grant. And because a script reaches the world only through kernel
verbs, its caching, its golden threads and its trace are the kernel's, unchanged:

- **Running is a read.** `…:result` is cacheable exactly as far as the script's own
  sub-requests are (a Lisp program opts in with `(cacheable …)`), so a pure public script
  answered a thousand times runs once. Republishing cuts the script's golden thread, and
  the cached answer goes with it.
- **Running is a write.** `…:runs` records a run atom (who, the principal the runner's
  capability names; which
  version; under exactly what capability; when; the outcome; the trace span when the host
  traced) and answers its IRI. A failed run is recorded too, and its error keeps its type
  and names the record. A run record, its absence included, hangs from `urn:script:{name}:runs`,
  which every run cuts, a failed one included (the kernel cuts a Sink's target when the
  endpoint ran, whatever it answered; ikigai-core 0.1.95).
- **Versions are content.** Every publish stores a version named by the sha256 of its
  language, declared capability and source (`sha256:` and hex, the ecosystem's tagged
  digest). The head moves; old versions stay fetchable by name.

## The authority rule

Three authorities, never merged:

1. **Publish or change**: `urn:cap:script:write:{name}`; retire with `urn:cap:script:delete:{name}`.
2. **Run**: `urn:cap:script:run:{name}`. A script marked `public=true` is also runnable by
   any holder of `urn:cap:script:run:public`, which is the grant a host gives its anonymous
   principal.
3. **Runs as**: the runner's own capability, attenuated to

   ```text
   { declared } ∩ { what the publisher held at publish } ∩ { the host's ceiling for this script }
     + every exclusion the publisher or the ceiling carries
   ```

**No elevation.** A publish that declares a scope its publisher does not hold is refused
(`Denied`, naming the scopes): a script never runs with more than its publisher held, and
its declared `requires` never says more than its runs get. A run never holds anything its
runner does not: the only way this crate makes a run's authority is
`Invocation::issue_attenuated`, and there is no form that widens. Exclusions travel: a
publisher who could not read `/root/secret` publishes a script that cannot either, whoever
runs it.

Reading a script's source is a fourth grant, `urn:cap:script:read:{name}` (or
`urn:cap:script:read:public` for a public, published script): code is a different
sensitivity from running it. A caller without the grant is refused the same way whether
the script exists or not.

**Namespaces.** Each of the four may be held for one script or for a NAMESPACE of them:
`urn:cap:script:{act}:{namespace}-*` covers every name that begins `{namespace}-`
(`authority::cap_namespace`), so `urn:cap:script:write:team-*` publishes `team-report` and
`team-a-report` but not `teammate`, `team` or `other`. The act stays spelled out and the
wildcard comes only at the end, after a `-`: core has no infix wildcard, and a grant to run a
namespace never publishes in it. An exclusion takes a script or a namespace back out
(`urn:cap:script:write:-team-payroll`, `urn:cap:script:write:-team-hr-*`) and wins over any
grant. There is no "every script" grant below root: `urn:cap:script:{act}:*` is spelled like
the family each door declares ("holds some grant of this act") and grants nothing.
`authority::holds` is the whole rule; a host filtering what it shows asks it, not
`Capability::allows`, which matches a held scope exactly and would miss a namespace.

⚠ A published query's or plan's own entry is checked at the kernel's floor before it runs,
and a description cannot depend on who asks. So a name in a namespace declares its TOP-LEVEL
namespace as its run gate (`team-a-report` declares `urn:cap:script:run:team-*`,
`authority::run_floor`) and the exact rule is checked inside: the entry is offered to a holder
of another grant in the same top-level namespace, who is refused when they call it. A name
with no `-` keeps its exact gate.

**Evaluating code is itself authority.** Every Lisp script declares `urn:cap:lisp`
implicitly, so its publisher must hold it, its host ceiling must allow it, and its runner
must hold it. See "What the host must supply" for what that means for anonymous runs.

## Drafts are private

A draft (`state=draft`, or `urn:script:eval save=`) is visible only to its **author** until it
is published. The author is the principal the writer's capability named (see "What the host
must supply"), the same value a publish records as the script's publisher, and a reader is the
author when their capability `acts_as` it: never an argument, so no caller can name itself the
author. Seeing a draft needs the read (or run) grant AND authorship, so privacy only narrows
what a grant reaches.

- To any other caller holding the grant, a draft is **absent**, and told so exactly as a name
  nobody wrote is: `NotFound` with the same words, `Exists` false, no catalog row, its compiled
  form (and so its run) not found. `Denied` would tell a reader "someone's draft is here",
  which is the thing privacy hides. A caller without the grant is `Denied` either way, as
  before.
- It is a property of the VERSION: one never published stays its author's after the head
  moves past it (fetching it by digest finds nothing), retiring a draft does not publish it,
  and once a version is published it is every reader's for good. Root sees every draft: it is
  the host's own authority, and holds the backend they are stored in.
- Every answer is **cacheable**, the author's included: the kernel keys its cache on the
  capability, and the capability carries the principal, so alice's cached draft is never served
  to bob even when the rest of their grants are the same. (Before 0.2.0 the principal came from
  a host stamper the cache could not see, and these answers were never cached.) Every answer,
  a NotFound included, hangs from the script's golden thread, so a publish or retire cuts it.
- A SPARQL query or plan that was never published has **no catalog entry of its own**. `Meta`
  is answered to anyone who can reach the door, and the script's own contract is made of its
  text (its parameters and leading comment), so a draft wears the generic contract until it is
  published.
- ⚠ **A capability that names no principal has no authors**: a draft written under one is
  recorded `UNSTAMPED`, and `UNSTAMPED` and `ANONYMOUS` name many callers at once, so a draft
  written under either is root's alone, and a refusal to a caller whose capability names no
  principal says so. The history in a published script's JSON record still lists each
  superseded draft's digest and who wrote it; never its content.

## The graph face

The catalog and every run record also answer `as=text/turtle`: PROV-O and the shared
vocabulary, every node an IRI this crate already names (no blank nodes), so the visualizers
and SPARQL read them as one graph and two answers merge without renaming.

```text
<urn:script:catalog>  dcterms:hasPart  <urn:script:{name}>              one per catalog row
<urn:script:{name}>   dcterms:identifier "{name}" ; ik:contentHash "sha256:…"   its head version
<urn:script:{name}:version:{digest}>  prov:specializationOf  <urn:script:{name}>
<urn:script:{name}:run:{id}>  a prov:Activity ;
    prov:used <urn:script:{name}:version:{digest}> ;          the version that ran
    prov:wasAssociatedWith <principal> ;                      as the door minted it (when an IRI)
    prov:startedAtTime "…"^^xsd:dateTime ; prov:endedAtTime "…"^^xsd:dateTime ;
    ik:outcome <urn:script:outcome:ok>                         or …:failed; absent while running
```

A run reaches its script through the version it used, so "every run of this script" and "its
last run" are queries rather than terms. Each field the graph carries is pinned against the
JSON face as an RDF term (`tests/turtle.rs`), with the `ik:` ranges read from the published
vocabulary.

⚠ **The graph carries less than the JSON**, because the vocabulary has no term for the rest and
this crate does not invent `ik:` terms: a script's state, public flag, language, declared and
granted capability and exclusions; a run's capability, failure kind and message, result, and
trace span. Use `as=application/json` for those.

## Mounting it

A host library: no binary. A host mounts `space(config)` beside the evaluator its scripts
are written for, and decides the three things only a host can.

```rust,no_run
use ikigai_core::{Fallback, Kernel, Space, BINDINGS_THREAD};
use ikigai_script::{authority::{Ceiling, CeilingPolicy}, space, DirBackend, SpaceConfig};
use ikigai_script::sparql::SparqlDoor;
use std::sync::{Arc, OnceLock, Weak};

let config_home = std::path::PathBuf::from("/path/to/config-home");
let backend = Arc::new(DirBackend::open(config_home.join("scripts")).expect("a directory"));
let ceilings = config_home.join("script-authority");
let ceiling: CeilingPolicy = Arc::new(move |name| {
    std::fs::read_to_string(ceilings.join(name))
        .ok()
        .and_then(|text| Ceiling::parse(&text).ok())
        .unwrap_or_else(Ceiling::nothing) // no file: the script may touch nothing
});
// The kernel does not exist yet when the space is built; the change hook reaches it later.
let kernel_cell: Arc<OnceLock<Weak<Kernel>>> = Arc::new(OnceLock::new());
let cell = Arc::clone(&kernel_cell);
let scripts = space(SpaceConfig::new(backend, ceiling)
    // SPARQL scripts, run against the store bound below.
    .sparql(SparqlDoor::store())
    // A published query is its own catalog entry: re-describe after every publish.
    .on_change(Arc::new(move |_name| {
        if let Some(kernel) = cell.get().and_then(Weak::upgrade) {
            kernel.cut(BINDINGS_THREAD);
        }
    })));
let store = ikigai_store::DurableStore::in_memory().expect("a store"); // `open(path)` for real
let root = Fallback::new(vec![
    Arc::new(scripts) as Arc<dyn Space>,
    Arc::new(ikigai_store::space(store)) as Arc<dyn Space>,
    Arc::new(ikigai_lisp::space()) as Arc<dyn Space>,
]);
let kernel = Arc::new(Kernel::new(Arc::new(root)));
let _ = kernel_cell.set(Arc::downgrade(&kernel));
```

### What the host must supply

- **Storage**: a `Backend`. `MemoryBackend` for tests and for hosts that publish their
  scripts from configuration at every start; `DirBackend` for plain files under a
  directory (one host process per directory).
- **The ceiling** for each script, from `<config home>/script-authority/{name}`: one
  `urn:cap:` scope per line, `#` comments, `prefix*` families allowed, `-` exclusions
  carried by every run, a lone `*` for no ceiling. `Ceiling::parse` reads the format; the
  library never reads the config home itself. **When the host changes a ceiling it cuts
  `urn:script:{name}:authority`**, or a cached result computed under the old ceiling is
  served until something else cuts it.
- **The principal**, minted by the host's door into the capability each request runs under:
  `capability.with_principal("urn:example:person:alice")`, the `urn:cap:principal:<iri>`
  convention of ikigai-core 0.1.93. It is recorded on every publish and run, and it is the
  identity a draft is private to. Never an argument: a caller cannot name itself, and narrowing
  a capability can never add or change a principal. A capability naming none (root, or a door
  that minted nothing) records `urn:script:principal:unstamped`, under which no caller is a
  draft's author (see "Drafts are private"); mint `urn:script:principal:anonymous` for a caller
  the door cannot identify. (0.1.0 took a `SpaceConfig::principal` stamper instead; 0.2.0
  removes it.)
- **A grant for anonymous runs**, if it wants them: `urn:cap:script:run:public`,
  `urn:cap:script:read:public`, and `urn:cap:lisp`. ⚠ The last is not optional: a run is
  a sub-request to `urn:lisp:eval` under the runner's narrowed capability, and narrowing
  cannot add the language grant the runner lacks. So a host that gives anonymous callers
  `urn:cap:lisp` should not also route `urn:lisp:eval` to its anonymous door, or they can
  evaluate any code there (under nothing else, but with the CPU). Rate-limit the door
  (`ikigai-throttle`), and put a `Timeout` in front of the evaluator.
- **An out-of-band edit is survivable, not visible.** `DirBackend` compares-and-sets every
  head against what the writer read (an editor who got there first wins, and the writer
  gets a `Conflict`), checks every version file against its digest (an edited version is
  refused by name; publishing the content again repairs it), and fails a broken head for
  that script alone. A read the kernel cached before a hand edit is served until the host
  cuts `urn:script:{name}`.

## Storage: why the atoms hold their own state

The ledger owns no bytes: it authors SPARQL against `ikigai-store`'s named graphs. Scripts
cannot, because **a sub-request carries the caller's capability unchanged**. Whatever this
crate writes on a caller's behalf, the caller must hold the grant to write directly, and
here the record IS the authority: every publisher would hold write over the graph (or
`urn:file:` path) holding its own granted-at-publish snapshot, and could widen it; every
runner, anonymous included, would hold write over the run log, and could forge it. So the
two atoms (a script, a run) hold their state behind a `Backend`, nothing but this crate's
endpoints write it, and no caller ever needs a storage grant. The golden threads are still
the kernel's: a Sink or Delete at `urn:script:{name}` cuts the thread every derived read
hangs from.

## Lisp

Reached as a resource: a run is a sub-request to
`urn:lisp:eval` with the program as `in` and the run's input as `data` (read with
`(input)`), so this crate links no interpreter. Built and tested against the published
`ikigai-lisp` 0.1.15. When 0.2.0 (the allowlist sandbox) is published nothing here changes
but the dev-dependency pin: the sandbox narrows what a program can do inside the
evaluator, and everything it can reach outside still goes through the verbs, under the
run's capability.

The compiled form, for Lisp, is preparation rather than compilation: `ikigai-lisp`
offers no compile step to cache, so `…:compiled` is the head version's program bound to
the authority it runs under, cached and cut with the script. A language with a real
compile step (plans, TypeScript) fills the same slot.

## Queries as scripts

A stored SPARQL query is a script whose language is `sparql`. No second system: it gets
versions, the three authorities, run records and the manifold from everything above, and
three things of its own, each read from the PARSED text and never from a caller's argument.

```text
sink urn:script:stale language=sparql content='
# Open items nobody has touched in a while.
# @param days xsd:integer default 7 -- untouched for more than this many days
PREFIX ledger: <https://ikigai-rs.dev/ns/ledger#>
SELECT ?item ?age FROM <urn:iki:ledger:default>
WHERE { ?item ledger:age ?age FILTER(?age > ?days) } ORDER BY DESC(?age)'

source urn:script:stale:result days=14 as=text/csv
```

**Its form.** SELECT, ASK, CONSTRUCT and DESCRIBE run as READS at `…:result`, cached as the
store's answer is (they hang from the store's write threads, so a write to the store
recomputes them, and a republish cuts the script's thread as for Lisp). An UPDATE runs as a
WRITE at `…:runs`, with a run record; `…:result` on an update is refused, naming `…:runs`. A
query may also run through `…:runs` when a run should be recorded.

**Its parameters**, declared in the comment block before the first token, one per line:

```text
# @param <name> <type> [required | optional | default <value>] [-- <summary>]
```

`<name>` is the query variable it binds (`?days` or `$days`); `<type>` is an XSD datatype
(`xsd:string`, `xsd:boolean`, `xsd:integer`, `xsd:decimal`, `xsd:double`, `xsd:float`,
`xsd:date`, `xsd:dateTime`, `xsd:time`, the three durations, `xsd:anyURI`), bound as a typed
literal after its lexical form is checked and in its canonical form; or a class (`<iri>`, or
`rdfs:Resource` for any IRI), bound as an IRI. Bare means required; a `default` is optional
with that value (a JSON string, `"like this"`, when it has a space). A declared parameter the
query never uses, one the query binds itself (`BIND … AS`, `VALUES`, `GROUP BY`), a datatype
parameter in a predicate or graph-name position, and a declaration outside that block are
refused at publish. The parameters become the ArgSpecs of the script's own `…:result` and
`…:runs`, so they appear in the catalog, MCP and the Emacs aliases as real arguments. A run
refuses a missing required parameter (`MissingArgument`), a value not of its type and an
argument the script does not declare (`InvalidArgument`: a binding the query does not mention
is refused, never ignored). Through `…:runs` they may also arrive as one JSON object piped as
`content`.

**The transports' arguments are not parameters** (`TRANSPORT_ARGUMENTS`, ledger #1173).
`ikigai-web` stamps a write with `received`, `client`, `principal` and the body's
`content-type`, and `ikigai-quic` stamps `principal` on every verb. A run ignores those four
names instead of refusing them as undeclared (which made every run for effects through the
HTTP door a `400`), and no query or plan may declare a parameter by one of them (refused at
publish, as `as`, `name` and `content` already were). A value a caller puts under one of them
is ignored the same way: who a run is for is the principal its CAPABILITY names, never an
argument.

**★ Values are bound as RDF terms, never spliced.** The text is parsed, each parameter's
variable is replaced by its term in the ALGEBRA (patterns, paths, expressions, templates; a
projected parameter becomes `(term AS ?p)`), and the store is sent what spargebra serializes
from that algebra, which writes a literal as one escaped token. A value that tries to close a
string, open a graph pattern or smuggle a second operation arrives as one literal:
`tests/sparql.rs` sends five such values through a query and a `DROP ALL` through an update,
and reads each back intact beside an untouched store. An IRI parameter refuses what is not an
IRI rather than mangling it.

### Derived authority

The author does not declare what a query needs; the text says it. Each graph a query names
(`FROM`, `FROM NAMED`, `GRAPH <iri>`, and the host's default dataset when it reads the default
graph without `FROM`) derives `urn:cap:store:read:graph:<iri>`; an update's one graph derives
`urn:cap:store:write:graph:<iri>`, and the read grant too when it has a `WHERE` (the store's
own rule). A `requires=` at publish that says anything else is refused, naming the derived
set. The phase-1 rule holds on top: a run gets the derived set, narrowed to what its publisher
held at publish and the host's ceiling allows, intersected with the runner's own capability.
A grant any of those withholds is refused before the store is asked, naming the graph and the
grant.

`GRAPH ?g` (a graph the text does not fix) derives the family `urn:cap:store:read:graph:*` and
runs over **the caller's readable union, and never more**: the graph grants the runner holds,
that the publisher held (all of them, when the publisher was root) and the ceiling allows,
computed per run. A parameter naming a graph is admitted the same way.

### The dataset, and what is refused at publish

A run is a sub-request to the store's graph-scoped doors (`urn:iki:store:graph-select`, `-ask`,
`-construct`, `-describe`, `-update`), so the store's pre-parse bound, sized stack, tenancy and
coming time budget apply to every run; this crate parses but never evaluates. Those doors take
ONE set of graphs, whose merge is the default graph and whose members are the named graphs, so
a script's dataset is every graph it names and its `FROM` clauses are removed from the text the
store sees. Where that one dataset would change the answer, the query is refused at publish
instead of answered differently: a query reading the default graph (a bare pattern, or a
DESCRIBE) must name its whole dataset with `FROM`, and may not also read a `GRAPH ?g`. An update
writes exactly one named graph and reads no other; `LOAD`, `SERVICE`, `DROP ALL` and a write to
the default graph are refused. `SERVICE` is refused in a query too (anywhere, `FILTER EXISTS` and
a variable service name included), at publish and again at every run, so no script reaches the
network even in a host whose graph compiles in oxigraph's HTTP client (`ikigai-cli` does, through
rudof). `tests/sparql_service_egress.rs` proves it with a local stub under the test-only feature
`http-client-probe`, which enables nothing a consumer links. Host the doors on ikigai-store 0.2.10
or later, which refuses both at its own doors as a second layer. The text is checked against the store's bound
(`src/limits.rs`, copied from ikigai-store) before it is parsed here at all.

### Faces

`as=` on `…:result`: `application/sparql-results+json` (the default), `+xml`, `text/csv` or
`text/tab-separated-values` for SELECT and ASK; `text/turtle` (the default) or
`application/n-triples` for CONSTRUCT and DESCRIBE. Anything else is refused, never substituted.

### What a host supplies for queries

- **The door**: `SpaceConfig::sparql(SparqlDoor::store())`, beside an `ikigai_store::space`.
  `SparqlDoor::store_at(prefix)` for a store mounted elsewhere; `.default_graphs(…)` for the
  dataset a query without `FROM` reads. Without a door, `language=sparql` is refused.
- **The change hook**: `SpaceConfig::on_change(…)`, wired to
  `kernel.cut(ikigai_core::BINDINGS_THREAD)`. Each published query is its own catalog entry
  with its own parameters, and the kernel caches descriptions under that thread, which only
  the host can cut. Unwired, a new query runs at once but the catalog, MCP and the engine's
  argument routing describe the old set.
- **The store grants** its runners need: the exact `urn:cap:store:read:graph:<iri>` (and
  write) tokens. A root runner of a query over `GRAPH ?g` that a root published lists the
  store's graphs through `urn:iki:store:graphs`, under the broad `urn:cap:store:read` it holds.
- ⚠ **A script's contract is public.** `Meta` is answered from the description, unguarded, so
  anyone who can reach the door can learn a published query's parameter names and types (not
  its text, which stays behind the read grant). The catalog itself needs the kernel's inspect
  grant, and the action manifold offers a private query only to holders of its run grant.

## Plans as scripts

A plan (an `ik:Process` graph in the process vocabulary, Turtle) is a script whose language is
`plan`. It is the most analyzable language there is: finite (no conditionals or loops; a branch
is a step that calls a language), so it is validated before it is stored and its authority is
derived rather than declared. Three host doors do the work, each reached by sub-request, so
this crate links no plan runner:

```text
urn:plan:validate   the SHACL report against the vocabulary's shapes, plus the executor's checks
urn:plan:requires   the capability each step's target contract requires (read with Meta: nothing runs)
urn:plan:eval       run the plan: every step a sub-request under the caller's capability
```

```text
sink urn:script:hello language=plan content='
# Greet someone.
@prefix ik: <https://ikigai-rs.dev/ns#> .
<urn:plan:hello> a ik:Process ; ik:input <urn:plan:hello:input:who> ;
    ik:step <urn:plan:hello:step:1> ; ik:result <urn:plan:hello:step:1> .
<urn:plan:hello:input:who> ik:inputName "who" ; ik:required false ; ik:default "world" .
<urn:plan:hello:step:1> a ik:Step ; ik:verb "Source" ; ik:resolves <urn:example:greet> ;
    ik:argument <urn:plan:hello:step:1:arg:who> .
<urn:plan:hello:step:1:arg:who> a ik:Argument ; ik:inputName "who" ;
    ik:ref <urn:plan:hello:var:who> .'

source urn:script:hello:result who=brian
```

**Publishing validates.** `urn:plan:validate` runs first, and a plan that does not conform is
refused (`InvalidArgument` on `content`) naming every shape it broke, the node and the shape's
message, e.g. `urn:ikigai:shape:step at <…:step:2>: a step is fed by at most one of
ik:pipeFrom, ik:mapOver, ik:forkOf`. Nothing is stored.

**Authority is derived.** `urn:plan:requires` reads each step's target contract and answers what
it requires (`Description::required_scopes` for the step's verb). The union is stored with the
version, and a `requires=` that says anything else is refused, naming the derived set. A step
whose target resolves nowhere makes the derivation incomplete, and the publish is refused,
naming the step: storing the rest would store a floor as the requirement. The phase-1 rule
holds on top: a run gets the derived set, narrowed to what the publisher held at publish and
the host's ceiling allows, intersected with the runner's own capability, and each step then
meets its own target's floor inside the evaluator. A plan's runner needs no language grant.
The set is derived at PUBLISH: if a step's target later asks for more, that step is refused
(fail closed) until the plan is republished and derived again.

**Read or write, from the steps.** A plan whose every step is a `Source`, `Exists` or `Meta`
runs as a READ at `…:result`, cacheable exactly as far as its least cacheable step (a republish
cuts it). Any `Sink` or `Delete` step anywhere in the graph makes it a WRITE: `…:result` refuses
it, naming `…:runs`, where every run is recorded. Decided from the parsed plan, never from an
argument.

**Its parameters** are its `ik:input` nodes: arguments of its own `…:result` and `…:runs`, with
their `ik:class`, `ik:default` and `ik:summary`. A run refuses an argument the plan does not
declare and a required one with no default before anything runs; through `…:runs` they may
also arrive as one JSON object piped as `content`. `as=` is passed to the evaluator, which
transrepts the result or refuses. `in`, `as`, `name` and `content` cannot be parameter names.

**A derived family** (a step whose target declares `urn:cap:net:*`, "holds some grant under this
prefix") is stored as the publisher's own grants under it, or, for a root publisher, as the
family, which each run turns into the RUNNER's grants under it that the ceiling allows. A root
runner cannot be enumerated, so it gets the members the ceiling names; under no ceiling it keeps
the bare family, which the kernel's floor admits and the target's own rule (a host, a path)
refuses. A host that wants a root-published plan with such a step to run under root lists the
members in that script's ceiling.

### What a host supplies for plans

Bind the three doors (`ikigai-engine`'s plan space, which needs `urn:shacl:validate` beside it),
and wire `SpaceConfig::on_change` as for queries: each published plan is its own catalog entry.
Without the doors, `language=plan` is refused (`this host takes no plans`). A plan typed ad hoc
runs at `urn:plan:eval` itself, under the caller's own capability: `urn:script:eval` points
there rather than being a second door onto it. `urn:script:eval` runs Lisp and only Lisp, so
its `urn:cap:lisp` floor is the language it runs, and its contract offers `language=lisp`
alone; a host without Lisp has no use for it and need not grant it.

⚠ **Tested against a test double.** The doors ship in `ikigai-engine` 0.1.44, which is not
published yet, so `tests/common/plan.rs` is a double honoring their contract (ledger #956, part
A). When it is published, the suite should run once against the real space too.

## Not in this version

- **PATCH** (edit in place) and **rollback** (re-pointing the head at an older version):
  republish the content instead.
- **Triggers** (startup, timers, tuplespace drops, thread cuts, ledger events, webhooks),
  **bindings** (a script as an endpoint, transreptor or overlay), the **stepper**, and
  **signed elevation**: later phases of the design.
- **A graph face for the script and its versions**: they are `text/plain` and
  `application/json` only (the catalog and run records have Turtle).
- **For SPARQL**: the SPARQL Protocol face over `urn:script:eval` (ledger #955; `eval` refuses
  `language=sparql` until then); list-valued parameters (an `IN (…)` or `VALUES` over several
  terms); an update whose graph is a parameter; `urn:sparql:*` as a door (its per-query space
  reads kernel resources under the caller's own authority, so there is no graph token to derive,
  and its shared-store space has one coarse update grant).
- **Piping into `…:result`**: its one input, `data`, is optional, so the engine has no
  required argument to route a pipe into. Pipe into `…:runs` (its `content`), or name
  `data=`.

## License

MIT OR Apache-2.0.
