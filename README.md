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

A published SPARQL query is also its OWN entry in the host's catalog: `urn:script:{name}:result`
and `…:runs` with the query's declared parameters as their arguments (see "Queries as scripts").

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
- **Running is a write.** `…:runs` records a run atom (who, as the host stamped it; which
  version; under exactly what capability; when; the outcome; the trace span when the host
  traced) and answers its IRI. A failed run is recorded too, and its error keeps its type
  and names the record.
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

**Evaluating code is itself authority.** Every Lisp script declares `urn:cap:lisp`
implicitly, so its publisher must hold it, its host ceiling must allow it, and its runner
must hold it. See "What the host must supply" for what that means for anonymous runs.

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
    .principal(Arc::new(|_inv| /* what your door authenticated */ "urn:example:me".into()))
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
- **The principal**, a function of the invocation (what the host's door authenticated),
  recorded on every publish and run. Never an argument: a caller cannot name itself. The
  default records `urn:script:principal:unstamped`.
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
the default graph are refused. The text is checked against the store's bound
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

## Not in this version

- **PATCH** (edit in place) and **rollback** (re-pointing the head at an older version):
  republish the content instead.
- **Triggers** (startup, timers, tuplespace drops, thread cuts, ledger events, webhooks),
  **bindings** (a script as an endpoint, transreptor or overlay), the **stepper**, and
  **signed elevation**: later phases of the design.
- **Draft privacy**: a draft is readable by any holder of the script's read grant, not
  only its author.
- **A Turtle face**: every record is `text/plain` and `application/json`.
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
