//! A SPARQL script that would run for hours is answered at the STORE's time budget, because
//! this crate never evaluates SPARQL itself (ledger #1344).
//!
//! The claim: ikigai-script "builds its own evaluator" outside the store's doors, so a
//! caller-influenced query there is bounded by stack only, never by time. **It does not hold
//! here.** The library links no evaluator (its normal dependency graph has `spargebra` for
//! parsing and no `spareval`, `sparopt`, `oxigraph` or `ikigai-store`), and every run of a
//! SPARQL script, query or update, is a sub-request to the host's graph-scoped store door
//! (`SparqlDoor`), which bounds the algebra before planning and answers at its time budget
//! (ikigai-store 0.2.8, ledger #964). The script's text is the publisher's and its parameters
//! the caller's, so the query IS caller-influenced, and these tests pin that the bound reaches
//! it through the door: a typed `Timeout` naming the budget, at the budget, with the store's
//! worker stopped soon after.
//!
//! A script may also DECLARE a budget (`budget=<ms>` at publish, ledger #1384), bounded like
//! the rest of its authority: refused at publish above what its publisher holds, and at run
//! time the least of the declaration, the publisher's value at publish, the host's ceiling and
//! the runner's own grant. A script declaring nothing gets the base whatever its runner holds.

mod common;

use std::time::{Duration, Instant};

use common::*;
use ikigai_core::{Error, Verb};
use ikigai_script::authority::{same_for_all, Ceiling};
use ikigai_script::sparql::SparqlDoor;
use ikigai_store::budget::TimeBudget;
use ikigai_store::DurableStore;

const G: &str = "urn:test:dense";
const READ_G: &str = "urn:cap:store:read:graph:urn:test:dense";
const WRITE_G: &str = "urn:cap:store:write:graph:urn:test:dense";

/// The store's own test graph: 60 nodes, two `<urn:p>` edges each, so a cross product of `n`
/// unconstrained patterns over it is 120^n rows.
fn dense() -> String {
    let mut triples = String::new();
    for i in 0..60usize {
        for j in [i + 1, i * 7 + 3] {
            triples.push_str(&format!("<urn:n{i}> <urn:p> <urn:n{}> . ", j % 60));
        }
    }
    format!("INSERT DATA {{ GRAPH <{G}> {{ {triples} }} }}")
}

/// Four unconstrained patterns in the script's one graph: 207 million rows, well inside the
/// store's algebra bounds (32 join operands, 1024 operators), so only the deadline stops it.
fn cross(head: &str) -> String {
    let patterns: String = (0..4).map(|i| format!("?s{i} ?p{i} ?o{i} . ")).collect();
    format!("{head} WHERE {{ GRAPH <{G}> {{ {patterns} }} }}")
}

/// The same cross product, answering NO rows: a filter over all four patterns, so the planner
/// cannot push it below the join. A budget above the base gives a streaming `SELECT *` time
/// to fill the store's 16 MiB answer bound first (seen at 900 ms on a 1.89 build), and that
/// refusal would race the deadline; with nothing to serialize, only the deadline can stop
/// this one. The literal is single-quoted so a Lisp string carries the query unescaped.
fn silent() -> String {
    let patterns: String = (0..4).map(|i| format!("?s{i} ?p{i} ?o{i} . ")).collect();
    format!(
        "SELECT ?s0 WHERE {{ GRAPH <{G}> {{ {patterns}\
         FILTER(CONCAT(STR(?o0), STR(?o1), STR(?o2), STR(?o3)) = 'never') }} }}"
    )
}

fn host(budget_ms: u64) -> (SparqlHost, DurableStore) {
    let store = DurableStore::in_memory()
        .expect("a store")
        .with_time_budget(TimeBudget::new(Duration::from_millis(budget_ms)));
    let host = sparql_host_on(
        SparqlDoor::store(),
        same_for_all(Ceiling::unbounded()),
        store.clone(),
    );
    seed(&host.kernel, &dense());
    (host, store)
}

fn assert_timeout(result: std::result::Result<String, Error>, budget_ms: u64) {
    match result {
        Err(Error::Timeout(message)) => assert!(
            message.contains(&format!("{budget_ms} ms")),
            "the refusal names the store's budget: {message}"
        ),
        other => panic!("expected a Timeout naming {budget_ms} ms, got {other:?}"),
    }
}

/// Wait (bounded) for the store's overdue evaluations to end.
fn settles(store: &DurableStore, within: Duration) -> Duration {
    let start = Instant::now();
    while store.overdue_evaluations() != 0 {
        assert!(
            start.elapsed() < within,
            "{} evaluation(s) still overdue after {within:?}",
            store.overdue_evaluations()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    start.elapsed()
}

#[test]
fn a_query_script_that_would_run_for_hours_is_answered_at_the_stores_budget() {
    let (host, store) = host(300);
    publish(
        &host.kernel,
        "hours",
        &cross("SELECT *"),
        &[("language", "sparql")],
    );
    // A runner holding exactly what the script needs, and no store budget grant: the base.
    let runner = cap(&["urn:cap:script:run:hours", READ_G]);
    let start = Instant::now();
    assert_timeout(
        call(
            &host.kernel,
            &runner,
            Verb::Source,
            "urn:script:hours:result",
            &[],
        ),
        300,
    );
    let waited = start.elapsed();
    assert!(
        waited >= Duration::from_millis(300),
        "answered before the budget: {waited:?}"
    );
    assert!(
        waited < Duration::from_millis(300 + 1500),
        "answered late: {waited:?}"
    );
    assert_eq!(host.queries(), 1, "the run went to the store's door");
    // The store's worker is told to stop and does.
    let stopped = settles(&store, Duration::from_secs(5));
    assert!(stopped < Duration::from_secs(2), "{stopped:?}");
    // A refusal is never cached: the next read evaluates again, and is refused again.
    assert_timeout(
        call(
            &host.kernel,
            &runner,
            Verb::Source,
            "urn:script:hours:result",
            &[],
        ),
        300,
    );
    assert_eq!(host.queries(), 2);
    settles(&store, Duration::from_secs(5));
}

#[test]
fn an_update_script_that_runs_out_of_time_is_answered_at_the_budget_and_writes_nothing() {
    let (host, store) = host(300);
    let update = format!(
        "INSERT {{ GRAPH <{G}> {{ ?s0 <urn:q> ?o3 }} }} WHERE {{ GRAPH <{G}> {{ {} }} }}",
        (0..4)
            .map(|i| format!("?s{i} ?p{i} ?o{i} . "))
            .collect::<String>()
    );
    publish(&host.kernel, "grind", &update, &[("language", "sparql")]);
    let runner = cap(&["urn:cap:script:run:grind", READ_G, WRITE_G]);
    let start = Instant::now();
    let result = call(
        &host.kernel,
        &runner,
        Verb::Sink,
        "urn:script:grind:runs",
        &[],
    );
    let waited = start.elapsed();
    assert!(
        matches!(&result, Err(Error::Timeout(m)) if m.contains("300 ms")),
        "{result:?}"
    );
    assert!(
        waited < Duration::from_millis(300 + 1500),
        "answered late: {waited:?}"
    );
    // The store documents that an update's worker may run on past the budget (its in-memory
    // join ignores the cancellation token) but never commits once abandoned. Wait for it,
    // as the store's own test does, then look.
    settles(&store, Duration::from_secs(120));
    assert!(!copied(&host), "a timed-out update script wrote");
    // The same kind of script with time to run does write, so the assertion is not vacuous.
    publish(
        &host.kernel,
        "copy",
        &format!(
            "INSERT {{ GRAPH <{G}> {{ ?s <urn:q> ?o }} }} WHERE {{ GRAPH <{G}> {{ ?s <urn:p> ?o }} }}"
        ),
        &[("language", "sparql")],
    );
    call(
        &host.kernel,
        &cap(&["urn:cap:script:run:copy", READ_G, WRITE_G]),
        Verb::Sink,
        "urn:script:copy:runs",
        &[],
    )
    .expect("a bounded update runs");
    assert!(copied(&host), "the bounded update wrote");
}

/// Whether any `<urn:q>` edge exists (read by the host, as root).
fn copied(host: &SparqlHost) -> bool {
    ok(
        &host.kernel,
        Verb::Source,
        "urn:iki:store:select",
        &[("query", "ASK { GRAPH ?g { ?s <urn:q> ?o } }")],
    )
    .contains("true")
}

#[test]
fn a_bounded_script_answers_under_the_budget() {
    let (host, _store) = host(300);
    publish(
        &host.kernel,
        "two-hops",
        &format!("SELECT ?o WHERE {{ GRAPH <{G}> {{ <urn:n0> <urn:p>/<urn:p> ?o }} }} ORDER BY ?o"),
        &[("language", "sparql")],
    );
    let out = call(
        &host.kernel,
        &cap(&["urn:cap:script:run:two-hops", READ_G]),
        Verb::Source,
        "urn:script:two-hops:result",
        &[],
    )
    .expect("a bounded query answers");
    assert!(out.contains("urn:n2"), "{out}");
}

// ---------------------------------------------------------------------------------------
// A declared budget (ledger #1384)
// ---------------------------------------------------------------------------------------

const BUDGET_900: &str = "urn:cap:store:budget:900";

/// Run `name`'s result under `runner` and answer how long the refusal took, asserting it is
/// a Timeout naming `budget_ms` and arrived at that budget.
fn times_out_at(
    host: &SparqlHost,
    store: &DurableStore,
    runner: &[&str],
    name: &str,
    budget_ms: u64,
) {
    let start = Instant::now();
    assert_timeout(
        call(
            &host.kernel,
            &cap(runner),
            Verb::Source,
            &format!("urn:script:{name}:result"),
            &[],
        ),
        budget_ms,
    );
    let waited = start.elapsed();
    eprintln!("{name} under {runner:?}: Timeout naming {budget_ms} ms after {waited:?}");
    assert!(
        waited >= Duration::from_millis(budget_ms),
        "answered before the {budget_ms} ms budget: {waited:?}"
    );
    assert!(
        waited < Duration::from_millis(budget_ms + 1500),
        "answered late for {budget_ms} ms: {waited:?}"
    );
    // Waited out so the next run is not refused for overdue evaluations. How PROMPTLY the
    // worker stops is the first test's assertion, over a streaming query; this filtered one
    // checks its cancellation less often (measured 2.3-2.9 s here, debug build), so the bound
    // is generous rather than a second claim about the store.
    let stopped = settles(store, Duration::from_secs(60));
    eprintln!("  worker stopped {stopped:?} after the answer");
}

#[test]
fn a_declared_budget_reaches_a_runner_who_holds_it_and_no_further() {
    let (host, store) = host(300);
    publish(
        &host.kernel,
        "long",
        &silent(),
        &[("language", "sparql"), ("budget", "900")],
    );
    // Declared 900, held by the runner: 900.
    times_out_at(
        &host,
        &store,
        &["urn:cap:script:run:long", READ_G, BUDGET_900],
        "long",
        900,
    );
    // A runner holding MORE than the script declares gets what it declares, not more: the
    // run carries the runner's grant and asks the store for `budget=900`.
    times_out_at(
        &host,
        &store,
        &[
            "urn:cap:script:run:long",
            READ_G,
            "urn:cap:store:budget:60000",
        ],
        "long",
        900,
    );
    // A runner holding LESS gets its own.
    times_out_at(
        &host,
        &store,
        &[
            "urn:cap:script:run:long",
            READ_G,
            "urn:cap:store:budget:600",
        ],
        "long",
        600,
    );
    // The same script, run by a runner holding no budget grant: the store's base.
    times_out_at(
        &host,
        &store,
        &["urn:cap:script:run:long", READ_G],
        "long",
        300,
    );
    // Root holds the store's ceiling, so a root run gets what the script declares.
    let start = Instant::now();
    assert_timeout(
        call(
            &host.kernel,
            &ikigai_core::Capability::root(),
            Verb::Source,
            "urn:script:long:result",
            &[],
        ),
        900,
    );
    assert!(start.elapsed() < Duration::from_millis(900 + 1500));
    settles(&store, Duration::from_secs(60));
}

#[test]
fn a_script_declaring_nothing_never_carries_its_runners_budget() {
    let (host, store) = host(300);
    publish(&host.kernel, "plain", &silent(), &[("language", "sparql")]);
    // The runner holds 900; the script declared nothing, so the run gets the base.
    times_out_at(
        &host,
        &store,
        &["urn:cap:script:run:plain", READ_G, BUDGET_900],
        "plain",
        300,
    );
    // The recorded capability of a run says so: no budget grant rode along.
    let runner = cap(&["urn:cap:script:run:plain", READ_G, BUDGET_900]);
    let failed = call(
        &host.kernel,
        &runner,
        Verb::Sink,
        "urn:script:plain:runs",
        &[],
    );
    assert!(
        matches!(&failed, Err(Error::Timeout(m)) if m.contains("300 ms")),
        "{failed:?}"
    );
    settles(&store, Duration::from_secs(60));
    let record = ok(
        &host.kernel,
        Verb::Source,
        "urn:script:plain:run:1",
        &[("as", "application/json")],
    );
    assert!(!record.contains("urn:cap:store:budget:"), "{record}");
}

#[test]
fn a_publish_declaring_more_than_its_publisher_holds_is_refused_naming_both() {
    let (host, _store) = host(300);
    let source = silent();
    let publisher = cap(&[
        "urn:cap:script:write:greedy",
        READ_G,
        "urn:cap:store:budget:500",
    ]);
    let args = [
        ("content", source.as_str()),
        ("language", "sparql"),
        ("budget", "900"),
    ];
    let message = denied(call(
        &host.kernel,
        &publisher,
        Verb::Sink,
        "urn:script:greedy",
        &args,
    ));
    assert!(
        message.contains("budget=900 ms") && message.contains("500 ms"),
        "the refusal names both values: {message}"
    );
    // Holding no budget grant at all is holding the base, and is refused the same way.
    let message = denied(call(
        &host.kernel,
        &cap(&["urn:cap:script:write:greedy", READ_G]),
        Verb::Sink,
        "urn:script:greedy",
        &args,
    ));
    assert!(message.contains("budget=900 ms"), "{message}");
    // Nothing was written.
    assert!(call(
        &host.kernel,
        &ikigai_core::Capability::root(),
        Verb::Source,
        "urn:script:greedy",
        &[]
    )
    .is_err());
    // Within what the publisher holds, it is admitted, and the head keeps what they held.
    let within = [
        ("content", source.as_str()),
        ("language", "sparql"),
        ("budget", "400"),
    ];
    call(
        &host.kernel,
        &publisher,
        Verb::Sink,
        "urn:script:greedy",
        &within,
    )
    .expect("a budget the publisher holds is admitted");
    let head = ok(
        &host.kernel,
        Verb::Source,
        "urn:script:greedy",
        &[("as", "application/json")],
    );
    let head: serde_json::Value = serde_json::from_str(&head).expect("the head as JSON");
    assert_eq!(head["budget"], 400, "the version declares it: {head}");
    assert_eq!(
        head["granted_budget"], 500,
        "the head keeps what the publisher held: {head}"
    );
}

#[test]
fn a_lisp_script_carries_its_declared_budget_to_the_store() {
    let (host, store) = host(300);
    let program = format!(
        "(invoke 'source \"urn:iki:store:graph-select\" \"query\" \"{}\" \"graph\" \"{G}\")",
        silent()
    );
    publish(
        &host.kernel,
        "lisp-long",
        &program,
        &[("requires", READ_G), ("budget", "900")],
    );
    let runner = cap(&[
        "urn:cap:script:run:lisp-long",
        "urn:cap:lisp",
        READ_G,
        BUDGET_900,
    ]);
    let start = Instant::now();
    let result = call(
        &host.kernel,
        &runner,
        Verb::Source,
        "urn:script:lisp-long:result",
        &[],
    );
    let waited = start.elapsed();
    let message = format!("{result:?}");
    assert!(
        result.is_err() && message.contains("900 ms"),
        "the store's refusal names the declared budget: {message}"
    );
    assert!(
        waited >= Duration::from_millis(900) && waited < Duration::from_millis(900 + 1500),
        "{waited:?}"
    );
    settles(&store, Duration::from_secs(60));
    // ⚠ The limit, pinned: a Lisp script's store requests are its own and carry no
    // `budget=`, and attenuation keeps grants by exact name, so a runner holding only a
    // LARGER grant cannot be narrowed to 900. The run carries no grant and gets the base:
    // less than declared, never more (`authority::budget_grant`).
    let larger = cap(&[
        "urn:cap:script:run:lisp-long",
        "urn:cap:lisp",
        READ_G,
        "urn:cap:store:budget:60000",
    ]);
    let result = call(
        &host.kernel,
        &larger,
        Verb::Source,
        "urn:script:lisp-long:result",
        &[],
    );
    assert!(format!("{result:?}").contains("300 ms"), "{result:?}");
    settles(&store, Duration::from_secs(60));
}
