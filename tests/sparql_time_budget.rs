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
