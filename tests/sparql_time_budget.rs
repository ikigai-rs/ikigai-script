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
//!
//! ★ **A read through the store's door is stopped by whichever bound fires FIRST** (ledger
//! #1685). The answer's SIZE is bounded too (16 MiB, 100,000 rows; ledger #970), and a
//! streaming cross product reaches that bound as fast as the machine serializes: under
//! `cargo test --release` on plasma the first test here was refused for size, not time. So
//! every read that must meet the clock reads [`slow`], whose whole answer is under both size
//! bounds by construction, and whose rows are each made expensive instead; and every read
//! that must NOT meet the clock runs under a budget long enough that a starved machine cannot
//! reach it. What remains machine-dependent is stated where it is: the upper bounds on when a
//! refusal arrives (1.5 s of slack) and on when a worker ends.

mod common;

use std::time::{Duration, Instant};

use common::*;
use ikigai_core::{Error, Verb};
use ikigai_script::authority::{cap_budget, same_for_all, Ceiling};
use ikigai_script::sparql::SparqlDoor;
use ikigai_store::budget::{TimeBudget, DEFAULT_MAX_BYTES, DEFAULT_MAX_ROWS};
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

/// How many triples [`dense`] writes: every one a `<urn:p>` edge in [`G`].
const DENSE_TRIPLES: u64 = 120;

/// The most rows [`slow`] can answer: two `<urn:p>` patterns over the one graph.
const SLOW_ROWS: u64 = DENSE_TRIPLES * DENSE_TRIPLES;

/// An upper bound on one of [`slow`]'s rows as the store serializes it: one IRI and one
/// integer as a SPARQL JSON binding (`{"a":{"type":"uri","value":"urn:n59"},"n":{"type":
/// "literal","value":"1000014","datatype":"http://www.w3.org/2001/XMLSchema#integer"}},` is
/// 134 bytes). Checked by `the_slow_query_cannot_reach_a_size_bound`.
const SLOW_ROW_BYTES: u64 = 192;

// The slow query cannot reach a size bound, so a refusal of it is the clock's. The head and
// tail of an answer are a few dozen bytes; one row's worth is ample room for them.
const _: () = {
    assert!(SLOW_ROWS < DEFAULT_MAX_ROWS);
    assert!((SLOW_ROWS + 1) * SLOW_ROW_BYTES < DEFAULT_MAX_BYTES);
};

/// `head` (a `SELECT` naming at most `?a` and `?n`) over every pair of `<urn:p>` triples in
/// [`G`], binding `?n` to the length of a string grown from the pair: ten `x`s and the two
/// subjects, every `x` replaced by ten five times over, so a million characters a row of
/// which only the length is kept. The string depends on `?a` and `?b`, so the planner cannot
/// fold it into one constant. This is ikigai-store's own `common::slow` (ikigai-store PR 65),
/// scoped to the script's one graph; its literals are single-quoted so a Lisp string carries
/// it unescaped.
///
/// Measured on plasma (2026-10-16, through a script's `:result`): about 1.3 ms a row in a
/// release build and 24 ms in a debug one, so its 14,400 rows take about 19 s in release and
/// six minutes in debug. Finishing inside the largest budget a test gives it
/// ([`MAX_BUDGET_MS`]) would take a machine about sixty times faster than plasma's release
/// build, and it would fail as "not slow enough", never as another bound standing in for the
/// clock. The serializer checks the cancellation token between rows, so a timed-out read's
/// worker ends within one row.
fn slow(head: &str) -> String {
    let mut grown = "CONCAT(STR(?a), STR(?b), 'xxxxxxxxxx')".to_string();
    for _ in 0..5 {
        grown = format!("REPLACE({grown}, 'x', 'xxxxxxxxxx')");
    }
    format!(
        "{head} WHERE {{ GRAPH <{G}> {{ ?a <urn:p> ?x . ?b <urn:p> ?y . \
         BIND(STRLEN({grown}) AS ?n) }} }}"
    )
}

/// The largest budget a read of [`slow`] may run under and still meet the clock. See
/// [`slow`] for the margin it leaves.
const MAX_BUDGET_MS: u64 = 300;

/// A budget long enough that no test's ordinary work can reach it, however loaded the
/// machine: for the reads and writes that must NOT meet the clock.
const LONG_MS: u64 = 60_000;

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
    assert!(
        budget_ms <= MAX_BUDGET_MS,
        "{budget_ms} ms is past the {MAX_BUDGET_MS} ms that `slow` is sized for"
    );
    match result {
        Err(Error::Timeout(message)) => assert!(
            message.contains(&format!("{budget_ms} ms")),
            "the refusal names the store's budget: {message}"
        ),
        Ok(answer) => panic!(
            "an ANSWER of {} bytes: the slow query finished inside its {budget_ms} ms budget, \
             so this machine is fast enough that `slow` needs more rounds (ledger #1685)",
            answer.len()
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
        &slow("SELECT ?a ?n"),
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
    // The store's worker is told to stop and does, within a row of `slow` (tens of ms).
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
    // Four unconstrained patterns: 207 million rows to insert, well inside the store's algebra
    // bounds (32 join operands, 1024 operators). An update's answer is not size-bounded, so
    // only the clock can stop it, and no machine inserts that many rows inside 300 ms.
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
    // "Time to run" is a declared budget its runner holds, not the 300 ms base, so a loaded
    // machine cannot fail this half by the clock (ledger #1685).
    let long = LONG_MS.to_string();
    publish(
        &host.kernel,
        "copy",
        &format!(
            "INSERT {{ GRAPH <{G}> {{ ?s <urn:q> ?o }} }} WHERE {{ GRAPH <{G}> {{ ?s <urn:p> ?o }} }}"
        ),
        &[("language", "sparql"), ("budget", &long)],
    );
    call(
        &host.kernel,
        &cap(&[
            "urn:cap:script:run:copy",
            READ_G,
            WRITE_G,
            &cap_budget(LONG_MS),
        ]),
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

/// The control for the refusals above: a bounded script is answered through the same door.
/// Under a budget no loaded machine can reach (a starved runner refused by a 300 ms clock was
/// seen in the store's own suite, ledger #1685), so a refusal here is a real defect.
#[test]
fn a_bounded_script_answers_under_the_budget() {
    let (host, _store) = host(LONG_MS);
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

/// Why a refusal of [`slow`] is the clock's: its rows are few and small. The pattern it joins
/// matches at most [`DENSE_TRIPLES`] triples (so [`SLOW_ROWS`] bounds its rows, and the const
/// assertion puts that under both size bounds), and a row as the store serializes it is within
/// [`SLOW_ROW_BYTES`].
#[test]
fn the_slow_query_cannot_reach_a_size_bound() {
    let (host, _store) = host(LONG_MS);
    let count = ok(
        &host.kernel,
        Verb::Source,
        "urn:iki:store:select",
        &[(
            "query",
            &format!("SELECT (COUNT(*) AS ?n) WHERE {{ GRAPH <{G}> {{ ?a <urn:p> ?x }} }}"),
        )],
    );
    let at = count.find("\"value\":\"").expect("a count") + 9;
    let matches: u64 = count[at..].split('"').next().unwrap().parse().unwrap();
    assert!(
        matches <= DENSE_TRIPLES,
        "{matches} matches: SLOW_ROWS no longer bounds the slow query's rows"
    );
    // Two rows through a script's `:result`, the door the tests above read (the answer
    // includes the head and tail).
    publish(
        &host.kernel,
        "two-rows",
        &format!("{} LIMIT 2", slow("SELECT ?a ?n")),
        &[("language", "sparql")],
    );
    let start = Instant::now();
    let answer = call(
        &host.kernel,
        &cap(&["urn:cap:script:run:two-rows", READ_G]),
        Verb::Source,
        "urn:script:two-rows:result",
        &[],
    )
    .expect("two rows of the slow query, under a long budget");
    eprintln!(
        "two rows of `slow` in {:?}, {} bytes",
        start.elapsed(),
        answer.len()
    );
    assert!(answer.contains("10000"), "{answer}");
    assert!(
        (answer.len() as u64) < 3 * SLOW_ROW_BYTES,
        "{} bytes for two rows: {answer}",
        answer.len()
    );
}

// ---------------------------------------------------------------------------------------
// A declared budget (ledger #1384)
// ---------------------------------------------------------------------------------------
//
// These hosts' base is 100 ms, so a declaration can lift a run above it and still stay within
// the [`MAX_BUDGET_MS`] that `slow` is sized for: declared 300, a smaller grant of 200, and the
// base. (They declared 900 over a 300 ms base before ledger #1685, which `slow` would meet
// with a third of its margin.)

/// The base of the hosts below: what a run carrying no budget grant gets.
const BASE: u64 = 100;
const BUDGET_300: &str = "urn:cap:store:budget:300";

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
    // worker stops is the first test's assertion; this bound is generous rather than a second
    // claim about the store.
    let stopped = settles(store, Duration::from_secs(60));
    eprintln!("  worker stopped {stopped:?} after the answer");
}

#[test]
fn a_declared_budget_reaches_a_runner_who_holds_it_and_no_further() {
    let (host, store) = host(BASE);
    publish(
        &host.kernel,
        "long",
        &slow("SELECT ?a ?n"),
        &[("language", "sparql"), ("budget", "300")],
    );
    // Declared 300, held by the runner: 300.
    times_out_at(
        &host,
        &store,
        &["urn:cap:script:run:long", READ_G, BUDGET_300],
        "long",
        300,
    );
    // A runner holding MORE than the script declares gets what it declares, not more: the
    // run carries the runner's grant and asks the store for `budget=300`.
    times_out_at(
        &host,
        &store,
        &[
            "urn:cap:script:run:long",
            READ_G,
            "urn:cap:store:budget:60000",
        ],
        "long",
        300,
    );
    // A runner holding LESS gets its own.
    times_out_at(
        &host,
        &store,
        &[
            "urn:cap:script:run:long",
            READ_G,
            "urn:cap:store:budget:200",
        ],
        "long",
        200,
    );
    // The same script, run by a runner holding no budget grant: the store's base.
    times_out_at(
        &host,
        &store,
        &["urn:cap:script:run:long", READ_G],
        "long",
        BASE,
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
        300,
    );
    assert!(start.elapsed() < Duration::from_millis(300 + 1500));
    settles(&store, Duration::from_secs(60));
}

#[test]
fn a_script_declaring_nothing_never_carries_its_runners_budget() {
    let (host, store) = host(BASE);
    publish(
        &host.kernel,
        "plain",
        &slow("SELECT ?a ?n"),
        &[("language", "sparql")],
    );
    // The runner holds 300; the script declared nothing, so the run gets the base.
    times_out_at(
        &host,
        &store,
        &["urn:cap:script:run:plain", READ_G, BUDGET_300],
        "plain",
        BASE,
    );
    // The recorded capability of a run says so: no budget grant rode along.
    let runner = cap(&["urn:cap:script:run:plain", READ_G, BUDGET_300]);
    let failed = call(
        &host.kernel,
        &runner,
        Verb::Sink,
        "urn:script:plain:runs",
        &[],
    );
    assert!(
        matches!(&failed, Err(Error::Timeout(m)) if m.contains(&format!("{BASE} ms"))),
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
    // Nothing here runs, so no number below meets the clock.
    let (host, _store) = host(300);
    let source = slow("SELECT ?a ?n");
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
    let (host, store) = host(BASE);
    let program = format!(
        "(invoke 'source \"urn:iki:store:graph-select\" \"query\" \"{}\" \"graph\" \"{G}\")",
        slow("SELECT ?a ?n")
    );
    publish(
        &host.kernel,
        "lisp-long",
        &program,
        &[("requires", READ_G), ("budget", "300")],
    );
    let runner = cap(&[
        "urn:cap:script:run:lisp-long",
        "urn:cap:lisp",
        READ_G,
        BUDGET_300,
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
        result.is_err() && message.contains("300 ms"),
        "the store's refusal names the declared budget: {message}"
    );
    assert!(
        waited >= Duration::from_millis(300) && waited < Duration::from_millis(300 + 1500),
        "{waited:?}"
    );
    settles(&store, Duration::from_secs(60));
    // ⚠ The limit, pinned: a Lisp script's store requests are its own and carry no
    // `budget=`, and attenuation keeps grants by exact name, so a runner holding only a
    // LARGER grant cannot be narrowed to 300. The run carries no grant and gets the base:
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
    assert!(
        format!("{result:?}").contains(&format!("{BASE} ms")),
        "{result:?}"
    );
    settles(&store, Duration::from_secs(60));
}
