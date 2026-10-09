//! The module recipe as one test: `ikigai-conformance` walks every resource this crate
//! binds and reports every violation at once.
//!
//! # The fixture
//!
//! The walk fires the mutating actions it checks, under root, so the kernel holds scripts
//! for it to act on, each chosen so one action cannot spoil another's fixture:
//!
//! - **`walk`** is what the reads and the runs point at. It is never retired.
//! - **`retiree`** exists so the script's Delete (retire) has something to retire that
//!   nothing else reads.
//! - **`published`** receives the walk's publish (the script's Sink).
//!
//! # What the suite cannot say, and this file says instead
//!
//! - **The version and run reads are `pure`.** A version is named by its content and a
//!   finished run never changes, so neither has a thread but its own name, and nothing
//!   writes through those names. That is what "pure" means to the suite.
//! - **`script-result` is neither declared cacheable nor live**: it is exactly as
//!   cacheable as the script it runs (the fixture's `(+ 1 2)` is not), and
//!   `tests/lifecycle.rs` covers both polarities.
//! - **`script-catalog` is live**: a failed run is recorded without a write through any
//!   name the catalog could hang from.
//! - **`urn:lisp:eval` is in this kernel** because a run composes over it; it is
//!   `ikigai-lisp`'s to conform, and its own suite does.

mod common;

use common::*;
use ikigai_conformance::{Fixture, Suite};
use ikigai_core::Verb;

fn seeded() -> (Host, String) {
    let host = host();
    let version = publish(&host.kernel, "walk", "(+ 1 2)", &[]);
    publish(&host.kernel, "retiree", "1", &[]);
    ok(&host.kernel, Verb::Sink, "urn:script:walk:runs", &[]);
    let digest = version
        .rsplit(":version:")
        .next()
        .expect("a version IRI")
        .to_string();
    (host, digest)
}

fn suite(digest: &str) -> Suite {
    Suite::new()
        .opt_out(
            "eval",
            None,
            "ikigai-lisp's own conformance suite covers it; it is bound here only because \
             every run composes over it",
        )
        .opt_out("whoami", None, "a test probe, not part of this crate")
        .opt_out("vault", None, "a test probe, not part of this crate")
        .fixture(Fixture::new("script", Verb::Source).binding("name", "walk"))
        .fixture(Fixture::new("script", Verb::Exists).binding("name", "walk"))
        .fixture(
            Fixture::new("script", Verb::Sink)
                .binding("name", "published")
                .arg("content", "(+ 2 2)"),
        )
        .fixture(Fixture::new("script", Verb::Delete).binding("name", "retiree"))
        .fixture(
            Fixture::new("script-version", Verb::Source)
                .binding("name", "walk")
                .binding("digest", digest),
        )
        .fixture(
            Fixture::new("script-version", Verb::Exists)
                .binding("name", "walk")
                .binding("digest", digest),
        )
        .fixture(Fixture::new("script-compiled", Verb::Source).binding("name", "walk"))
        .fixture(Fixture::new("script-result", Verb::Source).binding("name", "walk"))
        .fixture(Fixture::new("script-runs", Verb::Sink).binding("name", "walk"))
        .fixture(
            Fixture::new("script-run", Verb::Source)
                .binding("name", "walk")
                .binding("id", "1"),
        )
        .fixture(
            Fixture::new("script-run", Verb::Exists)
                .binding("name", "walk")
                .binding("id", "1"),
        )
        .fixture(Fixture::new("script-eval", Verb::Sink).arg("content", "(+ 1 2)"))
        .cacheable("script")
        .cacheable("script-compiled")
        .pure("script-version")
        .pure("script-run")
        .live("script-catalog")
}

#[test]
fn conforms() {
    let (host, digest) = seeded();
    let report = suite(&digest).run_blocking(&host.kernel);
    println!("{report}");
    assert!(report.is_clean(), "{report}");
}

/// ★ The positive half: a clean report over a walk that reached nothing would look
/// exactly like a clean report over a walk that reached everything. This pins the list.
#[test]
fn the_walk_reaches_every_resource_this_crate_binds() {
    let (host, digest) = seeded();
    let report = suite(&digest).run_blocking(&host.kernel);
    let mut walked: Vec<&str> = report
        .walked
        .iter()
        .map(String::as_str)
        .filter(|id| id.starts_with("script"))
        .collect();
    walked.sort_unstable();
    assert_eq!(
        walked,
        vec![
            "script",
            "script-catalog",
            "script-compiled",
            "script-eval",
            "script-result",
            "script-run",
            "script-runs",
            "script-version",
        ],
        "{report}"
    );
}

// ---------------------------------------------------------------------------------------
// The same walk over a host with a SPARQL door, where each published query is its own
// entry: the per-script `…:result` and `…:runs` must conform like any endpoint.
// ---------------------------------------------------------------------------------------

const STORE_IDS: [&str; 13] = [
    "store-select",
    "store-graph-select",
    "store-ask",
    "store-graph-ask",
    "store-construct",
    "store-graph-construct",
    "store-describe",
    "store-graph-describe",
    "store-info",
    "store-graphs",
    "store-update",
    "store-graph-update",
    "store-load",
];

fn sparql_seeded() -> (SparqlHost, String) {
    let host = sparql_host();
    seed(
        &host.kernel,
        "INSERT DATA { GRAPH <urn:test:g> { <urn:item:1> <urn:p:age> 10 } }",
    );
    let version = publish(&host.kernel, "walk", "(+ 1 2)", &[]);
    publish(&host.kernel, "retiree", "1", &[]);
    ok(&host.kernel, Verb::Sink, "urn:script:walk:runs", &[]);
    publish(
        &host.kernel,
        "walkq",
        "# The walk's query.\n# @param days xsd:integer -- older than this\n\
         SELECT ?item WHERE { GRAPH <urn:test:g> { ?item <urn:p:age> ?age FILTER(?age > ?days) } }",
        &[("language", "sparql")],
    );
    publish(
        &host.kernel,
        "walku",
        "# @param age xsd:integer\n\
         INSERT { GRAPH <urn:test:g> { ?item <urn:p:age> ?age } } WHERE { GRAPH <urn:test:g> { ?item <urn:p:age> ?old } }",
        &[("language", "sparql")],
    );
    let digest = version
        .rsplit(":version:")
        .next()
        .expect("a version IRI")
        .to_string();
    (host, digest)
}

fn sparql_suite(digest: &str) -> Suite {
    STORE_IDS
        .iter()
        .fold(suite(digest), |suite, id| {
            suite.opt_out(
                *id,
                None,
                "ikigai-store's own conformance suite covers it; it is bound here because \
                 every SPARQL run composes over it",
            )
        })
        .fixture(Fixture::new("script-walkq-result", Verb::Source).arg("days", "1"))
        // A SPARQL run's piped `content` is its parameters as one JSON object.
        .fixture(
            Fixture::new("script-walkq-runs", Verb::Sink)
                .arg("days", "1")
                .arg("content", "{}"),
        )
        .fixture(
            Fixture::new("script-walku-runs", Verb::Sink)
                .arg("age", "11")
                .arg("content", "{}"),
        )
}

#[test]
fn a_host_with_sparql_scripts_conforms() {
    let (host, digest) = sparql_seeded();
    let report = sparql_suite(&digest).run_blocking(&host.kernel);
    println!("{report}");
    assert!(report.is_clean(), "{report}");
    let mut walked: Vec<&str> = report
        .walked
        .iter()
        .map(String::as_str)
        .filter(|id| id.starts_with("script-walk"))
        .collect();
    walked.sort_unstable();
    assert_eq!(
        walked,
        vec![
            "script-walkq-result",
            "script-walkq-runs",
            "script-walku-runs"
        ],
        "{report}"
    );
}
