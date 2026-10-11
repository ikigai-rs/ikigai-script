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
//! - **`space(config)` is HOST-named** (`SPACE-NAME`, ledger #987): its doors are fixed,
//!   but what they answer is the backend, ceiling and SPARQL door it was handed, and every
//!   published SPARQL script or plan adds entries of its own. A name is a cache claim (same
//!   name, same doors), and only the host knows which instance it passed in, so the crate
//!   claims none and the suite holds it to that: the space the kernel binds is the value
//!   declared here.

mod common;

use std::sync::Arc;

use common::*;
use ikigai_conformance::{Fixture, Suite};
use ikigai_core::Verb;
use ikigai_script::ScriptSpace;

/// What findings name `space(config)` by, and the report line that says it was checked.
const SPACE_LABEL: &str = "ikigai_script::space(config)";

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

fn suite(digest: &str, space: &Arc<ScriptSpace>) -> Suite {
    Suite::new()
        .host_named_space(SPACE_LABEL, Arc::clone(space))
        .opt_out(
            "eval",
            None,
            "ikigai-lisp's own conformance suite covers it; it is bound here only because \
             every run composes over it",
        )
        .opt_out("whoami", None, "a test probe, not part of this crate")
        .opt_out("vault", None, "a test probe, not part of this crate")
        .opt_out("fallback", None, "a test probe, not part of this crate")
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
    let report = suite(&digest, &host.space).run_blocking(&host.kernel);
    println!("{report}");
    assert!(report.is_clean(), "{report}");
    // The positive half of SPACE-NAME: the declaration reached the check, and the space
    // the kernel binds claims no name.
    assert!(
        report
            .to_string()
            .contains(&format!("space: {SPACE_LABEL} host-named\n")),
        "{report}"
    );
}

/// ★ The positive half: a clean report over a walk that reached nothing would look
/// exactly like a clean report over a walk that reached everything. This pins the list.
#[test]
fn the_walk_reaches_every_resource_this_crate_binds() {
    let (host, digest) = seeded();
    let report = suite(&digest, &host.space).run_blocking(&host.kernel);
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

fn sparql_suite(digest: &str, space: &Arc<ScriptSpace>) -> Suite {
    STORE_IDS
        .iter()
        .fold(suite(digest, space), |suite, id| {
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
    let report = sparql_suite(&digest, &host.space).run_blocking(&host.kernel);
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

// ---------------------------------------------------------------------------------------
// The same walk over a host with the plan doors (the test double of part A's contract,
// `tests/common/plan.rs`, and the engine's real ones), where each published plan is its own
// entry.
// ---------------------------------------------------------------------------------------

const PLAN_READ: &str = r#"# The walk's read plan.
@prefix ik: <https://ikigai-rs.dev/ns#> .
<urn:plan:walkp> a ik:Process ;
    ik:input <urn:plan:walkp:input:who> ;
    ik:step <urn:plan:walkp:step:1> ;
    ik:result <urn:plan:walkp:step:1> .
<urn:plan:walkp:input:who> ik:inputName "who" ; ik:required false ; ik:default "walk" .
<urn:plan:walkp:step:1> a ik:Step ; ik:verb "Source" ; ik:resolves <urn:test:greet> ;
    ik:argument <urn:plan:walkp:step:1:arg:who> .
<urn:plan:walkp:step:1:arg:who> a ik:Argument ; ik:inputName "who" ;
    ik:ref <urn:plan:walkp:var:who> .
"#;

const PLAN_WRITE: &str = r#"@prefix ik: <https://ikigai-rs.dev/ns#> .
<urn:plan:walkw> a ik:Process ;
    ik:step <urn:plan:walkw:step:1> ;
    ik:result <urn:plan:walkw:step:1> .
<urn:plan:walkw:step:1> a ik:Step ; ik:verb "Sink" ; ik:resolves <urn:test:vault> .
"#;

fn plan_seeded(doors: Doors) -> (PlanHost, String) {
    let host = plan_host_of(doors);
    let version = publish(&host.kernel, "walk", "(+ 1 2)", &[]);
    publish(&host.kernel, "retiree", "1", &[]);
    ok(&host.kernel, Verb::Sink, "urn:script:walk:runs", &[]);
    publish(&host.kernel, "walkp", PLAN_READ, &[("language", "plan")]);
    publish(&host.kernel, "walkw", PLAN_WRITE, &[("language", "plan")]);
    let digest = version
        .rsplit(":version:")
        .next()
        .expect("a version IRI")
        .to_string();
    (host, digest)
}

fn plan_suite(doors: Doors, digest: &str, space: &Arc<ScriptSpace>) -> Suite {
    let which = match doors {
        Doors::Double => "here a test double of its contract",
        Doors::Engine => "here ikigai-engine's, conformance-tested in ikigai-cli",
    };
    let mut doors_and_probes = vec![
        ("plan-eval", format!("the host's plan evaluator ({which})")),
        (
            "plan-validate",
            format!("the host's plan validator ({which})"),
        ),
        ("plan-requires", format!("the host's derivation ({which})")),
        ("greet", "a test probe, not part of this crate".to_string()),
        ("host", "a test probe, not part of this crate".to_string()),
        ("held", "a test probe, not part of this crate".to_string()),
    ];
    if doors == Doors::Engine {
        doors_and_probes.push((
            "shacl-validate",
            "ikigai-shacl's validator, which the engine's plan doors compose; conformance-tested \
             in ikigai-shacl"
                .to_string(),
        ));
    }
    doors_and_probes
        .into_iter()
        .fold(suite(digest, space), |suite, (id, why)| {
            suite.opt_out(id, None, &why)
        })
        .fixture(Fixture::new("script-walkp-result", Verb::Source).arg("who", "conformance"))
        // A plan run's piped `content` is its parameters as one JSON object.
        .fixture(Fixture::new("script-walkp-runs", Verb::Sink).arg("content", "{}"))
        .fixture(Fixture::new("script-walkw-runs", Verb::Sink).arg("content", "{}"))
}

#[test]
fn a_host_with_plan_scripts_conforms() {
    both(|doors| {
        let (host, digest) = plan_seeded(doors);
        let report = plan_suite(doors, &digest, &host.space).run_blocking(&host.kernel);
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
                "script-walkp-result",
                "script-walkp-runs",
                "script-walkw-runs"
            ],
            "{report}"
        );
    });
}
