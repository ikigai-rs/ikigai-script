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
//! - **The version and run reads are NOT `pure`**, though a version is named by its
//!   content and a finished run never changes. Whether a version exists, and who may see
//!   it, is the script's state, so `script-version` hangs from the script's thread
//!   (`urn:script:{name}`, cut by every publish and retire); whether run `{id}` exists is
//!   the state a run writes, so `script-run` hangs from `urn:script:{name}:runs` (ledger
//!   #1076, #1079). A pure function hangs from nothing but what it read, and since
//!   conformance 0.8.3 the suite checks that claim (ledger #1508): declared pure, these two
//!   were refused for carrying a foreign thread. The thread they carry is what cuts them,
//!   so the "no thread but its own name" rule `pure` exempts from does not fire either.
//! - **`script-version` is declared cacheable**: a cached answer, the negative `Exists`
//!   included, is the point of hanging it from the script's thread (an uncacheable `Exists`
//!   would make every composite over it uncacheable). **`script-run` is neither cacheable
//!   nor live**: a finished run's record is cacheable, a running one's is not, and its
//!   `Exists` answers fresh.
//! - **`script-result` is neither declared cacheable nor live**: it is exactly as
//!   cacheable as the script it runs (the fixture's `(+ 1 2)` is not), and
//!   `tests/lifecycle.rs` covers both polarities.
//! - **`script-catalog` is live**: a failed run is recorded without a write through any
//!   name the catalog could hang from.
//! - **The walk is scoped to `script*`** (`Suite::own`): everything else a test kernel
//!   binds is INHERITED, not walked, and each host's inherited list is pinned exactly with
//!   the reason it is not this crate's (`BASE_INHERITED`, `STORE_IDS`, `plan_inherited`),
//!   so an endpoint this crate gains outside `script*` turns a test red rather than joining
//!   the pile unseen. `urn:lisp:eval` is in this kernel because a run composes over it; it
//!   is `ikigai-lisp`'s to conform, and its own suite does.
//! - **`REQUIRED` covers the mutating verbs too** (`Suite::required_on_mutating`): every
//!   kernel here is a test fixture, so a dropped input the endpoint wrongly accepted would
//!   write only into it. On a READ, REQUIRED has something to drop only where a published
//!   SPARQL script declares a required parameter (`walkq`'s `days`): this crate's own reads
//!   take their names from the IRI, and every by-value argument they declare is optional.
//! - **`space(config)` is HOST-named** (`SPACE-NAME`, ledger #987): its doors are fixed,
//!   but what they answer is the backend, ceiling and SPARQL door it was handed, and every
//!   published SPARQL script or plan adds entries of its own. A name is a cache claim (same
//!   name, same doors), and only the host knows which instance it passed in, so the crate
//!   claims none and the suite holds it to that: the space the kernel binds is the value
//!   declared here.

mod common;

use std::sync::Arc;

use common::*;
use ikigai_conformance::{Check, Fixture, Suite};
use ikigai_core::{Capability, Verb};
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

/// What every test kernel binds beside this crate, and why none of it is walked.
const BASE_INHERITED: [(&str, &str); 4] = [
    (
        "eval",
        "ikigai-lisp's own conformance suite covers it; it is bound here only because every \
         run composes over it",
    ),
    ("whoami", "a test probe, not part of this crate"),
    ("vault", "a test probe, not part of this crate"),
    ("fallback", "a test probe, not part of this crate"),
];

/// The inherited list is EXACTLY what each host binds beside the crate: a reason is only
/// true of the id it names, and a new id outside `script*` must be accounted for. Each
/// reason is printed beside the report, which no longer carries it as an opt-out would.
fn assert_inherited(report: &ikigai_conformance::Report, expected: &[(&str, String)]) {
    for (id, why) in expected {
        println!("inherited because: {id}: {why}");
    }
    let mut inherited: Vec<&str> = report
        .declared
        .inherited
        .iter()
        .map(String::as_str)
        .collect();
    inherited.sort_unstable();
    let mut expected: Vec<&str> = expected.iter().map(|(id, _)| *id).collect();
    expected.sort_unstable();
    assert_eq!(inherited, expected, "{report}");
}

/// Only volatile Source answers may skip BODIES. In particular, missing shared-space
/// wiring must fail even when the report has no findings. The module currently declares
/// no reads_body inputs; if it gains any, their transport probes must all run.
fn assert_body_coverage(report: &ikigai_conformance::Report) {
    assert!(report.checks.contains(Check::Bodies), "{report}");
    assert!(report.checks.contains(Check::BodyInputs), "{report}");
    for unprobed in report.unprobed.iter() {
        match unprobed.check {
            Check::Bodies => assert!(
                matches!(
                    unprobed.endpoint.as_str(),
                    "script-catalog" | "script-result"
                ) && unprobed
                    .reason
                    .starts_with("uncacheable, time-varying, or volatile answer:"),
                "{report}"
            ),
            Check::BodyInputs => panic!("{report}"),
            _ => {}
        }
    }
}

fn base_inherited() -> Vec<(&'static str, String)> {
    BASE_INHERITED
        .iter()
        .map(|(id, why)| (*id, why.to_string()))
        .collect()
}

fn suite(digest: &str, space: &Arc<ScriptSpace>) -> Suite {
    // BODIES lowers the caller's memory budget. Root would be replaced with only
    // the declared family marker (`read:*`), which is a presence test, not a grant
    // to this script. Keep the concrete read grant through the bounded probe.
    let read_walk = Capability::scoped([ikigai_script::authority::cap_read("walk")]);
    Suite::new()
        .own("script*")
        .required_on_mutating()
        .host_named_space(SPACE_LABEL, Arc::clone(space))
        .body_space(Arc::clone(space))
        .fixture(
            Fixture::new("script", Verb::Source)
                .binding("name", "walk")
                .capability(read_walk.clone()),
        )
        .fixture(Fixture::new("script", Verb::Exists).binding("name", "walk"))
        .fixture(
            Fixture::new("script", Verb::Sink)
                .binding("name", "published")
                .arg("content", "(+ 2 2)"),
        )
        .fixture(Fixture::new("script", Verb::Delete).binding("name", "retiree"))
        .fixture(
            Fixture::new("script-version", Verb::Source)
                .capability(read_walk.clone())
                .binding("name", "walk")
                .binding("digest", digest),
        )
        .fixture(
            Fixture::new("script-version", Verb::Exists)
                .binding("name", "walk")
                .binding("digest", digest),
        )
        .fixture(
            Fixture::new("script-compiled", Verb::Source)
                .binding("name", "walk")
                .capability(read_walk.clone()),
        )
        .fixture(Fixture::new("script-result", Verb::Source).binding("name", "walk"))
        .fixture(Fixture::new("script-runs", Verb::Sink).binding("name", "walk"))
        .fixture(
            Fixture::new("script-run", Verb::Source)
                .capability(read_walk)
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
        .cacheable("script-version")
        .live("script-catalog")
}

#[test]
fn conforms() {
    let (host, digest) = seeded();
    let report = suite(&digest, &host.space).run_blocking(&host.kernel);
    println!("{report}");
    assert!(report.is_clean(), "{report}");
    assert_body_coverage(&report);
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
    assert_inherited(&report, &base_inherited());
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

/// The store doors every SPARQL run composes over, inherited.
const STORE_IDS: [&str; 15] = [
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
    "store-graph-info",
    "store-dump",
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
    suite(digest, space)
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
    assert_body_coverage(&report);
    let store = STORE_IDS.iter().map(|id| {
        (
            *id,
            "ikigai-store's own conformance suite covers it; it is bound here because every \
             SPARQL run composes over it"
                .to_string(),
        )
    });
    assert_inherited(
        &report,
        &base_inherited()
            .into_iter()
            .chain(store)
            .collect::<Vec<_>>(),
    );
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

/// What a plan host binds beside the crate and the base kernel, and why none of it is
/// walked.
fn plan_inherited(doors: Doors) -> Vec<(&'static str, String)> {
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
}

fn plan_suite(digest: &str, space: &Arc<ScriptSpace>) -> Suite {
    suite(digest, space)
        .fixture(Fixture::new("script-walkp-result", Verb::Source).arg("who", "conformance"))
        // A plan run's piped `content` is its parameters as one JSON object.
        .fixture(Fixture::new("script-walkp-runs", Verb::Sink).arg("content", "{}"))
        .fixture(Fixture::new("script-walkw-runs", Verb::Sink).arg("content", "{}"))
}

#[test]
fn a_host_with_plan_scripts_conforms() {
    both(|doors| {
        let (host, digest) = plan_seeded(doors);
        let report = plan_suite(&digest, &host.space).run_blocking(&host.kernel);
        println!("{report}");
        assert!(report.is_clean(), "{report}");
        assert_body_coverage(&report);
        assert_inherited(&report, &[base_inherited(), plan_inherited(doors)].concat());
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
