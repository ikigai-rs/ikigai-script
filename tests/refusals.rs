//! Honest refusals (ledger #1261, #1278): a run of a script that is not published is
//! refused for its STATE, never for a language grant the script does not need; a script in
//! a namespace says what its run gate is and why; a query that reads no graph is refused at
//! publish saying why it cannot run; a reserved parameter name is refused naming every one.

mod common;

use common::*;
use ikigai_core::{Capability, Error, Kernel, Verb};
use ikigai_script::sparql::RESERVED_PARAMETERS;

const ALICE: &str = "urn:test:person:alice";
const BOB: &str = "urn:test:person:bob";
const READ_LEDGER: &str = "urn:cap:store:read:graph:urn:test:ledger";

const QUERY: &str =
    "# Every title.\nSELECT ?t WHERE { GRAPH <urn:test:ledger> { ?s <urn:p:title> ?t } }";

/// Everything `name` needs as a SPARQL script over the ledger, and NO `urn:cap:lisp`: the
/// case ledger #1261 found, where the author of a SPARQL draft was told her capability did
/// not grant Lisp.
fn sparql_editor(name: &str) -> Capability {
    cap(&[
        &format!("urn:cap:script:write:{name}"),
        &format!("urn:cap:script:read:{name}"),
        &format!("urn:cap:script:run:{name}"),
        READ_LEDGER,
    ])
}

fn as_who(who: &str, capability: &Capability) -> Capability {
    capability
        .with_principal(who)
        .expect("a principal a door can mint")
}

fn conflict(result: std::result::Result<String, Error>) -> String {
    match result {
        Err(Error::Conflict(message)) => message,
        other => panic!("expected a typed Conflict, got {other:?}"),
    }
}

fn not_found(result: std::result::Result<String, Error>) -> String {
    match result {
        Err(Error::NotFound(message)) => message,
        other => panic!("expected a typed NotFound, got {other:?}"),
    }
}

fn run(
    kernel: &Kernel,
    capability: &Capability,
    name: &str,
    door: &str,
) -> std::result::Result<String, Error> {
    let verb = if door == "runs" {
        Verb::Sink
    } else {
        Verb::Source
    };
    call(
        kernel,
        capability,
        verb,
        &format!("urn:script:{name}:{door}"),
        &[],
    )
}

fn draft_sparql(kernel: &Kernel, capability: &Capability, name: &str) {
    call(
        kernel,
        capability,
        Verb::Sink,
        &format!("urn:script:{name}"),
        &[
            ("content", QUERY),
            ("language", "sparql"),
            ("state", "draft"),
        ],
    )
    .unwrap();
}

/// ★ Ledger #1261: the author of a SPARQL draft, holding everything the query needs and no
/// Lisp grant, is told it is a draft, at both run doors, and is not pointed at
/// `urn:script:eval`, which takes no SPARQL.
#[test]
fn a_sparql_drafts_author_is_told_it_is_a_draft_not_that_lisp_is_missing() {
    let host = sparql_host();
    let k = &host.kernel;
    let alice = as_who(ALICE, &sparql_editor("q"));
    draft_sparql(k, &alice, "q");
    for door in ["result", "runs"] {
        let message = conflict(run(k, &alice, "q", door));
        assert!(
            message.contains("urn:script:q is a draft"),
            "{door}: {message}"
        );
        assert!(!message.contains("urn:cap:lisp"), "{door}: {message}");
        assert!(!message.contains("urn:script:eval"), "{door}: {message}");
    }
    // Published, it runs for her, still without Lisp.
    call(
        k,
        &alice,
        Verb::Sink,
        "urn:script:q",
        &[("content", QUERY), ("language", "sparql")],
    )
    .unwrap();
    run(k, &alice, "q", "result").unwrap();
}

/// Anyone else holding the same grants is told the draft is ABSENT, exactly as for a name
/// nobody wrote (ledger #952), and not that Lisp is missing either; a caller with no run
/// grant at all is still refused at the floor, before anything is read.
#[test]
fn a_drafts_other_readers_are_told_it_is_absent_and_the_run_gate_still_holds() {
    let host = sparql_host();
    let k = &host.kernel;
    draft_sparql(k, &as_who(ALICE, &sparql_editor("q")), "q");
    let bob = as_who(BOB, &sparql_editor("q"));
    let hidden = not_found(run(k, &bob, "q", "result"));
    let nobody = not_found(run(
        k,
        &as_who(BOB, &sparql_editor("none")),
        "none",
        "result",
    ));
    assert_eq!(hidden, nobody.replace("none", "q"));

    let message = denied(run(
        k,
        &cap(&["urn:cap:script:read:q", READ_LEDGER]),
        "q",
        "result",
    ));
    assert!(message.contains("urn:cap:script:run:"), "{message}");
}

/// A published Lisp script still needs the language grant at its door: only a script that
/// is not published wears the contract without it.
#[test]
fn a_published_lisp_script_still_requires_lisp_at_the_floor() {
    let host = host();
    publish(&host.kernel, "job", "1", &[]);
    let message = denied(run(
        &host.kernel,
        &cap(&["urn:cap:script:run:job"]),
        "job",
        "result",
    ));
    assert!(message.contains("urn:cap:lisp"), "{message}");
    // Its contract declares it; the generic one (a draft's, a name nobody wrote's) does not.
    let requires = |iri: &str| -> serde_json::Value {
        let meta = ok(&host.kernel, Verb::Meta, iri, &[("as", "application/json")]);
        serde_json::from_str::<serde_json::Value>(&meta).unwrap()["actions"][0]["requires"].clone()
    };
    assert_eq!(
        requires("urn:script:job:result"),
        serde_json::json!(["urn:cap:script:run:*", "urn:cap:lisp"])
    );
    assert_eq!(
        requires("urn:script:nobody:result"),
        serde_json::json!(["urn:cap:script:run:*"])
    );
}

/// The draft's hint names a door that takes its language: `urn:script:eval` for Lisp,
/// `urn:plan:eval` for a plan, and none for SPARQL.
#[test]
fn a_drafts_hint_names_a_door_that_takes_its_language() {
    let host = host();
    let root = Capability::root();
    call(
        &host.kernel,
        &root,
        Verb::Sink,
        "urn:script:lisp",
        &[("content", "(+ 1 2)"), ("state", "draft")],
    )
    .unwrap();
    let message = conflict(run(&host.kernel, &root, "lisp", "result"));
    assert!(message.contains("urn:script:eval"), "{message}");

    let host = plan_host();
    let plan = "@prefix ik: <https://ikigai-rs.dev/ns#> .\n\
                <urn:plan:p> a ik:Process ; ik:step <urn:plan:p:step:1> ; ik:result <urn:plan:p:step:1> .\n\
                <urn:plan:p:step:1> a ik:Step ; ik:verb \"Source\" ; ik:resolves <urn:test:held> .\n";
    call(
        &host.kernel,
        &root,
        Verb::Sink,
        "urn:script:p",
        &[("content", plan), ("language", "plan"), ("state", "draft")],
    )
    .unwrap();
    let message = conflict(run(&host.kernel, &root, "p", "result"));
    assert!(message.contains(ikigai_script::plan::EVAL), "{message}");
    assert!(!message.contains("urn:script:eval"), "{message}");
}

/// A run whose caller may see the draft but holds no run grant for it hears both: that it
/// is a draft, and the grant its run will need.
#[test]
fn a_draft_is_reported_before_the_run_grant_it_will_also_need() {
    let host = sparql_host();
    let k = &host.kernel;
    let alice = as_who(
        ALICE,
        &cap(&[
            "urn:cap:script:write:q",
            "urn:cap:script:read:q",
            "urn:cap:script:run:other",
            READ_LEDGER,
        ]),
    );
    draft_sparql(k, &alice, "q");
    let message = conflict(run(k, &alice, "q", "result"));
    assert!(message.contains("is a draft"), "{message}");
    assert!(message.contains("urn:cap:script:run:q"), "{message}");
}

/// ★ Ledger #1261, the second half: a name with a `-` is in a namespace, and its contract's
/// run gate is that namespace's family. The kernel's floor names only the family, so the
/// contract (what Meta answers to a refused caller) says what satisfies it and why.
#[test]
fn a_namespaced_scripts_contract_says_what_its_run_gate_is_and_why() {
    let host = sparql_host();
    let k = &host.kernel;
    publish(k, "open-items", QUERY, &[("language", "sparql")]);
    let message = denied(run(
        k,
        &cap(&["urn:cap:script:run:other", READ_LEDGER]),
        "open-items",
        "result",
    ));
    assert!(message.contains("urn:cap:script:run:open-*"), "{message}");
    for door in ["result", "runs"] {
        let meta = ok(k, Verb::Meta, &format!("urn:script:open-items:{door}"), &[]);
        assert!(
            meta.contains("urn:cap:script:run:open-items"),
            "{door}: {meta}"
        );
        assert!(meta.contains("namespace"), "{door}: {meta}");
    }
    // A name with no `-` declares its own grant, and needs no such note.
    publish(k, "items", QUERY, &[("language", "sparql")]);
    let meta = ok(k, Verb::Meta, "urn:script:items:result", &[]);
    assert!(!meta.contains("namespace"), "{meta}");
}

/// Ledger #1278: a query that reads no graph is refused at publish, and the refusal says why
/// it cannot run (the store's scoped doors refuse an empty dataset) and what to write.
#[test]
fn a_query_that_reads_no_graph_is_refused_saying_why() {
    let host = sparql_host();
    let result = call(
        &host.kernel,
        &Capability::root(),
        Verb::Sink,
        "urn:script:hello",
        &[
            ("content", "SELECT (\"Hello, world!\" AS ?greeting) {}"),
            ("language", "sparql"),
        ],
    );
    let detail = match result {
        Err(Error::InvalidArgument { name, detail }) if name == "content" => detail,
        other => panic!("expected InvalidArgument on content, got {other:?}"),
    };
    assert!(detail.contains("reads no graph"), "{detail}");
    assert!(detail.contains("empty dataset"), "{detail}");
    assert!(detail.contains("FROM <"), "{detail}");
}

/// Ledger #1278: a `@param` that takes a reserved name is refused naming every reserved one.
#[test]
fn a_reserved_parameter_name_is_refused_naming_every_reserved_name() {
    let host = sparql_host();
    for reserved in ["name", "as", "content"] {
        let text = format!(
            "# @param {reserved} xsd:string\nSELECT * WHERE {{ GRAPH <urn:test:ledger> {{ ?s ?p ?{reserved} }} }}"
        );
        let result = call(
            &host.kernel,
            &Capability::root(),
            Verb::Sink,
            "urn:script:r",
            &[("content", &text), ("language", "sparql")],
        );
        let detail = match result {
            Err(Error::InvalidArgument { detail, .. }) => detail,
            other => panic!("expected InvalidArgument, got {other:?}"),
        };
        for name in RESERVED_PARAMETERS {
            assert!(detail.contains(name), "{reserved}: {detail}");
        }
    }
}
