//! The arguments a TRANSPORT adds to a request (ledger #1173): `ikigai-web` stamps a write
//! with `received`, `client`, `principal` and the body's `content-type`, and `ikigai-quic`
//! stamps `principal` on every verb. They are the door's, never the caller's, and never a
//! script's parameters: a run through either door must neither be refused for them nor hand
//! them to the script, and who a run is recorded for stays the CAPABILITY's principal.
//!
//! Every kernel here has a JSON Meta renderer (`Kernel::with_meta_renderer`), as the engine
//! needs to route arguments by the contract.

mod common;

use common::*;
use ikigai_core::{Capability, Error, Verb};

const DATA: &str = r#"INSERT DATA {
  GRAPH <urn:test:ledger> {
    <urn:item:1> <urn:p:title> "first" ; <urn:p:age> 10 .
    <urn:item:2> <urn:p:title> "second" ; <urn:p:age> 3 .
  }
}"#;

const STALE: &str = r#"# Items older than some number of days.
# @param days xsd:integer default 7 -- older than this many days
SELECT ?item ?title WHERE {
  GRAPH <urn:test:ledger> { ?item <urn:p:title> ?title ; <urn:p:age> ?age FILTER(?age > ?days) }
} ORDER BY ?item"#;

const RETITLE: &str = r#"# Give an item a new title.
# @param item rdfs:Resource -- the item
# @param title xsd:string -- its new title
DELETE { GRAPH <urn:test:ledger> { ?item <urn:p:title> ?old } }
INSERT { GRAPH <urn:test:ledger> { ?item <urn:p:title> ?title } }
WHERE { GRAPH <urn:test:ledger> { ?item <urn:p:title> ?old } }"#;

/// What `ikigai-web` adds to a write, as it adds it.
const WEB_WRITE_STAMPS: [(&str, &str); 4] = [
    ("received", "2026-10-10T12:00:00Z"),
    ("client", "192.0.2.7"),
    ("principal", "urn:example:person:mallory"),
    ("content-type", "application/x-www-form-urlencoded"),
];

fn sparql_host_seeded() -> SparqlHost {
    let host = sparql_host();
    seed(&host.kernel, DATA);
    host
}

fn titles(host: &SparqlHost) -> String {
    ok(
        &host.kernel,
        Verb::Source,
        "urn:script:stale:result",
        &[("days", "0"), ("as", "text/csv")],
    )
}

#[test]
fn a_run_for_effects_through_the_http_door_is_not_refused_for_its_stamps() {
    let host = sparql_host_seeded();
    publish(&host.kernel, "stale", STALE, &[("language", "sparql")]);
    publish(&host.kernel, "retitle", RETITLE, &[("language", "sparql")]);

    let alice = Capability::root();
    let mut args = vec![("item", "urn:item:1"), ("title", "renamed")];
    args.extend_from_slice(&WEB_WRITE_STAMPS);
    let run = call(
        &host.kernel,
        &alice,
        Verb::Sink,
        "urn:script:retitle:runs",
        &args,
    )
    .unwrap_or_else(|e| panic!("a stamped run for effects was refused: {e}"));
    assert_eq!(run.trim(), "urn:script:retitle:run:1");
    assert!(titles(&host).contains("renamed"), "{}", titles(&host));
}

#[test]
fn a_read_through_the_quic_door_is_not_refused_for_its_principal() {
    let host = sparql_host_seeded();
    publish(&host.kernel, "stale", STALE, &[("language", "sparql")]);
    let answer = call(
        &host.kernel,
        &Capability::root(),
        Verb::Source,
        "urn:script:stale:result",
        &[("principal", "urn:iki:gonk:client:abc"), ("as", "text/csv")],
    )
    .unwrap_or_else(|e| panic!("a stamped read was refused: {e}"));
    assert!(answer.contains("first"), "{answer}");
}

#[test]
fn a_stamped_principal_is_never_who_a_run_is_recorded_for() {
    let host = sparql_host_seeded();
    publish(&host.kernel, "retitle", RETITLE, &[("language", "sparql")]);
    let alice = Capability::root()
        .attenuate([
            "urn:cap:script:run:retitle",
            "urn:cap:script:read:retitle",
            "urn:cap:store:read:graph:urn:test:ledger",
            "urn:cap:store:write:graph:urn:test:ledger",
        ])
        .with_principal("urn:example:person:alice")
        .unwrap();
    let mut args = vec![("item", "urn:item:2"), ("title", "by alice")];
    args.extend_from_slice(&WEB_WRITE_STAMPS);
    let run = call(
        &host.kernel,
        &alice,
        Verb::Sink,
        "urn:script:retitle:runs",
        &args,
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let record: serde_json::Value = serde_json::from_str(
        &call(
            &host.kernel,
            &alice,
            Verb::Source,
            run.trim(),
            &[("as", "application/json")],
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(record["principal"], "urn:example:person:alice", "{record}");
    assert_eq!(record["outcome"]["status"], "ok", "{record}");
}

#[test]
fn a_plan_run_is_not_refused_for_its_stamps() {
    let host = plan_host();
    const HELLO: &str = r#"@prefix ik: <https://ikigai-rs.dev/ns#> .
<urn:plan:hello> a ik:Process ;
    ik:input <urn:plan:hello:input:who> ;
    ik:step <urn:plan:hello:step:1> ;
    ik:result <urn:plan:hello:step:1> .
<urn:plan:hello:input:who> ik:inputName "who" ; ik:required false ; ik:default "world" .
<urn:plan:hello:step:1> a ik:Step ; ik:verb "Source" ; ik:resolves <urn:test:greet> ;
    ik:argument <urn:plan:hello:step:1:arg:who> .
<urn:plan:hello:step:1:arg:who> a ik:Argument ; ik:inputName "who" ;
    ik:ref <urn:plan:hello:var:who> .
"#;
    publish(&host.kernel, "hello", HELLO, &[("language", "plan")]);
    let answer = call(
        &host.kernel,
        &Capability::root(),
        Verb::Source,
        "urn:script:hello:result",
        &[("who", "brian"), ("principal", "urn:iki:gonk:client:abc")],
    )
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(answer, "hello, brian");
    let mut args = vec![("who", "brian")];
    args.extend_from_slice(&WEB_WRITE_STAMPS);
    call(
        &host.kernel,
        &Capability::root(),
        Verb::Sink,
        "urn:script:hello:runs",
        &args,
    )
    .unwrap_or_else(|e| panic!("{e}"));
}

#[test]
fn a_script_cannot_declare_a_name_the_transports_own() {
    let host = sparql_host_seeded();
    for stamp in ["received", "client", "principal"] {
        let text = format!(
            "# @param {stamp} xsd:string\nSELECT * WHERE {{ GRAPH <urn:test:ledger> {{ ?s ?p ?{stamp} }} }}"
        );
        match call(
            &host.kernel,
            &Capability::root(),
            Verb::Sink,
            "urn:script:owned",
            &[("content", &text), ("language", "sparql")],
        ) {
            Err(Error::InvalidArgument { detail, .. }) => {
                assert!(detail.contains(stamp), "{detail}")
            }
            other => panic!("`{stamp}` as a parameter: expected InvalidArgument, got {other:?}"),
        }
    }
}

#[test]
fn a_plan_cannot_declare_a_name_the_transports_own() {
    let host = plan_host();
    for stamp in ["received", "client", "principal", "content-type"] {
        let text = format!(
            r#"@prefix ik: <https://ikigai-rs.dev/ns#> .
<urn:plan:p> a ik:Process ;
    ik:input <urn:plan:p:input:x> ;
    ik:step <urn:plan:p:step:1> ;
    ik:result <urn:plan:p:step:1> .
<urn:plan:p:input:x> ik:inputName "{stamp}" ; ik:required false ; ik:default "world" .
<urn:plan:p:step:1> a ik:Step ; ik:verb "Source" ; ik:resolves <urn:test:greet> ;
    ik:argument <urn:plan:p:step:1:arg:who> .
<urn:plan:p:step:1:arg:who> a ik:Argument ; ik:inputName "who" ;
    ik:ref <urn:plan:p:var:{stamp}> .
"#
        );
        match call(
            &host.kernel,
            &Capability::root(),
            Verb::Sink,
            "urn:script:owned",
            &[("content", &text), ("language", "plan")],
        ) {
            Err(Error::InvalidArgument { detail, .. }) => {
                assert!(detail.contains(stamp), "{detail}")
            }
            other => {
                panic!("`{stamp}` as a plan parameter: expected InvalidArgument, got {other:?}")
            }
        }
    }
}
