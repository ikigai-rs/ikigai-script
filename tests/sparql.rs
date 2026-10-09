//! SPARQL as a script language, end to end against a real `ikigai-store`: publish and
//! fetch without running, a query as a cached read recomputed after a write, an update as
//! a recorded write, typed parameters, injection, derived authority, the result faces, the
//! pre-parse bound, and each published query as its own catalog entry.

mod common;

use std::sync::Arc;

use common::*;
use futures::executor::block_on;
use ikigai_core::{Capability, Error, Verb};
use ikigai_script::authority::{Ceiling, CeilingPolicy};
use ikigai_script::sparql::SparqlDoor;

const LEDGER: &str = "urn:test:ledger";
const SECRET: &str = "urn:test:secret";
const READ_LEDGER: &str = "urn:cap:store:read:graph:urn:test:ledger";
const READ_SECRET: &str = "urn:cap:store:read:graph:urn:test:secret";
const WRITE_LEDGER: &str = "urn:cap:store:write:graph:urn:test:ledger";

const DATA: &str = r#"INSERT DATA {
  GRAPH <urn:test:ledger> {
    <urn:item:1> <urn:p:title> "first" ; <urn:p:age> 10 ; <urn:p:repo> <urn:repo:core> .
    <urn:item:2> <urn:p:title> "second" ; <urn:p:age> 3 ; <urn:p:repo> <urn:repo:cli> .
  }
  GRAPH <urn:test:secret> {
    <urn:item:9> <urn:p:title> "secret" ; <urn:p:age> 99 .
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

const TITLES: &str = r#"# Every title in every graph the caller may read.
SELECT ?g ?title WHERE { GRAPH ?g { ?s <urn:p:title> ?title } } ORDER BY ?title"#;

fn host() -> SparqlHost {
    let host = sparql_host();
    seed(&host.kernel, DATA);
    host
}

fn sparql(kernel: &ikigai_core::Kernel, name: &str, text: &str) -> String {
    publish(kernel, name, text, &[("language", "sparql")])
}

/// One variable's values, from a SPARQL JSON result, in order.
fn column(json: &str, variable: &str) -> Vec<String> {
    let value: serde_json::Value =
        serde_json::from_str(json).unwrap_or_else(|e| panic!("{e}: {json}"));
    value["results"]["bindings"]
        .as_array()
        .unwrap_or_else(|| panic!("no bindings: {json}"))
        .iter()
        .map(|row| row[variable]["value"].as_str().unwrap_or("").to_string())
        .collect()
}

fn result(
    host: &SparqlHost,
    capability: &Capability,
    name: &str,
    args: &[(&str, &str)],
) -> std::result::Result<String, Error> {
    call(
        &host.kernel,
        capability,
        Verb::Source,
        &format!("urn:script:{name}:result"),
        args,
    )
}

fn root_result(host: &SparqlHost, name: &str, args: &[(&str, &str)]) -> String {
    result(host, &Capability::root(), name, args).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn invalid(result: std::result::Result<String, Error>) -> (String, String) {
    match result {
        Err(Error::InvalidArgument { name, detail }) => (name, detail),
        other => panic!("expected InvalidArgument, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------

#[test]
fn publish_then_fetch_without_running() {
    let host = host();
    let version = sparql(&host.kernel, "stale", STALE);
    assert!(
        version.starts_with("urn:script:stale:version:sha256:"),
        "{version}"
    );
    assert_eq!(
        ok(&host.kernel, Verb::Source, "urn:script:stale", &[]),
        STALE
    );
    let record: serde_json::Value = serde_json::from_str(&ok(
        &host.kernel,
        Verb::Source,
        "urn:script:stale",
        &[("as", "application/json")],
    ))
    .unwrap();
    assert_eq!(record["language"], "sparql");
    // Derived from the graph the text names; no language capability for SPARQL.
    assert_eq!(record["requires"], serde_json::json!([READ_LEDGER]));
    let compiled: serde_json::Value = serde_json::from_str(&ok(
        &host.kernel,
        Verb::Source,
        "urn:script:stale:compiled",
        &[],
    ))
    .unwrap();
    assert_eq!(compiled["evaluator"], "urn:iki:store:graph-select");
    assert_eq!(compiled["sparql"]["form"], "select");
    assert_eq!(compiled["sparql"]["parameters"][0]["name"], "days");
    assert_eq!(host.queries(), 0, "fetching a query must not run it");
}

#[test]
fn a_query_is_a_cached_read_recomputed_after_a_write_to_a_graph_it_reads() {
    let host = host();
    sparql(&host.kernel, "stale", STALE);
    assert_eq!(
        column(&root_result(&host, "stale", &[]), "item"),
        vec!["urn:item:1"]
    );
    assert_eq!(
        column(&root_result(&host, "stale", &[]), "item"),
        vec!["urn:item:1"]
    );
    assert_eq!(
        host.queries(),
        1,
        "the second read is served from the cache"
    );

    // Another value is another answer.
    assert_eq!(
        column(&root_result(&host, "stale", &[("days", "2")]), "item"),
        vec!["urn:item:1", "urn:item:2"]
    );
    assert_eq!(host.queries(), 2);

    // A write to the store cuts the thread the answer hangs from.
    seed(
        &host.kernel,
        "INSERT DATA { GRAPH <urn:test:ledger> { <urn:item:3> <urn:p:title> \"third\" ; <urn:p:age> 30 } }",
    );
    assert_eq!(
        column(&root_result(&host, "stale", &[]), "item"),
        vec!["urn:item:1", "urn:item:3"]
    );
    assert_eq!(host.queries(), 3, "recomputed after the write");

    // So does republishing the query.
    sparql(
        &host.kernel,
        "stale",
        &STALE.replace("ORDER BY ?item", "ORDER BY DESC(?item)"),
    );
    assert_eq!(
        column(&root_result(&host, "stale", &[]), "item"),
        vec!["urn:item:3", "urn:item:1"]
    );
    assert_eq!(host.queries(), 4);
}

#[test]
fn an_update_runs_as_a_recorded_write_and_the_reads_follow_it() {
    let host = host();
    sparql(&host.kernel, "stale", STALE);
    sparql(&host.kernel, "retitle", RETITLE);
    assert_eq!(
        column(&root_result(&host, "stale", &[]), "title"),
        vec!["first"]
    );

    let run = ok(
        &host.kernel,
        Verb::Sink,
        "urn:script:retitle:runs",
        &[("item", "urn:item:1"), ("title", "renamed")],
    );
    let run = run.trim();
    assert_eq!(run, "urn:script:retitle:run:1");
    let record: serde_json::Value = serde_json::from_str(&ok(
        &host.kernel,
        Verb::Source,
        run,
        &[("as", "application/json")],
    ))
    .unwrap();
    assert_eq!(record["outcome"]["status"], "ok", "{record}");
    assert!(
        record["result"]
            .as_str()
            .unwrap()
            .contains("updated <urn:test:ledger>"),
        "{record}"
    );
    // Exactly the derived authority: write the graph, and read it (the update has a WHERE).
    assert_eq!(
        record["capability"],
        serde_json::json!([READ_LEDGER, WRITE_LEDGER])
    );

    // The cached read was cut by the write.
    assert_eq!(
        column(&root_result(&host, "stale", &[]), "title"),
        vec!["renamed"]
    );

    // The parameters may arrive as one JSON object, piped.
    ok(
        &host.kernel,
        Verb::Sink,
        "urn:script:retitle:runs",
        &[("content", r#"{"item": "urn:item:1", "title": "piped"}"#)],
    );
    assert_eq!(
        column(&root_result(&host, "stale", &[]), "title"),
        vec!["piped"]
    );
    let (name, _) = invalid(call(
        &host.kernel,
        &Capability::root(),
        Verb::Sink,
        "urn:script:retitle:runs",
        &[
            ("content", r#"{"title": "x"}"#),
            ("title", "y"),
            ("item", "urn:item:1"),
        ],
    ));
    assert_eq!(name, "title", "a parameter given both ways is refused");

    // An update is a write: never a read, whoever asks (and never refused for a Lisp
    // capability it does not need).
    let (name, detail) = invalid(result(&host, &Capability::root(), "retitle", &[]));
    assert_eq!(name, "name");
    assert!(detail.contains("urn:script:retitle:runs"), "{detail}");
    let runner = cap(&["urn:cap:script:run:retitle", READ_LEDGER, WRITE_LEDGER]);
    assert_eq!(invalid(result(&host, &runner, "retitle", &[])).0, "name");
    // And a runner holding exactly the derived authority runs it.
    ok_as(
        &host,
        &runner,
        "retitle",
        &[("item", "urn:item:2"), ("title", "by a runner")],
    );
    // A draft is refused for its state, under its own contract.
    publish(
        &host.kernel,
        "retitle",
        RETITLE,
        &[("language", "sparql"), ("state", "draft")],
    );
    match call(
        &host.kernel,
        &runner,
        Verb::Sink,
        "urn:script:retitle:runs",
        &[("item", "urn:item:2"), ("title", "x")],
    ) {
        Err(Error::Conflict(message)) => assert!(message.contains("draft"), "{message}"),
        other => panic!("expected Conflict, got {other:?}"),
    }
}

fn ok_as(host: &SparqlHost, capability: &Capability, name: &str, args: &[(&str, &str)]) {
    call(
        &host.kernel,
        capability,
        Verb::Sink,
        &format!("urn:script:{name}:runs"),
        args,
    )
    .unwrap_or_else(|e| panic!("running {name}: {e}"));
}

#[test]
fn parameters_are_typed_defaulted_and_required() {
    let host = host();
    sparql(&host.kernel, "stale", STALE);
    sparql(
        &host.kernel,
        "by-repo",
        "# @param repo <urn:class:Repo>\n\
         SELECT ?item ?repo WHERE { GRAPH <urn:test:ledger> { ?item <urn:p:repo> ?repo } }",
    );
    match result(&host, &Capability::root(), "by-repo", &[]) {
        Err(Error::MissingArgument(name)) => assert_eq!(name, "repo"),
        other => panic!("expected MissingArgument, got {other:?}"),
    }
    assert_eq!(
        invalid(result(
            &host,
            &Capability::root(),
            "by-repo",
            &[("repo", "not an iri")]
        ))
        .0,
        "repo"
    );
    let rows = root_result(&host, "by-repo", &[("repo", "urn:repo:cli")]);
    assert_eq!(column(&rows, "item"), vec!["urn:item:2"]);
    // A projected parameter keeps its column, bound to the value.
    assert_eq!(column(&rows, "repo"), vec!["urn:repo:cli"]);

    assert_eq!(
        invalid(result(
            &host,
            &Capability::root(),
            "stale",
            &[("days", "seven")]
        ))
        .0,
        "days"
    );
    // An argument the query does not declare is refused, not ignored.
    assert_eq!(
        invalid(result(
            &host,
            &Capability::root(),
            "stale",
            &[("dayz", "1")]
        ))
        .0,
        "dayz"
    );
    // Canonical forms: `+002` is the integer 2.
    assert_eq!(
        column(&root_result(&host, "stale", &[("days", "+002")]), "item"),
        vec!["urn:item:1", "urn:item:2"]
    );

    // A datetime parameter, compared as a datetime.
    seed(
        &host.kernel,
        "INSERT DATA { GRAPH <urn:test:ledger> { <urn:item:1> <urn:p:filed> \"2026-09-01T00:00:00Z\"^^<http://www.w3.org/2001/XMLSchema#dateTime> } }",
    );
    sparql(
        &host.kernel,
        "since",
        "# @param since xsd:dateTime\n\
         SELECT ?item WHERE { GRAPH <urn:test:ledger> { ?item <urn:p:filed> ?f FILTER(?f >= ?since) } }",
    );
    assert_eq!(
        column(
            &root_result(&host, "since", &[("since", "2026-08-31T23:00:00-02:00")]),
            "item"
        ),
        Vec::<String>::new(),
        "2026-09-01T01:00Z is after the item was filed"
    );
    assert_eq!(
        column(
            &root_result(&host, "since", &[("since", "2026-08-31T00:00:00Z")]),
            "item"
        ),
        vec!["urn:item:1"]
    );
    assert_eq!(
        invalid(result(
            &host,
            &Capability::root(),
            "since",
            &[("since", "yesterday")]
        ))
        .0,
        "since"
    );
}

#[test]
fn a_parameter_value_arrives_as_one_literal_whatever_it_holds() {
    let host = host();
    sparql(
        &host.kernel,
        "echo",
        "# @param text xsd:string\n\
         SELECT ?v WHERE { GRAPH <urn:test:ledger> { <urn:item:1> <urn:p:title> ?t } BIND(?text AS ?v) }",
    );
    sparql(
        &host.kernel,
        "find",
        "# @param text xsd:string\n\
         SELECT ?item WHERE { GRAPH <urn:test:ledger> { ?item <urn:p:title> ?t FILTER(?t = ?text) } }",
    );
    let hostile = [
        // close the string, and open a pattern over another graph
        "first\" } GRAPH <urn:test:secret> { ?s ?p ?o } #",
        // close the string, end the query, smuggle an update
        "\" } ; DROP ALL ; INSERT DATA { <urn:x> <urn:y> \"",
        // close everything, start a second query
        "\"} } SELECT * WHERE { GRAPH ?g { ?s ?p ?o } } #",
        // an expression that is always true
        "first\" || true || \"",
        // escapes and quotes of every kind
        "a\\\"b\nc'''d\"\"\"e\\",
    ];
    for text in hostile {
        let rows = root_result(&host, "echo", &[("text", text)]);
        assert_eq!(
            column(&rows, "v"),
            vec![text.to_string()],
            "{text:?} → {rows}"
        );
        assert_eq!(
            column(&root_result(&host, "find", &[("text", text)]), "item"),
            Vec::<String>::new(),
            "{text:?} matched something"
        );
    }
    // The real title still matches, so the filter is live.
    assert_eq!(
        column(&root_result(&host, "find", &[("text", "first")]), "item"),
        vec!["urn:item:1"]
    );

    // An update: the hostile value is stored as ONE literal, and nothing else changed.
    sparql(&host.kernel, "retitle", RETITLE);
    let drop_all = "\" } } ; DROP ALL ; INSERT DATA { GRAPH <urn:test:ledger> { <urn:x> <urn:y> \"";
    ok(
        &host.kernel,
        Verb::Sink,
        "urn:script:retitle:runs",
        &[("item", "urn:item:2"), ("title", drop_all)],
    );
    let check = |graph: &str, query: &str| {
        ok(
            &host.kernel,
            Verb::Source,
            "urn:iki:store:graph-select",
            &[("graph", graph), ("query", query)],
        )
    };
    let titles = check(LEDGER, "SELECT ?t WHERE { <urn:item:2> <urn:p:title> ?t }");
    assert_eq!(column(&titles, "t"), vec![drop_all.to_string()]);
    let all = check(LEDGER, "SELECT ?s WHERE { ?s ?p ?o }");
    assert_eq!(
        column(&all, "s").len(),
        6,
        "the ledger lost or gained a triple: {all}"
    );
    let secret = check(SECRET, "SELECT ?s WHERE { ?s ?p ?o }");
    assert_eq!(
        column(&secret, "s").len(),
        2,
        "the other graph is untouched: {secret}"
    );

    // An IRI parameter refuses what is not an IRI rather than mangling it.
    let (name, _) = invalid(call(
        &host.kernel,
        &Capability::root(),
        Verb::Sink,
        "urn:script:retitle:runs",
        &[
            ("item", "urn:item:1> } ; DROP ALL ; <urn:x"),
            ("title", "t"),
        ],
    ));
    assert_eq!(name, "item");
}

#[test]
fn authority_is_derived_from_the_graphs_the_query_names() {
    let host = host();
    // A declared `requires` that disagrees with the derived set is refused, naming it.
    let (name, detail) = invalid(call(
        &host.kernel,
        &Capability::root(),
        Verb::Sink,
        "urn:script:stale",
        &[
            ("content", STALE),
            ("language", "sparql"),
            ("requires", "urn:cap:store:read"),
        ],
    ));
    assert_eq!(name, "requires");
    assert!(detail.contains(READ_LEDGER), "{detail}");
    // One that agrees is accepted.
    publish(
        &host.kernel,
        "stale",
        STALE,
        &[("language", "sparql"), ("requires", READ_LEDGER)],
    );

    // No elevation: a publisher who cannot read the graph cannot publish a query over it.
    let message = denied(call(
        &host.kernel,
        &cap(&["urn:cap:script:write:mine", READ_SECRET]),
        Verb::Sink,
        "urn:script:mine",
        &[("content", STALE), ("language", "sparql")],
    ));
    assert!(message.contains(READ_LEDGER), "{message}");

    // A runner without the graph's read grant is refused; with it, answered.
    let runner = cap(&["urn:cap:script:run:stale"]);
    let message = denied(result(&host, &runner, "stale", &[]));
    assert!(message.contains(READ_LEDGER), "{message}");
    let runner = cap(&["urn:cap:script:run:stale", READ_LEDGER]);
    assert_eq!(
        column(&result(&host, &runner, "stale", &[]).unwrap(), "item"),
        vec!["urn:item:1"]
    );
    // The run grant is still needed: the graph grant alone runs nothing.
    denied(result(&host, &cap(&[READ_LEDGER]), "stale", &[]));
}

#[test]
fn the_host_ceiling_bounds_the_graphs_a_query_may_read() {
    let ceiling: CeilingPolicy = Arc::new(|name: &str| match name {
        "stale" => Ceiling::nothing(),
        _ => Ceiling::unbounded(),
    });
    let host = sparql_host_with(SparqlDoor::store(), ceiling, None);
    seed(&host.kernel, DATA);
    sparql(&host.kernel, "stale", STALE);
    let message = denied(result(&host, &Capability::root(), "stale", &[]));
    assert!(message.contains(READ_LEDGER), "{message}");
}

#[test]
fn a_graph_variable_reads_the_callers_readable_union_and_never_more() {
    let host = host();
    sparql(&host.kernel, "titles", TITLES);
    let titles = |capability: &Capability| {
        let rows = result(&host, capability, "titles", &[]).unwrap();
        column(&rows, "title")
    };
    assert_eq!(
        titles(&cap(&["urn:cap:script:run:titles", READ_LEDGER])),
        vec!["first", "second"],
        "the secret graph exists, but this caller may not read it"
    );
    assert_eq!(
        titles(&cap(&[
            "urn:cap:script:run:titles",
            READ_LEDGER,
            READ_SECRET
        ])),
        vec!["first", "second", "secret"]
    );
    assert_eq!(
        titles(&Capability::root()),
        vec!["first", "second", "secret"]
    );
    denied(result(
        &host,
        &cap(&["urn:cap:script:run:titles"]),
        "titles",
        &[],
    ));

    // The publisher's union bounds it too: published by a caller who could read the ledger
    // only, it never reads the secret graph, even for root.
    publish_as(
        &host,
        &cap(&["urn:cap:script:write:mine", READ_LEDGER]),
        "mine",
        TITLES,
    );
    assert_eq!(
        column(&root_result(&host, "mine", &[]), "title"),
        vec!["first", "second"]
    );

    // A parameter naming the graph: inside the union, answered; outside it, refused.
    sparql(
        &host.kernel,
        "in-graph",
        "# @param graph rdfs:Resource\n\
         SELECT ?title WHERE { GRAPH ?graph { ?s <urn:p:title> ?title } } ORDER BY ?title",
    );
    let runner = cap(&["urn:cap:script:run:in-graph", READ_LEDGER]);
    assert_eq!(
        column(
            &result(&host, &runner, "in-graph", &[("graph", LEDGER)]).unwrap(),
            "title"
        ),
        vec!["first", "second"]
    );
    let message = denied(result(&host, &runner, "in-graph", &[("graph", SECRET)]));
    assert!(message.contains(READ_SECRET), "{message}");
}

fn publish_as(host: &SparqlHost, capability: &Capability, name: &str, text: &str) {
    call(
        &host.kernel,
        capability,
        Verb::Sink,
        &format!("urn:script:{name}"),
        &[("content", text), ("language", "sparql")],
    )
    .unwrap_or_else(|e| panic!("publishing {name}: {e}"));
}

#[test]
fn the_result_faces_are_the_sparql_formats() {
    let host = host();
    sparql(&host.kernel, "stale", STALE);
    let face = |args: &[(&str, &str)]| {
        let request = request(Verb::Source, "urn:script:stale:result", args);
        let repr = block_on(host.kernel.issue(request, &Capability::root())).unwrap();
        (
            repr.repr_type.to_string(),
            String::from_utf8_lossy(&repr.bytes).into_owned(),
        )
    };
    let (media, _) = face(&[]);
    assert!(
        media.starts_with("application/sparql-results+json"),
        "{media}"
    );
    let (media, body) = face(&[("as", "text/csv")]);
    assert!(media.starts_with("text/csv"), "{media}");
    assert!(body.starts_with("item,title"), "{body}");
    let (_, body) = face(&[("as", "application/sparql-results+xml")]);
    assert!(body.contains("<sparql"), "{body}");
    let (_, body) = face(&[("as", "text/tab-separated-values")]);
    assert!(body.starts_with("?item\t?title"), "{body}");
    assert_eq!(
        invalid(result(
            &host,
            &Capability::root(),
            "stale",
            &[("as", "text/turtle")]
        ))
        .0,
        "as"
    );

    sparql(
        &host.kernel,
        "graph",
        "CONSTRUCT { ?s <urn:p:title> ?t } WHERE { GRAPH <urn:test:ledger> { ?s <urn:p:title> ?t } }",
    );
    let request = request(Verb::Source, "urn:script:graph:result", &[]);
    let repr = block_on(host.kernel.issue(request, &Capability::root())).unwrap();
    assert!(
        repr.repr_type.to_string().starts_with("text/turtle"),
        "{}",
        repr.repr_type
    );
    let triples = root_result(&host, "graph", &[("as", "application/n-triples")]);
    assert_eq!(triples.lines().count(), 2, "{triples}");

    sparql(
        &host.kernel,
        "any",
        "ASK { GRAPH <urn:test:ledger> { ?s ?p ?o } }",
    );
    let answer: serde_json::Value = serde_json::from_str(&root_result(&host, "any", &[])).unwrap();
    assert_eq!(answer["boolean"], true);
}

#[test]
fn an_over_bound_text_is_refused_before_it_is_parsed() {
    let host = host();
    let deep = format!(
        "SELECT * WHERE {{ GRAPH <urn:g> {{ ?s ?p ?o FILTER({}1{}) }} }}",
        "(".repeat(100),
        ")".repeat(100)
    );
    let (name, detail) = invalid(call(
        &host.kernel,
        &Capability::root(),
        Verb::Sink,
        "urn:script:deep",
        &[("content", &deep), ("language", "sparql")],
    ));
    assert_eq!(name, "content");
    // The restated bound, as `src/limits.rs`'s own test says it is.
    assert!(detail.contains("deeper than 64"), "{detail}");
    let huge = format!(
        "# {}\nASK {{ GRAPH <urn:g> {{ ?s ?p ?o }} }}",
        "x".repeat(1 << 20)
    );
    let (_, detail) = invalid(call(
        &host.kernel,
        &Capability::root(),
        Verb::Sink,
        "urn:script:huge",
        &[("content", &huge), ("language", "sparql")],
    ));
    assert!(detail.contains("bytes"), "{detail}");
    // Nothing was published.
    assert_eq!(
        ok(&host.kernel, Verb::Exists, "urn:script:deep", &[]),
        "false\n"
    );
}

#[test]
fn a_query_whose_answer_the_dataset_would_change_is_refused_at_publish() {
    let host = host();
    let (_, detail) = invalid(call(
        &host.kernel,
        &Capability::root(),
        Verb::Sink,
        "urn:script:mixed",
        &[
            (
                "content",
                "SELECT * FROM <urn:test:ledger> WHERE { ?s ?p ?o GRAPH <urn:test:secret> { ?s ?q ?r } }",
            ),
            ("language", "sparql"),
        ],
    ));
    assert!(detail.contains("<urn:test:secret>"), "{detail}");
    // With FROM naming the whole dataset, bare patterns are fine.
    sparql(
        &host.kernel,
        "bare",
        "SELECT ?t FROM <urn:test:ledger> WHERE { <urn:item:2> <urn:p:title> ?t }",
    );
    assert_eq!(
        column(&root_result(&host, "bare", &[]), "t"),
        vec!["second"]
    );
}

#[test]
fn a_host_without_a_sparql_door_refuses_sparql_scripts() {
    let host = common::host();
    let (name, _) = invalid(call(
        &host.kernel,
        &Capability::root(),
        Verb::Sink,
        "urn:script:q",
        &[("content", STALE), ("language", "sparql")],
    ));
    assert_eq!(name, "language");
    // And urn:script:eval is not the SPARQL Protocol face (ledger #955).
    let (name, _) = invalid(call(
        &host.kernel,
        &Capability::root(),
        Verb::Sink,
        "urn:script:eval",
        &[("content", STALE), ("language", "sparql")],
    ));
    assert_eq!(name, "language");
}

#[test]
fn each_published_query_is_its_own_entry_with_its_parameters() {
    let host = host();
    sparql(&host.kernel, "stale", STALE);
    publish(&host.kernel, "lisp", "(+ 1 2)", &[]);
    let catalog = || ok(&host.kernel, Verb::Source, "urn:kernel:catalog", &[]);
    let before = catalog();
    assert!(before.contains("script-stale-result"), "{before}");
    assert!(before.contains("script-stale-runs"));
    assert!(
        !before.contains("script-lisp-result"),
        "a Lisp script is the template's"
    );

    let meta = ok(
        &host.kernel,
        Verb::Meta,
        "urn:script:stale:result",
        &[("as", "application/json")],
    );
    assert!(meta.contains("\"days\""), "{meta}");
    assert!(meta.contains("XMLSchema#integer"), "{meta}");
    assert!(
        meta.contains(READ_LEDGER),
        "the derived authority is declared: {meta}"
    );
    assert!(meta.contains("urn:cap:script:run:stale"), "{meta}");
    assert!(!meta.contains("urn:cap:lisp"), "{meta}");

    // Republish with another parameter: the host's change hook cuts the bindings thread,
    // and the catalog says so.
    sparql(
        &host.kernel,
        "stale",
        &STALE
            .replace(
                "SELECT",
                "# @param minimum_title xsd:string optional\nSELECT",
            )
            .replace(
                "FILTER(?age > ?days)",
                "FILTER(?age > ?days && (!BOUND(?minimum_title) || ?title >= ?minimum_title))",
            ),
    );
    assert!(host.changed.lock().unwrap().iter().any(|n| n == "stale"));
    let after = catalog();
    assert!(after.contains("minimum_title"), "{after}");
    assert_eq!(
        column(
            &root_result(&host, "stale", &[("days", "0"), ("minimum_title", "s")]),
            "item"
        ),
        vec!["urn:item:2"]
    );

    // Retired, it leaves the catalog.
    ok(&host.kernel, Verb::Delete, "urn:script:stale", &[]);
    assert!(!catalog().contains("script-stale-result"));
}
