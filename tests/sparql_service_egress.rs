//! No SPARQL script reaches the network: a `SERVICE` or `LOAD` is refused, typed, at publish,
//! and again at run if a version holding one reaches the backend some other way (ledger #1085,
//! the store's half in ledger #1083, the history in ledger #145).
//!
//! The claim (ledger #1085): this crate "builds its own evaluator", so in a host whose graph
//! turns on `oxigraph/http-client` (rudof_rdf does, through ikigai-shacl, so ikigai-cli has
//! it) `SERVICE <http://…>` in a script is an outbound request no `urn:cap:net:*` gates. **It
//! does not hold here**: the library links no evaluator at all (no oxigraph, no spareval; see
//! `Cargo.toml`), it PARSES a script with spargebra and refuses `SERVICE` (anywhere in the
//! algebra, `EXISTS` included) and `LOAD` in `sparql::analyze` and again in `sparql::bind`,
//! and a run is a sub-request to the host store's graph-scoped doors, which ikigai-store
//! 0.2.10 makes refuse both too. These tests pin that, in both builds.
//!
//! Under `--features http-client-probe` (CI's `features:` job) the client is compiled in, the
//! `oxigraph_alone_*` controls prove it is live (without them, "the stub saw nothing" would be
//! vacuous), and every path a script's text can take is shown to send the stub nothing. In the
//! default build the same refusals are pinned, so neither build regresses the other.
//!
//! The stub is a plain TCP listener on 127.0.0.1 at an ephemeral port. It answers any request
//! with a SPARQL JSON result or an N-Triples document, so a leak is a SUCCESS that brings data
//! in from the network, and it counts every connection. No real host is ever named.

mod common;

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use common::*;
use ikigai_core::{Capability, Error, Verb};
use ikigai_script::{Head, Language, State, Version};

/// A local HTTP stub that counts the connections it accepts.
struct Stub {
    base: String,
    hits: Arc<AtomicUsize>,
}

impl Stub {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        // Detached: the thread blocks in `accept` and dies with the test process.
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                counter.fetch_add(1, Ordering::SeqCst);
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                let _ = reader.read_line(&mut request_line);
                let mut content_length = 0usize;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        content_length = v.trim().parse().unwrap_or(0);
                    }
                }
                let mut body = vec![0u8; content_length];
                let _ = std::io::Read::read_exact(&mut reader, &mut body);
                let (media, payload) = if request_line.contains("/load") {
                    (
                        "application/n-triples",
                        "<urn:stub:s> <urn:stub:p> \"from-the-network\" .\n".to_string(),
                    )
                } else {
                    (
                        "application/sparql-results+json",
                        r#"{"head":{"vars":["s","p","o"]},"results":{"bindings":[{"s":{"type":"uri","value":"urn:stub:s"},"p":{"type":"uri","value":"urn:stub:p"},"o":{"type":"literal","value":"from-the-network"}}]}}"#
                            .to_string(),
                    )
                };
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: {media}\r\nContent-Length: {}\r\n\
                     Connection: close\r\n\r\n{payload}",
                    payload.len()
                );
            }
        });
        Stub { base, hits }
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

const GRAPH: &str = "urn:test:ledger";

/// The script texts that would fetch: (what is in it, its door, the word its refusal names,
/// the text). `{s}` is the stub's base IRI. Each is otherwise a script this crate accepts,
/// so the refusal is about the fetch and not some other rule.
fn cases(s: &str) -> Vec<(&'static str, Door, &'static str, String)> {
    let g = GRAPH;
    vec![
        (
            "SERVICE in a SELECT",
            Door::Result,
            "SERVICE",
            format!("SELECT * WHERE {{ GRAPH <{g}> {{ SERVICE <{s}/sparql> {{ ?s ?p ?o }} }} }}"),
        ),
        (
            "SERVICE in an ASK",
            Door::Result,
            "SERVICE",
            format!("ASK {{ GRAPH <{g}> {{ SERVICE <{s}/sparql> {{ ?s ?p ?o }} }} }}"),
        ),
        (
            "SERVICE in a CONSTRUCT",
            Door::Result,
            "SERVICE",
            format!(
                "CONSTRUCT {{ ?s ?p ?o }} WHERE {{ GRAPH <{g}> {{ SERVICE <{s}/sparql> {{ ?s ?p ?o }} }} }}"
            ),
        ),
        (
            "SERVICE SILENT, which answers empty instead of failing",
            Door::Result,
            "SERVICE",
            format!(
                "SELECT * WHERE {{ GRAPH <{g}> {{ SERVICE SILENT <{s}/sparql> {{ ?s ?p ?o }} }} }}"
            ),
        ),
        (
            "SERVICE named by a variable, no IRI in the text",
            Door::Result,
            "SERVICE",
            format!(
                "SELECT * WHERE {{ GRAPH <{g}> {{ VALUES ?svc {{ <{s}/sparql> }} SERVICE ?svc {{ ?s ?p ?o }} }} }}"
            ),
        ),
        (
            "SERVICE buried in FILTER EXISTS",
            Door::Result,
            "SERVICE",
            format!(
                "SELECT * WHERE {{ GRAPH <{g}> {{ ?a ?b ?c FILTER EXISTS {{ SERVICE <{s}/sparql> {{ ?s ?p ?o }} }} }} }}"
            ),
        ),
        (
            "SERVICE in an update's WHERE",
            Door::Runs,
            "SERVICE",
            format!(
                "INSERT {{ GRAPH <{g}> {{ ?s ?p ?o }} }} WHERE {{ GRAPH <{g}> {{ SERVICE <{s}/sparql> {{ ?s ?p ?o }} }} }}"
            ),
        ),
        ("LOAD", Door::Runs, "LOAD", format!("LOAD <{s}/load> INTO GRAPH <{g}>")),
        (
            "LOAD SILENT",
            Door::Runs,
            "LOAD",
            format!("LOAD SILENT <{s}/load> INTO GRAPH <{g}>"),
        ),
        (
            "LOAD after an operation the script may run",
            Door::Runs,
            "LOAD",
            format!(
                "INSERT DATA {{ GRAPH <{g}> {{ <urn:a> <urn:b> <urn:c> }} }} ; LOAD <{s}/load> INTO GRAPH <{g}>"
            ),
        ),
    ]
}

#[derive(Clone, Copy, PartialEq)]
enum Door {
    /// `urn:script:{name}:result`, Source.
    Result,
    /// `urn:script:{name}:runs`, Sink.
    Runs,
}

fn run(host: &SparqlHost, name: &str, door: Door) -> std::result::Result<String, Error> {
    let (verb, iri) = match door {
        Door::Result => (Verb::Source, format!("urn:script:{name}:result")),
        Door::Runs => (Verb::Sink, format!("urn:script:{name}:runs")),
    };
    call(&host.kernel, &Capability::root(), verb, &iri, &[])
}

/// What the store holds, as N-Quads, read straight from it under root.
fn store_dump(host: &SparqlHost) -> String {
    ok(
        &host.kernel,
        Verb::Source,
        "urn:iki:store:construct",
        &[(
            "query",
            "CONSTRUCT { ?s ?p ?o } WHERE { GRAPH ?g { ?s ?p ?o } }",
        )],
    )
}

/// Expect THIS crate's typed refusal of `content` ("a script cannot …") naming `word`; anything
/// else is a failure line. The wording is checked so the test pins this layer: the store's own
/// refusal (the second layer) says "not available through this store", and a run that reached it
/// would mean this crate let the text through.
fn refused(
    what: &str,
    got: std::result::Result<String, Error>,
    word: &str,
    failures: &mut Vec<String>,
) {
    match got {
        Err(Error::InvalidArgument { name, detail }) if name == "content" => {
            if !detail.contains("a script cannot") || !detail.contains(word) {
                failures.push(format!(
                    "{what}: refused, but not by this crate for {word}: {detail}"
                ));
            }
        }
        Err(other) => failures.push(format!(
            "{what}: failed, but not as a typed refusal of `content`: {other:?}"
        )),
        Ok(body) => failures.push(format!("{what}: SUCCEEDED: {body}")),
    }
}

/// Every fetching text is refused at PUBLISH, typed, naming `content` and what it refused; the
/// stub sees no connection and the store is never asked to evaluate anything.
#[test]
fn a_fetching_script_is_refused_at_publish_and_reaches_no_network() {
    let stub = Stub::start();
    let host = sparql_host();
    let mut failures = Vec::new();
    for (i, (what, _, word, text)) in cases(&stub.base).into_iter().enumerate() {
        let before = stub.hits();
        let got = call(
            &host.kernel,
            &Capability::root(),
            Verb::Sink,
            &format!("urn:script:egress{i}"),
            &[("content", &text), ("language", "sparql")],
        );
        if stub.hits() != before {
            failures.push(format!(
                "publishing {what} CONNECTED to the stub ({} request(s))",
                stub.hits() - before
            ));
        }
        refused(&format!("publishing {what}"), got, word, &mut failures);
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
    assert_eq!(host.queries(), 0, "the store was asked to evaluate");
}

/// The second check, at RUN: a version that holds a fetch and reached the backend without
/// passing publish (a `DirBackend` file edited out of band, or a version stored by an older
/// build of this crate) is refused before the store is asked, typed the same way, with no
/// connection and nothing written to the store.
#[test]
fn a_fetching_version_that_skipped_publish_is_refused_at_run() {
    let stub = Stub::start();
    let host = sparql_host();
    // A benign script of each form, published normally, gives a real head to repoint, and its
    // grant (read, or read and write, the ledger graph) covers every case's derived authority:
    // so the run is not stopped by authority first, and only the fetch refusal stands between
    // the text and the store.
    let read = format!("SELECT * WHERE {{ GRAPH <{GRAPH}> {{ ?s ?p ?o }} }}");
    let write = format!(
        "DELETE {{ GRAPH <{GRAPH}> {{ ?s ?p ?o }} }} WHERE {{ GRAPH <{GRAPH}> {{ ?s ?p ?o }} }}"
    );
    let empty = store_dump(&host);
    let mut failures = Vec::new();
    for (i, (what, door, word, text)) in cases(&stub.base).into_iter().enumerate() {
        let name = format!("tampered{i}");
        let benign = if door == Door::Result { &read } else { &write };
        publish(&host.kernel, &name, benign, &[("language", "sparql")]);
        let head: Head = host.backend.head(&name).unwrap().expect("a head");
        assert_eq!(head.state, State::Published);
        let published = host
            .backend
            .version(&name, &head.version)
            .unwrap()
            .expect("the published version");
        let tampered = Version {
            language: Language::Sparql,
            requires: published.requires,
            source: text,
        };
        host.backend.put_version(&name, &tampered).unwrap();
        let mut repointed = head.clone();
        repointed.version = tampered.digest();
        host.backend
            .swap_head(&name, Some(&head), &repointed)
            .unwrap();

        let before = stub.hits();
        let got = run(&host, &name, door);
        if stub.hits() != before {
            failures.push(format!(
                "running {what} CONNECTED to the stub ({} request(s))",
                stub.hits() - before
            ));
        }
        refused(&format!("running {what}"), got, word, &mut failures);
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
    assert_eq!(host.queries(), 0, "the store was asked to evaluate");
    assert_eq!(store_dump(&host), empty, "a refused run wrote to the store");
}

/// The second LAYER, which a host gets by linking ikigai-store 0.2.10 or later: the store's own
/// scoped doors, the ones a run is a sub-request to, refuse the same texts if one were sent to
/// them directly. Pinned here because this suite's host is built on that store.
#[test]
fn the_store_doors_a_run_reaches_refuse_them_too() {
    let stub = Stub::start();
    let host = sparql_host();
    let mut failures = Vec::new();
    for (what, door, _, text) in cases(&stub.base) {
        // Each query form has its own door, as `SparqlDoor::query_iri` picks it.
        let (verb, iri, arg) = match door {
            Door::Runs => (Verb::Sink, "urn:iki:store:graph-update", "content"),
            Door::Result if text.starts_with("ASK") => {
                (Verb::Source, "urn:iki:store:graph-ask", "query")
            }
            Door::Result if text.starts_with("CONSTRUCT") => {
                (Verb::Source, "urn:iki:store:graph-construct", "query")
            }
            Door::Result => (Verb::Source, "urn:iki:store:graph-select", "query"),
        };
        let before = stub.hits();
        let got = call(
            &host.kernel,
            &Capability::root(),
            verb,
            iri,
            &[(arg, &text), ("graph", GRAPH)],
        );
        if stub.hits() != before {
            failures.push(format!(
                "{iri} with {what} CONNECTED to the stub ({} request(s))",
                stub.hits() - before
            ));
        }
        if !matches!(&got, Err(Error::InvalidArgument { name, .. }) if name == arg) {
            failures.push(format!(
                "{iri} with {what}: not a typed refusal of `{arg}`: {got:?}"
            ));
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

/// The control: oxigraph's own evaluator, with no ikigai layer, sends `SERVICE` to the stub and
/// returns its row in the probe build, so the client really is compiled in.
#[cfg(feature = "http-client-probe")]
#[test]
fn oxigraph_alone_sends_service_to_the_network_when_the_client_is_compiled_in() {
    use oxigraph::sparql::{QueryResults, SparqlEvaluator};
    use oxigraph::store::Store;
    let stub = Stub::start();
    let store = Store::new().unwrap();
    let query = format!(
        "SELECT ?o WHERE {{ SERVICE <{}/sparql> {{ ?s ?p ?o }} }}",
        stub.base
    );
    let results = SparqlEvaluator::new()
        .parse_query(&query)
        .unwrap()
        .on_store(&store)
        .execute()
        .unwrap();
    let QueryResults::Solutions(solutions) = results else {
        panic!("not solutions")
    };
    let rows: Vec<_> = solutions.collect::<Result<_, _>>().unwrap();
    assert_eq!(
        stub.hits(),
        1,
        "oxigraph alone contacts the SERVICE endpoint"
    );
    assert_eq!(
        rows[0].get("o").unwrap().to_string(),
        "\"from-the-network\""
    );
}

/// The same for `LOAD`, which takes no service handler at all: oxigraph fetches it with its own
/// client whenever the feature is on.
#[cfg(feature = "http-client-probe")]
#[test]
fn oxigraph_alone_fetches_load_when_the_client_is_compiled_in() {
    use oxigraph::sparql::SparqlEvaluator;
    use oxigraph::store::Store;
    let stub = Stub::start();
    let store = Store::new().unwrap();
    SparqlEvaluator::new()
        .parse_update(&format!("LOAD <{}/load>", stub.base))
        .unwrap()
        .on_store(&store)
        .execute()
        .unwrap();
    assert_eq!(stub.hits(), 1, "oxigraph alone fetches the LOAD source");
    assert_eq!(store.len().unwrap(), 1, "and loads what it fetched");
}
