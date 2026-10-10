//! The graph face (ledger #952, part 3): the catalog and every run record answer
//! `as=text/turtle`, skolemized, in PROV-O and the shared vocabulary, so the visualizers and
//! SPARQL read them as graphs.
//!
//! Every field the Turtle face carries is pinned against the JSON face as an RDF TERM: the
//! term its JSON value denotes under the predicate's range, and the range of an `ik:` term is
//! read from `ikigai_vocab::VOCABULARY`, so a vocabulary change turns this red (the pattern
//! of ikigai-meeting PR 7).

mod common;

use std::sync::Arc;

use common::*;
use ikigai_core::{Capability, Error, Verb};
use ikigai_script::authority::{same_for_all, Ceiling, PrincipalStamper};
use ikigai_script::model::when;
use ikigai_script::MemoryBackend;
use oxrdf::{Literal, NamedNode, NamedOrBlankNode, Term, Triple};

const TURTLE: &str = "text/turtle";
const XSD: &str = "http://www.w3.org/2001/XMLSchema#";
const PROV: &str = "http://www.w3.org/ns/prov#";
const DCTERMS: &str = "http://purl.org/dc/terms/";
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";

fn ik(term: &str) -> String {
    format!("{}{term}", ikigai_vocab::NS)
}

/// The range the shared vocabulary states for `ik:{term}`.
fn ik_range(term: &str) -> String {
    let vocabulary = ikigai_conformance::rdf::parse(TURTLE, ikigai_vocab::VOCABULARY.as_bytes())
        .expect("the shared vocabulary parses");
    let subject = NamedOrBlankNode::from(NamedNode::new(ik(term)).unwrap());
    vocabulary
        .iter()
        .find(|t| {
            t.subject == subject
                && t.predicate.as_str() == "http://www.w3.org/2000/01/rdf-schema#range"
        })
        .map(|t| match &t.object {
            Term::NamedNode(range) => range.as_str().to_string(),
            other => panic!("ik:{term}'s range is not an IRI: {other}"),
        })
        .unwrap_or_else(|| panic!("the vocabulary states no range for ik:{term}"))
}

fn parse(bytes: &str) -> Vec<Triple> {
    ikigai_conformance::rdf::parse(TURTLE, bytes.as_bytes())
        .unwrap_or_else(|e| panic!("the Turtle face does not parse: {e}\n{bytes}"))
}

fn objects(triples: &[Triple], subject: &str, predicate: &str) -> Vec<Term> {
    let subject = NamedOrBlankNode::from(NamedNode::new(subject).unwrap());
    let mut found: Vec<Term> = triples
        .iter()
        .filter(|t| t.subject == subject && t.predicate.as_str() == predicate)
        .map(|t| t.object.clone())
        .collect();
    found.sort_by_key(|t| t.to_string());
    found
}

fn iri(text: &str) -> Term {
    NamedNode::new(text).unwrap().into()
}

fn typed(lexical: &str, datatype: &str) -> Term {
    Literal::new_typed_literal(lexical, NamedNode::new(datatype).unwrap()).into()
}

fn no_blank_nodes(triples: &[Triple], text: &str) {
    let blanks = ikigai_conformance::rdf::blank_nodes(triples);
    assert!(blanks.is_empty(), "blank nodes {blanks:?} in\n{text}");
}

/// A host whose principal is a person, so the run face has an agent to name.
fn stamped_host() -> Host {
    let stamper: PrincipalStamper = Arc::new(|_| "urn:test:person:brian".to_string());
    host_with(
        Arc::new(MemoryBackend::new()),
        same_for_all(Ceiling::unbounded()),
        Some(stamper),
    )
}

#[test]
fn the_catalog_and_a_run_answer_a_turtle_face() {
    let host = stamped_host();
    publish(&host.kernel, "a", "(+ 1 2)", &[]);
    let run = ok(&host.kernel, Verb::Sink, "urn:script:a:runs", &[]);
    for iri in [run.trim(), "urn:script:catalog"] {
        let answer = ok(&host.kernel, Verb::Source, iri, &[("as", TURTLE)]);
        no_blank_nodes(&parse(&answer), &answer);
    }
}

#[test]
fn a_run_records_turtle_and_json_faces_are_term_equal() {
    let host = stamped_host();
    publish(&host.kernel, "ok", "(+ 1 2)", &[]);
    publish(&host.kernel, "bad", "(car 1)", &[]);
    let fine = ok(&host.kernel, Verb::Sink, "urn:script:ok:runs", &[]);
    let failed = match call(
        &host.kernel,
        &Capability::root(),
        Verb::Sink,
        "urn:script:bad:runs",
        &[],
    ) {
        Err(error) => {
            let text = error.to_string();
            let at = text
                .find("urn:script:bad:run:")
                .expect("the error names its run");
            text[at..].trim_end_matches(')').to_string()
        }
        Ok(answer) => panic!("(car 1) ran: {answer}"),
    };
    let content_hash = ik_range("contentHash");
    let _ = content_hash; // the catalog's; read here so a missing term fails both tests
    for (run, status) in [(fine.trim().to_string(), "ok"), (failed, "failed")] {
        let turtle = ok(&host.kernel, Verb::Source, &run, &[("as", TURTLE)]);
        let triples = parse(&turtle);
        no_blank_nodes(&triples, &turtle);
        let json: serde_json::Value = serde_json::from_str(&ok(
            &host.kernel,
            Verb::Source,
            &run,
            &[("as", "application/json")],
        ))
        .unwrap();
        assert_eq!(json["outcome"]["status"], status, "{json}");
        let name = json["name"].as_str().unwrap();
        let version = format!(
            "urn:script:{name}:version:{}",
            json["version"].as_str().unwrap()
        );
        let millis = |field: &str| json[field].as_u64().unwrap_or_else(|| panic!("{field}"));
        for (predicate, want) in [
            (RDF_TYPE.to_string(), vec![iri(&format!("{PROV}Activity"))]),
            (format!("{PROV}used"), vec![iri(&version)]),
            (
                format!("{PROV}wasAssociatedWith"),
                vec![iri(json["principal"].as_str().unwrap())],
            ),
            (
                format!("{PROV}startedAtTime"),
                vec![typed(
                    &when(Some(millis("started"))),
                    &format!("{XSD}dateTime"),
                )],
            ),
            (
                format!("{PROV}endedAtTime"),
                vec![typed(
                    &when(Some(millis("ended"))),
                    &format!("{XSD}dateTime"),
                )],
            ),
            (
                ik("outcome"),
                vec![iri(&format!("urn:script:outcome:{status}"))],
            ),
        ] {
            assert_eq!(
                objects(&triples, &run, &predicate),
                want,
                "{run}: <{predicate}>\n{turtle}"
            );
        }
        assert_eq!(
            objects(&triples, &version, &format!("{PROV}specializationOf")),
            vec![iri(&format!("urn:script:{name}"))],
            "{turtle}"
        );
    }
}

#[test]
fn the_catalogs_turtle_and_json_faces_are_term_equal() {
    let host = stamped_host();
    publish(&host.kernel, "a", "(+ 1 2)", &[]);
    publish(&host.kernel, "b", "2", &[("public", "true")]);
    publish(&host.kernel, "c", "3", &[]);
    ok(&host.kernel, Verb::Sink, "urn:script:a:runs", &[]);
    let turtle = ok(
        &host.kernel,
        Verb::Source,
        "urn:script:catalog",
        &[("as", TURTLE)],
    );
    let triples = parse(&turtle);
    no_blank_nodes(&triples, &turtle);
    let json: serde_json::Value = serde_json::from_str(&ok(
        &host.kernel,
        Verb::Source,
        "urn:script:catalog",
        &[("as", "application/json")],
    ))
    .unwrap();
    let rows = json["scripts"].as_array().unwrap();
    assert_eq!(rows.len(), 3);
    let mut parts: Vec<Term> = rows
        .iter()
        .map(|r| iri(r["iri"].as_str().unwrap()))
        .collect();
    parts.sort_by_key(|t| t.to_string());
    assert_eq!(
        objects(&triples, "urn:script:catalog", &format!("{DCTERMS}hasPart")),
        parts
    );
    let content_hash = ik_range("contentHash");
    for row in rows {
        let script = row["iri"].as_str().unwrap();
        let field = |name: &str| row[name].as_str().unwrap().to_string();
        for (predicate, want) in [
            (
                format!("{DCTERMS}identifier"),
                vec![typed(&field("name"), &format!("{XSD}string"))],
            ),
            (
                ik("contentHash"),
                vec![typed(&field("version"), &content_hash)],
            ),
        ] {
            assert_eq!(
                objects(&triples, script, &predicate),
                want,
                "{script}: <{predicate}>"
            );
        }
        let version = format!("{script}:version:{}", field("version"));
        assert_eq!(
            objects(&triples, &version, &format!("{PROV}specializationOf")),
            vec![iri(script)]
        );
        let last = &row["lastRun"];
        if last.is_null() {
            continue;
        }
        let run = last["iri"].as_str().unwrap();
        assert_eq!(
            objects(&triples, run, &ik("outcome")),
            vec![iri(&format!(
                "urn:script:outcome:{}",
                last["status"].as_str().unwrap()
            ))]
        );
        assert_eq!(
            objects(&triples, run, &format!("{PROV}endedAtTime")),
            vec![typed(
                &when(Some(last["ended"].as_u64().unwrap())),
                &format!("{XSD}dateTime")
            )]
        );
        // The run reaches its script through the version it used.
        assert_eq!(
            objects(&triples, run, &format!("{PROV}used")),
            vec![iri(&version)]
        );
    }
}

#[test]
fn an_awkward_principal_or_result_cannot_break_the_graph() {
    // A principal that is not an IRI names no agent (the JSON face still carries it), and a
    // result with quotes and line breaks never reaches the graph at all.
    let stamper: PrincipalStamper = Arc::new(|_| "not an iri \"<x>\"".to_string());
    let host = host_with(
        Arc::new(MemoryBackend::new()),
        same_for_all(Ceiling::unbounded()),
        Some(stamper),
    );
    publish(&host.kernel, "w", "\"say \\\"hi\\\"\\n\\tthen > go\"", &[]);
    let run = ok(&host.kernel, Verb::Sink, "urn:script:w:runs", &[]);
    let turtle = ok(&host.kernel, Verb::Source, run.trim(), &[("as", TURTLE)]);
    let triples = parse(&turtle);
    assert!(
        objects(&triples, run.trim(), &format!("{PROV}wasAssociatedWith")).is_empty(),
        "{turtle}"
    );
    assert_eq!(objects(&triples, run.trim(), &ik("outcome")).len(), 1);
}

#[test]
fn the_turtle_face_is_declared_and_other_records_still_refuse_it() {
    let host = stamped_host();
    publish(&host.kernel, "a", "1", &[]);
    for iri in ["urn:script:catalog", "urn:script:a:run:1"] {
        let meta = ok(&host.kernel, Verb::Meta, iri, &[]);
        assert!(
            meta.contains("\"text/turtle\""),
            "{iri} declares no Turtle output:\n{meta}"
        );
    }
    // The script itself and its versions have no graph face yet: refused, never substituted.
    match call(
        &host.kernel,
        &Capability::root(),
        Verb::Source,
        "urn:script:a",
        &[("as", TURTLE)],
    ) {
        Err(Error::InvalidArgument { name, .. }) => assert_eq!(name, "as"),
        other => panic!("expected InvalidArgument on `as`, got {other:?}"),
    }
}
