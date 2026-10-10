//! The graph face (`as=text/turtle`) of the catalog and the run records.
//!
//! PROV-O and the shared vocabulary, skolemized: every node is an IRI this crate already
//! names, so two answers diff and merge without blank-node renaming.
//!
//! ```text
//! <urn:script:catalog>  dcterms:hasPart  <urn:script:{name}>            one per catalog row
//! <urn:script:{name}>   dcterms:identifier "{name}" ;
//!                       ik:contentHash "sha256:…"                        its head version
//! <urn:script:{name}:version:{digest}>  prov:specializationOf  <urn:script:{name}>
//! <urn:script:{name}:run:{id}>  a prov:Activity ;
//!     prov:used <urn:script:{name}:version:{digest}> ;                 the version that ran
//!     prov:wasAssociatedWith <principal> ;                            who, as the door minted it
//!     prov:startedAtTime "…"^^xsd:dateTime ; prov:endedAtTime "…"^^xsd:dateTime ;
//!     ik:outcome <urn:script:outcome:ok> | <urn:script:outcome:failed>   absent while running
//! ```
//!
//! A run reaches its script through the version it used, so "every run of this script" and
//! "its last run" are queries, not terms.
//!
//! ⚠ **What the graph does not carry, because the vocabulary has no term for it** (the JSON
//! face has every one): a script's state, its public flag, its language, what it declares,
//! what its publisher held and their exclusions, and a broken head's error; a run's
//! capability, the failure's kind and message, its result and whether it was cut, and its
//! trace span. Nothing here invents an `ik:` term for them.

use std::collections::HashSet;

use oxrdf::{vocab::rdf, vocab::xsd, Literal, NamedNode, Triple};
use oxttl::TurtleSerializer;

use crate::model::{when, Outcome, Run};
use crate::name;

/// The shared vocabulary's namespace.
const IK: &str = "https://ikigai-rs.dev/ns#";
const PROV: &str = "http://www.w3.org/ns/prov#";
const DCTERMS: &str = "http://purl.org/dc/terms/";
const XSD: &str = "http://www.w3.org/2001/XMLSchema#";

/// `ik:outcome` of a run that finished with an answer.
pub const OUTCOME_OK: &str = "urn:script:outcome:ok";
/// `ik:outcome` of a run that finished with an error.
pub const OUTCOME_FAILED: &str = "urn:script:outcome:failed";

/// The triples being built for one answer: a set, kept in the order first stated so the
/// text reads top-down (a catalog row's head and its last run often name one version).
#[derive(Default)]
pub(crate) struct Graph {
    triples: Vec<Triple>,
    seen: HashSet<Triple>,
}

/// `text` as an IRI, when it is one.
fn node(text: &str) -> Option<NamedNode> {
    NamedNode::new(text).ok()
}

/// A term this module spells itself, so certainly an IRI.
fn term(namespace: &str, local: &str) -> NamedNode {
    NamedNode::new_unchecked(format!("{namespace}{local}"))
}

fn date_time(millis: u64) -> Literal {
    Literal::new_typed_literal(when(Some(millis)), xsd::DATE_TIME)
}

impl Graph {
    fn add(&mut self, subject: &NamedNode, predicate: NamedNode, object: impl Into<oxrdf::Term>) {
        let triple = Triple::new(subject.clone(), predicate, object.into());
        if self.seen.insert(triple.clone()) {
            self.triples.push(triple);
        }
    }

    /// `<version> prov:specializationOf <script>`: a version is the script, fixed.
    fn version(&mut self, script: &str, digest: &str) -> Option<NamedNode> {
        let version = node(&name::version_iri(script, digest))?;
        let of = node(&name::script_iri(script))?;
        self.add(&version, term(PROV, "specializationOf"), of);
        Some(version)
    }

    /// One run, as far as `run` is known: the catalog's last run carries less than a record.
    fn run(
        &mut self,
        iri: &str,
        script: &str,
        digest: &str,
        outcome: &Outcome,
        ended: Option<u64>,
    ) -> Option<NamedNode> {
        let subject = node(iri)?;
        self.add(&subject, rdf::TYPE.into_owned(), term(PROV, "Activity"));
        if let Some(version) = self.version(script, digest) {
            self.add(&subject, term(PROV, "used"), version);
        }
        if let Some(ended) = ended {
            self.add(&subject, term(PROV, "endedAtTime"), date_time(ended));
        }
        let outcome = match outcome {
            Outcome::Running => None,
            Outcome::Ok => Some(OUTCOME_OK),
            Outcome::Failed { .. } => Some(OUTCOME_FAILED),
        };
        if let Some(outcome) = outcome.and_then(node) {
            self.add(&subject, term(IK, "outcome"), outcome);
        }
        Some(subject)
    }

    /// A run record: what [`Graph::run`] says, and who ran it when.
    pub(crate) fn record(&mut self, record: &Run) {
        let Some(subject) = self.run(
            &record.iri(),
            &record.name,
            &record.version,
            &record.outcome,
            record.ended,
        ) else {
            return;
        };
        // A principal that is not an IRI names no agent here; the JSON face still has it.
        if let Some(agent) = node(&record.principal) {
            self.add(&subject, term(PROV, "wasAssociatedWith"), agent);
        }
        if let Some(started) = record.started {
            self.add(&subject, term(PROV, "startedAtTime"), date_time(started));
        }
    }

    /// One catalog row: the script, its head version and, when it has run, its last run.
    pub(crate) fn script(&mut self, script: &str, head: Option<&str>, last: Option<&Run>) {
        let (Some(catalog), Some(subject)) =
            (node(name::CATALOG_IRI), node(&name::script_iri(script)))
        else {
            return;
        };
        self.add(&catalog, term(DCTERMS, "hasPart"), subject.clone());
        self.add(
            &subject,
            term(DCTERMS, "identifier"),
            Literal::new_simple_literal(script),
        );
        if let Some(digest) = head {
            self.add(
                &subject,
                term(IK, "contentHash"),
                Literal::new_simple_literal(digest),
            );
            self.version(script, digest);
        }
        if let Some(run) = last {
            self.run(&run.iri(), script, &run.version, &run.outcome, run.ended);
        }
    }

    /// The Turtle text.
    pub(crate) fn turtle(self) -> std::io::Result<Vec<u8>> {
        let mut out = TurtleSerializer::new()
            .with_prefix("ik", IK)
            .and_then(|s| s.with_prefix("prov", PROV))
            .and_then(|s| s.with_prefix("dcterms", DCTERMS))
            .and_then(|s| s.with_prefix("xsd", XSD))
            .map_err(std::io::Error::other)?
            .for_writer(Vec::new());
        for triple in &self.triples {
            out.serialize_triple(triple)?;
        }
        out.finish()
    }
}
