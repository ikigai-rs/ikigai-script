//! **Plans as a script language**: a stored `ik:Process` graph is a script whose language is
//! `plan`.
//!
//! A plan is the most analyzable script there is: finite (no conditionals, no loops; a
//! branch is a step that calls a language), so it is validated before it is stored, every
//! step's target is known in advance, and **the capability it needs is DERIVED from its
//! steps' own contracts** rather than declared by its author. It gets everything a Lisp or
//! SPARQL script gets (versions, the three authorities, run records, the manifold) and three
//! things of its own, none of which is ever taken from a caller's argument:
//!
//! - **validation at publish**: the plan is a sub-request to `urn:plan:validate` (the SHACL
//!   shapes of the process vocabulary plus the executor's own checks), and one that does not
//!   conform is refused, naming the shape it broke. See [`validate()`].
//! - **derived authority**: a sub-request to `urn:plan:requires`, which reads each step's
//!   target contract (`Description::required_scopes` for the step's verb) without invoking
//!   it. The union is stored with the version; a `requires=` that says anything else is
//!   refused, naming the derived set. See [`derive()`].
//! - **read or write, from the steps**: a plan whose every step is a `Source`, `Exists` or
//!   `Meta` runs as a READ at `…:result`; one with any `Sink` or `Delete` step anywhere in the
//!   graph is a WRITE, run at `…:runs`. See [`Analysis::mutates`].
//!
//! A run is a sub-request to `urn:plan:eval` with the plan as `in` and the plan's own
//! parameters (`ik:input`) by name, issued under the runner's capability narrowed exactly as
//! every script's is (see [`crate::authority`]). The three names are the HOST's: this crate
//! links no plan runner, as it links no Lisp interpreter and no SPARQL evaluator.
//!
//! # The shallow read
//!
//! [`analyze`] reads a plan with a Turtle parser for exactly three things this crate must
//! decide itself and cannot ask a resource for without running something: the process node,
//! the verb of every step (read or write), and the declared parameters (the arguments of the
//! script's own catalog entry). Everything about whether the plan is well formed is
//! `urn:plan:validate`'s, and publish asks it first.
//!
//! ```
//! use ikigai_script::plan::analyze;
//!
//! let plan = r#"
//! @prefix ik: <https://ikigai-rs.dev/ns#> .
//! <urn:plan:hello> a ik:Process ;
//!     ik:input <urn:plan:hello:input:who> ;
//!     ik:step <urn:plan:hello:step:1> ;
//!     ik:result <urn:plan:hello:step:1> .
//! <urn:plan:hello:input:who> ik:inputName "who" ; ik:required false ; ik:default "world" .
//! <urn:plan:hello:step:1> a ik:Step ; ik:verb "Source" ; ik:resolves <urn:example:greet> .
//! "#;
//! let analysis = analyze(plan).unwrap();
//! assert_eq!(analysis.process, "urn:plan:hello");
//! assert!(!analysis.mutates()); // every step a Source: a read, at `…:result`
//! assert_eq!(analysis.parameters[0].name, "who");
//! assert_eq!(analysis.parameters[0].default.as_deref(), Some("world"));
//! ```
//!
//! # Preference order
//!
//! When assembling anything: **a query, then a plan, then Lisp.** A query and a plan both
//! derive their authority and can be checked before they run; Lisp declares its authority
//! and can do anything its capability allows in any order. Use Lisp for control flow a plan
//! cannot express, and preferably as ONE step inside a plan.

use std::collections::{BTreeMap, BTreeSet};

use ikigai_core::{
    is_deny_scope, ArgRef, Capability, Error, Invocation, Iri, Request, Result, Verb,
};
use oxrdf::{NamedOrBlankNode, Term, Triple};
use oxttl::TurtleParser;
use serde::{Deserialize, Serialize};

use crate::authority::Ceiling;

/// The host's plan evaluator: runs a plan's steps as sub-requests under the caller's
/// capability.
pub const EVAL: &str = "urn:plan:eval";
/// The host's plan validator: the SHACL report plus the executor's checks.
pub const VALIDATE: &str = "urn:plan:validate";
/// The host's derivation of a plan's capability from its steps' contracts.
pub const REQUIRES: &str = "urn:plan:requires";

/// The longest plan accepted, in bytes. A bound on the work a publish does (two
/// sub-requests and a parse over the text), refused rather than truncated. The Turtle
/// parser keeps an explicit stack, so nesting is not a claim on the thread's stack.
pub const MAX_PLAN_BYTES: usize = 1 << 20;

/// Parameter names the doors already use: `in` and `as` are `urn:plan:eval`'s own, `name`
/// is the script's binding, `content` is `…:runs`' piped body, and the rest are the
/// transports' stamps ([`crate::TRANSPORT_ARGUMENTS`]), which a run ignores. A plan
/// declaring one could never be given it.
pub const RESERVED_PARAMETERS: [&str; 8] = [
    "in",
    "as",
    "name",
    "content",
    "received",
    "client",
    "principal",
    "content-type",
];

const IK: &str = "https://ikigai-rs.dev/ns#";
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const RDFS_COMMENT: &str = "http://www.w3.org/2000/01/rdf-schema#comment";
const SH: &str = "http://www.w3.org/ns/shacl#";
const TURTLE: &str = "text/turtle";
/// Where `urn:plan:requires` names its outcomes.
const OUTCOME: &str = "urn:ikigai:plan:requires:outcome:";

/// One step, as far as this crate reads it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    /// The step's IRI.
    pub iri: String,
    /// Its verb, as the vocabulary spells it: `Source`, `Sink`, `Exists`, `Delete`, `Meta`.
    pub verb: String,
    /// The IRI it resolves.
    pub resolves: String,
}

impl Step {
    /// Whether the step changes anything: a `Sink` or a `Delete`.
    pub fn mutates(&self) -> bool {
        matches!(self.verb.as_str(), "Sink" | "Delete")
    }
}

/// One of a plan's declared parameters (an `ik:input` ArgSpec node).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Parameter {
    /// `ik:inputName`: the argument it arrives as.
    pub name: String,
    /// `ik:required` (an ArgSpec is required unless it says otherwise).
    pub required: bool,
    /// `ik:default`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    /// `ik:class`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    /// `ik:summary`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

impl Parameter {
    /// Whether a run must be given it: required, with no default to fall back on.
    pub fn must_be_given(&self) -> bool {
        self.required && self.default.is_none()
    }
}

/// What a plan says about itself, read from its graph.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Analysis {
    /// The `ik:Process` node: `urn:plan:{id}`.
    pub process: String,
    /// Every step in the graph, by IRI.
    pub steps: Vec<Step>,
    /// Its declared parameters, by name.
    pub parameters: Vec<Parameter>,
}

impl Analysis {
    /// Whether the plan is a WRITE: any `Sink` or `Delete` step ANYWHERE in the graph,
    /// including one the result does not depend on. Conservative on purpose: deciding from
    /// the steps a run reaches would make the answer depend on the executor's reachability
    /// rule, and calling a read a write only costs a run record.
    pub fn mutates(&self) -> bool {
        self.steps.iter().any(Step::mutates)
    }
}

// ---------------------------------------------------------------------------------------
// The shallow read
// ---------------------------------------------------------------------------------------

/// A parsed Turtle graph, queried by subject and predicate.
struct Graph {
    triples: Vec<Triple>,
}

/// A subject or object node, keyed so the two can be compared: an IRI as itself, a blank
/// node as `_:{id}`.
fn key(node: &NamedOrBlankNode) -> String {
    match node {
        NamedOrBlankNode::NamedNode(n) => n.as_str().to_string(),
        NamedOrBlankNode::BlankNode(b) => format!("_:{}", b.as_str()),
    }
}

fn object_key(term: &Term) -> Option<String> {
    if let Term::NamedNode(n) = term {
        return Some(n.as_str().to_string());
    }
    if let Term::BlankNode(b) = term {
        return Some(format!("_:{}", b.as_str()));
    }
    None
}

fn object_literal(term: &Term) -> Option<&str> {
    if let Term::Literal(l) = term {
        return Some(l.value());
    }
    None
}

impl Graph {
    fn parse(text: &str, arg: &str, what: &str) -> Result<Graph> {
        let triples = TurtleParser::new()
            .for_slice(text.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::InvalidArgument {
                name: arg.to_string(),
                detail: format!("{what} is not valid Turtle: {e}"),
            })?;
        Ok(Graph { triples })
    }

    fn objects<'a>(
        &'a self,
        subject: &'a str,
        predicate: &'a str,
    ) -> impl Iterator<Item = &'a Term> {
        self.triples
            .iter()
            .filter(move |t| key(&t.subject) == subject && t.predicate.as_str() == predicate)
            .map(|t| &t.object)
    }

    fn of_class(&self, class: &str) -> BTreeSet<String> {
        self.triples
            .iter()
            .filter(|t| {
                t.predicate.as_str() == RDF_TYPE && object_key(&t.object).as_deref() == Some(class)
            })
            .map(|t| key(&t.subject))
            .collect()
    }

    fn with_predicate(&self, predicate: &str) -> BTreeSet<String> {
        self.triples
            .iter()
            .filter(|t| t.predicate.as_str() == predicate)
            .map(|t| key(&t.subject))
            .collect()
    }

    /// The one literal of `subject predicate`, or `None` when there is none. Two is a
    /// refusal: the read cannot choose between them.
    fn literal(&self, subject: &str, predicate: &str, arg: &str) -> Result<Option<String>> {
        let mut values = self.objects(subject, predicate);
        let first = values.next();
        if values.next().is_some() {
            return Err(Error::InvalidArgument {
                name: arg.to_string(),
                detail: format!("<{subject}> has more than one <{predicate}>"),
            });
        }
        match first {
            None => Ok(None),
            Some(term) => object_literal(term)
                .map(|v| Some(v.to_string()))
                .ok_or_else(|| Error::InvalidArgument {
                    name: arg.to_string(),
                    detail: format!("<{subject}> <{predicate}> is not a literal"),
                }),
        }
    }

    fn iri(&self, subject: &str, predicate: &str, arg: &str) -> Result<Option<String>> {
        let mut values = self.objects(subject, predicate);
        let first = values.next();
        if values.next().is_some() {
            return Err(Error::InvalidArgument {
                name: arg.to_string(),
                detail: format!("<{subject}> has more than one <{predicate}>"),
            });
        }
        match first {
            None => Ok(None),
            Some(term) => object_key(term)
                .map(Some)
                .ok_or_else(|| Error::InvalidArgument {
                    name: arg.to_string(),
                    detail: format!("<{subject}> <{predicate}> is not a node"),
                }),
        }
    }
}

/// Refuse a plan over [`MAX_PLAN_BYTES`] (never truncate it), before anything is parsed or
/// sent anywhere.
pub fn check_bound(source: &str) -> Result<()> {
    if source.len() > MAX_PLAN_BYTES {
        return Err(Error::InvalidArgument {
            name: "content".to_string(),
            detail: format!(
                "the plan is {} bytes; a plan is at most {MAX_PLAN_BYTES}",
                source.len()
            ),
        });
    }
    Ok(())
}

fn ik(term: &str) -> String {
    format!("{IK}{term}")
}

/// Read a plan for what this crate decides itself: its process node, the verb of every step
/// and its declared parameters. Every refusal is an `InvalidArgument` on `content`.
///
/// A step is any node typed `ik:Step` or carrying an `ik:verb`: the wider of the two, so a
/// mutating step cannot hide from the read/write decision by leaving off its type.
pub fn analyze(source: &str) -> Result<Analysis> {
    const ARG: &str = "content";
    check_bound(source)?;
    let graph = Graph::parse(source, ARG, "the plan")?;
    let processes = graph.of_class(&ik("Process"));
    let process = match processes.len() {
        1 => processes.into_iter().next().expect("one"),
        0 => {
            return Err(Error::InvalidArgument {
                name: ARG.to_string(),
                detail: "no ik:Process in this graph: it is not a plan".to_string(),
            })
        }
        n => {
            return Err(Error::InvalidArgument {
                name: ARG.to_string(),
                detail: format!("{n} ik:Process nodes in one graph; a plan holds exactly one"),
            })
        }
    };

    let mut step_iris = graph.of_class(&ik("Step"));
    step_iris.extend(graph.with_predicate(&ik("verb")));
    let mut steps = Vec::with_capacity(step_iris.len());
    for iri in step_iris {
        let verb =
            graph
                .literal(&iri, &ik("verb"), ARG)?
                .ok_or_else(|| Error::InvalidArgument {
                    name: ARG.to_string(),
                    detail: format!("<{iri}> is a step with no ik:verb"),
                })?;
        if !matches!(
            verb.as_str(),
            "Source" | "Sink" | "Exists" | "Delete" | "Meta"
        ) {
            return Err(Error::InvalidArgument {
                name: ARG.to_string(),
                detail: format!(
                    "<{iri}> issues \"{verb}\"; a step issues one of Source, Sink, Exists, \
                     Delete, Meta"
                ),
            });
        }
        let resolves = graph.iri(&iri, &ik("resolves"), ARG)?.unwrap_or_default();
        steps.push(Step {
            iri,
            verb,
            resolves,
        });
    }

    let mut parameters = Vec::new();
    for node in graph.objects(&process, &ik("input")) {
        let Some(node) = object_key(node) else {
            return Err(Error::InvalidArgument {
                name: ARG.to_string(),
                detail: format!("<{process}> ik:input is not a node"),
            });
        };
        let name = graph
            .literal(&node, &ik("inputName"), ARG)?
            .ok_or_else(|| Error::InvalidArgument {
                name: ARG.to_string(),
                detail: format!("<{node}> is a parameter with no ik:inputName"),
            })?;
        if RESERVED_PARAMETERS.contains(&name.as_str()) {
            return Err(Error::InvalidArgument {
                name: ARG.to_string(),
                detail: format!(
                    "the parameter `{name}` would never arrive: {} are taken by the doors \
                     a plan runs through",
                    RESERVED_PARAMETERS.join(", ")
                ),
            });
        }
        let required = match graph.literal(&node, &ik("required"), ARG)?.as_deref() {
            None | Some("true") | Some("1") => true,
            Some("false") | Some("0") => false,
            Some(other) => {
                return Err(Error::InvalidArgument {
                    name: ARG.to_string(),
                    detail: format!("<{node}> ik:required \"{other}\" is not a boolean"),
                })
            }
        };
        parameters.push(Parameter {
            name,
            required,
            default: graph.literal(&node, &ik("default"), ARG)?,
            class: graph.iri(&node, &ik("class"), ARG)?,
            summary: graph.literal(&node, &ik("summary"), ARG)?,
        });
    }
    parameters.sort_by(|a, b| a.name.cmp(&b.name));
    if let Some(pair) = parameters.windows(2).find(|w| w[0].name == w[1].name) {
        return Err(Error::InvalidArgument {
            name: ARG.to_string(),
            detail: format!("the parameter `{}` is declared twice", pair[0].name),
        });
    }
    Ok(Analysis {
        process,
        steps,
        parameters,
    })
}

// ---------------------------------------------------------------------------------------
// Publish: validate, then derive
// ---------------------------------------------------------------------------------------

fn door_request(door: &str, plan: &str) -> Request {
    Request::new(Verb::Source, Iri::parse(door).expect("a constant IRI"))
        .with_arg("in", ArgRef::Inline(plan.as_bytes().to_vec()))
        .with_arg("as", ArgRef::Inline(TURTLE.as_bytes().to_vec()))
}

/// A door's refusal of the plan, said about the script's `content` (what the publisher
/// sent), and a door that is not there said as what it is: this host takes no plans.
fn from_door(door: &str, error: Error) -> Error {
    match error {
        Error::InvalidArgument { name, detail } if name == "in" => Error::InvalidArgument {
            name: "content".to_string(),
            detail: format!("{door}: {detail}"),
        },
        Error::Unresolved(_) => Error::InvalidArgument {
            name: "language".to_string(),
            detail: format!(
                "this host takes no plans: {door} does not resolve here (a host offers plans \
                 by binding the plan evaluator's three doors, {EVAL}, {VALIDATE} and \
                 {REQUIRES})"
            ),
        },
        other => other,
    }
}

/// Validate a plan through the host's `urn:plan:validate`, under the publisher's
/// capability. A plan that does not conform is refused with `InvalidArgument` on `content`,
/// naming every shape (or executor check) it broke, the node, and the shape's message.
pub async fn validate(inv: &Invocation<'_>, plan: &str) -> Result<()> {
    let report = inv
        .issue(door_request(VALIDATE, plan))
        .await
        .map_err(|e| from_door(VALIDATE, e))?;
    let text = String::from_utf8_lossy(&report.bytes);
    let graph = Graph::parse(&text, "content", &format!("{VALIDATE}'s report"))
        .map_err(|e| Error::Endpoint(e.to_string()))?;
    let sh = |term: &str| format!("{SH}{term}");
    let reports = graph.of_class(&sh("ValidationReport"));
    let Some(report_node) = reports.iter().next() else {
        return Err(Error::Endpoint(format!(
            "{VALIDATE} answered a report with no sh:ValidationReport"
        )));
    };
    let conforms = graph
        .objects(report_node, &sh("conforms"))
        .any(|o| object_literal(o) == Some("true"));
    if conforms {
        return Ok(());
    }
    let mut problems = Vec::new();
    for result in graph.objects(report_node, &sh("result")) {
        let Some(node) = object_key(result) else {
            continue;
        };
        let first = |predicate: &str| -> Option<String> {
            graph.objects(&node, &sh(predicate)).next().map(|o| {
                object_key(o)
                    .or_else(|| object_literal(o).map(str::to_string))
                    .unwrap_or_default()
            })
        };
        let rule = first("sourceConstraint")
            .or_else(|| first("sourceShape"))
            .or_else(|| first("sourceConstraintComponent"))
            .unwrap_or_else(|| "a SHACL constraint".to_string());
        let focus = first("focusNode").unwrap_or_default();
        let message = first("resultMessage").unwrap_or_default();
        problems.push(format!("{rule} at <{focus}>: {message}"));
    }
    problems.sort();
    Err(Error::InvalidArgument {
        name: "content".to_string(),
        detail: format!(
            "the plan does not validate ({VALIDATE}), so it is not stored: {}",
            if problems.is_empty() {
                "the report names no result".to_string()
            } else {
                problems.join("; ")
            }
        ),
    })
}

/// A plan's capability, DERIVED by the host's `urn:plan:requires` from its steps' contracts
/// (read with `Meta`, so nothing is invoked).
///
/// Refused, with `InvalidArgument` on `content`, when the derivation is incomplete: a step
/// whose target resolves nowhere (or whose contract cannot be read) has no known
/// requirement, and storing the rest would be storing a floor as the requirement. Refused
/// on `requires` when the publisher states a `requires` that is not exactly the derived set,
/// naming it: an author can neither under- nor over-declare.
pub async fn derive(
    inv: &Invocation<'_>,
    plan: &str,
    declared: Option<&str>,
) -> Result<BTreeSet<String>> {
    let answer = inv
        .issue(door_request(REQUIRES, plan))
        .await
        .map_err(|e| from_door(REQUIRES, e))?;
    let text = String::from_utf8_lossy(&answer.bytes);
    let graph = Graph::parse(&text, "content", &format!("{REQUIRES}'s answer"))
        .map_err(|e| Error::Endpoint(e.to_string()))?;
    let processes = graph.of_class(&ik("Process"));
    let [process] = processes.iter().collect::<Vec<_>>()[..] else {
        return Err(Error::Endpoint(format!(
            "{REQUIRES} answered {} ik:Process nodes; it describes exactly one plan",
            processes.len()
        )));
    };
    let outcome = graph.iri(process, &ik("outcome"), "content")?;
    if outcome.as_deref() != Some(&format!("{OUTCOME}complete")) {
        let mut unresolved = Vec::new();
        for step in graph.of_class(&ik("Step")) {
            let resolved = graph.iri(&step, &ik("outcome"), "content")?;
            if resolved.as_deref() == Some(&format!("{OUTCOME}resolved")) {
                continue;
            }
            let reasons: Vec<String> = graph
                .objects(&step, RDFS_COMMENT)
                .filter_map(object_literal)
                .map(str::to_string)
                .collect();
            unresolved.push(format!(
                "<{step}> ({})",
                if reasons.is_empty() {
                    "no reason given".to_string()
                } else {
                    reasons.join("; ")
                }
            ));
        }
        return Err(Error::InvalidArgument {
            name: "content".to_string(),
            detail: format!(
                "the plan's authority cannot be derived, so it is not stored: {REQUIRES} could \
                 not read every step's contract, and a partial set would be a floor, not the \
                 requirement. Unresolved: {}",
                if unresolved.is_empty() {
                    format!("{REQUIRES} answered {outcome:?} and named no step")
                } else {
                    unresolved.join(", ")
                }
            ),
        });
    }
    let derived: BTreeSet<String> = graph
        .objects(process, &ik("requires"))
        .filter_map(object_key)
        .collect();
    if let Some(bad) = derived.iter().find(|s| is_deny_scope(s)) {
        return Err(Error::Endpoint(format!(
            "{REQUIRES} derived the exclusion `{bad}`, which is not a requirement"
        )));
    }
    if let Some(said) = declared {
        let said: BTreeSet<String> = said.split_whitespace().map(str::to_string).collect();
        if said != derived {
            let listed = |set: &BTreeSet<String>| {
                if set.is_empty() {
                    "nothing".to_string()
                } else {
                    set.iter().cloned().collect::<Vec<_>>().join(" ")
                }
            };
            return Err(Error::InvalidArgument {
                name: "requires".to_string(),
                detail: format!(
                    "a plan's authority is derived from its steps' contracts, not declared, \
                     and this one derives {}; the `requires` given says {}. Omit `requires`",
                    listed(&derived),
                    listed(&said)
                ),
            });
        }
    }
    Ok(derived)
}

// ---------------------------------------------------------------------------------------
// Running
// ---------------------------------------------------------------------------------------

/// The scopes a plan run is issued under, with every derived FAMILY (`prefix*`) turned
/// into exact grants.
///
/// A family reaches a run's `keep` only as the marker a ROOT publisher's grant leaves
/// ([`crate::authority::effective`]); a scoped publisher's grant already holds the exact
/// members it had. Attenuation keeps grants by exact name, so the marker is replaced here:
///
/// - a scoped runner: each grant the runner holds under the prefix that the host's ceiling
///   allows (the publisher, root, held all of them);
/// - a root runner: each exact grant under the prefix that the ceiling NAMES, and the
///   family itself only when the ceiling allows the whole family (no ceiling, or a
///   `prefix*` line). Root cannot be enumerated, so then the run keeps the bare family: the kernel's floor (a presence test) admits the step, and
///   the target module's own rule (`urn:cap:net:<host>`, `urn:cap:fs:read:<path>`) refuses
///   it, fail closed. A host that wants a root-published plan with such a step to run under
///   root lists the members in the script's ceiling.
pub fn expand_families(
    keep: BTreeSet<String>,
    runner: &Capability,
    ceiling: &Ceiling,
) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for scope in keep {
        let Some(prefix) = scope.strip_suffix('*').filter(|_| !is_deny_scope(&scope)) else {
            out.insert(scope);
            continue;
        };
        match runner.scopes() {
            Some(held) => out.extend(
                held.iter()
                    .filter(|s| s.starts_with(prefix) && !s.ends_with('*') && !is_deny_scope(s))
                    .filter(|s| ceiling.allows(s))
                    .cloned(),
            ),
            None => {
                if let Ceiling::Scopes(named) = ceiling {
                    out.extend(
                        named
                            .iter()
                            .filter(|s| {
                                s.starts_with(prefix) && !s.ends_with('*') && !is_deny_scope(s)
                            })
                            .cloned(),
                    );
                }
                if ceiling.allows(&scope) {
                    out.insert(scope.clone());
                }
            }
        }
    }
    out
}

/// The request a run issues: `urn:plan:eval` with the plan as `in`, each given parameter by
/// its own name, and `as` when the caller asked for a face.
pub fn eval_request(
    program: &str,
    values: &BTreeMap<String, String>,
    face: Option<&str>,
) -> Request {
    let mut request = Request::new(Verb::Source, Iri::parse(EVAL).expect("a constant IRI"))
        .with_arg("in", ArgRef::Inline(program.as_bytes().to_vec()));
    for (name, value) in values {
        request = request.with_arg(name.clone(), ArgRef::Inline(value.as_bytes().to_vec()));
    }
    if let Some(face) = face {
        request = request.with_arg("as", ArgRef::Inline(face.as_bytes().to_vec()));
    }
    request
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(xs: &[&str]) -> BTreeSet<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    const TWO_STEPS: &str = r#"
@prefix ik: <https://ikigai-rs.dev/ns#> .
<urn:plan:p> a ik:Process ; ik:step <urn:plan:p:step:1> , <urn:plan:p:step:2> ;
    ik:result <urn:plan:p:step:2> .
<urn:plan:p:step:1> a ik:Step ; ik:verb "Source" ; ik:resolves <urn:a> .
<urn:plan:p:step:2> ik:verb "Sink" ; ik:resolves <urn:b> ; ik:pipeFrom <urn:plan:p:step:1> .
"#;

    #[test]
    fn a_sink_anywhere_makes_a_write_even_untyped() {
        let analysis = analyze(TWO_STEPS).unwrap();
        assert_eq!(analysis.steps.len(), 2);
        assert!(analysis.mutates());
        let read = TWO_STEPS.replace("\"Sink\"", "\"Exists\"");
        assert!(!analyze(&read).unwrap().mutates());
    }

    #[test]
    fn the_read_refuses_what_it_cannot_classify() {
        for (plan, says) in [
            ("not turtle at all {", "not valid Turtle"),
            ("<urn:x> <urn:y> <urn:z> .", "no ik:Process"),
            (
                &TWO_STEPS.replace("\"Sink\"", "\"Launch\"") as &str,
                "Launch",
            ),
            (
                &TWO_STEPS.replace("ik:verb \"Sink\"", "ik:verb \"Sink\" , \"Source\""),
                "more than one",
            ),
        ] {
            match analyze(plan) {
                Err(Error::InvalidArgument { name, detail }) => {
                    assert_eq!(name, "content");
                    assert!(detail.contains(says), "{says}: {detail}");
                }
                other => panic!("{says}: {other:?}"),
            }
        }
        let huge = format!("{TWO_STEPS}#{}", "x".repeat(MAX_PLAN_BYTES));
        assert!(analyze(&huge).is_err());
    }

    #[test]
    fn a_reserved_parameter_is_refused() {
        let plan = format!(
            "{TWO_STEPS}<urn:plan:p> ik:input <urn:plan:p:input:in> .\n\
             <urn:plan:p:input:in> ik:inputName \"in\" .\n"
        );
        assert!(matches!(analyze(&plan), Err(Error::InvalidArgument { .. })));
    }

    #[test]
    fn a_root_publishers_family_becomes_the_runners_members() {
        let keep = set(&["urn:cap:a", "urn:cap:net:*"]);
        let runner = Capability::scoped([
            "urn:cap:a",
            "urn:cap:net:example.com",
            "urn:cap:net:other.org",
            "urn:cap:net:-example.com/admin",
        ]);
        let ceiling = Ceiling::scoped(["urn:cap:a", "urn:cap:net:example.com"]);
        assert_eq!(
            expand_families(keep.clone(), &runner, &ceiling),
            set(&["urn:cap:a", "urn:cap:net:example.com"])
        );
        // Root runner: the members the ceiling names (and not the family it does not).
        assert_eq!(
            expand_families(keep.clone(), &Capability::root(), &ceiling),
            set(&["urn:cap:a", "urn:cap:net:example.com"])
        );
        // Root runner, no ceiling: nothing to enumerate, so the bare family, which the
        // floor admits and the module refuses.
        assert_eq!(
            expand_families(keep.clone(), &Capability::root(), &Ceiling::Unbounded),
            set(&["urn:cap:a", "urn:cap:net:*"])
        );
        // A ceiling that allows none of the family keeps none of it.
        assert_eq!(
            expand_families(keep, &Capability::root(), &Ceiling::scoped(["urn:cap:a"])),
            set(&["urn:cap:a"])
        );
    }
}
