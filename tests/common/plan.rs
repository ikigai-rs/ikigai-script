//! A TEST DOUBLE of the host's plan doors, honoring the contract part A of ledger #956 built
//! in ikigai-cli (`ikigai-engine`'s `plan_space`, cli PR 429): `urn:plan:eval`,
//! `urn:plan:validate` and `urn:plan:requires`.
//!
//! The double is kept now that the real doors are published (`ikigai-engine` 0.1.44 and
//! later): it states, in one file, the contract this crate relies on, and every plan suite
//! runs its cases against it AND against `ikigai_engine::plan_space::space()` beside
//! `ikigai_shacl::space()` (`common::both`, ledger #1222), so a drift between the two fails
//! a case rather than hiding in the double.
//!
//! What it honors, and where it is smaller than the real one:
//!
//! - **validate**: `in` = Turtle (not Turtle: `InvalidArgument{in}`); `as` = `text/turtle`
//!   (a report graph with `sh:conforms` and one `sh:result` per problem, naming the shape
//!   as `sh:sourceShape`, as rudof does) or `text/plain`. It checks a handful of the
//!   vocabulary's shapes by hand (one process, one result, one verb per step from the five,
//!   at most one feed per step), not SHACL.
//! - **requires**: each step's target contract by `Meta as=application/json` (invokes
//!   nothing), `Description::required_scopes(verb)`, per-step `ik:requires` / `ik:lacks` /
//!   `ik:outcome`, the plan-level union only when complete. Every step counts as reached.
//!   ⚠ The engine's does NOT: it derives and runs only the steps the result depends on (its
//!   `run_order`), so a step left dangling is neither in its derived authority nor run. Every
//!   fixture here therefore feeds each step into the result (the first run against the real
//!   doors found two that did not, ledger #1222).
//! - **eval**: validates first and refuses a non-conforming plan with `InvalidArgument{in}`;
//!   parameters by name (undeclared: `InvalidArgument{name}`, required with no default:
//!   `MissingArgument`, optional with none: the argument is omitted); steps run IN ORDER as
//!   sub-requests through the invocation (so under the caller's capability), each `ik:value`
//!   and `ik:ref` to a parameter passed by name, `ik:pipeFrom` passed as `content`; the
//!   answer is the result step's representation, marked cacheable. `as` must equal the
//!   served type (the double does not transrept). No map, fork or `ik:binds` references.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use ikigai_core::{
    ArgRef, Description, Endpoint, EndpointSpace, Error, Exact, Invocation, Iri, ReprType,
    Representation, Request, Result, Verb,
};
use oxrdf::{NamedOrBlankNode, Term, Triple};
use oxttl::TurtleParser;

const IK: &str = "https://ikigai-rs.dev/ns#";
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const OUTCOME: &str = "urn:ikigai:plan:requires:outcome:";

fn ik(term: &str) -> String {
    format!("{IK}{term}")
}

struct Graph(Vec<Triple>);

fn key(node: &NamedOrBlankNode) -> String {
    match node {
        NamedOrBlankNode::NamedNode(n) => n.as_str().to_string(),
        NamedOrBlankNode::BlankNode(b) => format!("_:{}", b.as_str()),
    }
}

fn node(term: &Term) -> Option<String> {
    if let Term::NamedNode(n) = term {
        return Some(n.as_str().to_string());
    }
    if let Term::BlankNode(b) = term {
        return Some(format!("_:{}", b.as_str()));
    }
    None
}

fn lit(term: &Term) -> Option<String> {
    if let Term::Literal(l) = term {
        return Some(l.value().to_string());
    }
    None
}

impl Graph {
    fn parse(text: &str) -> Result<Graph> {
        TurtleParser::new()
            .for_slice(text.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()
            .map(Graph)
            .map_err(|e| Error::InvalidArgument {
                name: "in".to_string(),
                detail: format!("the plan is not valid Turtle: {e}"),
            })
    }
    fn objects(&self, s: &str, p: &str) -> Vec<Term> {
        self.0
            .iter()
            .filter(|t| key(&t.subject) == s && t.predicate.as_str() == p)
            .map(|t| t.object.clone())
            .collect()
    }
    fn of_class(&self, class: &str) -> Vec<String> {
        let mut out: Vec<String> = self
            .0
            .iter()
            .filter(|t| {
                t.predicate.as_str() == RDF_TYPE && node(&t.object).as_deref() == Some(class)
            })
            .map(|t| key(&t.subject))
            .collect();
        out.sort();
        out.dedup();
        out
    }
    fn one_node(&self, s: &str, p: &str) -> Option<String> {
        self.objects(s, p).first().and_then(node)
    }
    fn one_lit(&self, s: &str, p: &str) -> Option<String> {
        self.objects(s, p).first().and_then(lit)
    }
}

struct Param {
    name: String,
    required: bool,
    default: Option<String>,
}

enum ArgValue {
    Value(String),
    Var(String),
}

struct Step {
    iri: String,
    verb: Verb,
    resolves: String,
    pipe: Option<String>,
    args: Vec<(String, ArgValue)>,
}

struct Plan {
    iri: String,
    params: Vec<Param>,
    steps: Vec<Step>,
    result: String,
}

fn verb(name: &str) -> Option<Verb> {
    Some(match name {
        "Source" => Verb::Source,
        "Sink" => Verb::Sink,
        "Exists" => Verb::Exists,
        "Delete" => Verb::Delete,
        "Meta" => Verb::Meta,
        _ => return None,
    })
}

fn verb_name(verb: Verb) -> &'static str {
    match verb {
        Verb::Source => "Source",
        Verb::Sink => "Sink",
        Verb::Exists => "Exists",
        Verb::Delete => "Delete",
        Verb::Meta => "Meta",
    }
}

/// `urn:plan:p:step:10` after `…:step:9`.
fn step_number(iri: &str) -> usize {
    iri.rsplit(':')
        .next()
        .and_then(|n| n.parse().ok())
        .unwrap_or(usize::MAX)
}

struct Problem {
    shape: &'static str,
    focus: String,
    message: &'static str,
}

/// The double's validation: the problems, and the plan when there are none.
fn check(graph: &Graph) -> (Vec<Problem>, Option<Plan>) {
    let mut problems = Vec::new();
    let processes = graph.of_class(&ik("Process"));
    let [process] = processes.as_slice() else {
        problems.push(Problem {
            shape: "urn:ikigai:shape:process",
            focus: processes.first().cloned().unwrap_or_default(),
            message: "a plan holds exactly one ik:Process",
        });
        return (problems, None);
    };
    let results = graph.objects(process, &ik("result"));
    if results.len() != 1 {
        problems.push(Problem {
            shape: "urn:ikigai:shape:process:result",
            focus: process.clone(),
            message: "a process has exactly one ik:result (a step or fork of the same plan)",
        });
    }
    let mut step_iris: Vec<String> = graph
        .objects(process, &ik("step"))
        .iter()
        .filter_map(node)
        .collect();
    step_iris.sort_by_key(|iri| step_number(iri));
    let mut steps = Vec::new();
    for iri in &step_iris {
        let verbs = graph.objects(iri, &ik("verb"));
        let v = match verbs.as_slice() {
            [one] => lit(one).as_deref().and_then(verb),
            _ => None,
        };
        let Some(v) = v else {
            problems.push(Problem {
                shape: "urn:ikigai:shape:step",
                focus: iri.clone(),
                message: "a step issues exactly one verb: Source, Sink, Exists, Delete, or Meta",
            });
            continue;
        };
        let feeds = ["pipeFrom", "mapOver", "forkOf"]
            .iter()
            .map(|p| graph.objects(iri, &ik(p)).len())
            .sum::<usize>();
        if feeds > 1 {
            problems.push(Problem {
                shape: "urn:ikigai:shape:step",
                focus: iri.clone(),
                message: "a step is fed by at most one of ik:pipeFrom, ik:mapOver, ik:forkOf",
            });
        }
        let mut args = Vec::new();
        for arg in graph.objects(iri, &ik("argument")).iter().filter_map(node) {
            let name = graph.one_lit(&arg, &ik("inputName")).unwrap_or_default();
            let value = match (
                graph.one_lit(&arg, &ik("value")),
                graph.one_node(&arg, &ik("ref")),
            ) {
                (Some(v), _) => ArgValue::Value(v),
                (None, Some(r)) => {
                    ArgValue::Var(r.rsplit(":var:").next().unwrap_or("").to_string())
                }
                (None, None) => ArgValue::Value(String::new()),
            };
            args.push((name, value));
        }
        steps.push(Step {
            iri: iri.clone(),
            verb: v,
            resolves: graph.one_node(iri, &ik("resolves")).unwrap_or_default(),
            pipe: graph.one_node(iri, &ik("pipeFrom")),
            args,
        });
    }
    let params = graph
        .objects(process, &ik("input"))
        .iter()
        .filter_map(node)
        .map(|n| Param {
            name: graph.one_lit(&n, &ik("inputName")).unwrap_or_default(),
            required: graph.one_lit(&n, &ik("required")).as_deref() != Some("false"),
            default: graph.one_lit(&n, &ik("default")),
        })
        .collect();
    if !problems.is_empty() {
        return (problems, None);
    }
    let result = graph.one_node(process, &ik("result")).unwrap_or_default();
    (
        problems,
        Some(Plan {
            iri: process.clone(),
            params,
            steps,
            result,
        }),
    )
}

fn in_text(inv: &Invocation<'_>) -> Result<String> {
    Ok(inv.inline_str("in")?.to_string())
}

fn face(inv: &Invocation<'_>) -> Option<String> {
    inv.inline_str("as").ok().map(|s| s.trim().to_string())
}

fn text(body: String, media: &str) -> Representation {
    Representation::new(ReprType::new(media), body.into_bytes()).cacheable()
}

/// `urn:plan:validate`.
pub struct Validate;

#[async_trait]
impl Endpoint for Validate {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        let graph = Graph::parse(&in_text(inv)?)?;
        let (problems, _) = check(&graph);
        if face(inv).as_deref() == Some("text/turtle") {
            let mut out = format!(
                "@prefix sh: <http://www.w3.org/ns/shacl#> .\n<urn:test:report> a \
                 sh:ValidationReport ; sh:conforms {} .\n",
                problems.is_empty()
            );
            for (i, p) in problems.iter().enumerate() {
                out.push_str(&format!(
                    "<urn:test:report> sh:result <urn:test:result:{i}> .\n<urn:test:result:{i}> \
                     a sh:ValidationResult ; sh:sourceShape <{}> ; sh:focusNode <{}> ; \
                     sh:resultMessage \"{}\" .\n",
                    p.shape, p.focus, p.message
                ));
            }
            return Ok(text(out, "text/turtle"));
        }
        let body = if problems.is_empty() {
            "the plan conforms\n".to_string()
        } else {
            problems
                .iter()
                .map(|p| format!("{} at <{}>: {}\n", p.shape, p.focus, p.message))
                .collect()
        };
        Ok(text(body, "text/plain"))
    }
    fn name(&self) -> &str {
        "plan-validate"
    }
    fn describe(&self) -> Description {
        Description::new("plan-validate")
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .output("text/plain")
            .output("text/turtle")
    }
}

/// `urn:plan:requires`.
pub struct Requires;

#[async_trait]
impl Endpoint for Requires {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        let graph = Graph::parse(&in_text(inv)?)?;
        let (problems, plan) = check(&graph);
        let Some(plan) = plan else {
            return Err(Error::InvalidArgument {
                name: "in".to_string(),
                detail: problems[0].message.to_string(),
            });
        };
        let mut union = BTreeSet::new();
        let mut complete = true;
        let mut steps = String::new();
        for step in &plan.steps {
            let meta = Request::new(Verb::Meta, Iri::parse(&step.resolves).expect("an IRI"))
                .with_arg("as", ArgRef::Inline(b"application/json".to_vec()));
            let contract = match inv.issue(meta).await {
                Ok(repr) => {
                    serde_json::from_slice::<Description>(&repr.bytes).map_err(|e| e.to_string())
                }
                Err(e) => Err(e.to_string()),
            };
            steps.push_str(&format!(
                "<{}> a ik:Step ; ik:verb \"{}\" ; ik:resolves <{}>",
                step.iri,
                verb_name(step.verb),
                step.resolves
            ));
            match contract {
                Ok(description) => {
                    let needs = description.required_scopes(step.verb);
                    let lacks = description.unsatisfied_scopes(step.verb, inv.capability);
                    steps.push_str(&format!(" ; ik:outcome <{OUTCOME}resolved>"));
                    for scope in &needs {
                        steps.push_str(&format!(" ; ik:requires <{scope}>"));
                    }
                    for scope in &lacks {
                        steps.push_str(&format!(" ; ik:lacks <{scope}>"));
                    }
                    union.extend(needs);
                }
                Err(reason) => {
                    complete = false;
                    steps.push_str(&format!(
                        " ; ik:outcome <{OUTCOME}unresolved> ; rdfs:comment {:?}",
                        format!("<{}>: {reason}", step.resolves)
                    ));
                }
            }
            steps.push_str(" .\n");
        }
        let mut out = format!(
            "@prefix ik: <{IK}> .\n@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .\n\
             <{}> a ik:Process ; ik:outcome <{OUTCOME}{}>",
            plan.iri,
            if complete { "complete" } else { "incomplete" }
        );
        if complete {
            for scope in &union {
                out.push_str(&format!(" ; ik:requires <{scope}>"));
            }
        }
        out.push_str(" .\n");
        out.push_str(&steps);
        if face(inv).as_deref() == Some("text/turtle") {
            Ok(text(out, "text/turtle"))
        } else {
            Ok(text(
                format!("<{}> requires {:?}\n", plan.iri, union),
                "text/plain",
            ))
        }
    }
    fn name(&self) -> &str {
        "plan-requires"
    }
    fn describe(&self) -> Description {
        Description::new("plan-requires")
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .output("text/plain")
            .output("text/turtle")
    }
}

/// `urn:plan:eval`, counted.
pub struct Eval {
    pub calls: Arc<AtomicUsize>,
}

#[async_trait]
impl Endpoint for Eval {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let graph = Graph::parse(&in_text(inv)?)?;
        let (problems, plan) = check(&graph);
        let Some(plan) = plan else {
            let p = &problems[0];
            return Err(Error::InvalidArgument {
                name: "in".to_string(),
                detail: format!(
                    "the plan does not validate, so it does not run: {} at <{}>: {}",
                    p.shape, p.focus, p.message
                ),
            });
        };
        let mut supplied = BTreeMap::new();
        for name in inv.request.args.keys() {
            if name == "in" || name == "as" {
                continue;
            }
            if !plan.params.iter().any(|p| &p.name == name) {
                return Err(Error::InvalidArgument {
                    name: name.clone(),
                    detail: "is not a parameter this plan declares".to_string(),
                });
            }
            supplied.insert(name.clone(), inv.inline_str(name)?.to_string());
        }
        let mut vars = BTreeMap::new();
        for p in &plan.params {
            match supplied.get(&p.name).cloned().or_else(|| p.default.clone()) {
                Some(v) => {
                    vars.insert(p.name.clone(), v);
                }
                None if p.required => return Err(Error::MissingArgument(p.name.clone())),
                None => {}
            }
        }
        let mut outputs: BTreeMap<String, Representation> = BTreeMap::new();
        for step in &plan.steps {
            let mut request = Request::new(step.verb, Iri::parse(&step.resolves).expect("an IRI"));
            for (name, value) in &step.args {
                let value = match value {
                    ArgValue::Value(v) => Some(v.clone()),
                    ArgValue::Var(var) => vars.get(var).cloned(),
                };
                if let Some(value) = value {
                    request = request.with_arg(name.clone(), ArgRef::Inline(value.into_bytes()));
                }
            }
            if let Some(up) = &step.pipe {
                let bytes = outputs.get(up).map(|r| r.bytes.clone()).unwrap_or_default();
                request = request.with_arg("content", ArgRef::Inline(bytes));
            }
            // Through the invocation: under the CALLER's capability, recorded.
            let answer = inv.issue(request).await?;
            outputs.insert(step.iri.clone(), answer);
        }
        let answer = outputs
            .remove(&plan.result)
            .ok_or_else(|| Error::InvalidArgument {
                name: "in".to_string(),
                detail: "the result is not a step this double ran".to_string(),
            })?;
        if let Some(asked) = face(inv) {
            if asked != answer.repr_type.media_type {
                return Err(Error::InvalidArgument {
                    name: "as".to_string(),
                    detail: format!(
                        "the plan's result is `{}`, and nothing converts it to `{asked}`",
                        answer.repr_type.media_type
                    ),
                });
            }
        }
        Ok(Representation::new(answer.repr_type, answer.bytes).cacheable())
    }
    fn name(&self) -> &str {
        "plan-eval"
    }
    fn describe(&self) -> Description {
        Description::new("plan-eval")
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .output("text/plain")
    }
}

/// The three doors, `urn:plan:eval` counted by `calls`.
pub fn doors(calls: Arc<AtomicUsize>) -> EndpointSpace {
    EndpointSpace::new()
        .bind(Exact::new("urn:plan:eval"), Eval { calls })
        .bind(Exact::new("urn:plan:validate"), Validate)
        .bind(Exact::new("urn:plan:requires"), Requires)
}
