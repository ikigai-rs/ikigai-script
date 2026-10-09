//! **SPARQL as a script language**: a stored query is a script whose language is SPARQL.
//!
//! A query gets everything a Lisp script gets (versions, the three authorities, run records,
//! the manifold) and three things of its own, all read from the PARSED text, never from a
//! caller's argument:
//!
//! - **its form**: SELECT, ASK, CONSTRUCT and DESCRIBE run as reads (`…:result`); an UPDATE
//!   runs as a write (`…:runs`). See [`Form`].
//! - **its parameters**, declared in the query's leading comment block and bound as typed
//!   RDF terms by substitution into the parsed algebra, never by splicing text. See
//!   [`Parameter`] and [`bind`].
//! - **its authority**, derived from the graphs it names: `urn:cap:store:read:graph:<g>` for
//!   each graph a query reads, `urn:cap:store:write:graph:<g>` (and the read token when it
//!   has a `WHERE`) for the one graph an update writes. See [`Analysis::requires`].
//!
//! # Declaring parameters
//!
//! In the comment block before the query's first token, one line per parameter:
//!
//! ```text
//! # @param <name> <type> [required | optional | default <value>] [-- <summary>]
//! ```
//!
//! - `<name>` is the query variable it binds (`?days` or `$days` in the text), ASCII letters,
//!   digits and `_`. `as`, `name` and `content` are taken by the doors.
//! - `<type>` is an XSD datatype (`xsd:integer`, `xsd:dateTime`, …: see [`DATATYPES`]),
//!   bound as a typed literal after its lexical form is checked; or a class (`<iri>`, or
//!   `rdfs:Resource` for "any IRI"), bound as an IRI.
//! - Bare means required; `default <value>` makes it optional with that value (a value with
//!   a space in it is a JSON string, `"like this"`).
//!
//! ```
//! use ikigai_script::sparql::{analyze, Form, SparqlDoor};
//!
//! // (`##` is how rustdoc spells a line that starts with `#`.)
//! let text = r#"
//! ## Items untouched for a while.
//! ## @param days xsd:integer default 7 -- days without a touch
//! ## @param repo <https://ikigai-rs.dev/ns#Repo> optional
//! PREFIX ledger: <https://ikigai-rs.dev/ns/ledger#>
//! SELECT ?item WHERE {
//!   GRAPH <urn:iki:ledger:default> {
//!     ?item ledger:age ?age ; ledger:repo ?repo FILTER(?age > ?days)
//!   }
//! }"#;
//! let analysis = analyze(text, &SparqlDoor::store()).unwrap();
//! assert_eq!(analysis.form, Form::Select);
//! assert_eq!(analysis.parameters[0].name, "days");
//! assert_eq!(analysis.parameters[0].default.as_deref(), Some("7"));
//! assert!(!analysis.parameters[1].required);
//! // Authority comes from the graphs the text names, never from the author.
//! assert_eq!(
//!     analysis.requires().into_iter().collect::<Vec<_>>(),
//!     vec!["urn:cap:store:read:graph:urn:iki:ledger:default".to_string()]
//! );
//! ```
//!
//! # The dataset, and why some queries are refused at publish
//!
//! Evaluation is a sub-request to the host's store through its graph-scoped doors
//! (`urn:iki:store:graph-{select,ask,construct,describe}` and `…:graph-update`), so the
//! store's bounds and tenancy apply unchanged. Those doors take ONE set of graphs `G`: the
//! default graph is the merge of `G` and the named graphs are `G` (ikigai-store's
//! `src/scope.rs`). A script's `G` is every graph its text names: `FROM`, `FROM NAMED` and
//! `GRAPH <iri>` all add to it, and the clauses themselves are removed from the text the
//! store sees (that door refuses them, because `graph=` IS the dataset).
//!
//! That is one dataset where SPARQL has two, so a query whose answer would CHANGE under it
//! is refused at publish rather than answered differently:
//!
//! - a query that reads the default graph (a pattern outside every `GRAPH` block, or a
//!   `DESCRIBE`) must name its whole dataset with `FROM` (or the host gives one,
//!   [`SparqlDoor::default_graphs`]): a `FROM NAMED` or `GRAPH <iri>` graph outside it would
//!   join the merge its bare patterns read, and a `GRAPH ?g` would pull the caller's whole
//!   readable union into it;
//! - a query that names no graph at all and has no variable `GRAPH` reads nothing.
//!
//! A `GRAPH ?g` whose graph the text does not fix runs over **the caller's readable union**
//! (and never more): the graphs the run may read, computed per run.

use std::collections::{BTreeMap, BTreeSet};

use ikigai_core::{Error, Result};
use serde::{Deserialize, Serialize};
use spargebra::algebra::{
    AggregateExpression, Expression, GraphPattern, GraphTarget, OrderExpression, QueryDataset,
};
use spargebra::term::{
    GraphName, GraphNamePattern, GroundQuadPattern, GroundTermPattern, Literal, NamedNode,
    NamedNodePattern, QuadPattern, TermPattern, TriplePattern, Variable,
};
use spargebra::{GraphUpdateOperation, Query, SparqlParser, Update};

use crate::limits;

/// The store's per-graph read scope, as a family: "holds SOME grant under this prefix".
/// A query that reads the caller's readable union (`GRAPH ?g`) declares it.
pub const CAP_READ_GRAPH: &str = "urn:cap:store:read:graph:*";
/// The prefix of every per-graph read grant.
pub const READ_GRAPH_PREFIX: &str = "urn:cap:store:read:graph:";
/// The prefix of every per-graph write grant.
pub const WRITE_GRAPH_PREFIX: &str = "urn:cap:store:write:graph:";
/// The store's broad read scope: what enumerating every graph needs when the run's
/// authority is root (see `urn:iki:store:graphs`).
pub const CAP_STORE_READ: &str = "urn:cap:store:read";

/// The exact grant to read graph `iri` through the store's scoped doors.
pub fn cap_read_graph(iri: &str) -> String {
    format!("{READ_GRAPH_PREFIX}{iri}")
}

/// The exact grant to write graph `iri` through `urn:iki:store:graph-update`.
pub fn cap_write_graph(iri: &str) -> String {
    format!("{WRITE_GRAPH_PREFIX}{iri}")
}

const XSD: &str = "http://www.w3.org/2001/XMLSchema#";
const RDFS_RESOURCE: &str = "http://www.w3.org/2000/01/rdf-schema#Resource";

/// The XSD datatypes a parameter may declare, by local name. A value's lexical form is
/// checked against its type and bound in its canonical form, so `007` binds as `7`.
pub const DATATYPES: [&str; 13] = [
    "string",
    "boolean",
    "integer",
    "decimal",
    "double",
    "float",
    "date",
    "dateTime",
    "time",
    "duration",
    "dayTimeDuration",
    "yearMonthDuration",
    "anyURI",
];

/// Names a parameter may not take: each is an argument a door already reads.
pub const RESERVED_PARAMETERS: [&str; 3] = ["as", "name", "content"];

/// The result faces of SELECT and ASK, default first.
pub const RESULT_FACES: [&str; 4] = [
    "application/sparql-results+json",
    "application/sparql-results+xml",
    "text/csv",
    "text/tab-separated-values",
];
/// The faces of CONSTRUCT and DESCRIBE, default first.
pub const GRAPH_FACES: [&str; 2] = ["text/turtle", "application/n-triples"];

// ---------------------------------------------------------------------------------------
// The host's door
// ---------------------------------------------------------------------------------------

/// Where a host evaluates SPARQL scripts: the store's graph-scoped doors, under a prefix.
///
/// A host decides this, as it decides which evaluator a Lisp script reaches. Evaluation is
/// always a sub-request, so the store's bounds (the pre-parse nesting bound, the sized
/// stack, any time budget) and its tenancy apply to every run; this crate never evaluates
/// a query itself.
///
/// ```
/// use ikigai_script::sparql::{Form, SparqlDoor};
/// let door = SparqlDoor::store();
/// assert_eq!(door.query_iri(Form::Select), "urn:iki:store:graph-select");
/// assert_eq!(door.query_iri(Form::Update), "urn:iki:store:graph-update");
/// assert_eq!(door.graphs_iri(), "urn:iki:store:graphs");
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SparqlDoor {
    prefix: String,
    default_graphs: BTreeSet<String>,
}

impl SparqlDoor {
    /// `ikigai-store` bound at its own names, `urn:iki:store:`, with no default dataset.
    pub fn store() -> SparqlDoor {
        SparqlDoor::store_at("urn:iki:store:")
    }

    /// `ikigai-store`'s doors under another prefix (a host that mounts the store elsewhere).
    /// The prefix ends in `:`.
    pub fn store_at(prefix: impl Into<String>) -> SparqlDoor {
        SparqlDoor {
            prefix: prefix.into(),
            default_graphs: BTreeSet::new(),
        }
    }

    /// The graphs a query reads when it reads the default graph and names none with
    /// `FROM`: this host's default dataset. They are part of what such a query DERIVES, so
    /// its runs need their read grants like any other graph's. ⚠ Changing them changes what
    /// a published query reads at its next run; republish to restate its `requires`.
    pub fn default_graphs<I, S>(mut self, graphs: I) -> SparqlDoor
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.default_graphs = graphs.into_iter().map(Into::into).collect();
        self
    }

    /// The door a query of `form` is issued to: `{prefix}graph-{form}`.
    pub fn query_iri(&self, form: Form) -> String {
        format!("{}graph-{}", self.prefix, form.as_str())
    }

    /// The door that lists which graphs a caller may read: `{prefix}graphs`.
    pub fn graphs_iri(&self) -> String {
        format!("{}graphs", self.prefix)
    }

    /// The host's default dataset.
    pub fn defaults(&self) -> &BTreeSet<String> {
        &self.default_graphs
    }
}

// ---------------------------------------------------------------------------------------
// Forms and parameters
// ---------------------------------------------------------------------------------------

/// What a SPARQL script is, read from its parsed text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Form {
    /// SELECT: a result set.
    Select,
    /// ASK: a boolean result.
    Ask,
    /// CONSTRUCT: a graph.
    Construct,
    /// DESCRIBE: a graph.
    Describe,
    /// An UPDATE: a write.
    Update,
}

impl Form {
    /// The word the store's doors and every face use.
    pub fn as_str(self) -> &'static str {
        match self {
            Form::Select => "select",
            Form::Ask => "ask",
            Form::Construct => "construct",
            Form::Describe => "describe",
            Form::Update => "update",
        }
    }

    /// Whether running it is a READ (`…:result`); an update is a write (`…:runs` only).
    pub fn is_read(self) -> bool {
        self != Form::Update
    }

    /// The faces a run of this form can answer in, default first: the SPARQL 1.1 result
    /// formats for SELECT and ASK, Turtle and N-Triples for CONSTRUCT and DESCRIBE, plain
    /// text for an update (the store's report).
    pub fn faces(self) -> &'static [&'static str] {
        match self {
            Form::Select | Form::Ask => &RESULT_FACES,
            Form::Construct | Form::Describe => &GRAPH_FACES,
            Form::Update => &["text/plain"],
        }
    }
}

/// What a parameter's value is.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", tag = "kind", content = "iri")]
pub enum ParamType {
    /// A typed literal of this XSD datatype (its full IRI).
    Datatype(String),
    /// An IRI naming an instance of this class (its full IRI; `rdfs:Resource` for any).
    Class(String),
}

impl ParamType {
    /// The IRI an `ArgSpec` carries as its `class`.
    pub fn iri(&self) -> &str {
        match self {
            ParamType::Datatype(iri) | ParamType::Class(iri) => iri,
        }
    }
}

/// One declared parameter of a SPARQL script.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Parameter {
    /// The variable it binds, and the argument a run passes it as.
    pub name: String,
    /// What its value is.
    #[serde(rename = "type")]
    pub kind: ParamType,
    /// Whether a run must pass it.
    pub required: bool,
    /// The value an absent argument takes, in its lexical form.
    pub default: Option<String>,
    /// What it means, for the catalog.
    pub summary: Option<String>,
}

/// A parameter's value as an RDF term.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// An IRI (a class-typed parameter).
    Iri(NamedNode),
    /// A typed literal (a datatype-typed parameter).
    Literal(Literal),
}

impl Parameter {
    /// Check `lexical` against this parameter's type and make it a term: a typed literal
    /// in its canonical form, or an IRI. Refused with `InvalidArgument` naming the
    /// parameter when it is not one.
    ///
    /// ```
    /// use ikigai_script::sparql::{ParamType, Parameter, Value};
    /// let days = Parameter {
    ///     name: "days".into(),
    ///     kind: ParamType::Datatype("http://www.w3.org/2001/XMLSchema#integer".into()),
    ///     required: true,
    ///     default: None,
    ///     summary: None,
    /// };
    /// match days.value("007").unwrap() {
    ///     Value::Literal(l) => assert_eq!(l.to_string(), "\"7\"^^<http://www.w3.org/2001/XMLSchema#integer>"),
    ///     other => panic!("{other:?}"),
    /// }
    /// assert!(days.value("seven").is_err());
    /// // Whatever a string parameter holds, it is ONE literal: the serializer escapes it.
    /// let text = Parameter { kind: ParamType::Datatype("http://www.w3.org/2001/XMLSchema#string".into()), ..days };
    /// match text.value("\" } ; DROP ALL ; #").unwrap() {
    ///     Value::Literal(l) => assert_eq!(l.value(), "\" } ; DROP ALL ; #"),
    ///     other => panic!("{other:?}"),
    /// }
    /// ```
    pub fn value(&self, lexical: &str) -> Result<Value> {
        let bad = |detail: String| Error::InvalidArgument {
            name: self.name.clone(),
            detail,
        };
        match &self.kind {
            ParamType::Class(class) => {
                NamedNode::new(lexical.trim()).map(Value::Iri).map_err(|e| {
                    bad(format!(
                        "`{lexical}` is not an IRI ({e}); this parameter names an instance of \
                         <{class}>"
                    ))
                })
            }
            ParamType::Datatype(datatype) => {
                let local = datatype.strip_prefix(XSD).unwrap_or(datatype);
                let canonical = canonical(local, lexical)
                    .ok_or_else(|| bad(format!("`{lexical}` is not a valid xsd:{local}")))?;
                Ok(Value::Literal(Literal::new_typed_literal(
                    canonical,
                    NamedNode::new_unchecked(datatype.clone()),
                )))
            }
        }
    }
}

/// The canonical lexical form of `lexical` as `xsd:{local}`, or `None` when it is not one.
fn canonical(local: &str, lexical: &str) -> Option<String> {
    use oxsdatatypes::{
        Boolean, Date, DateTime, DayTimeDuration, Decimal, Double, Duration, Float, Integer, Time,
        YearMonthDuration,
    };
    // XSD's whitespace facet is `collapse` for every type here but string.
    let t = lexical.trim();
    match local {
        "string" => Some(lexical.to_string()),
        "anyURI" => Some(t.to_string()),
        "boolean" => t.parse::<Boolean>().ok().map(|v| v.to_string()),
        "integer" => t.parse::<Integer>().ok().map(|v| v.to_string()),
        "decimal" => t.parse::<Decimal>().ok().map(|v| v.to_string()),
        "double" => t.parse::<Double>().ok().map(|v| v.to_string()),
        "float" => t.parse::<Float>().ok().map(|v| v.to_string()),
        "date" => t.parse::<Date>().ok().map(|v| v.to_string()),
        "dateTime" => t.parse::<DateTime>().ok().map(|v| v.to_string()),
        "time" => t.parse::<Time>().ok().map(|v| v.to_string()),
        "duration" => t.parse::<Duration>().ok().map(|v| v.to_string()),
        "dayTimeDuration" => t.parse::<DayTimeDuration>().ok().map(|v| v.to_string()),
        "yearMonthDuration" => t.parse::<YearMonthDuration>().ok().map(|v| v.to_string()),
        _ => None,
    }
}

fn invalid(detail: impl Into<String>) -> Error {
    Error::InvalidArgument {
        name: "content".to_string(),
        detail: detail.into(),
    }
}

/// The parameters declared in `source`'s leading comment block.
///
/// Only that block declares: before the first token, a `#` line is a comment and nothing
/// else. A declaration-shaped comment after it is refused rather than ignored, because an
/// ignored declaration leaves its variable unbound and the query silently answers a
/// different question.
pub fn parameters(source: &str) -> Result<Vec<Parameter>> {
    let mut out: Vec<Parameter> = Vec::new();
    let mut header = true;
    for (number, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        let comment = trimmed.strip_prefix('#').map(str::trim_start);
        if header && trimmed.is_empty() {
            continue;
        }
        match comment {
            Some(body) if header => {
                if let Some(rest) = body.strip_prefix("@param") {
                    if !rest.starts_with(char::is_whitespace) {
                        return Err(invalid(format!(
                            "line {}: `@param` needs a name and a type",
                            number + 1
                        )));
                    }
                    let parameter = declaration(rest, number + 1)?;
                    if out.iter().any(|p| p.name == parameter.name) {
                        return Err(invalid(format!(
                            "line {}: `{}` is declared twice",
                            number + 1,
                            parameter.name
                        )));
                    }
                    out.push(parameter);
                }
            }
            Some(body) if body.starts_with("@param") => {
                return Err(invalid(format!(
                    "line {}: a parameter is declared only in the comment block before the \
                     query's first token; this one would be ignored, and its variable left \
                     unbound",
                    number + 1
                )));
            }
            _ => header = false,
        }
    }
    Ok(out)
}

/// One `@param` line, after the keyword.
fn declaration(rest: &str, line: usize) -> Result<Parameter> {
    let bad = |detail: String| invalid(format!("line {line}: {detail}"));
    let mut tokens = Tokens { rest: rest.trim() };
    let name = tokens
        .word()
        .ok_or_else(|| bad("`@param` needs a name and a type".to_string()))?;
    let name = name.strip_prefix(['?', '$']).unwrap_or(&name).to_string();
    let valid = name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !valid {
        return Err(bad(format!(
            "`{name}` is not a parameter name: ASCII letters, digits and `_`, not starting \
             with a digit"
        )));
    }
    if RESERVED_PARAMETERS.contains(&name.as_str()) {
        return Err(bad(format!(
            "`{name}` is an argument a door already reads ({}); choose another name",
            RESERVED_PARAMETERS.join(", ")
        )));
    }
    let kind = tokens
        .word()
        .ok_or_else(|| {
            bad(format!(
                "`{name}` needs a type: `xsd:integer`, `<class IRI>`, …"
            ))
        })
        .and_then(|t| param_type(&t).map_err(bad))?;
    let mut parameter = Parameter {
        name,
        kind,
        required: true,
        default: None,
        summary: None,
    };
    while let Some(word) = tokens.word() {
        match word.as_str() {
            "required" => parameter.required = true,
            "optional" => parameter.required = false,
            "default" => {
                let value = tokens
                    .value()
                    .map_err(bad)?
                    .ok_or_else(|| bad("`default` needs a value".to_string()))?;
                // The default must be a value of its own type: checked here, at publish.
                parameter.value(&value)?;
                parameter.default = Some(value);
                parameter.required = false;
            }
            "--" => {
                let summary = tokens.rest.trim();
                if !summary.is_empty() {
                    parameter.summary = Some(summary.to_string());
                }
                break;
            }
            other => {
                return Err(bad(format!(
                    "`{other}` is not `required`, `optional`, `default <value>` or \
                     `-- <summary>`"
                )))
            }
        }
    }
    Ok(parameter)
}

fn param_type(token: &str) -> std::result::Result<ParamType, String> {
    if let Some(local) = token.strip_prefix("xsd:") {
        return datatype(&format!("{XSD}{local}"));
    }
    if token == "rdfs:Resource" {
        return Ok(ParamType::Class(RDFS_RESOURCE.to_string()));
    }
    if let Some(iri) = token.strip_prefix('<').and_then(|t| t.strip_suffix('>')) {
        NamedNode::new(iri).map_err(|e| format!("`{token}` is not an IRI: {e}"))?;
        if iri.starts_with(XSD) {
            return datatype(iri);
        }
        return Ok(ParamType::Class(iri.to_string()));
    }
    Err(format!(
        "`{token}` is not a type: an XSD datatype (`xsd:integer`, one of {}), a class \
         (`<iri>`), or `rdfs:Resource` for any IRI",
        DATATYPES.join(", ")
    ))
}

fn datatype(iri: &str) -> std::result::Result<ParamType, String> {
    let local = iri.strip_prefix(XSD).unwrap_or(iri);
    if DATATYPES.contains(&local) {
        Ok(ParamType::Datatype(iri.to_string()))
    } else {
        Err(format!(
            "xsd:{local} is not a parameter datatype here; one of {}",
            DATATYPES.join(", ")
        ))
    }
}

/// A tiny tokenizer for a declaration line: whitespace-separated words, and a value that
/// may be a JSON string.
struct Tokens<'a> {
    rest: &'a str,
}

impl Tokens<'_> {
    fn word(&mut self) -> Option<String> {
        let rest = self.rest.trim_start();
        if rest.is_empty() {
            return None;
        }
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        let (word, tail) = rest.split_at(end);
        self.rest = tail;
        Some(word.to_string())
    }

    fn value(&mut self) -> std::result::Result<Option<String>, String> {
        let rest = self.rest.trim_start();
        if !rest.starts_with('"') {
            return Ok(self.word());
        }
        // A JSON string: find its end by letting serde read exactly one value.
        let mut stream = serde_json::Deserializer::from_str(rest).into_iter::<String>();
        match stream.next() {
            Some(Ok(value)) => {
                self.rest = &rest[stream.byte_offset()..];
                Ok(Some(value))
            }
            _ => Err(format!(
                "`{rest}` does not start with a complete JSON string"
            )),
        }
    }
}

// ---------------------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------------------

/// What a SPARQL script's text says about itself, read from the parsed query.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Analysis {
    /// Its form.
    pub form: Form,
    /// Its declared parameters, in declaration order.
    pub parameters: Vec<Parameter>,
    /// For a query: the graphs it reads that the text fixes. For an update: the one graph
    /// it writes.
    pub graphs: BTreeSet<String>,
    /// Whether it also reads a graph only a run decides (`GRAPH ?g`): the caller's
    /// readable union.
    #[serde(rename = "anyGraph")]
    pub any_graph: bool,
    /// For an update: whether it reads its graph too (it has a `WHERE`).
    #[serde(rename = "updateReads")]
    pub update_reads: bool,
}

impl Analysis {
    /// The capability its runs need, DERIVED from the text: never declared by an author.
    ///
    /// A query: `urn:cap:store:read:graph:<g>` for each graph it fixes, and the family
    /// [`CAP_READ_GRAPH`] when it reads the caller's readable union. An update:
    /// `urn:cap:store:write:graph:<g>` for its graph, and `urn:cap:store:read:graph:<g>`
    /// when it has a `WHERE` (the store's own rule).
    pub fn requires(&self) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for graph in &self.graphs {
            if self.form == Form::Update {
                out.insert(cap_write_graph(graph));
                if self.update_reads {
                    out.insert(cap_read_graph(graph));
                }
            } else {
                out.insert(cap_read_graph(graph));
            }
        }
        if self.any_graph {
            out.insert(CAP_READ_GRAPH.to_string());
        }
        out
    }
}

/// Analyze a SPARQL script: bounded before it is parsed, then parsed (on a stack sized for
/// it) for its form, parameters, dataset and derived authority. Every refusal is an
/// `InvalidArgument` on `content` that says what to write instead.
pub fn analyze(source: &str, door: &SparqlDoor) -> Result<Analysis> {
    // ★ Bounded before the parser sees a byte (ledger #915): the parser is recursive, and
    // a stack overflow aborts the whole host, not this request.
    limits::check_sparql(source, "content")?;
    let parameters = parameters(source)?;
    limits::on_sparql_stack(source, || {
        let parsed = parse(source)?;
        let shape = shape(&parsed, door)?;
        check_parameters(&parameters, &shape)?;
        Ok(Analysis {
            form: parsed.form(),
            parameters,
            graphs: shape.graphs,
            any_graph: shape.any_graph,
            update_reads: shape.update_reads,
        })
    })
}

/// The text the store is sent, and the dataset it runs over, after binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bound {
    /// Its form.
    pub form: Form,
    /// The query or update, serialized from the bound algebra, with no dataset clauses.
    pub text: String,
    /// The graphs the bound text fixes (a parameter naming a graph is one of them now).
    pub graphs: BTreeSet<String>,
    /// Whether it still reads a graph only the run decides.
    pub any_graph: bool,
}

/// Bind `values` into `source` and serialize it for the store.
///
/// ★ **Never string interpolation.** The text is parsed, each parameter's variable is
/// replaced by its term IN THE ALGEBRA (in patterns, paths, expressions and templates; a
/// projected parameter is bound in the projection, `(term AS ?p)`), and the store is sent
/// what spargebra serializes from that algebra, which writes a literal as one escaped
/// token whatever it holds. A value cannot close a string, open a pattern or start a
/// second operation, because it is never text to a parser. A parameter without a value
/// (optional, no default) stays an unbound variable.
pub fn bind(source: &str, door: &SparqlDoor, values: &BTreeMap<String, Value>) -> Result<Bound> {
    limits::check_sparql(source, "content")?;
    limits::on_sparql_stack(source, || {
        let mut parsed = parse(source)?;
        let subst = Subst { values };
        match &mut parsed {
            Parsed::Query(query) => subst.query(query)?,
            Parsed::Update(update) => subst.update(update)?,
        }
        let shape = shape(&parsed, door)?;
        let text = match &mut parsed {
            Parsed::Query(query) => {
                // The store's scoped door refuses dataset clauses: `graph=` IS the dataset,
                // and it is `shape.graphs`, which the clauses contributed to.
                *dataset_of(query) = None;
                query.to_string()
            }
            Parsed::Update(update) => update.to_string(),
        };
        Ok(Bound {
            form: parsed.form(),
            text,
            graphs: shape.graphs,
            any_graph: shape.any_graph,
        })
    })
}

enum Parsed {
    Query(Box<Query>),
    Update(Update),
}

impl Parsed {
    fn form(&self) -> Form {
        match self {
            Parsed::Query(query) => match **query {
                Query::Select { .. } => Form::Select,
                Query::Ask { .. } => Form::Ask,
                Query::Construct { .. } => Form::Construct,
                Query::Describe { .. } => Form::Describe,
            },
            Parsed::Update(_) => Form::Update,
        }
    }
}

/// Parse as a query, then as an update. The FORM comes from which one parses: there is no
/// argument a caller could use to say otherwise.
fn parse(source: &str) -> Result<Parsed> {
    let query_error = match SparqlParser::new().parse_query(source) {
        Ok(query) => return Ok(Parsed::Query(Box::new(query))),
        Err(e) => e,
    };
    match SparqlParser::new().parse_update(source) {
        Ok(update) => Ok(Parsed::Update(update)),
        Err(update_error) => Err(invalid(format!(
            "not a SPARQL query ({query_error}) nor an update ({update_error})"
        ))),
    }
}

fn dataset_of(query: &mut Query) -> &mut Option<QueryDataset> {
    match query {
        Query::Select { dataset, .. }
        | Query::Ask { dataset, .. }
        | Query::Construct { dataset, .. }
        | Query::Describe { dataset, .. } => dataset,
    }
}

/// What a walk of the algebra found.
#[derive(Default)]
struct Scan {
    /// A triple pattern or path outside every `GRAPH` block.
    reads_default: bool,
    /// `GRAPH <iri>`.
    graphs: BTreeSet<String>,
    /// `GRAPH ?v`.
    graph_variables: BTreeSet<String>,
    /// Every variable the text uses.
    used: BTreeSet<String>,
    /// Variables the text BINDS or groups by: `BIND … AS`, `VALUES`, `GROUP BY`, an
    /// aggregate's name. A parameter cannot be one.
    bound: BTreeSet<String>,
    /// Variables in a position only an IRI can fill: a predicate or a graph name.
    iri_only: BTreeSet<String>,
    /// A `SERVICE` clause.
    service: bool,
}

/// The dataset and the shape a query or update has.
struct Shape {
    graphs: BTreeSet<String>,
    any_graph: bool,
    update_reads: bool,
    scan: Scan,
}

fn shape(parsed: &Parsed, door: &SparqlDoor) -> Result<Shape> {
    match parsed {
        Parsed::Query(query) => query_shape(query, door),
        Parsed::Update(update) => update_shape(update),
    }
}

fn query_shape(query: &Query, door: &SparqlDoor) -> Result<Shape> {
    let mut scan = Scan::default();
    let (dataset, describe) = match query {
        Query::Select {
            dataset, pattern, ..
        }
        | Query::Ask {
            dataset, pattern, ..
        } => {
            scan.pattern(pattern, false);
            (dataset, false)
        }
        Query::Construct {
            template,
            dataset,
            pattern,
            ..
        } => {
            for triple in template {
                scan.triple(triple, true);
            }
            scan.pattern(pattern, false);
            (dataset, false)
        }
        Query::Describe {
            dataset, pattern, ..
        } => {
            scan.pattern(pattern, false);
            (dataset, true)
        }
    };
    if scan.service {
        return Err(invalid(
            "a script cannot use SERVICE: the store refuses federation, and a run's authority \
             is derived from graphs this store holds",
        ));
    }
    let from: BTreeSet<String> = dataset
        .iter()
        .flat_map(|d| d.default.iter())
        .map(|g| g.as_str().to_string())
        .collect();
    let from_named: BTreeSet<String> = dataset
        .iter()
        .flat_map(|d| d.named.iter().flatten())
        .map(|g| g.as_str().to_string())
        .collect();
    let any_graph = !scan.graph_variables.is_empty();
    // ⚠ DESCRIBE collects from the DEFAULT graph (spareval's DescribeIterator), so it
    // reads the default graph whatever its pattern says.
    let reads_default = scan.reads_default || describe;
    let graphs = if reads_default {
        let base = if from.is_empty() {
            door.defaults().clone()
        } else {
            from.clone()
        };
        if base.is_empty() {
            return Err(invalid(
                "this query reads the default graph (a pattern outside every GRAPH block, or \
                 a DESCRIBE) but names no graph with FROM, and this host gives no default \
                 dataset. Name the graphs it reads with FROM <…>, or put its patterns in \
                 GRAPH <…> blocks",
            ));
        }
        let extra: Vec<&String> = from_named
            .iter()
            .chain(scan.graphs.iter())
            .filter(|g| !base.contains(*g))
            .collect();
        if !extra.is_empty() {
            return Err(invalid(format!(
                "this query reads the default graph, which a script's dataset makes the merge \
                 of EVERY graph it names; it also names {} outside its FROM set ({}), so its \
                 bare patterns would read them too. Add them to FROM, or put the bare \
                 patterns in GRAPH blocks",
                extra
                    .iter()
                    .map(|g| format!("<{g}>"))
                    .collect::<Vec<_>>()
                    .join(", "),
                base.iter()
                    .map(|g| format!("<{g}>"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
        if any_graph {
            return Err(invalid(
                "this query reads the default graph and also has a GRAPH ?variable, which \
                 runs over the caller's readable union: in a script's one dataset the bare \
                 patterns would read that whole union too. Put the bare patterns in GRAPH \
                 blocks, or fix the variable graph with GRAPH <…>",
            ));
        }
        base
    } else {
        let mut all = from;
        all.extend(from_named);
        all.extend(scan.graphs.iter().cloned());
        if all.is_empty() && !any_graph {
            return Err(invalid(
                "this query names no graph (no FROM, FROM NAMED or GRAPH), so it reads \
                 nothing; name the graphs it reads",
            ));
        }
        all
    };
    Ok(Shape {
        graphs,
        any_graph,
        update_reads: false,
        scan,
    })
}

fn update_shape(update: &Update) -> Result<Shape> {
    let mut scan = Scan::default();
    let mut targets: BTreeSet<String> = BTreeSet::new();
    let mut reads: BTreeSet<String> = BTreeSet::new();
    let mut has_where = false;
    let unnamed_target = || {
        invalid(
            "an update script names the graph it writes: CLEAR GRAPH <…> or DROP GRAPH <…>, \
             not DEFAULT, NAMED or ALL",
        )
    };
    for operation in &update.operations {
        match operation {
            GraphUpdateOperation::InsertData { data } => {
                for quad in data {
                    match &quad.graph_name {
                        GraphName::NamedNode(g) => targets.insert(g.as_str().to_string()),
                        GraphName::DefaultGraph => return Err(writes_default()),
                    };
                }
            }
            GraphUpdateOperation::DeleteData { data } => {
                for quad in data {
                    match &quad.graph_name {
                        GraphName::NamedNode(g) => targets.insert(g.as_str().to_string()),
                        GraphName::DefaultGraph => return Err(writes_default()),
                    };
                }
            }
            GraphUpdateOperation::DeleteInsert {
                delete,
                insert,
                using,
                pattern,
            } => {
                has_where = true;
                for quad in delete {
                    scan.ground_quad(quad);
                    template_target(&quad.graph_name, &mut targets)?;
                }
                for quad in insert {
                    scan.quad(quad);
                    template_target(&quad.graph_name, &mut targets)?;
                }
                let mut inner = Scan::default();
                inner.pattern(pattern, false);
                let using_default: Vec<String> = using
                    .iter()
                    .flat_map(|d| d.default.iter())
                    .map(|g| g.as_str().to_string())
                    .collect();
                if inner.reads_default && using_default.is_empty() {
                    return Err(invalid(
                        "this update's WHERE reads the default graph, which the store's scoped \
                         door does not hold: match inside GRAPH <…>, or name the graph with \
                         USING <…> or WITH <…>",
                    ));
                }
                if !inner.graph_variables.is_empty() {
                    return Err(invalid(
                        "an update script's WHERE cannot use GRAPH ?variable: the graph it reads \
                         is part of its authority, so the text names it",
                    ));
                }
                reads.extend(using_default);
                reads.extend(
                    using
                        .iter()
                        .flat_map(|d| d.named.iter().flatten())
                        .map(|g| g.as_str().to_string()),
                );
                reads.extend(inner.graphs.iter().cloned());
                scan.absorb(inner);
            }
            GraphUpdateOperation::Load { .. } => {
                return Err(invalid(
                    "a script cannot LOAD: the store fetches nothing over the network, and \
                     an update script writes only what its text says",
                ))
            }
            GraphUpdateOperation::Clear { graph, .. }
            | GraphUpdateOperation::Drop { graph, .. } => match graph {
                GraphTarget::NamedNode(g) => {
                    targets.insert(g.as_str().to_string());
                }
                _ => return Err(unnamed_target()),
            },
            GraphUpdateOperation::Create { graph, .. } => {
                targets.insert(graph.as_str().to_string());
            }
        }
    }
    if scan.service {
        return Err(invalid(
            "a script cannot use SERVICE: the store refuses federation",
        ));
    }
    let mut all = targets.clone();
    all.extend(reads);
    if all.len() != 1 || targets.len() != 1 {
        return Err(invalid(format!(
            "an update script writes exactly one named graph and reads no other (the store's \
             scoped door confines it to one); this one names {}",
            if all.is_empty() {
                "none".to_string()
            } else {
                all.iter()
                    .map(|g| format!("<{g}>"))
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        )));
    }
    Ok(Shape {
        graphs: targets,
        any_graph: false,
        update_reads: has_where,
        scan,
    })
}

/// The graph a DELETE or INSERT template writes into, recorded.
fn template_target(graph: &GraphNamePattern, targets: &mut BTreeSet<String>) -> Result<()> {
    match graph {
        GraphNamePattern::NamedNode(g) => {
            targets.insert(g.as_str().to_string());
            Ok(())
        }
        GraphNamePattern::DefaultGraph => Err(writes_default()),
        GraphNamePattern::Variable(_) => Err(invalid(
            "an update script cannot write GRAPH ?variable: the graph it writes is its \
             authority, so the text names it",
        )),
    }
}

fn writes_default() -> Error {
    invalid(
        "this update writes the default graph, which a script cannot: the store's scoped \
         door confines an update to one named graph. Write inside GRAPH <…> (or use \
         WITH <…>)",
    )
}

/// Every declared parameter is used, can be a value where it is used, and binds nothing.
fn check_parameters(parameters: &[Parameter], shape: &Shape) -> Result<()> {
    let scan = &shape.scan;
    for p in parameters {
        if !scan.used.contains(&p.name) {
            return Err(invalid(format!(
                "parameter `{}` is declared but the query never uses ?{0}",
                p.name
            )));
        }
        if scan.bound.contains(&p.name) {
            return Err(invalid(format!(
                "parameter `{}` is a value, but the query binds ?{0} itself (BIND … AS, \
                 VALUES, GROUP BY or an aggregate's name); rename one of them",
                p.name
            )));
        }
        if scan.iri_only.contains(&p.name) && !matches!(p.kind, ParamType::Class(_)) {
            return Err(invalid(format!(
                "parameter `{}` is used as a predicate or a graph name, which only an IRI can \
                 fill; declare it with a class (`rdfs:Resource` for any IRI)",
                p.name
            )));
        }
    }
    Ok(())
}

impl Scan {
    fn absorb(&mut self, other: Scan) {
        self.reads_default |= other.reads_default;
        self.graphs.extend(other.graphs);
        self.graph_variables.extend(other.graph_variables);
        self.used.extend(other.used);
        self.bound.extend(other.bound);
        self.iri_only.extend(other.iri_only);
        self.service |= other.service;
    }

    fn var(&mut self, v: &Variable) {
        self.used.insert(v.as_str().to_string());
    }

    fn term(&mut self, t: &TermPattern) {
        // A variable inside a quoted triple (RDF 1.2, when a host's build enables it) is
        // not seen, so a parameter used only there is refused as unused: the safe side.
        if let TermPattern::Variable(v) = t {
            self.var(v);
        }
    }

    fn named(&mut self, n: &NamedNodePattern) {
        if let NamedNodePattern::Variable(v) = n {
            self.var(v);
            self.iri_only.insert(v.as_str().to_string());
        }
    }

    fn triple(&mut self, t: &TriplePattern, in_graph: bool) {
        if !in_graph {
            self.reads_default = true;
        }
        self.term(&t.subject);
        self.named(&t.predicate);
        self.term(&t.object);
    }

    fn quad(&mut self, q: &QuadPattern) {
        self.term(&q.subject);
        self.named(&q.predicate);
        self.term(&q.object);
        if let GraphNamePattern::Variable(v) = &q.graph_name {
            self.var(v);
        }
    }

    fn ground_quad(&mut self, q: &GroundQuadPattern) {
        if let GroundTermPattern::Variable(v) = &q.subject {
            self.var(v);
        }
        self.named(&q.predicate);
        if let GroundTermPattern::Variable(v) = &q.object {
            self.var(v);
        }
        if let GraphNamePattern::Variable(v) = &q.graph_name {
            self.var(v);
        }
    }

    fn pattern(&mut self, p: &GraphPattern, in_graph: bool) {
        match p {
            GraphPattern::Bgp { patterns } => {
                for t in patterns {
                    self.triple(t, in_graph);
                }
            }
            GraphPattern::Path {
                subject, object, ..
            } => {
                if !in_graph {
                    self.reads_default = true;
                }
                self.term(subject);
                self.term(object);
            }
            GraphPattern::Join { left, right }
            | GraphPattern::Union { left, right }
            | GraphPattern::Minus { left, right } => {
                self.pattern(left, in_graph);
                self.pattern(right, in_graph);
            }
            GraphPattern::LeftJoin {
                left,
                right,
                expression,
            } => {
                self.pattern(left, in_graph);
                self.pattern(right, in_graph);
                if let Some(e) = expression {
                    self.expression(e, in_graph);
                }
            }
            GraphPattern::Filter { expr, inner } => {
                self.expression(expr, in_graph);
                self.pattern(inner, in_graph);
            }
            GraphPattern::Graph { name, inner } => {
                match name {
                    NamedNodePattern::NamedNode(g) => {
                        self.graphs.insert(g.as_str().to_string());
                    }
                    NamedNodePattern::Variable(v) => {
                        self.graph_variables.insert(v.as_str().to_string());
                    }
                }
                self.named(name);
                self.pattern(inner, true);
            }
            GraphPattern::Extend {
                inner,
                variable,
                expression,
            } => {
                self.bound.insert(variable.as_str().to_string());
                self.var(variable);
                self.expression(expression, in_graph);
                self.pattern(inner, in_graph);
            }
            GraphPattern::Values { variables, .. } => {
                for v in variables {
                    self.var(v);
                    self.bound.insert(v.as_str().to_string());
                }
            }
            GraphPattern::OrderBy { inner, expression } => {
                for e in expression {
                    match e {
                        OrderExpression::Asc(e) | OrderExpression::Desc(e) => {
                            self.expression(e, in_graph)
                        }
                    }
                }
                self.pattern(inner, in_graph);
            }
            GraphPattern::Project { inner, variables } => {
                for v in variables {
                    self.var(v);
                }
                self.pattern(inner, in_graph);
            }
            GraphPattern::Distinct { inner }
            | GraphPattern::Reduced { inner }
            | GraphPattern::Slice { inner, .. } => self.pattern(inner, in_graph),
            GraphPattern::Group {
                inner,
                variables,
                aggregates,
            } => {
                for v in variables {
                    self.var(v);
                    self.bound.insert(v.as_str().to_string());
                }
                for (v, aggregate) in aggregates {
                    self.bound.insert(v.as_str().to_string());
                    if let AggregateExpression::FunctionCall { expr, .. } = aggregate {
                        self.expression(expr, in_graph);
                    }
                }
                self.pattern(inner, in_graph);
            }
            GraphPattern::Service { inner, .. } => {
                self.service = true;
                self.pattern(inner, in_graph);
            }
            // LATERAL (SEP-0006), when a host's build enables it through feature
            // unification: not something a script can use yet, so it is refused as SERVICE
            // is, rather than walked by a rule written without it.
            #[allow(unreachable_patterns)] // feature unification can add variants
            _ => self.service = true,
        }
    }

    fn expression(&mut self, e: &Expression, in_graph: bool) {
        match e {
            Expression::Variable(v) | Expression::Bound(v) => self.var(v),
            Expression::Exists(p) => self.pattern(p, in_graph),
            Expression::Or(a, b)
            | Expression::And(a, b)
            | Expression::Equal(a, b)
            | Expression::SameTerm(a, b)
            | Expression::Greater(a, b)
            | Expression::GreaterOrEqual(a, b)
            | Expression::Less(a, b)
            | Expression::LessOrEqual(a, b)
            | Expression::Add(a, b)
            | Expression::Subtract(a, b)
            | Expression::Multiply(a, b)
            | Expression::Divide(a, b) => {
                self.expression(a, in_graph);
                self.expression(b, in_graph);
            }
            Expression::In(a, list) => {
                self.expression(a, in_graph);
                for x in list {
                    self.expression(x, in_graph);
                }
            }
            Expression::UnaryPlus(a) | Expression::UnaryMinus(a) | Expression::Not(a) => {
                self.expression(a, in_graph)
            }
            Expression::If(a, b, c) => {
                self.expression(a, in_graph);
                self.expression(b, in_graph);
                self.expression(c, in_graph);
            }
            Expression::Coalesce(list) | Expression::FunctionCall(_, list) => {
                for x in list {
                    self.expression(x, in_graph);
                }
            }
            Expression::NamedNode(_) | Expression::Literal(_) => {}
        }
    }
}

// ---------------------------------------------------------------------------------------
// Substitution
// ---------------------------------------------------------------------------------------

struct Subst<'a> {
    values: &'a BTreeMap<String, Value>,
}

impl Subst<'_> {
    fn value(&self, v: &Variable) -> Option<&Value> {
        self.values.get(v.as_str())
    }

    fn query(&self, query: &mut Query) -> Result<()> {
        match query {
            Query::Select { pattern, .. }
            | Query::Ask { pattern, .. }
            | Query::Describe { pattern, .. } => {
                self.pattern(pattern)?;
            }
            Query::Construct {
                template, pattern, ..
            } => {
                for triple in template {
                    self.triple(triple)?;
                }
                self.pattern(pattern)?;
            }
        }
        Ok(())
    }

    fn update(&self, update: &mut Update) -> Result<()> {
        for operation in &mut update.operations {
            if let GraphUpdateOperation::DeleteInsert {
                delete,
                insert,
                pattern,
                ..
            } = operation
            {
                for quad in delete {
                    quad.subject = self.ground_term(quad.subject.clone());
                    quad.predicate = self.named(quad.predicate.clone())?;
                    quad.object = self.ground_term(quad.object.clone());
                }
                for quad in insert {
                    quad.subject = self.term(quad.subject.clone());
                    quad.predicate = self.named(quad.predicate.clone())?;
                    quad.object = self.term(quad.object.clone());
                }
                self.pattern(pattern)?;
            }
        }
        Ok(())
    }

    fn term(&self, t: TermPattern) -> TermPattern {
        match &t {
            TermPattern::Variable(v) => match self.value(v) {
                Some(Value::Iri(n)) => TermPattern::NamedNode(n.clone()),
                Some(Value::Literal(l)) => TermPattern::Literal(l.clone()),
                None => t,
            },
            _ => t,
        }
    }

    fn ground_term(&self, t: GroundTermPattern) -> GroundTermPattern {
        match &t {
            GroundTermPattern::Variable(v) => match self.value(v) {
                Some(Value::Iri(n)) => GroundTermPattern::NamedNode(n.clone()),
                Some(Value::Literal(l)) => GroundTermPattern::Literal(l.clone()),
                None => t,
            },
            _ => t,
        }
    }

    fn named(&self, n: NamedNodePattern) -> Result<NamedNodePattern> {
        match &n {
            NamedNodePattern::Variable(v) => match self.value(v) {
                Some(Value::Iri(iri)) => Ok(NamedNodePattern::NamedNode(iri.clone())),
                // `check_parameters` refuses a datatype parameter in an IRI-only position
                // at publish, so this is reached only by a hand-edited record.
                Some(Value::Literal(_)) => Err(Error::InvalidArgument {
                    name: v.as_str().to_string(),
                    detail: "is used as a predicate or a graph name, which only an IRI can fill"
                        .to_string(),
                }),
                None => Ok(n),
            },
            NamedNodePattern::NamedNode(_) => Ok(n),
        }
    }

    fn triple(&self, t: &mut TriplePattern) -> Result<()> {
        t.subject = self.term(t.subject.clone());
        t.predicate = self.named(t.predicate.clone())?;
        t.object = self.term(t.object.clone());
        Ok(())
    }

    fn constant(&self, v: &Variable) -> Option<Expression> {
        self.value(v).map(|value| match value {
            Value::Iri(n) => Expression::NamedNode(n.clone()),
            Value::Literal(l) => Expression::Literal(l.clone()),
        })
    }

    /// Substitute inside `p`; answers the parameters `p` now BINDS for whatever encloses
    /// it (those a sub-select projects), so a projection above does not bind them twice.
    fn pattern(&self, p: &mut GraphPattern) -> Result<BTreeSet<String>> {
        Ok(match p {
            GraphPattern::Bgp { patterns } => {
                for t in patterns {
                    self.triple(t)?;
                }
                BTreeSet::new()
            }
            GraphPattern::Path {
                subject, object, ..
            } => {
                *subject = self.term(subject.clone());
                *object = self.term(object.clone());
                BTreeSet::new()
            }
            GraphPattern::Join { left, right } | GraphPattern::Union { left, right } => {
                let mut out = self.pattern(left)?;
                out.extend(self.pattern(right)?);
                out
            }
            GraphPattern::Minus { left, right } => {
                self.pattern(right)?;
                self.pattern(left)?
            }
            GraphPattern::LeftJoin {
                left,
                right,
                expression,
            } => {
                let mut out = self.pattern(left)?;
                out.extend(self.pattern(right)?);
                if let Some(e) = expression {
                    self.expression(e)?;
                }
                out
            }
            GraphPattern::Filter { expr, inner } => {
                self.expression(expr)?;
                self.pattern(inner)?
            }
            GraphPattern::Graph { name, inner } => {
                *name = self.named(name.clone())?;
                self.pattern(inner)?
            }
            GraphPattern::Extend {
                inner, expression, ..
            } => {
                self.expression(expression)?;
                self.pattern(inner)?
            }
            GraphPattern::Values { .. } => BTreeSet::new(),
            GraphPattern::OrderBy { inner, expression } => {
                for e in expression {
                    match e {
                        OrderExpression::Asc(e) | OrderExpression::Desc(e) => self.expression(e)?,
                    }
                }
                self.pattern(inner)?
            }
            GraphPattern::Project { inner, variables } => {
                let exposed = self.pattern(inner)?;
                // A projected parameter is bound IN the projection, `(term AS ?p)`, so the
                // answer still has its column: the variable is gone from the pattern now.
                for v in variables.iter() {
                    if exposed.contains(v.as_str()) {
                        continue;
                    }
                    if let Some(constant) = self.constant(v) {
                        let taken = std::mem::replace(
                            &mut **inner,
                            GraphPattern::Bgp {
                                patterns: Vec::new(),
                            },
                        );
                        **inner = GraphPattern::Extend {
                            inner: Box::new(taken),
                            variable: v.clone(),
                            expression: constant,
                        };
                    }
                }
                variables
                    .iter()
                    .filter(|v| self.value(v).is_some())
                    .map(|v| v.as_str().to_string())
                    .collect()
            }
            GraphPattern::Distinct { inner }
            | GraphPattern::Reduced { inner }
            | GraphPattern::Slice { inner, .. } => self.pattern(inner)?,
            GraphPattern::Group {
                inner, aggregates, ..
            } => {
                for (_, aggregate) in aggregates {
                    if let AggregateExpression::FunctionCall { expr, .. } = aggregate {
                        self.expression(expr)?;
                    }
                }
                self.pattern(inner)?;
                BTreeSet::new()
            }
            GraphPattern::Service { .. } => BTreeSet::new(),
            #[allow(unreachable_patterns)] // feature unification can add variants
            _ => BTreeSet::new(),
        })
    }

    fn expression(&self, e: &mut Expression) -> Result<()> {
        match e {
            Expression::Variable(v) => {
                if let Some(constant) = self.constant(v) {
                    *e = constant;
                }
            }
            Expression::Bound(v) => {
                if self.value(v).is_some() {
                    *e = Expression::Literal(Literal::from(true));
                }
            }
            Expression::Exists(p) => {
                self.pattern(p)?;
            }
            Expression::Or(a, b)
            | Expression::And(a, b)
            | Expression::Equal(a, b)
            | Expression::SameTerm(a, b)
            | Expression::Greater(a, b)
            | Expression::GreaterOrEqual(a, b)
            | Expression::Less(a, b)
            | Expression::LessOrEqual(a, b)
            | Expression::Add(a, b)
            | Expression::Subtract(a, b)
            | Expression::Multiply(a, b)
            | Expression::Divide(a, b) => {
                self.expression(a)?;
                self.expression(b)?;
            }
            Expression::In(a, list) => {
                self.expression(a)?;
                for x in list {
                    self.expression(x)?;
                }
            }
            Expression::UnaryPlus(a) | Expression::UnaryMinus(a) | Expression::Not(a) => {
                self.expression(a)?
            }
            Expression::If(a, b, c) => {
                self.expression(a)?;
                self.expression(b)?;
                self.expression(c)?;
            }
            Expression::Coalesce(list) | Expression::FunctionCall(_, list) => {
                for x in list {
                    self.expression(x)?;
                }
            }
            Expression::NamedNode(_) | Expression::Literal(_) => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn door() -> SparqlDoor {
        SparqlDoor::store()
    }

    fn values(pairs: &[(&str, Value)]) -> BTreeMap<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    fn int(n: i64) -> Value {
        Value::Literal(Literal::from(n))
    }

    #[test]
    fn the_form_is_read_from_the_text() {
        let cases = [
            (
                "SELECT * WHERE { GRAPH <urn:g> { ?s ?p ?o } }",
                Form::Select,
            ),
            ("ASK { GRAPH <urn:g> { ?s ?p ?o } }", Form::Ask),
            (
                "CONSTRUCT { ?s ?p ?o } WHERE { GRAPH <urn:g> { ?s ?p ?o } }",
                Form::Construct,
            ),
            ("DESCRIBE <urn:x> FROM <urn:g>", Form::Describe),
            (
                "INSERT DATA { GRAPH <urn:g> { <urn:a> <urn:b> 1 } }",
                Form::Update,
            ),
        ];
        for (text, form) in cases {
            assert_eq!(analyze(text, &door()).unwrap().form, form, "{text}");
        }
    }

    #[test]
    fn graphs_come_from_from_from_named_and_graph() {
        let a = analyze(
            "SELECT * FROM NAMED <urn:b> WHERE { GRAPH <urn:a> { ?s ?p ?o } GRAPH <urn:b> { ?s ?q ?r } }",
            &door(),
        )
        .unwrap();
        assert_eq!(
            a.graphs.iter().cloned().collect::<Vec<_>>(),
            vec!["urn:a", "urn:b"]
        );
        assert!(!a.any_graph);
        let a = analyze("SELECT ?g WHERE { GRAPH ?g { ?s ?p ?o } }", &door()).unwrap();
        assert!(a.any_graph && a.graphs.is_empty());
        assert_eq!(
            a.requires().into_iter().collect::<Vec<_>>(),
            vec![CAP_READ_GRAPH.to_string()]
        );
    }

    #[test]
    fn a_query_whose_answer_would_change_is_refused() {
        // Bare patterns with a graph outside FROM.
        let e = analyze(
            "SELECT * FROM <urn:a> WHERE { ?s ?p ?o GRAPH <urn:b> { ?s ?q ?r } }",
            &door(),
        )
        .unwrap_err();
        assert!(e.to_string().contains("<urn:b>"), "{e}");
        // Bare patterns and no FROM, no host default.
        assert!(analyze("SELECT * WHERE { ?s ?p ?o }", &door()).is_err());
        // ... with a host default, fine.
        let a = analyze(
            "SELECT * WHERE { ?s ?p ?o }",
            &door().default_graphs(["urn:d"]),
        )
        .unwrap();
        assert_eq!(a.graphs.into_iter().collect::<Vec<_>>(), vec!["urn:d"]);
        // Bare patterns beside GRAPH ?g.
        assert!(analyze(
            "SELECT * FROM <urn:a> WHERE { ?s ?p ?o GRAPH ?g { ?s ?q ?r } }",
            &door()
        )
        .is_err());
        // SERVICE.
        assert!(analyze(
            "SELECT * WHERE { SERVICE <http://example.com/sparql> { ?s ?p ?o } }",
            &door()
        )
        .is_err());
    }

    #[test]
    fn an_update_writes_one_named_graph() {
        let a = analyze(
            "DELETE { GRAPH <urn:g> { ?s <urn:p> ?o } } WHERE { GRAPH <urn:g> { ?s <urn:p> ?o } }",
            &door(),
        )
        .unwrap();
        assert_eq!(a.form, Form::Update);
        assert!(a.update_reads);
        assert_eq!(
            a.requires().into_iter().collect::<Vec<_>>(),
            vec![
                "urn:cap:store:read:graph:urn:g".to_string(),
                "urn:cap:store:write:graph:urn:g".to_string()
            ]
        );
        let a = analyze(
            "INSERT DATA { GRAPH <urn:g> { <urn:a> <urn:b> 1 } }",
            &door(),
        )
        .unwrap();
        assert!(!a.update_reads);
        let a = analyze(
            "WITH <urn:g> DELETE { ?s <urn:p> ?o } WHERE { ?s <urn:p> ?o }",
            &door(),
        )
        .unwrap();
        assert_eq!(a.graphs.into_iter().collect::<Vec<_>>(), vec!["urn:g"]);
        for refused in [
            "INSERT DATA { <urn:a> <urn:b> 1 }",
            "INSERT DATA { GRAPH <urn:g> { <urn:a> <urn:b> 1 } GRAPH <urn:h> { <urn:a> <urn:b> 1 } }",
            "DROP ALL",
            "COPY <urn:a> TO <urn:b>",
            "LOAD <http://example.com/x.ttl> INTO GRAPH <urn:g>",
            "DELETE { GRAPH ?g { ?s ?p ?o } } WHERE { GRAPH ?g { ?s ?p ?o } }",
        ] {
            assert!(analyze(refused, &door()).is_err(), "{refused}");
        }
    }

    #[test]
    fn parameters_are_declared_in_the_header_and_checked() {
        let text = "# @param days xsd:integer default 7 -- how long\n\
                    # @param who <urn:class:Person>\n\
                    # @param note xsd:string default \"two words\"\n\
                    SELECT * WHERE { GRAPH <urn:g> { ?who <urn:p> ?d FILTER(?d > ?days && ?note != \"\") } }";
        let a = analyze(text, &door()).unwrap();
        let names: Vec<_> = a.parameters.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["days", "who", "note"]);
        assert_eq!(a.parameters[0].summary.as_deref(), Some("how long"));
        assert!(a.parameters[1].required);
        assert_eq!(a.parameters[2].default.as_deref(), Some("two words"));

        for (bad, why) in [
            ("# @param x xsd:integer\nSELECT * WHERE { GRAPH <urn:g> { ?s ?p ?o } }", "unused"),
            ("# @param x xsd:nope\nSELECT * WHERE { GRAPH <urn:g> { ?s ?p ?x } }", "type"),
            ("# @param x xsd:integer default seven\nSELECT * WHERE { GRAPH <urn:g> { ?s ?p ?x } }", "default"),
            ("# @param as xsd:integer\nSELECT * WHERE { GRAPH <urn:g> { ?s ?p ?as } }", "reserved"),
            ("# @param p xsd:string\nSELECT * WHERE { GRAPH <urn:g> { ?s ?p ?o } }", "predicate"),
            ("# @param x xsd:integer\nSELECT * WHERE { GRAPH <urn:g> { ?s ?p ?o } BIND(1 AS ?x) }", "bound"),
            ("SELECT * WHERE { GRAPH <urn:g> { ?s ?p ?x } }\n# @param x xsd:integer", "misplaced"),
        ] {
            assert!(analyze(bad, &door()).is_err(), "{why}: {bad}");
        }
    }

    #[test]
    fn binding_substitutes_terms_into_the_algebra() {
        let text = "# @param days xsd:integer\n\
                    SELECT ?s ?days FROM <urn:g> WHERE { ?s <urn:age> ?a FILTER(?a > ?days) }";
        let bound = bind(text, &door(), &values(&[("days", int(7))])).unwrap();
        assert!(!bound.text.contains("FROM"), "{}", bound.text);
        assert!(
            !bound.text.contains("?days >") && !bound.text.contains("> ?days"),
            "{}",
            bound.text
        );
        assert!(bound.text.contains("AS ?days"), "{}", bound.text);
        assert_eq!(
            bound.graphs.iter().cloned().collect::<Vec<_>>(),
            vec!["urn:g"]
        );
        // And the text it serialized parses back.
        SparqlParser::new().parse_query(&bound.text).unwrap();
    }

    #[test]
    fn a_hostile_string_is_one_literal() {
        let text = "# @param q xsd:string\n\
                    SELECT ?v WHERE { GRAPH <urn:g> { ?s ?p ?o } BIND(?q AS ?v) }";
        let hostile = "\" } ; DROP ALL ; INSERT DATA { <urn:x> <urn:y> \"";
        let p = parameters(text).unwrap().remove(0);
        let bound = bind(text, &door(), &values(&[("q", p.value(hostile).unwrap())])).unwrap();
        let reparsed = SparqlParser::new().parse_query(&bound.text).unwrap();
        // Still one SELECT, and the literal is intact inside it.
        assert!(matches!(reparsed, Query::Select { .. }), "{}", bound.text);
        assert!(
            bound.text.contains("DROP ALL"),
            "the value is there, as a literal"
        );
        assert!(SparqlParser::new().parse_update(&bound.text).is_err());
    }

    #[test]
    fn a_graph_parameter_becomes_a_fixed_graph() {
        let text = "# @param graph rdfs:Resource\nSELECT * WHERE { GRAPH ?graph { ?s ?p ?o } }";
        let a = analyze(text, &door()).unwrap();
        assert!(a.any_graph);
        let bound = bind(
            text,
            &door(),
            &values(&[("graph", Value::Iri(NamedNode::new("urn:g").unwrap()))]),
        )
        .unwrap();
        assert!(!bound.any_graph);
        assert_eq!(bound.graphs.into_iter().collect::<Vec<_>>(), vec!["urn:g"]);
    }
}
