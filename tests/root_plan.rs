//! **A plan run under gonk's script ceiling, over a real ledger** (ledger #1220).
//!
//! A published plan whose one step is `Source urn:iki:ledger:{L}:next` was refused on gonk
//! when the owner (root) published it and the owner (root) ran it:
//! `capability does not grant urn:cap:store:read:graph:* (declared by urn:iki:ledger:{L}:next)`.
//! This file reproduces it with `ikigai-ledger` and `ikigai-store` bound as a host binds them,
//! under gonk's ceiling copied verbatim, for every combination of root and exact publisher and
//! runner.
//!
//! What it shows:
//!
//! - **Three of the four combinations run.** An exact publisher or an exact runner carries the
//!   exact per-ledger tokens the ledger checks inside, and the run keeps them.
//! - **Root published, root run, cannot be EXACT here.** Every ledger read declares two FAMILIES
//!   and checks two exact tokens inside: `urn:cap:ledger:read:{L}` and the store's
//!   `urn:cap:store:read:graph:urn:iki:ledger:graph:{L}`. A step's contract
//!   (`Description::requires`) is static, so `urn:plan:requires` derives the families and never
//!   the members; root holds no list to pick members from; and gonk's ceiling names only
//!   families. The member is the ledger's own naming (the bare `urn:iki:ledger:next` needs
//!   `…:read:default`, a word its IRI does not contain), so no rule over the target's text can
//!   derive it. The run keeps the families as MARKERS (the meet of each declared family and the
//!   ceiling), which a module checking an exact token refuses, and the refusal now says so and
//!   names the two remedies.
//! - **Running root UNATTENUATED would not be equivalent**, so it is not done: the store's
//!   scoped query door declares the same family `next` does, so no check over the declared
//!   families can tell "read the ledger graph" from "read any graph", and an unattenuated run
//!   would read a graph the ceiling forbids. [`a_step_outside_the_ceiling_is_refused_in_every_combination`]
//!   pins that refusal.
//! - **The remedy a host has today**: a ceiling that NAMES the members (the policy is asked on
//!   every run, so a host can list the ledgers it holds) runs root/root exactly.

mod common;

use std::collections::BTreeSet;
use std::sync::Arc;

use common::*;
use ikigai_core::{Capability, Error, Space, Verb};
use ikigai_script::authority::{effective, grant_at_publish, same_for_all, Ceiling};
use ikigai_script::plan::expand_families;

/// A named ledger, never `default`, so a token that ignored the ledger would still have to
/// name this one.
const LEDGER: &str = "library";

/// gonk's script ceiling, verbatim (`ikigai-gonk/src/script.rs`, `CEILING`).
const GONK_CEILING: [&str; 2] = [
    "urn:cap:ledger:read:*",
    "urn:cap:store:read:graph:urn:iki:ledger:graph:*",
];

/// A graph that is not a ledger's, which gonk's ceiling therefore does not admit.
const SECRET_GRAPH: &str = "urn:test:secret:graph";

/// The ledger's read check, in the two tokens it asks of a caller for one ledger.
fn ledger_read(ledger: &str) -> [String; 2] {
    [
        format!("urn:cap:ledger:read:{ledger}"),
        format!("urn:cap:store:read:graph:urn:iki:ledger:graph:{ledger}"),
    ]
}

/// A plan with one step: `Source urn:iki:ledger:{LEDGER}:{resource}`.
fn reading(id: &str, resource: &str) -> String {
    format!(
        "@prefix ik: <https://ikigai-rs.dev/ns#> .\n\
         <urn:plan:{id}> a ik:Process ; ik:step <urn:plan:{id}:step:1> ;\n    \
             ik:result <urn:plan:{id}:step:1> .\n\
         <urn:plan:{id}:step:1> a ik:Step ; ik:verb \"Source\" ;\n    \
             ik:resolves <urn:iki:ledger:{LEDGER}:{resource}> .\n"
    )
}

/// A plan with one step outside gonk's ceiling: the store's scoped SELECT over a graph that is
/// not a ledger's. Its step declares exactly the store family `next` declares.
fn outside() -> String {
    format!(
        "@prefix ik: <https://ikigai-rs.dev/ns#> .\n\
         <urn:plan:outside> a ik:Process ; ik:step <urn:plan:outside:step:1> ;\n    \
             ik:result <urn:plan:outside:step:1> .\n\
         <urn:plan:outside:step:1> a ik:Step ; ik:verb \"Source\" ;\n    \
             ik:resolves <urn:iki:store:graph-select> ;\n    \
             ik:argument <urn:plan:outside:step:1:arg:graph> , \
                         <urn:plan:outside:step:1:arg:query> .\n\
         <urn:plan:outside:step:1:arg:graph> a ik:Argument ; ik:inputName \"graph\" ;\n    \
             ik:value \"{SECRET_GRAPH}\" .\n\
         <urn:plan:outside:step:1:arg:query> a ik:Argument ; ik:inputName \"query\" ;\n    \
             ik:value \"SELECT ?o WHERE {{ ?s ?p ?o }}\" .\n"
    )
}

/// A plan host with the store and the ledger bound behind it, one item filed in [`LEDGER`] and
/// one triple in [`SECRET_GRAPH`] (both as root: neither is under test).
fn host(ceiling: Ceiling) -> PlanHost {
    let store = ikigai_store::DurableStore::in_memory().expect("an in-memory store");
    let host = plan_host_over(
        same_for_all(ceiling),
        vec![
            Arc::new(ikigai_store::space(store)) as Arc<dyn Space>,
            Arc::new(ikigai_ledger::space()) as Arc<dyn Space>,
        ],
    );
    ok(
        &host.kernel,
        Verb::Sink,
        &format!("urn:iki:ledger:{LEDGER}:append"),
        &[("content", "The first item")],
    );
    seed(
        &host.kernel,
        &format!("INSERT DATA {{ GRAPH <{SECRET_GRAPH}> {{ <urn:s> <urn:p> \"secret\" }} }}"),
    );
    host
}

fn gonk() -> Ceiling {
    Ceiling::scoped(GONK_CEILING)
}

/// Who publishes or runs: root (the owner's socket) or a capability holding exactly the
/// script grant and the ledger's two read tokens (a passkey or QUIC caller with the read row),
/// plus `extra`.
#[derive(Clone, Copy, Debug)]
enum Who {
    Root,
    Exact,
}

fn capability(who: Who, script: &str, act: &str, extra: &[&str]) -> Capability {
    match who {
        Who::Root => Capability::root(),
        Who::Exact => {
            let mut scopes: Vec<String> = ledger_read(LEDGER).to_vec();
            scopes.push(format!("urn:cap:script:{act}:{script}"));
            scopes.extend(extra.iter().map(|s| s.to_string()));
            Capability::scoped(scopes)
        }
    }
}

fn publish_as(host: &PlanHost, who: Who, name: &str, plan: &str, extra: &[&str]) {
    call(
        &host.kernel,
        &capability(who, name, "write", extra),
        Verb::Sink,
        &format!("urn:script:{name}"),
        &[("content", plan), ("language", "plan")],
    )
    .unwrap_or_else(|e| panic!("publishing {name} as {who:?}: {e}"));
}

fn run_as(
    host: &PlanHost,
    who: Who,
    name: &str,
    extra: &[&str],
) -> std::result::Result<String, Error> {
    call(
        &host.kernel,
        &capability(who, name, "run", extra),
        Verb::Source,
        &format!("urn:script:{name}:result"),
        &[],
    )
}

const READS: [(&str, &str); 2] = [("nextwork", "next"), ("allitems", "items")];

/// ★ Root/exact, exact/root and exact/exact read `next` and `items` under gonk's ceiling: the
/// run holds the ledger's exact tokens, because one of the two parties named them.
#[test]
fn an_exact_publisher_or_runner_reads_next_and_items_under_gonks_ceiling() {
    for (publisher, runner) in [
        (Who::Root, Who::Exact),
        (Who::Exact, Who::Root),
        (Who::Exact, Who::Exact),
    ] {
        let host = host(gonk());
        for (name, resource) in READS {
            publish_as(&host, publisher, name, &reading(name, resource), &[]);
            let answer = run_as(&host, runner, name, &[]).unwrap_or_else(|e| {
                panic!("{resource}, published {publisher:?}, run {runner:?}: {e}")
            });
            assert!(
                answer.contains("The first item"),
                "{resource}, published {publisher:?}, run {runner:?}: {answer}"
            );
        }
    }
}

/// ★ Root published, root run, under gonk's family-only ceiling: refused, and the refusal says
/// why and what would admit it. There is no exact grant to derive (see the module docs), and
/// nothing wider than the least of declared, publisher, ceiling and runner is ever held.
///
/// When core can derive a step's EXACT requirement from its target (a `requires` templated
/// from the grammar's bindings, the family-versus-exact design of ledger #1197 and #1200), this
/// is the assertion to flip: `urn:plan:requires` would derive the members, and the root run
/// would keep exactly them.
#[test]
fn root_published_and_root_run_is_refused_legibly_under_a_family_only_ceiling() {
    let host = host(gonk());
    for (name, resource) in READS {
        publish_as(&host, Who::Root, name, &reading(name, resource), &[]);
        let message = denied(run_as(&host, Who::Root, name, &[]));
        // The ledger's exact check refuses it (the floor no longer does: the run now holds the
        // store family the ceiling narrows to, rather than dropping it)...
        assert!(
            message.contains(&format!("urn:cap:ledger:read:{LEDGER}")),
            "{resource}: {message}"
        );
        // ...and the script host says the run held only markers, and how to give it members.
        assert!(
            message.contains("a family held is not a grant")
                && message.contains("urn:cap:store:read:graph:urn:iki:ledger:graph:*")
                && message.contains("ceiling"),
            "{resource}: {message}"
        );
    }
}

/// What the root/root run is attenuated to under gonk's ceiling, computed with the library's
/// own functions: the MEET of each declared family and the ceiling. Before ledger #1220 the
/// store family was dropped (the ceiling's narrower family does not `allows` the wider one),
/// and the kernel's floor refused `next` naming a scope `next` was never short of.
#[test]
fn a_root_run_keeps_the_meet_of_each_declared_family_and_the_ceiling() {
    let declared: BTreeSet<String> = ["urn:cap:ledger:read:*", "urn:cap:store:read:graph:*"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let grant = grant_at_publish(&Capability::root(), &declared).unwrap();
    let keep = effective(&declared, &grant.granted, &grant.exclusions, &gonk());
    let expanded = expand_families(keep, &Capability::root(), &gonk());
    assert_eq!(
        expanded,
        GONK_CEILING.iter().map(|s| s.to_string()).collect(),
        "the ledger family whole (the ceiling admits it whole) and the store family as \
         narrowed by the ceiling"
    );
    // An exact runner: its own members, the markers gone.
    let runner = Capability::scoped(ledger_read(LEDGER));
    let keep = effective(&declared, &grant.granted, &grant.exclusions, &gonk());
    assert_eq!(
        expand_families(keep, &runner, &gonk()),
        ledger_read(LEDGER).into_iter().collect()
    );
}

/// ★ The remedy a host has today, with no change anywhere else: a ceiling that NAMES the
/// members beside the families. The ceiling policy is asked on every run, so a host can list
/// the ledgers it holds. Root/root then runs holding exactly those members.
#[test]
fn a_ceiling_naming_the_members_runs_root_published_root_run() {
    let mut lines: Vec<String> = GONK_CEILING.iter().map(|s| s.to_string()).collect();
    lines.extend(ledger_read(LEDGER));
    let host = host(Ceiling::scoped(lines));
    for (name, resource) in READS {
        publish_as(&host, Who::Root, name, &reading(name, resource), &[]);
        let answer = run_as(&host, Who::Root, name, &[])
            .unwrap_or_else(|e| panic!("{resource}, root/root, members named: {e}"));
        assert!(answer.contains("The first item"), "{resource}: {answer}");
    }
}

/// ★ A step outside the ceiling is refused in every combination, even when the publisher and
/// the runner both hold its exact grant. This is also why a root run is not simply left
/// unattenuated: the step declares exactly the store family `next` declares, and as root it
/// would read the graph.
#[test]
fn a_step_outside_the_ceiling_is_refused_in_every_combination() {
    let secret = format!("urn:cap:store:read:graph:{SECRET_GRAPH}");
    for (publisher, runner) in [
        (Who::Root, Who::Root),
        (Who::Root, Who::Exact),
        (Who::Exact, Who::Root),
        (Who::Exact, Who::Exact),
    ] {
        let host = host(gonk());
        publish_as(&host, publisher, "outside", &outside(), &[&secret]);
        let message = denied(run_as(&host, runner, "outside", &[&secret]));
        assert!(
            message.contains("urn:cap:store:read:graph"),
            "published {publisher:?}, run {runner:?}: {message}"
        );
        // Control: with no ceiling the same plan reads the graph for an exact pair, so the
        // refusal above is the ceiling's and not a broken fixture.
        if let (Who::Exact, Who::Exact) = (publisher, runner) {
            let open = self::host(Ceiling::unbounded());
            publish_as(&open, publisher, "outside", &outside(), &[&secret]);
            let answer = run_as(&open, runner, "outside", &[&secret]).unwrap();
            assert!(answer.contains("secret"), "{answer}");
        }
    }
}
