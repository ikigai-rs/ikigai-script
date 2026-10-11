//! NAMESPACE grants (ledger #1174): `urn:cap:script:{act}:{namespace}-*` covers every
//! script whose name begins `{namespace}-`, and nothing else. Each rule is shown refusing
//! (a typed `Denied`, and nothing written) beside the positive half, so a test that passes
//! because nothing works cannot pass.

mod common;

use common::*;
use ikigai_core::{Capability, Error, Verb};
use ikigai_script::authority::{cap_namespace, Act};

const LISP: &str = "urn:cap:lisp";

fn exists(host: &Host, name: &str) -> bool {
    ok(
        &host.kernel,
        Verb::Exists,
        &format!("urn:script:{name}"),
        &[],
    ) == "true\n"
}

fn publish_as(host: &Host, who: &Capability, name: &str) -> Result<String, Error> {
    call(
        &host.kernel,
        who,
        Verb::Sink,
        &format!("urn:script:{name}"),
        &[("content", "(+ 1 2)")],
    )
}

#[test]
fn a_namespace_grant_publishes_inside_its_namespace_and_nowhere_else() {
    let host = host();
    let team = cap_namespace(Act::Write, "team").unwrap();
    let alice = cap(&[&team, LISP]);

    for inside in ["team-report", "team-a-report", "team-"] {
        publish_as(&host, &alice, inside).unwrap_or_else(|e| panic!("{inside}: {e}"));
        assert!(exists(&host, inside), "{inside}");
    }
    for outside in ["teammate", "team", "other", "report-team"] {
        let message = denied(publish_as(&host, &alice, outside));
        assert!(
            message.contains(&format!("urn:cap:script:write:{outside}")),
            "{message}"
        );
        assert!(message.contains("{namespace}-*"), "{message}");
        assert!(!exists(&host, outside), "a refused publish wrote {outside}");
    }
}

#[test]
fn a_nested_namespace_is_narrower_than_its_parent() {
    let host = host();
    let alice = cap(&[&cap_namespace(Act::Write, "team-a").unwrap(), LISP]);
    publish_as(&host, &alice, "team-a-report").unwrap();
    denied(publish_as(&host, &alice, "team-b-report"));
    denied(publish_as(&host, &alice, "team-report"));
}

#[test]
fn an_exclusion_takes_a_script_or_a_namespace_back_out() {
    let host = host();
    let alice = cap(&[
        &cap_namespace(Act::Write, "team").unwrap(),
        "urn:cap:script:write:-team-payroll",
        "urn:cap:script:write:-team-hr-*",
        // An exclusion wins over an exact grant too.
        "urn:cap:script:write:team-secret",
        "urn:cap:script:write:-team-secret",
        LISP,
    ]);
    publish_as(&host, &alice, "team-report").unwrap();
    for out in ["team-payroll", "team-hr-salaries", "team-secret"] {
        denied(publish_as(&host, &alice, out));
        assert!(!exists(&host, out), "{out}");
    }
}

#[test]
fn there_is_no_every_script_grant_below_root() {
    let host = host();
    // Spelled like the family each door declares ("holds some write grant"), so it is not a
    // grant of everything: it publishes nothing, here or anywhere.
    for held in [
        "urn:cap:script:write:*",
        "urn:cap:script:write:team*",
        "urn:cap:script:*",
    ] {
        let who = cap(&[held, LISP]);
        for name in ["team-report", "teammate", "anything"] {
            denied(publish_as(&host, &who, name));
            assert!(!exists(&host, name), "{held} published {name}");
        }
    }
}

#[test]
fn a_namespace_grant_is_for_its_own_act() {
    let host = host();
    publish(&host.kernel, "team-report", "(+ 1 2)", &[]);
    let runner = cap(&[&cap_namespace(Act::Run, "team").unwrap(), LISP]);
    // It runs…
    assert_eq!(
        call(
            &host.kernel,
            &runner,
            Verb::Source,
            "urn:script:team-report:result",
            &[]
        )
        .unwrap(),
        "3"
    );
    // …but neither publishes, reads the source, nor retires.
    denied(publish_as(&host, &runner, "team-report"));
    denied(call(
        &host.kernel,
        &runner,
        Verb::Source,
        "urn:script:team-report",
        &[],
    ));
    denied(call(
        &host.kernel,
        &runner,
        Verb::Delete,
        "urn:script:team-report",
        &[],
    ));
    // And a runner of the namespace runs nothing outside it.
    publish(&host.kernel, "other", "(+ 1 2)", &[]);
    denied(call(
        &host.kernel,
        &runner,
        Verb::Source,
        "urn:script:other:result",
        &[],
    ));
}

#[test]
fn reading_and_retiring_by_namespace() {
    let host = host();
    publish(&host.kernel, "team-report", "(+ 1 2)", &[]);
    publish(&host.kernel, "other", "(+ 4 5)", &[]);
    let reader = cap(&[&cap_namespace(Act::Read, "team").unwrap()]);
    assert_eq!(
        call(
            &host.kernel,
            &reader,
            Verb::Source,
            "urn:script:team-report",
            &[]
        )
        .unwrap(),
        "(+ 1 2)"
    );
    denied(call(
        &host.kernel,
        &reader,
        Verb::Source,
        "urn:script:other",
        &[],
    ));
    // The catalog lists what the namespace covers, and nothing else.
    let catalog: serde_json::Value = serde_json::from_str(
        &call(
            &host.kernel,
            &reader,
            Verb::Source,
            "urn:script:catalog",
            &[("as", "application/json")],
        )
        .unwrap(),
    )
    .unwrap();
    let listed: Vec<(&str, bool)> = catalog["scripts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| (row["name"].as_str().unwrap(), row["state"].is_string()))
        .collect();
    assert!(listed.contains(&("team-report", true)), "{catalog}");
    assert!(!listed.contains(&("other", true)), "{catalog}");

    let retirer = cap(&[&cap_namespace(Act::Delete, "team").unwrap()]);
    call(
        &host.kernel,
        &retirer,
        Verb::Delete,
        "urn:script:team-report",
        &[],
    )
    .unwrap();
    denied(call(
        &host.kernel,
        &retirer,
        Verb::Delete,
        "urn:script:other",
        &[],
    ));
}

// ------------------------------------------------------------------ a script's own contract

const READ_LEDGER: &str = "urn:cap:store:read:graph:urn:test:ledger";
const TITLES: &str = r#"# Every title in the ledger.
SELECT ?title WHERE { GRAPH <urn:test:ledger> { ?s <urn:p:title> ?title } } ORDER BY ?title"#;

/// A published query is its OWN entry, whose run gate the kernel checks at the floor before
/// the endpoint runs. A namespace grant must pass that floor, and the exact rule still holds
/// inside it.
#[test]
fn a_namespace_runner_passes_a_querys_own_floor_and_only_for_its_namespace() {
    let host = sparql_host();
    seed(
        &host.kernel,
        r#"INSERT DATA { GRAPH <urn:test:ledger> { <urn:item:1> <urn:p:title> "first" } }"#,
    );
    for name in ["team-a-titles", "team-b-titles", "titles"] {
        publish(&host.kernel, name, TITLES, &[("language", "sparql")]);
    }
    let read = |who: &Capability, name: &str| {
        call(
            &host.kernel,
            who,
            Verb::Source,
            &format!("urn:script:{name}:result"),
            &[("as", "text/csv")],
        )
    };
    for grant in [
        "urn:cap:script:run:team-*",
        "urn:cap:script:run:team-a-*",
        "urn:cap:script:run:team-a-titles",
    ] {
        let who = cap(&[grant, READ_LEDGER]);
        let answer = read(&who, "team-a-titles").unwrap_or_else(|e| panic!("{grant}: {e}"));
        assert!(answer.contains("first"), "{grant}: {answer}");
    }
    // In the same top-level namespace, so past the floor, but refused inside.
    let b = cap(&["urn:cap:script:run:team-b-*", READ_LEDGER]);
    read(&b, "team-b-titles").unwrap();
    let message = denied(read(&b, "team-a-titles"));
    assert!(
        message.contains("urn:cap:script:run:team-a-titles"),
        "{message}"
    );
    // A name in no namespace keeps its exact gate.
    let team = cap(&["urn:cap:script:run:team-*", READ_LEDGER]);
    denied(read(&team, "titles"));
    read(&cap(&["urn:cap:script:run:titles", READ_LEDGER]), "titles").unwrap();
}

#[test]
fn a_querys_own_contract_declares_its_top_level_namespace() {
    let host = sparql_host();
    publish(
        &host.kernel,
        "team-a-titles",
        TITLES,
        &[("language", "sparql")],
    );
    publish(&host.kernel, "titles", TITLES, &[("language", "sparql")]);
    let meta = |name: &str| -> serde_json::Value {
        serde_json::from_str(&ok(
            &host.kernel,
            Verb::Meta,
            &format!("urn:script:{name}:result"),
            &[("as", "application/json")],
        ))
        .unwrap()
    };
    let text = meta("team-a-titles").to_string();
    assert!(text.contains("urn:cap:script:run:team-*"), "{text}");
    assert!(!text.contains("urn:cap:script:run:team-a-titles"), "{text}");
    let text = meta("titles").to_string();
    assert!(text.contains("urn:cap:script:run:titles"), "{text}");
}
