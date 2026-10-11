//! The authority rules, each as a refusal with a typed `Denied` — and the positive half of
//! each, so a test that passes because nothing works cannot pass.

mod common;

use std::sync::Arc;

use common::*;
use ikigai_core::{Capability, Error, Verb};
use ikigai_script::authority::{
    same_for_all, Ceiling, ANONYMOUS, CAP_READ_PUBLIC, CAP_RUN_PUBLIC, UNSTAMPED,
};
use ikigai_script::{MemoryBackend, Run};

/// A publisher of `name` who holds Lisp and whatever else is listed.
fn publisher(name: &str, more: &[&str]) -> Capability {
    let write = format!("urn:cap:script:write:{name}");
    let mut scopes = vec![write.as_str(), "urn:cap:lisp"];
    scopes.extend_from_slice(more);
    cap(&scopes)
}

/// A runner of `name` who holds Lisp and whatever else is listed.
fn runner(name: &str, more: &[&str]) -> Capability {
    let run = format!("urn:cap:script:run:{name}");
    let mut scopes = vec![run.as_str(), "urn:cap:lisp"];
    scopes.extend_from_slice(more);
    cap(&scopes)
}

fn lines(text: &str) -> Vec<&str> {
    text.lines().collect()
}

// ------------------------------------------------------------------ publish

#[test]
fn a_publisher_cannot_give_a_script_more_than_they_hold() {
    let host = host();
    let message = denied(call(
        &host.kernel,
        &publisher("grab", &[]),
        Verb::Sink,
        "urn:script:grab",
        &[("content", "1"), ("requires", CAP_VAULT)],
    ));
    assert!(message.contains(CAP_VAULT), "{message}");
    assert!(
        matches!(
            call(&host.kernel, &Capability::root(), Verb::Exists, "urn:script:grab", &[]),
            Ok(ref t) if t == "false\n"
        ),
        "a refused publish writes nothing"
    );
    // Holding it, the same publish is accepted.
    call(
        &host.kernel,
        &publisher("grab", &[CAP_VAULT]),
        Verb::Sink,
        "urn:script:grab",
        &[("content", "1"), ("requires", CAP_VAULT)],
    )
    .unwrap();
}

#[test]
fn a_publisher_who_may_not_run_lisp_may_not_publish_it() {
    let host = host();
    let message = denied(call(
        &host.kernel,
        &cap(&["urn:cap:script:write:x"]),
        Verb::Sink,
        "urn:script:x",
        &[("content", "1")],
    ));
    assert!(message.contains("urn:cap:lisp"), "{message}");
}

#[test]
fn writing_and_retiring_need_their_own_grants_for_that_script() {
    let host = host();
    publish(&host.kernel, "mine", "1", &[]);
    // A write grant for ANOTHER script satisfies the declared family, not this one.
    denied(call(
        &host.kernel,
        &publisher("other", &[]),
        Verb::Sink,
        "urn:script:mine",
        &[("content", "2")],
    ));
    // No write grant at all: the kernel refuses before dispatch.
    denied(call(
        &host.kernel,
        &cap(&["urn:cap:lisp"]),
        Verb::Sink,
        "urn:script:mine",
        &[("content", "2")],
    ));
    // Writing is not retiring.
    denied(call(
        &host.kernel,
        &publisher("mine", &["urn:cap:script:delete:other"]),
        Verb::Delete,
        "urn:script:mine",
        &[],
    ));
    call(
        &host.kernel,
        &cap(&["urn:cap:script:delete:mine"]),
        Verb::Delete,
        "urn:script:mine",
        &[],
    )
    .unwrap();
}

// ------------------------------------------------------------------ run

#[test]
fn a_runner_without_the_run_grant_is_refused() {
    let host = host();
    publish(&host.kernel, "job", "(+ 1 2)", &[]);
    for iri in ["urn:script:job:result", "urn:script:job:runs"] {
        let verb = if iri.ends_with("runs") {
            Verb::Sink
        } else {
            Verb::Source
        };
        // Holding no run grant: refused before dispatch, by the declared family.
        denied(call(&host.kernel, &cap(&["urn:cap:lisp"]), verb, iri, &[]));
        // Holding another script's: the family is satisfied, the exact grant is not.
        denied(call(&host.kernel, &runner("other", &[]), verb, iri, &[]));
        // Holding read but not run.
        denied(call(
            &host.kernel,
            &cap(&["urn:cap:lisp", "urn:cap:script:read:job"]),
            verb,
            iri,
            &[],
        ));
    }
    assert_eq!(host.evals(), 0);
    assert_eq!(
        call(
            &host.kernel,
            &runner("job", &[]),
            Verb::Source,
            "urn:script:job:result",
            &[]
        )
        .unwrap(),
        "3"
    );
}

#[test]
fn a_refused_run_records_nothing() {
    let host = host();
    publish(&host.kernel, "job", "1", &[]);
    denied(call(
        &host.kernel,
        &runner("other", &[]),
        Verb::Sink,
        "urn:script:job:runs",
        &[],
    ));
    assert_eq!(
        ok(&host.kernel, Verb::Exists, "urn:script:job:run:1", &[]),
        "false\n"
    );
}

#[test]
fn a_runner_without_the_language_grant_is_refused() {
    let host = host();
    publish(&host.kernel, "job", "1", &[]);
    let message = denied(call(
        &host.kernel,
        &cap(&["urn:cap:script:run:job"]),
        Verb::Source,
        "urn:script:job:result",
        &[],
    ));
    assert!(message.contains("urn:cap:lisp"), "{message}");
}

#[test]
fn a_run_holds_only_what_both_runner_and_script_hold() {
    let host = host();
    publish(
        &host.kernel,
        "probe",
        "(source \"urn:test:whoami\")",
        &[("requires", CAP_VAULT)],
    );
    // A runner who holds MORE than the script declares: the run keeps only the declared.
    let rich = runner("probe", &[CAP_VAULT, "urn:cap:mail:send"]);
    assert_eq!(
        lines(
            &call(
                &host.kernel,
                &rich,
                Verb::Source,
                "urn:script:probe:result",
                &[]
            )
            .unwrap()
        ),
        vec!["urn:cap:lisp", CAP_VAULT]
    );
    // A runner who holds LESS: the run keeps only what the runner holds. Never minted.
    let poor = runner("probe", &[]);
    assert_eq!(
        lines(
            &call(
                &host.kernel,
                &poor,
                Verb::Source,
                "urn:script:probe:result",
                &[]
            )
            .unwrap()
        ),
        vec!["urn:cap:lisp"]
    );
    // …so the script's own write is refused for the poor runner, typed.
    publish(
        &host.kernel,
        "stash",
        "(sink \"urn:test:vault\" \"x\")",
        &[("requires", CAP_VAULT)],
    );
    denied(call(
        &host.kernel,
        &runner("stash", &[]),
        Verb::Source,
        "urn:script:stash:result",
        &[],
    ));
    call(
        &host.kernel,
        &runner("stash", &[CAP_VAULT]),
        Verb::Source,
        "urn:script:stash:result",
        &[],
    )
    .unwrap();
}

#[test]
fn the_host_ceiling_clamps() {
    let host = host_with(
        Arc::new(MemoryBackend::new()),
        same_for_all(Ceiling::scoped(["urn:cap:lisp"])),
    );
    publish(
        &host.kernel,
        "stash",
        "(sink \"urn:test:vault\" \"x\")",
        &[("requires", CAP_VAULT)],
    );
    // Root runs it, the publisher (root) held the vault, the script declares it — and the
    // host's ceiling withholds it.
    let message = denied(call(
        &host.kernel,
        &Capability::root(),
        Verb::Source,
        "urn:script:stash:result",
        &[],
    ));
    assert!(message.contains(CAP_VAULT), "{message}");
    publish(
        &host.kernel,
        "probe",
        "(source \"urn:test:whoami\")",
        &[("requires", CAP_VAULT)],
    );
    assert_eq!(
        ok(&host.kernel, Verb::Source, "urn:script:probe:result", &[]),
        "urn:cap:lisp"
    );
}

#[test]
fn a_host_that_fails_closed_runs_nothing() {
    let host = host_with(
        Arc::new(MemoryBackend::new()),
        same_for_all(Ceiling::nothing()),
    );
    publish(&host.kernel, "pure", "(+ 1 2)", &[]);
    // Even the language is withheld, so the evaluator refuses the run.
    let message = denied(call(
        &host.kernel,
        &Capability::root(),
        Verb::Source,
        "urn:script:pure:result",
        &[],
    ));
    assert!(message.contains("urn:cap:lisp"), "{message}");
}

#[test]
fn the_ceiling_is_asked_per_script() {
    let policy: ikigai_script::authority::CeilingPolicy = Arc::new(|name: &str| {
        if name == "trusted" {
            Ceiling::unbounded()
        } else {
            Ceiling::scoped(["urn:cap:lisp"])
        }
    });
    let host = host_with(Arc::new(MemoryBackend::new()), policy);
    for name in ["trusted", "untrusted"] {
        publish(
            &host.kernel,
            name,
            "(source \"urn:test:whoami\")",
            &[("requires", CAP_VAULT)],
        );
    }
    assert_eq!(
        ok(&host.kernel, Verb::Source, "urn:script:trusted:result", &[]),
        format!("urn:cap:lisp\n{CAP_VAULT}")
    );
    assert_eq!(
        ok(
            &host.kernel,
            Verb::Source,
            "urn:script:untrusted:result",
            &[]
        ),
        "urn:cap:lisp"
    );
}

#[test]
fn the_publishers_exclusions_travel_with_the_script() {
    let host = host();
    let read_root = "urn:cap:fs:read:/root";
    let not_secret = "urn:cap:fs:read:-/root/secret";
    call(
        &host.kernel,
        &publisher("reader", &[read_root, not_secret]),
        Verb::Sink,
        "urn:script:reader",
        &[
            ("content", "(source \"urn:test:whoami\")"),
            ("requires", read_root),
        ],
    )
    .unwrap();
    // Root runs it — a runner with no exclusion at all — and the run still carries the
    // publisher's: the publisher could not read the secret, so neither can the script.
    assert_eq!(
        lines(&ok(
            &host.kernel,
            Verb::Source,
            "urn:script:reader:result",
            &[]
        )),
        vec![not_secret, read_root, "urn:cap:lisp"]
    );
}

// ------------------------------------------------------------------ anonymous

/// What a host gives its unauthenticated door.
fn anonymous() -> Capability {
    cap(&[CAP_RUN_PUBLIC, CAP_READ_PUBLIC, "urn:cap:lisp"])
}

#[test]
fn an_anonymous_caller_runs_only_a_public_script() {
    let host = host();
    publish(&host.kernel, "open", "(+ 1 2)", &[("public", "true")]);
    publish(&host.kernel, "closed", "(+ 1 2)", &[]);
    publish(
        &host.kernel,
        "unfinished",
        "(+ 1 2)",
        &[("public", "true"), ("state", "draft")],
    );
    assert_eq!(
        call(
            &host.kernel,
            &anonymous(),
            Verb::Source,
            "urn:script:open:result",
            &[]
        )
        .unwrap(),
        "3"
    );
    call(
        &host.kernel,
        &anonymous(),
        Verb::Sink,
        "urn:script:open:runs",
        &[],
    )
    .unwrap();
    for name in ["closed", "unfinished", "absent"] {
        let iri = format!("urn:script:{name}:result");
        denied(call(&host.kernel, &anonymous(), Verb::Source, &iri, &[]));
    }
    // A public script is still not anonymous's to change.
    denied(call(
        &host.kernel,
        &anonymous(),
        Verb::Sink,
        "urn:script:open",
        &[("content", "(+ 2 2)")],
    ));
}

#[test]
fn an_anonymous_caller_reads_only_a_public_script_and_learns_nothing_else() {
    let host = host();
    publish(&host.kernel, "open", "(+ 1 2)", &[("public", "true")]);
    publish(&host.kernel, "closed", "(+ 1 2)", &[]);
    assert_eq!(
        call(
            &host.kernel,
            &anonymous(),
            Verb::Source,
            "urn:script:open",
            &[]
        )
        .unwrap(),
        "(+ 1 2)"
    );
    // A private script and a missing one are refused the SAME way: no existence oracle.
    let private = denied(call(
        &host.kernel,
        &anonymous(),
        Verb::Source,
        "urn:script:closed",
        &[],
    ));
    let missing = denied(call(
        &host.kernel,
        &anonymous(),
        Verb::Source,
        "urn:script:absent",
        &[],
    ));
    assert_eq!(
        private.replace("closed", "NAME"),
        missing.replace("absent", "NAME")
    );
    // Run records are never public.
    call(
        &host.kernel,
        &anonymous(),
        Verb::Sink,
        "urn:script:open:runs",
        &[],
    )
    .unwrap();
    denied(call(
        &host.kernel,
        &anonymous(),
        Verb::Source,
        "urn:script:open:run:1",
        &[],
    ));
    // The catalog shows what anonymous may read.
    let catalog = call(
        &host.kernel,
        &anonymous(),
        Verb::Source,
        "urn:script:catalog",
        &[],
    )
    .unwrap();
    assert!(catalog.contains("urn:script:open "), "{catalog}");
    assert!(!catalog.contains("closed"), "{catalog}");
}

// ------------------------------------------------------------------ eval

#[test]
fn eval_runs_under_the_callers_own_authority_and_nothing_more() {
    let host = host();
    let caller = cap(&["urn:cap:lisp"]);
    assert_eq!(
        call(
            &host.kernel,
            &caller,
            Verb::Sink,
            "urn:script:eval",
            &[("content", "(source \"urn:test:whoami\")")],
        )
        .unwrap(),
        "urn:cap:lisp"
    );
    denied(call(
        &host.kernel,
        &caller,
        Verb::Sink,
        "urn:script:eval",
        &[("content", "(sink \"urn:test:vault\" \"x\")")],
    ));
    // With the grant, the same code is allowed: it is the caller's authority, unchanged.
    call(
        &host.kernel,
        &cap(&["urn:cap:lisp", CAP_VAULT]),
        Verb::Sink,
        "urn:script:eval",
        &[("content", "(sink \"urn:test:vault\" \"x\")")],
    )
    .unwrap();
    // No Lisp grant, no eval.
    denied(call(
        &host.kernel,
        &cap(&[CAP_VAULT]),
        Verb::Sink,
        "urn:script:eval",
        &[("content", "1")],
    ));
}

/// `urn:script:eval` runs Lisp and only Lisp, so its `urn:cap:lisp` floor is the language it
/// runs (ledger #1174): its contract offers `language=lisp` alone, and a plan or a query is
/// pointed at its own door rather than advertised and then refused.
#[test]
fn eval_offers_only_the_language_its_floor_is_for() {
    let host = host();
    let contract: ikigai_core::Description = serde_json::from_str(&ok(
        &host.kernel,
        Verb::Meta,
        "urn:script:eval",
        &[("as", "application/json")],
    ))
    .unwrap();
    let sink = contract
        .action_specs()
        .into_iter()
        .find(|a| a.verb == Verb::Sink)
        .expect("a Sink action");
    assert_eq!(sink.requires, vec!["urn:cap:lisp".to_string()]);
    let language = sink
        .inputs
        .iter()
        .find(|i| i.name == "language")
        .expect("a language argument");
    assert_eq!(language.one_of, vec!["lisp".to_string()]);
    for (language, points_at) in [("plan", "urn:plan:eval"), ("sparql", "Protocol")] {
        match call(
            &host.kernel,
            &Capability::root(),
            Verb::Sink,
            "urn:script:eval",
            &[("content", "x"), ("language", language)],
        ) {
            Err(Error::InvalidArgument { name, detail }) => {
                assert_eq!(name, "language");
                assert!(detail.contains(points_at), "{detail}");
            }
            other => panic!("{language}: expected InvalidArgument, got {other:?}"),
        }
    }
}

#[test]
fn eval_saves_a_draft_only_with_that_scripts_write_grant() {
    let host = host();
    denied(call(
        &host.kernel,
        &cap(&["urn:cap:lisp"]),
        Verb::Sink,
        "urn:script:eval",
        &[("content", "(+ 1 2)"), ("save", "keeper")],
    ));
    assert_eq!(
        ok(&host.kernel, Verb::Exists, "urn:script:keeper", &[]),
        "false\n"
    );
    assert_eq!(
        call(
            &host.kernel,
            &cap(&["urn:cap:lisp", "urn:cap:script:write:keeper"]),
            Verb::Sink,
            "urn:script:eval",
            &[("content", "(+ 1 2)"), ("save", "keeper")],
        )
        .unwrap(),
        "3"
    );
    let record: serde_json::Value = serde_json::from_str(&ok(
        &host.kernel,
        Verb::Source,
        "urn:script:keeper",
        &[("as", "application/json")],
    ))
    .unwrap();
    assert_eq!(record["state"], "draft");
    assert_eq!(record["source"], "(+ 1 2)");
}

#[test]
fn saving_a_draft_cuts_a_cached_read_of_the_script() {
    let host = host();
    publish(&host.kernel, "notes", "1", &[]);
    assert_eq!(ok(&host.kernel, Verb::Source, "urn:script:notes", &[]), "1");
    ok(
        &host.kernel,
        Verb::Sink,
        "urn:script:eval",
        &[("content", "2"), ("save", "notes")],
    );
    assert_eq!(ok(&host.kernel, Verb::Source, "urn:script:notes", &[]), "2");
}

// ------------------------------------------------------------------ the record

#[test]
fn the_principal_is_the_capabilitys_never_the_callers() {
    // The door mints who is calling into the capability; an argument claiming otherwise is
    // never read.
    let host = host();
    let brian = "urn:test:person:brian";
    call(
        &host.kernel,
        &publisher("job", &[]).with_principal(brian).unwrap(),
        Verb::Sink,
        "urn:script:job",
        &[
            ("content", "1"),
            ("public", "true"),
            ("principal", "urn:test:person:mallory"),
        ],
    )
    .unwrap();
    // The caller claims to be someone; the record says what the capability said.
    call(
        &host.kernel,
        &anonymous().with_principal(ANONYMOUS).unwrap(),
        Verb::Sink,
        "urn:script:job:runs",
        &[("principal", brian)],
    )
    .unwrap();
    call(
        &host.kernel,
        &runner("job", &[]).with_principal(brian).unwrap(),
        Verb::Sink,
        "urn:script:job:runs",
        &[],
    )
    .unwrap();
    // Root names no principal (it is the host's own authority), and neither does a
    // capability its door minted nothing into.
    ok(&host.kernel, Verb::Sink, "urn:script:job:runs", &[]);
    call(
        &host.kernel,
        &runner("job", &[]),
        Verb::Sink,
        "urn:script:job:runs",
        &[],
    )
    .unwrap();
    let principal = |id: u64| {
        let run: Run = serde_json::from_str(&ok(
            &host.kernel,
            Verb::Source,
            &format!("urn:script:job:run:{id}"),
            &[("as", "application/json")],
        ))
        .unwrap();
        run.principal
    };
    assert_eq!(principal(1), ANONYMOUS);
    assert_eq!(principal(2), brian);
    assert_eq!(principal(3), UNSTAMPED);
    assert_eq!(principal(4), UNSTAMPED);
    let record: serde_json::Value = serde_json::from_str(&ok(
        &host.kernel,
        Verb::Source,
        "urn:script:job",
        &[("as", "application/json")],
    ))
    .unwrap();
    assert_eq!(record["publisher"], brian);
}

#[test]
fn reading_needs_the_read_grant_for_that_script() {
    let host = host();
    publish(&host.kernel, "secret", "(+ 1 2)", &[]);
    denied(call(
        &host.kernel,
        &cap(&["urn:cap:script:read:other"]),
        Verb::Source,
        "urn:script:secret",
        &[],
    ));
    // A runner may run it but not read its source.
    denied(call(
        &host.kernel,
        &runner("secret", &["urn:cap:script:read:other"]),
        Verb::Source,
        "urn:script:secret",
        &[],
    ));
    assert_eq!(
        call(
            &host.kernel,
            &cap(&["urn:cap:script:read:secret"]),
            Verb::Source,
            "urn:script:secret",
            &[],
        )
        .unwrap(),
        "(+ 1 2)"
    );
    let missing = call(
        &host.kernel,
        &cap(&["urn:cap:script:read:absent"]),
        Verb::Source,
        "urn:script:absent",
        &[],
    );
    assert!(matches!(missing, Err(Error::NotFound(_))), "{missing:?}");
}
