//! Plans as a script language, end to end, every case against both the TEST DOUBLE of the
//! host's plan doors (`tests/common/plan.rs`) and the real ones (`ikigai-engine`'s
//! `plan_space`, validating through `ikigai-shacl`; `common::both`). Publish validates and
//! derives; fetching does not run; a read plan runs at `…:result` and caches; a plan with a
//! Sink step is a write; derived authority is refused and answered exactly; each plan is its
//! own catalog entry.

mod common;

use common::*;
use ikigai_core::{Capability, Error, Verb};
use ikigai_script::authority::{same_for_all, Ceiling};

/// A read: one step, greeting the plan's one parameter (optional, default `world`).
const HELLO: &str = r#"# Greet someone.
@prefix ik: <https://ikigai-rs.dev/ns#> .
<urn:plan:hello> a ik:Process ;
    ik:input <urn:plan:hello:input:who> ;
    ik:step <urn:plan:hello:step:1> ;
    ik:result <urn:plan:hello:step:1> .
<urn:plan:hello:input:who> ik:inputName "who" ; ik:required false ; ik:default "world" .
<urn:plan:hello:step:1> a ik:Step ; ik:verb "Source" ; ik:resolves <urn:test:greet> ;
    ik:argument <urn:plan:hello:step:1:arg:who> .
<urn:plan:hello:step:1:arg:who> a ik:Argument ; ik:inputName "who" ;
    ik:ref <urn:plan:hello:var:who> .
"#;

/// A read whose answer is the capability its steps ran under, seen from the far side. The
/// second step is FED by the first, so the engine (which runs only what the result depends
/// on) runs both.
const OBSERVE: &str = r#"@prefix ik: <https://ikigai-rs.dev/ns#> .
<urn:plan:observe> a ik:Process ;
    ik:step <urn:plan:observe:step:1> , <urn:plan:observe:step:2> ;
    ik:result <urn:plan:observe:step:2> .
<urn:plan:observe:step:1> a ik:Step ; ik:verb "Source" ; ik:resolves <urn:test:greet> ;
    ik:argument <urn:plan:observe:step:1:arg:who> .
<urn:plan:observe:step:1:arg:who> a ik:Argument ; ik:inputName "who" ; ik:value "x" .
<urn:plan:observe:step:2> a ik:Step ; ik:verb "Source" ; ik:resolves <urn:test:held> ;
    ik:pipeFrom <urn:plan:observe:step:1> .
"#;

/// A write: what the run held, piped into the vault.
const STORE: &str = r#"@prefix ik: <https://ikigai-rs.dev/ns#> .
<urn:plan:store> a ik:Process ;
    ik:step <urn:plan:store:step:1> , <urn:plan:store:step:2> ;
    ik:result <urn:plan:store:step:2> .
<urn:plan:store:step:1> a ik:Step ; ik:verb "Source" ; ik:resolves <urn:test:whoami> .
<urn:plan:store:step:2> a ik:Step ; ik:verb "Sink" ; ik:resolves <urn:test:vault> ;
    ik:pipeFrom <urn:plan:store:step:1> .
"#;

/// A step reaching a host by a parameter: the step's target declares a FAMILY.
const REACH: &str = r#"@prefix ik: <https://ikigai-rs.dev/ns#> .
<urn:plan:reach> a ik:Process ;
    ik:input <urn:plan:reach:input:host> ;
    ik:step <urn:plan:reach:step:1> , <urn:plan:reach:step:2> ;
    ik:result <urn:plan:reach:step:2> .
<urn:plan:reach:input:host> ik:inputName "host" ; ik:required false ; ik:default "example.com" .
<urn:plan:reach:step:1> a ik:Step ; ik:verb "Source" ; ik:resolves <urn:test:host> ;
    ik:argument <urn:plan:reach:step:1:arg:host> .
<urn:plan:reach:step:1:arg:host> a ik:Argument ; ik:inputName "host" ;
    ik:ref <urn:plan:reach:var:host> .
<urn:plan:reach:step:2> a ik:Step ; ik:verb "Source" ; ik:resolves <urn:test:held> ;
    ik:pipeFrom <urn:plan:reach:step:1> .
"#;

fn plan(kernel: &ikigai_core::Kernel, name: &str, text: &str) -> String {
    publish(kernel, name, text, &[("language", "plan")])
}

fn invalid(result: std::result::Result<String, Error>) -> (String, String) {
    match result {
        Err(Error::InvalidArgument { name, detail }) => (name, detail),
        other => panic!("expected InvalidArgument, got {other:?}"),
    }
}

fn result(
    host: &PlanHost,
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

fn json(text: &str) -> serde_json::Value {
    serde_json::from_str(text).unwrap_or_else(|e| panic!("{e}: {text}"))
}

// ---------------------------------------------------------------------------------------

#[test]
fn publish_validates_derives_and_fetches_without_running() {
    both(|doors| {
        let host = plan_host_of(doors);
        let version = plan(&host.kernel, "hello", HELLO);
        assert!(
            version.starts_with("urn:script:hello:version:sha256:"),
            "{version}"
        );
        assert_eq!(
            ok(&host.kernel, Verb::Source, "urn:script:hello", &[]),
            HELLO
        );
        let record = json(&ok(
            &host.kernel,
            Verb::Source,
            "urn:script:hello",
            &[("as", "application/json")],
        ));
        assert_eq!(record["language"], "plan");
        // DERIVED from the step's contract; no language capability for a plan.
        assert_eq!(record["requires"], serde_json::json!([CAP_GREET]));
        let compiled = json(&ok(
            &host.kernel,
            Verb::Source,
            "urn:script:hello:compiled",
            &[],
        ));
        assert_eq!(compiled["evaluator"], "urn:plan:eval");
        assert_eq!(compiled["plan"]["process"], "urn:plan:hello");
        assert_eq!(compiled["plan"]["steps"][0]["verb"], "Source");
        assert_eq!(compiled["plan"]["parameters"][0]["name"], "who");
        assert_eq!(
            host.evals(),
            0,
            "publishing or fetching a plan must not run it"
        );
    });
}

#[test]
fn a_read_plan_runs_at_result_with_its_parameters_and_is_cached() {
    both(|doors| {
        let host = plan_host_of(doors);
        plan(&host.kernel, "hello", HELLO);
        let root = Capability::root();
        assert_eq!(result(&host, &root, "hello", &[]).unwrap(), "hello, world");
        assert_eq!(
            result(&host, &root, "hello", &[("who", "brian")]).unwrap(),
            "hello, brian"
        );
        assert_eq!(host.evals(), 2);
        // Every step is cacheable, so the plan is: the same read runs nothing.
        assert_eq!(result(&host, &root, "hello", &[]).unwrap(), "hello, world");
        assert_eq!(host.evals(), 2, "a pure plan's answer is cached");
        // A binding the plan does not declare is refused, never ignored.
        let (name, detail) = invalid(result(&host, &root, "hello", &[("whom", "x")]));
        assert_eq!(name, "whom");
        assert!(detail.contains("its parameters are who"), "{detail}");
        // A republish cuts the cached answer.
        plan(
            &host.kernel,
            "hello",
            &HELLO.replace("\"world\"", "\"there\""),
        );
        assert_eq!(result(&host, &root, "hello", &[]).unwrap(), "hello, there");
        assert_eq!(host.evals(), 3);
    });
}

#[test]
fn a_required_parameter_is_refused_before_anything_runs() {
    both(|doors| {
        let host = plan_host_of(doors);
        let strict = HELLO.replace(
            "ik:required false ; ik:default \"world\"",
            "ik:required true",
        );
        plan(&host.kernel, "hello", &strict);
        match result(&host, &Capability::root(), "hello", &[]) {
            Err(Error::MissingArgument(name)) => assert_eq!(name, "who"),
            other => panic!("{other:?}"),
        }
        assert_eq!(host.evals(), 0);
        // Through `…:runs`, as one JSON object piped as `content`.
        let run = ok(
            &host.kernel,
            Verb::Sink,
            "urn:script:hello:runs",
            &[("content", r#"{"who": "pipe"}"#)],
        );
        let record = ok(&host.kernel, Verb::Source, run.trim(), &[]);
        assert!(record.contains("hello, pipe"), "{record}");
    });
}

#[test]
fn a_malformed_plan_is_refused_at_publish_naming_the_shape() {
    both(|doors| {
        let host = plan_host_of(doors);
        // A step fed two ways.
        let two_feeds = STORE.replace(
            "ik:pipeFrom <urn:plan:store:step:1> .",
            "ik:pipeFrom <urn:plan:store:step:1> ; ik:mapOver <urn:plan:store:step:1> .",
        );
        let (name, detail) = invalid(call(
            &host.kernel,
            &Capability::root(),
            Verb::Sink,
            "urn:script:bad",
            &[("content", &two_feeds), ("language", "plan")],
        ));
        assert_eq!(name, "content");
        assert!(detail.contains("urn:ikigai:shape:step"), "{detail}");
        assert!(detail.contains("<urn:plan:store:step:2>"), "{detail}");
        assert!(detail.contains("at most one of ik:pipeFrom"), "{detail}");
        // Not Turtle at all: the validator's refusal, said about `content`.
        let (name, detail) = invalid(call(
            &host.kernel,
            &Capability::root(),
            Verb::Sink,
            "urn:script:bad",
            &[("content", "this is { not turtle"), ("language", "plan")],
        ));
        assert_eq!(name, "content");
        assert!(detail.contains("not valid Turtle"), "{detail}");
        // Nothing was stored.
        assert_eq!(
            ok(&host.kernel, Verb::Exists, "urn:script:bad", &[]).trim(),
            "false"
        );
    });
}

#[test]
fn a_plan_whose_step_resolves_nowhere_cannot_derive_its_authority() {
    both(|doors| {
        let host = plan_host_of(doors);
        let nowhere = HELLO.replace("<urn:test:greet>", "<urn:test:nowhere>");
        let (name, detail) = invalid(call(
            &host.kernel,
            &Capability::root(),
            Verb::Sink,
            "urn:script:lost",
            &[("content", &nowhere), ("language", "plan")],
        ));
        assert_eq!(name, "content");
        assert!(detail.contains("cannot be derived"), "{detail}");
        assert!(detail.contains("<urn:plan:hello:step:1>"), "{detail}");
        assert!(detail.contains("urn:test:nowhere"), "{detail}");
    });
}

#[test]
fn a_plan_with_a_sink_step_is_a_write() {
    both(|doors| {
        let host = plan_host_of(doors);
        plan(&host.kernel, "store", STORE);
        let record = json(&ok(
            &host.kernel,
            Verb::Source,
            "urn:script:store",
            &[("as", "application/json")],
        ));
        assert_eq!(record["requires"], serde_json::json!([CAP_VAULT]));
        // Decided from the parsed plan: the read door refuses it, naming the write door.
        let (name, detail) = invalid(result(&host, &Capability::root(), "store", &[]));
        assert_eq!(name, "name");
        assert!(detail.contains("urn:script:store:runs"), "{detail}");
        assert!(detail.contains("Sink <urn:test:vault>"), "{detail}");
        assert_eq!(host.evals(), 0);
        // The write door runs it and records the run.
        let run = ok(&host.kernel, Verb::Sink, "urn:script:store:runs", &[]);
        assert_eq!(run.trim(), "urn:script:store:run:1");
        let record = json(&ok(
            &host.kernel,
            Verb::Source,
            "urn:script:store:run:1",
            &[("as", "application/json")],
        ));
        assert_eq!(record["outcome"]["status"], "ok");
        assert_eq!(record["result"], "stored");
        assert_eq!(record["capability"], serde_json::json!([CAP_VAULT]));
        // Not offered as a read: the per-script `…:result` declares no Source.
        let meta = ok(
            &host.kernel,
            Verb::Meta,
            "urn:script:store:result",
            &[("as", "application/json")],
        );
        let meta = json(&meta);
        assert_eq!(meta["id"], "script-store-result");
        assert!(
            !meta.to_string().contains("\"Source\""),
            "a writing plan offers no read: {meta}"
        );
    });
}

#[test]
fn a_declared_requires_must_be_exactly_the_derived_set() {
    both(|doors| {
        let host = plan_host_of(doors);
        for said in [
            "",
            "urn:cap:test:other",
            "urn:cap:test:greet urn:cap:test:other",
        ] {
            let (name, detail) = invalid(call(
                &host.kernel,
                &Capability::root(),
                Verb::Sink,
                "urn:script:hello",
                &[("content", HELLO), ("language", "plan"), ("requires", said)],
            ));
            assert_eq!(name, "requires");
            assert!(detail.contains("derives urn:cap:test:greet"), "{detail}");
        }
        // Saying exactly the derived set is accepted.
        publish(
            &host.kernel,
            "hello",
            HELLO,
            &[("language", "plan"), ("requires", CAP_GREET)],
        );
    });
}

#[test]
fn a_publisher_cannot_publish_a_plan_needing_more_than_they_hold() {
    both(|doors| {
        let host = plan_host_of(doors);
        let publisher = cap(&["urn:cap:script:write:hello"]);
        let message = denied(call(
            &host.kernel,
            &publisher,
            Verb::Sink,
            "urn:script:hello",
            &[("content", HELLO), ("language", "plan")],
        ));
        assert!(message.contains(CAP_GREET), "{message}");
        // Holding it, they may.
        let publisher = cap(&["urn:cap:script:write:hello", CAP_GREET]);
        call(
            &host.kernel,
            &publisher,
            Verb::Sink,
            "urn:script:hello",
            &[("content", HELLO), ("language", "plan")],
        )
        .unwrap();
    });
}

#[test]
fn a_run_holds_exactly_the_derived_authority_and_never_more_than_its_runner() {
    both(|doors| {
        let host = plan_host_of(doors);
        plan(&host.kernel, "observe", OBSERVE);
        // Answered: a runner holding much more runs under exactly what the plan derived.
        let runner = cap(&[
            "urn:cap:script:run:observe",
            CAP_GREET,
            CAP_VAULT,
            "urn:cap:lisp",
        ]);
        assert_eq!(result(&host, &runner, "observe", &[]).unwrap(), CAP_GREET);
        // Refused: a runner without the derived scope is refused at the floor, naming it.
        let message = denied(result(
            &host,
            &cap(&["urn:cap:script:run:observe"]),
            "observe",
            &[],
        ));
        assert!(message.contains(CAP_GREET), "{message}");
        // And without the run grant, holding everything else.
        denied(result(&host, &cap(&[CAP_GREET]), "observe", &[]));
        // No language grant is asked of a plan's runner (the template's `urn:cap:lisp` is not).
        let runner = cap(&["urn:cap:script:run:observe", CAP_GREET]);
        assert_eq!(result(&host, &runner, "observe", &[]).unwrap(), CAP_GREET);
    });
}

#[test]
fn the_ceiling_withholds_a_derived_scope_at_the_step() {
    both(|doors| {
        let host = plan_host_on(doors, same_for_all(Ceiling::nothing()));
        plan(&host.kernel, "hello", HELLO);
        let runner = cap(&["urn:cap:script:run:hello", CAP_GREET]);
        // The runner and the publisher hold it; the host does not allow it, so the step's own
        // floor refuses it inside the evaluator, typed and unchanged.
        let message = denied(result(&host, &runner, "hello", &[]));
        assert!(message.contains(CAP_GREET), "{message}");
    });
}

#[test]
fn a_derived_family_becomes_the_runners_own_members() {
    both(|doors| {
        let host = plan_host_of(doors);
        // A root publisher: the family is stored as the marker.
        plan(&host.kernel, "reach", REACH);
        let record = json(&ok(
            &host.kernel,
            Verb::Source,
            "urn:script:reach",
            &[("as", "application/json")],
        ));
        assert_eq!(record["requires"], serde_json::json!([CAP_NET]));
        let runner = cap(&[
            "urn:cap:script:run:reach",
            "urn:cap:test:net:example.com",
            "urn:cap:test:net:other.org",
            "urn:cap:test:net:-example.com/admin",
            CAP_VAULT,
        ]);
        // The run holds the runner's members of the family (and its exclusion), nothing else.
        assert_eq!(
        result(&host, &runner, "reach", &[]).unwrap(),
        "urn:cap:test:net:-example.com/admin\nurn:cap:test:net:example.com\nurn:cap:test:net:other.org"
    );
        // A host the runner does not hold is refused by the target's own rule, inside the run.
        let message = denied(result(
            &host,
            &runner,
            "reach",
            &[("host", "elsewhere.net")],
        ));
        assert!(
            message.contains("urn:cap:test:net:elsewhere.net"),
            "{message}"
        );

        // A host ceiling naming one member narrows the family to it.
        let host = plan_host_on(
            doors,
            same_for_all(Ceiling::scoped(["urn:cap:test:net:example.com"])),
        );
        plan(&host.kernel, "reach", REACH);
        assert_eq!(
            result(&host, &runner, "reach", &[]).unwrap(),
            "urn:cap:test:net:-example.com/admin\nurn:cap:test:net:example.com"
        );
        denied(result(&host, &runner, "reach", &[("host", "other.org")]));

        // A SCOPED publisher's grant is the members they held: other.org is never reachable,
        // whoever runs it.
        let host = plan_host_of(doors);
        let publisher = cap(&["urn:cap:script:write:reach", "urn:cap:test:net:example.com"]);
        call(
            &host.kernel,
            &publisher,
            Verb::Sink,
            "urn:script:reach",
            &[("content", REACH), ("language", "plan")],
        )
        .unwrap();
        assert_eq!(
            result(&host, &runner, "reach", &[]).unwrap(),
            "urn:cap:test:net:-example.com/admin\nurn:cap:test:net:example.com"
        );
        denied(result(&host, &runner, "reach", &[("host", "other.org")]));
    });
}

#[test]
fn a_plan_is_its_own_catalog_entry_with_its_parameters() {
    both(|doors| {
        let host = plan_host_of(doors);
        plan(&host.kernel, "hello", HELLO);
        let meta = json(&ok(
            &host.kernel,
            Verb::Meta,
            "urn:script:hello:result",
            &[("as", "application/json")],
        ));
        assert_eq!(meta["id"], "script-hello-result");
        let text = meta.to_string();
        assert!(text.contains("\"who\""), "{text}");
        assert!(text.contains(CAP_GREET), "{text}");
        assert!(!text.contains("urn:cap:lisp"), "{text}");
        assert!(text.contains("Greet someone."), "{text}");
    });
}

#[test]
fn a_host_without_plan_doors_takes_no_plans() {
    let host = host();
    let (name, detail) = invalid(call(
        &host.kernel,
        &Capability::root(),
        Verb::Sink,
        "urn:script:hello",
        &[("content", HELLO), ("language", "plan")],
    ));
    assert_eq!(name, "language");
    assert!(detail.contains("takes no plans"), "{detail}");
}

#[test]
fn eval_points_a_plan_at_the_hosts_evaluator() {
    both(|doors| {
        let host = plan_host_of(doors);
        let (name, detail) = invalid(call(
            &host.kernel,
            &Capability::root(),
            Verb::Sink,
            "urn:script:eval",
            &[("content", HELLO), ("language", "plan")],
        ));
        assert_eq!(name, "language");
        assert!(detail.contains("urn:plan:eval"), "{detail}");
    });
}

/// A plan whose one step runs ANOTHER script, `team-x`, in the `team` namespace. Its step's
/// target declares the namespace family (`authority::run_floor`), so a root publisher's
/// version stores `urn:cap:script:run:team-*` as a marker.
const OUTER: &str = r#"@prefix ik: <https://ikigai-rs.dev/ns#> .
<urn:plan:outer> a ik:Process ; ik:step <urn:plan:outer:step:1> ;
    ik:result <urn:plan:outer:step:1> .
<urn:plan:outer:step:1> a ik:Step ; ik:verb "Source" ; ik:resolves <urn:script:team-x:result> .
"#;

/// ★ Ledger #1222: a runner holding exactly the namespace grant `urn:cap:script:run:team-*`
/// runs a plan whose step calls `urn:script:team-x:result`. Before the fix the scoped-runner
/// branch of `plan::expand_families` kept only the runner's grants NOT ending in `*`, so the
/// run held nothing under the marker and the step was refused at its floor.
#[test]
fn a_namespace_runner_runs_a_step_calling_a_script_in_its_namespace() {
    both(|doors| {
        let host = plan_host_of(doors);
        plan(&host.kernel, "team-x", HELLO);
        plan(&host.kernel, "outer", OUTER);
        let record = json(&ok(
            &host.kernel,
            Verb::Source,
            "urn:script:outer",
            &[("as", "application/json")],
        ));
        assert_eq!(
            record["requires"],
            serde_json::json!(["urn:cap:script:run:team-*", CAP_GREET])
        );
        // Control: an EXACT grant for the inner script runs (it did before the fix too), so the
        // fixture is sound and the refusal below was the family's.
        let exact = cap(&[
            "urn:cap:script:run:outer",
            "urn:cap:script:run:team-x",
            CAP_GREET,
        ]);
        assert_eq!(result(&host, &exact, "outer", &[]).unwrap(), "hello, world");
        // The namespace grant runs it.
        let namespace = cap(&[
            "urn:cap:script:run:outer",
            "urn:cap:script:run:team-*",
            CAP_GREET,
        ]);
        assert_eq!(
            result(&host, &namespace, "outer", &[]).unwrap(),
            "hello, world"
        );
    });
}

/// The other side of ledger #1222: the runner's namespace grant passes through only as the
/// runner's own grant UNDER the marker, inside the ceiling, never wider.
#[test]
fn a_runners_namespace_grant_never_widens_a_plan_run() {
    both(|doors| {
        let host = plan_host_of(doors);
        plan(&host.kernel, "team-x", HELLO);
        plan(&host.kernel, "outer", OUTER);
        let runner = |extra: &[&str]| {
            let mut scopes = vec!["urn:cap:script:run:outer", CAP_GREET];
            scopes.extend_from_slice(extra);
            cap(&scopes)
        };
        // An exclusion the runner holds still takes the script back out.
        denied(result(
            &host,
            &runner(&["urn:cap:script:run:team-*", "urn:cap:script:run:-team-x"]),
            "outer",
            &[],
        ));
        // Another namespace, a prefix that is not a namespace, and the "every script" spelling
        // (which grants nothing) do not reach team-x.
        for other in [
            "urn:cap:script:run:other-*",
            "urn:cap:script:run:te*",
            "urn:cap:script:run:*",
        ] {
            denied(result(&host, &runner(&[other]), "outer", &[]));
        }

        // A ceiling that names only the exact inner grant does not admit the runner's wider
        // namespace grant: refused (fail closed), while an exact runner runs.
        let host = plan_host_on(
            doors,
            same_for_all(Ceiling::scoped([CAP_GREET, "urn:cap:script:run:team-x"])),
        );
        plan(&host.kernel, "team-x", HELLO);
        plan(&host.kernel, "outer", OUTER);
        denied(result(
            &host,
            &runner(&["urn:cap:script:run:team-*"]),
            "outer",
            &[],
        ));
        assert_eq!(
            result(&host, &runner(&["urn:cap:script:run:team-x"]), "outer", &[]).unwrap(),
            "hello, world"
        );
        // A ceiling admitting the namespace (or wider) admits the runner's grant.
        for line in ["urn:cap:script:run:team-*", "urn:cap:script:run:*"] {
            let host = plan_host_on(doors, same_for_all(Ceiling::scoped([CAP_GREET, line])));
            plan(&host.kernel, "team-x", HELLO);
            plan(&host.kernel, "outer", OUTER);
            assert_eq!(
                result(&host, &runner(&["urn:cap:script:run:team-*"]), "outer", &[]).unwrap(),
                "hello, world",
                "ceiling {line}"
            );
        }

        // A SCOPED publisher holding the namespace grant leaves the same marker, and a namespace
        // runner runs it.
        let host = plan_host_of(doors);
        plan(&host.kernel, "team-x", HELLO);
        let publisher = cap(&[
            "urn:cap:script:write:outer",
            "urn:cap:script:run:team-*",
            CAP_GREET,
        ]);
        call(
            &host.kernel,
            &publisher,
            Verb::Sink,
            "urn:script:outer",
            &[("content", OUTER), ("language", "plan")],
        )
        .unwrap();
        assert_eq!(
            result(&host, &runner(&["urn:cap:script:run:team-*"]), "outer", &[]).unwrap(),
            "hello, world"
        );
    });
}
