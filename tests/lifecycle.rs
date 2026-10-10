//! The life of a script: publish, fetch without running, run as a read (and its caching),
//! run for effects (and the run record), versions, retire.

mod common;

use std::sync::{Arc, Mutex};

use common::*;
use ikigai_core::{Capability, Error, Verb};
use ikigai_script::authority::{Ceiling, CeilingPolicy};
use ikigai_script::{Catalog, MemoryBackend, Run};

#[test]
fn publish_then_fetch_without_running() {
    let host = host();
    let version = publish(&host.kernel, "hello", "(+ 1 2)", &[]);
    assert!(
        version.starts_with("urn:script:hello:version:sha256:"),
        "{version}"
    );
    // The source, verbatim — and nothing ran.
    let source = ok(&host.kernel, Verb::Source, "urn:script:hello", &[]);
    assert_eq!(source, "(+ 1 2)");
    let record = ok(
        &host.kernel,
        Verb::Source,
        "urn:script:hello",
        &[("as", "application/json")],
    );
    let record: serde_json::Value = serde_json::from_str(&record).unwrap();
    assert_eq!(record["state"], "published");
    assert_eq!(record["public"], false);
    assert_eq!(record["language"], "lisp");
    assert_eq!(record["versionIri"], version.as_str());
    // The language's capability is declared implicitly.
    assert_eq!(record["requires"], serde_json::json!(["urn:cap:lisp"]));
    assert_eq!(record["publisher"], "urn:script:principal:unstamped");
    assert_eq!(host.evals(), 0, "fetching a script must not run it");
    assert_eq!(
        ok(&host.kernel, Verb::Exists, "urn:script:hello", &[]),
        "true\n"
    );
    assert_eq!(
        ok(&host.kernel, Verb::Exists, "urn:script:nobody", &[]),
        "false\n"
    );
}

#[test]
fn a_result_is_the_scripts_answer_and_runs_each_time_unless_it_opts_in() {
    let host = host();
    publish(&host.kernel, "live", "(+ 1 2)", &[]);
    assert_eq!(
        ok(&host.kernel, Verb::Source, "urn:script:live:result", &[]),
        "3"
    );
    assert_eq!(
        ok(&host.kernel, Verb::Source, "urn:script:live:result", &[]),
        "3"
    );
    assert_eq!(host.evals(), 2, "an uncacheable program runs on every read");

    publish(&host.kernel, "pure", "(cacheable (* 6 7))", &[]);
    let before = host.evals();
    assert_eq!(
        ok(&host.kernel, Verb::Source, "urn:script:pure:result", &[]),
        "42"
    );
    assert_eq!(
        ok(&host.kernel, Verb::Source, "urn:script:pure:result", &[]),
        "42"
    );
    assert_eq!(
        host.evals() - before,
        1,
        "a program that opts in is served from the cache the second time"
    );

    // Republishing cuts the script's thread, so the cached answer is not served again.
    publish(&host.kernel, "pure", "(cacheable (* 6 8))", &[]);
    assert_eq!(
        ok(&host.kernel, Verb::Source, "urn:script:pure:result", &[]),
        "48"
    );
    assert_eq!(host.evals() - before, 2);
}

#[test]
fn the_host_cuts_the_authority_thread_when_it_changes_a_ceiling() {
    let ceiling = Arc::new(Mutex::new(Ceiling::unbounded()));
    let policy: CeilingPolicy = {
        let ceiling = Arc::clone(&ceiling);
        Arc::new(move |_| ceiling.lock().unwrap().clone())
    };
    let host = host_with(Arc::new(MemoryBackend::new()), policy);
    publish(
        &host.kernel,
        "whoami",
        "(cacheable (source \"urn:test:whoami\"))",
        &[("requires", CAP_VAULT)],
    );
    let read = || ok(&host.kernel, Verb::Source, "urn:script:whoami:result", &[]);
    assert_eq!(read(), format!("urn:cap:lisp\n{CAP_VAULT}"));

    // The host narrows the ceiling. The library cannot see the host's file change, so a
    // cached answer computed under the old ceiling is still served…
    *ceiling.lock().unwrap() = Ceiling::scoped(["urn:cap:lisp"]);
    assert_eq!(read(), format!("urn:cap:lisp\n{CAP_VAULT}"));
    // …until the host cuts the script's authority thread, which is its half of the contract.
    host.kernel.cut("urn:script:whoami:authority");
    assert_eq!(read(), "urn:cap:lisp");
}

#[test]
fn data_reaches_the_script_as_input_never_as_code() {
    let host = host();
    publish(
        &host.kernel,
        "echo",
        "(string-append \"got \" (input))",
        &[],
    );
    assert_eq!(
        ok(
            &host.kernel,
            Verb::Source,
            "urn:script:echo:result",
            &[("data", "(+ 1 2)")]
        ),
        "got (+ 1 2)"
    );
}

#[test]
fn a_run_for_effects_is_recorded() {
    let host = host();
    let version = publish(
        &host.kernel,
        "stash",
        "(sink \"urn:test:vault\" (input))",
        &[("requires", CAP_VAULT)],
    );
    let run = ok(
        &host.kernel,
        Verb::Sink,
        "urn:script:stash:runs",
        &[("content", "the payload")],
    );
    assert_eq!(run.trim(), "urn:script:stash:run:1");
    let record = ok(
        &host.kernel,
        Verb::Source,
        "urn:script:stash:run:1",
        &[("as", "application/json")],
    );
    let record: Run = serde_json::from_str(&record).unwrap();
    assert_eq!(record.id, 1);
    assert_eq!(
        Some(record.version.as_str()),
        version.rsplit(":version:").next()
    );
    assert_eq!(record.outcome, ikigai_script::Outcome::Ok);
    assert_eq!(record.result.as_deref(), Some("stored"));
    assert!(record.started.is_some() && record.ended > record.started);
    // Under root the run holds exactly what the script declared, and nothing else.
    assert_eq!(
        record
            .capability
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec!["urn:cap:lisp", CAP_VAULT]
    );
    let text = ok(&host.kernel, Verb::Source, "urn:script:stash:run:1", &[]);
    assert!(text.contains("outcome:    ok"), "{text}");
    // A second run is the next number.
    let run = ok(
        &host.kernel,
        Verb::Sink,
        "urn:script:stash:runs",
        &[("content", "x")],
    );
    assert_eq!(run.trim(), "urn:script:stash:run:2");
    assert_eq!(
        ok(&host.kernel, Verb::Exists, "urn:script:stash:run:2", &[]),
        "true\n"
    );
    assert_eq!(
        ok(&host.kernel, Verb::Exists, "urn:script:stash:run:3", &[]),
        "false\n"
    );
}

#[test]
fn a_failed_run_is_recorded_and_its_error_keeps_its_type() {
    let host = host();
    // Declares nothing beyond Lisp, so the vault refuses it.
    publish(
        &host.kernel,
        "overreach",
        "(sink \"urn:test:vault\" \"x\")",
        &[],
    );
    let message = denied(call(
        &host.kernel,
        &Capability::root(),
        Verb::Sink,
        "urn:script:overreach:runs",
        &[],
    ));
    assert!(
        message.contains("run recorded at urn:script:overreach:run:1"),
        "{message}"
    );
    let record: Run = serde_json::from_str(&ok(
        &host.kernel,
        Verb::Source,
        "urn:script:overreach:run:1",
        &[("as", "application/json")],
    ))
    .unwrap();
    assert!(
        matches!(&record.outcome, ikigai_script::Outcome::Failed { kind, .. } if kind == "denied"),
        "{record:?}"
    );
}

#[test]
fn republishing_makes_a_new_version_and_the_old_one_stays() {
    let host = host();
    let first = publish(&host.kernel, "evolving", "1", &[]);
    let second = publish(&host.kernel, "evolving", "2", &[]);
    assert_ne!(first, second);
    // The head moved.
    assert_eq!(
        ok(
            &host.kernel,
            Verb::Source,
            "urn:script:evolving:result",
            &[]
        ),
        "2"
    );
    // Both versions are fetchable, by their own names.
    assert_eq!(ok(&host.kernel, Verb::Source, &first, &[]), "1");
    assert_eq!(ok(&host.kernel, Verb::Source, &second, &[]), "2");
    assert_eq!(ok(&host.kernel, Verb::Exists, &first, &[]), "true\n");
    // The same content is the same version: content-addressed.
    assert_eq!(publish(&host.kernel, "evolving", "1", &[]), first);
    // The history keeps every change.
    let record: serde_json::Value = serde_json::from_str(&ok(
        &host.kernel,
        Verb::Source,
        "urn:script:evolving",
        &[("as", "application/json")],
    ))
    .unwrap();
    assert_eq!(record["history"].as_array().unwrap().len(), 3);
    // A version of another content is not found.
    let missing = format!("urn:script:evolving:version:sha256:{}", "0".repeat(64));
    assert!(matches!(
        call(
            &host.kernel,
            &Capability::root(),
            Verb::Source,
            &missing,
            &[]
        ),
        Err(Error::NotFound(_))
    ));
}

#[test]
fn if_version_refuses_a_write_that_lost_a_race() {
    let host = host();
    let first = publish(&host.kernel, "raced", "1", &[("if-version", "none")]);
    let digest = first.rsplit(":version:").next().unwrap().to_string();
    publish(&host.kernel, "raced", "2", &[]);
    let lost = call(
        &host.kernel,
        &Capability::root(),
        Verb::Sink,
        "urn:script:raced",
        &[("content", "3"), ("if-version", &digest)],
    );
    assert!(matches!(lost, Err(Error::Conflict(_))), "{lost:?}");
    assert_eq!(ok(&host.kernel, Verb::Source, "urn:script:raced", &[]), "2");
}

#[test]
fn a_retired_script_is_readable_and_never_runs() {
    let host = host();
    let version = publish(&host.kernel, "old", "1", &[]);
    assert_eq!(
        ok(&host.kernel, Verb::Source, "urn:script:old:result", &[]),
        "1"
    );
    assert_eq!(
        ok(&host.kernel, Verb::Delete, "urn:script:old", &[]),
        "retired urn:script:old\n"
    );
    // Retiring cut the cached compiled form, so the run sees it at once.
    let refused = call(
        &host.kernel,
        &Capability::root(),
        Verb::Source,
        "urn:script:old:result",
        &[],
    );
    assert!(matches!(refused, Err(Error::Conflict(_))), "{refused:?}");
    let refused = call(
        &host.kernel,
        &Capability::root(),
        Verb::Sink,
        "urn:script:old:runs",
        &[],
    );
    assert!(matches!(refused, Err(Error::Conflict(_))), "{refused:?}");
    // Still readable, and its version still fetchable.
    assert_eq!(ok(&host.kernel, Verb::Source, "urn:script:old", &[]), "1");
    assert_eq!(ok(&host.kernel, Verb::Source, &version, &[]), "1");
    // Retiring twice is not an error.
    assert!(ok(&host.kernel, Verb::Delete, "urn:script:old", &[]).contains("already"));
    // Publishing again brings it back.
    publish(&host.kernel, "old", "1", &[]);
    assert_eq!(
        ok(&host.kernel, Verb::Source, "urn:script:old:result", &[]),
        "1"
    );
}

#[test]
fn a_draft_is_saved_but_does_not_run() {
    let host = host();
    publish(&host.kernel, "wip", "(+ 1 1)", &[("state", "draft")]);
    let refused = call(
        &host.kernel,
        &Capability::root(),
        Verb::Source,
        "urn:script:wip:result",
        &[],
    );
    assert!(matches!(refused, Err(Error::Conflict(_))), "{refused:?}");
    assert_eq!(host.evals(), 0);
}

#[test]
fn the_catalog_lists_state_version_and_last_run() {
    let host = host();
    publish(&host.kernel, "a", "1", &[]);
    publish(&host.kernel, "b", "2", &[("public", "true")]);
    ok(&host.kernel, Verb::Sink, "urn:script:a:runs", &[]);
    let catalog: Catalog = serde_json::from_str(&ok(
        &host.kernel,
        Verb::Source,
        "urn:script:catalog",
        &[("as", "application/json")],
    ))
    .unwrap();
    let names: Vec<&str> = catalog.scripts.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["a", "b"]);
    let a = &catalog.scripts[0];
    assert_eq!(a.last_run.as_ref().unwrap().iri, "urn:script:a:run:1");
    assert_eq!(a.last_run.as_ref().unwrap().status, "ok");
    assert_eq!(catalog.scripts[1].public, Some(true));
    let text = ok(&host.kernel, Verb::Source, "urn:script:catalog", &[]);
    assert!(text.contains("urn:script:b  published public"), "{text}");
}

#[test]
fn names_are_checked() {
    let host = host();
    for bad in ["eval-me:x", "Upper", "public", "outcome", "principal"] {
        let iri = format!("urn:script:{bad}");
        let result = call(
            &host.kernel,
            &Capability::root(),
            Verb::Sink,
            &iri,
            &[("content", "1")],
        );
        assert!(
            matches!(result, Err(Error::InvalidArgument { .. })),
            "{bad}: {result:?}"
        );
    }
}

#[test]
fn requires_refuses_what_attenuation_could_not_keep() {
    let host = host();
    for bad in ["urn:cap:net:*", "urn:cap:fs:read:-/secret", "lisp"] {
        let result = call(
            &host.kernel,
            &Capability::root(),
            Verb::Sink,
            "urn:script:x",
            &[("content", "1"), ("requires", bad)],
        );
        assert!(
            matches!(result, Err(Error::InvalidArgument { .. })),
            "{bad}: {result:?}"
        );
    }
}

/// Ledger #1076: a version's answer is a projection of its SCRIPT's state (whether that
/// content has been written under the name, and who may read the name), so it must hang
/// from the thread a publish or a retire cuts, which is the script's, not only its own.
#[test]
fn a_version_asked_for_before_it_was_published_is_found_after() {
    let host = host();
    // Learn a digest without writing it under `later`: a version is named by its content,
    // never by the script it belongs to.
    let elsewhere = publish(&host.kernel, "elsewhere", "(+ 40 2)", &[]);
    let digest = elsewhere.rsplit(":version:").next().unwrap().to_string();
    let version = format!("urn:script:later:version:{digest}");
    assert_eq!(ok(&host.kernel, Verb::Exists, &version, &[]), "false\n");
    // Asked twice: the negative is still worth caching (it is a backend read), as long as
    // the write that changes it cuts it.
    assert_eq!(ok(&host.kernel, Verb::Exists, &version, &[]), "false\n");
    assert_eq!(publish(&host.kernel, "later", "(+ 40 2)", &[]), version);
    assert_eq!(
        ok(&host.kernel, Verb::Exists, &version, &[]),
        "true\n",
        "a cached `false` outlived the publish that made the version"
    );
    assert_eq!(ok(&host.kernel, Verb::Source, &version, &[]), "(+ 40 2)");
}

#[test]
fn a_public_version_is_not_served_from_the_cache_once_its_script_is_retired() {
    let host = host();
    let version = publish(&host.kernel, "shown", "1", &[("public", "true")]);
    let reader = cap(&[ikigai_script::authority::CAP_READ_PUBLIC]);
    let read = |verb| call(&host.kernel, &reader, verb, &version, &[]);
    assert_eq!(read(Verb::Exists).unwrap(), "true\n");
    assert_eq!(read(Verb::Source).unwrap(), "1");
    ok(&host.kernel, Verb::Delete, "urn:script:shown", &[]);
    // Retired is no longer public, so the public grant reaches nothing: the same answer an
    // uncached read gives, and the one the head itself gives.
    assert!(
        matches!(read(Verb::Exists), Err(Error::Denied(_))),
        "{:?}",
        read(Verb::Exists)
    );
    assert!(
        matches!(read(Verb::Source), Err(Error::Denied(_))),
        "{:?}",
        read(Verb::Source)
    );
}

/// Ledger #1079, the failure half of ledger #1076: a version's ABSENCE is its script's state
/// too, so a composite that caches a fallback over a version's NotFound must be cut by the
/// publish that ends the absence. The success side already hung from the script's thread;
/// a NotFound carried only the version IRI's, which no write targets.
#[test]
fn a_cached_fallback_over_a_missing_version_is_cut_by_the_publish() {
    let host = host();
    let elsewhere = publish(&host.kernel, "elsewhere", "(+ 40 2)", &[]);
    let digest = elsewhere.rsplit(":version:").next().unwrap().to_string();
    let version = format!("urn:script:later:version:{digest}");
    let fallback = || {
        ok(
            &host.kernel,
            Verb::Source,
            "urn:test:fallback",
            &[("of", &version)],
        )
    };
    let cached = || {
        host.kernel.is_cached(
            &request(Verb::Source, "urn:test:fallback", &[("of", &version)]),
            &Capability::root(),
        )
    };
    assert_eq!(fallback(), "fallback");
    assert!(cached(), "the fallback over a miss is worth caching");
    assert_eq!(publish(&host.kernel, "later", "(+ 40 2)", &[]), version);
    assert!(
        !cached(),
        "the publish that wrote the version did not reach the fallback over its absence"
    );
    assert_eq!(fallback(), "(+ 40 2)");
}

/// The same, for a version that EXISTS but is someone else's draft: absent to the caller,
/// and present once published, so the publish must cut that fallback too.
#[test]
fn a_cached_fallback_over_a_hidden_draft_version_is_cut_by_the_publish() {
    let host = host();
    let writer = cap(&["urn:cap:script:write:later", "urn:cap:lisp"]);
    let draft = call(
        &host.kernel,
        &writer,
        Verb::Sink,
        "urn:script:later",
        &[("content", "(+ 40 2)"), ("state", "draft")],
    )
    .unwrap();
    let draft = draft.trim().to_string();
    let reader = cap(&["urn:cap:script:read:later"]);
    let fallback = || {
        call(
            &host.kernel,
            &reader,
            Verb::Source,
            "urn:test:fallback",
            &[("of", &draft)],
        )
        .unwrap()
    };
    let cached = || {
        host.kernel.is_cached(
            &request(Verb::Source, "urn:test:fallback", &[("of", &draft)]),
            &reader,
        )
    };
    assert_eq!(
        fallback(),
        "fallback",
        "nobody's draft is absent to a reader"
    );
    assert!(cached());
    publish(&host.kernel, "later", "(+ 40 2)", &[]);
    assert!(
        !cached(),
        "the publish did not reach the fallback over the hidden draft"
    );
    assert_eq!(fallback(), "(+ 40 2)");
}

/// The compiled form and a run as a read answer NotFound for a script nobody may see yet,
/// and that absence is the script's state as well: a publish must reach a fallback over it.
#[test]
fn a_cached_fallback_over_a_missing_compiled_form_or_result_is_cut_by_the_publish() {
    for part in ["compiled", "result"] {
        let host = host();
        let target = format!("urn:script:soon:{part}");
        let fallback = || {
            ok(
                &host.kernel,
                Verb::Source,
                "urn:test:fallback",
                &[("of", &target)],
            )
        };
        let cached = || {
            host.kernel.is_cached(
                &request(Verb::Source, "urn:test:fallback", &[("of", &target)]),
                &Capability::root(),
            )
        };
        assert_eq!(fallback(), "fallback", "{part}");
        assert!(cached(), "{part}");
        publish(&host.kernel, "soon", "(+ 40 2)", &[]);
        assert!(!cached(), "{part}: the publish did not reach the fallback");
        assert_ne!(fallback(), "fallback", "{part}");
    }
}

/// Publish `source` as `name` on a fresh host, and read a fallback over `…:run:1` before any
/// run exists, so it is cached. The host, the record's IRI, and whether the fallback is cached.
fn fallback_over_run_one(name: &str, source: &str) -> (Host, String) {
    let host = host();
    publish(&host.kernel, name, source, &[]);
    let record = format!("urn:script:{name}:run:1");
    assert_eq!(fallback_of(&host, &record), "fallback");
    assert!(fallback_cached(&host, &record));
    (host, record)
}

fn fallback_of(host: &Host, of: &str) -> String {
    ok(
        &host.kernel,
        Verb::Source,
        "urn:test:fallback",
        &[("of", of)],
    )
}

fn fallback_cached(host: &Host, of: &str) -> bool {
    host.kernel.is_cached(
        &request(Verb::Source, "urn:test:fallback", &[("of", of)]),
        &Capability::root(),
    )
}

/// A run record's ABSENCE is the state a run writes: a composite that caches a fallback over
/// `…:run:{id}`'s NotFound must be cut by the run that records that id. The record hangs from
/// `urn:script:{name}:runs`, the thread the kernel cuts after a successful Sink to it.
#[test]
fn a_cached_fallback_over_a_run_not_yet_recorded_is_cut_by_the_run() {
    let (host, record) = fallback_over_run_one("fine", "(+ 1 1)");
    ok(&host.kernel, Verb::Sink, "urn:script:fine:runs", &[]);
    assert!(
        !fallback_cached(&host, &record),
        "the run that recorded {record} did not reach the fallback"
    );
    assert!(fallback_of(&host, &record).starts_with(&record));
}

/// A FAILED run is recorded too, so its record's absence is state it wrote: the fallback over
/// that NotFound must be cut by the failed run as well. The kernel cuts a Sink's target when
/// the endpoint RAN and then failed (ikigai-core 0.1.95, ledger #1105); a refusal before
/// dispatch cuts nothing, and records nothing either.
#[test]
fn a_failed_run_cuts_a_fallback_over_its_record() {
    let (host, record) = fallback_over_run_one("broken", "(car 1)");
    let ran = call(
        &host.kernel,
        &Capability::root(),
        Verb::Sink,
        "urn:script:broken:runs",
        &[],
    );
    assert!(ran.is_err(), "{ran:?}");
    assert!(
        !fallback_cached(&host, &record),
        "the failed run that recorded {record} did not reach the fallback"
    );
    assert!(fallback_of(&host, &record).starts_with(&record));
}
