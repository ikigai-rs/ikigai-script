//! The directory backend: durable across hosts, and survivable when someone edits the
//! files by hand.
//!
//! Every test works in its own directory under the system temp dir, named for the test and
//! the process, and removes it when it passes.

mod common;

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use common::*;
use ikigai_core::{Capability, Error, Verb};
use ikigai_script::authority::{same_for_all, Ceiling};
use ikigai_script::{Backend, Catalog, DirBackend};

struct Scratch(PathBuf);

impl Scratch {
    fn new(test: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("ikigai-script-{test}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn host_over(dir: &PathBuf) -> Host {
    host_with(
        Arc::new(DirBackend::open(dir).expect("a scratch directory")),
        same_for_all(Ceiling::unbounded()),
    )
}

#[test]
fn scripts_versions_and_runs_survive_the_host() {
    let scratch = Scratch::new("survive");
    let first = {
        let host = host_over(&scratch.0);
        let first = publish(&host.kernel, "keep", "(+ 1 2)", &[]);
        publish(&host.kernel, "keep", "(+ 2 2)", &[]);
        ok(&host.kernel, Verb::Sink, "urn:script:keep:runs", &[]);
        first
    };
    // A new host over the same directory: the head, both versions and the run are there,
    // and run numbers continue.
    let host = host_over(&scratch.0);
    assert_eq!(
        ok(&host.kernel, Verb::Source, "urn:script:keep:result", &[]),
        "4"
    );
    assert_eq!(ok(&host.kernel, Verb::Source, &first, &[]), "(+ 1 2)");
    assert!(ok(&host.kernel, Verb::Source, "urn:script:keep:run:1", &[]).contains("ok"));
    assert_eq!(
        ok(&host.kernel, Verb::Sink, "urn:script:keep:runs", &[]).trim(),
        "urn:script:keep:run:2"
    );
    // The files are the layout the documentation states.
    let dir = scratch.0.join("keep");
    assert!(dir.join("head.json").is_file());
    assert_eq!(fs::read_dir(dir.join("versions")).unwrap().count(), 2);
    assert!(dir.join("runs").join("2.json").is_file());
}

#[test]
fn a_version_edited_by_hand_is_refused_by_name_and_nothing_else_breaks() {
    let scratch = Scratch::new("edited-version");
    let host = host_over(&scratch.0);
    let first = publish(&host.kernel, "keep", "(+ 1 2)", &[]);
    publish(&host.kernel, "other", "7", &[]);
    let hex = first.rsplit("sha256:").next().unwrap();
    let file = scratch
        .0
        .join("keep")
        .join("versions")
        .join(format!("{hex}.json"));
    let text = fs::read_to_string(&file).unwrap();
    fs::write(&file, text.replace("(+ 1 2)", "(+ 1 3)")).unwrap();

    // A fresh host, so nothing is served from a cache that predates the edit.
    let host = host_over(&scratch.0);
    let refused = call(
        &host.kernel,
        &Capability::root(),
        Verb::Source,
        "urn:script:keep:result",
        &[],
    );
    assert!(
        matches!(&refused, Err(Error::Endpoint(m)) if m.contains("edited out of band")),
        "{refused:?}"
    );
    assert_eq!(
        host.evals(),
        0,
        "a tampered version never reaches the evaluator"
    );
    assert_eq!(
        ok(&host.kernel, Verb::Source, "urn:script:other:result", &[]),
        "7"
    );
    // Publishing the content again repairs it.
    publish(&host.kernel, "keep", "(+ 1 2)", &[]);
    assert_eq!(
        ok(&host.kernel, Verb::Source, "urn:script:keep:result", &[]),
        "3"
    );
}

#[test]
fn a_broken_head_fails_that_script_alone() {
    let scratch = Scratch::new("broken-head");
    let host = host_over(&scratch.0);
    publish(&host.kernel, "good", "1", &[]);
    publish(&host.kernel, "bad", "2", &[]);
    fs::write(scratch.0.join("bad").join("head.json"), "{ not json").unwrap();
    // A stray file beside the scripts is not a script.
    fs::write(scratch.0.join("README.txt"), "notes").unwrap();

    let host = host_over(&scratch.0);
    let broken = call(
        &host.kernel,
        &Capability::root(),
        Verb::Source,
        "urn:script:bad",
        &[],
    );
    assert!(
        matches!(&broken, Err(Error::Endpoint(m)) if m.contains("head.json")),
        "{broken:?}"
    );
    assert_eq!(
        ok(&host.kernel, Verb::Source, "urn:script:good:result", &[]),
        "1"
    );
    let catalog: Catalog = serde_json::from_str(&ok(
        &host.kernel,
        Verb::Source,
        "urn:script:catalog",
        &[("as", "application/json")],
    ))
    .unwrap();
    let rows: Vec<(&str, bool)> = catalog
        .scripts
        .iter()
        .map(|e| (e.name.as_str(), e.error.is_some()))
        .collect();
    assert_eq!(rows, vec![("bad", true), ("good", false)]);
    // Republishing over a broken head is a conflict (the writer cannot know what it is
    // replacing) — the file has to be put right or removed by hand.
    let conflict = call(
        &host.kernel,
        &Capability::root(),
        Verb::Sink,
        "urn:script:bad",
        &[("content", "3")],
    );
    assert!(conflict.is_err(), "{conflict:?}");
    fs::remove_file(scratch.0.join("bad").join("head.json")).unwrap();
    publish(&host.kernel, "bad", "3", &[]);
}

#[test]
fn an_editor_who_got_there_first_wins_and_the_writer_is_told() {
    let scratch = Scratch::new("editor-first");
    let backend = DirBackend::open(&scratch.0).unwrap();
    let host = host_with(
        Arc::new(DirBackend::open(&scratch.0).unwrap()),
        same_for_all(Ceiling::unbounded()),
    );
    publish(&host.kernel, "shared", "1", &[]);
    // A writer reads the head…
    let read = backend.head("shared").unwrap().unwrap();
    // …a person edits the file (here: makes it public)…
    let path = scratch.0.join("shared").join("head.json");
    let text = fs::read_to_string(&path).unwrap();
    fs::write(&path, text.replace("\"public\": false", "\"public\": true")).unwrap();
    // …and the writer's replacement is refused rather than silently undoing the edit.
    let mut next = read.clone();
    next.state = ikigai_script::State::Retired;
    let lost = backend.swap_head("shared", Some(&read), &next);
    assert!(matches!(lost, Err(Error::Conflict(_))), "{lost:?}");
    assert!(backend.head("shared").unwrap().unwrap().public);
}

#[test]
fn a_run_record_written_by_hand_is_never_overwritten() {
    let scratch = Scratch::new("hand-run");
    let host = host_over(&scratch.0);
    publish(&host.kernel, "job", "1", &[]);
    ok(&host.kernel, Verb::Sink, "urn:script:job:runs", &[]);
    // Someone drops a file at the next number.
    let runs = scratch.0.join("job").join("runs");
    fs::write(runs.join("2.json"), "a note, not a run").unwrap();
    let next = ok(&host.kernel, Verb::Sink, "urn:script:job:runs", &[]);
    assert_eq!(next.trim(), "urn:script:job:run:3");
    assert_eq!(
        fs::read_to_string(runs.join("2.json")).unwrap(),
        "a note, not a run"
    );
}

#[test]
fn a_starting_run_is_never_read_half_written() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Barrier;

    use ikigai_script::model::{Outcome, Run, SCHEMA};

    let scratch = Scratch::new("atomic-start");
    let backend = DirBackend::open(&scratch.0).unwrap();
    // A large capability snapshot widens the publication window without sleeps or
    // changes to the backend. Both readers must see absence or a complete record.
    let run = Run {
        schema: SCHEMA,
        name: "job".into(),
        id: 0,
        version: "sha256:test".into(),
        principal: "urn:test:runner".into(),
        capability: [format!("urn:cap:test:{}", "x".repeat(8 * 1024 * 1024))].into(),
        started: None,
        ended: None,
        outcome: Outcome::Running,
        result: None,
        truncated: false,
        trace_span: None,
    };
    let ready = Barrier::new(3);
    let done = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let writer = scope.spawn(|| {
            ready.wait();
            let result = backend.start_run("job", &run);
            done.store(true, Ordering::Release);
            result
        });
        let readers: Vec<_> = [false, true]
            .into_iter()
            .map(|latest| {
                let backend = &backend;
                let ready = &ready;
                let done = &done;
                scope.spawn(move || {
                    ready.wait();
                    loop {
                        let record = if latest {
                            backend.last_run("job")
                        } else {
                            backend.run("job", 1)
                        }?;
                        if let Some(record) = record {
                            assert_eq!(record.id, 1);
                            return Ok::<_, Error>(record);
                        }
                        if done.load(Ordering::Acquire) {
                            return backend.run("job", 1).map(|r| r.expect("published run"));
                        }
                        std::thread::yield_now();
                    }
                })
            })
            .collect();
        assert_eq!(writer.join().unwrap().unwrap(), 1);
        let expected = Run {
            id: 1,
            ..run.clone()
        };
        for reader in readers {
            assert_eq!(
                reader.join().unwrap().expect("complete run record"),
                expected
            );
        }
    });
}

#[test]
fn a_version_digest_has_only_one_spelling() {
    let scratch = Scratch::new("canonical-digest");
    let host = host_over(&scratch.0);
    let iri = publish(&host.kernel, "job", "1", &[]);
    let (prefix, hex) = iri.split_once("sha256:").unwrap();
    let alias = format!("{prefix}sha256:{}", hex.to_ascii_uppercase());
    assert_ne!(alias, iri);
    assert_eq!(ok(&host.kernel, Verb::Source, &iri, &[]), "1");
    let answer = call(&host.kernel, &Capability::root(), Verb::Source, &alias, &[]);
    assert!(
        matches!(
            answer,
            Err(Error::InvalidArgument { .. }) | Err(Error::NotFound(_))
        ),
        "{answer:?}"
    );
    assert_eq!(ok(&host.kernel, Verb::Exists, &alias, &[]), "false\n");
}

#[test]
fn noncanonical_run_filenames_do_not_allocate_run_numbers() {
    let scratch = Scratch::new("canonical-run-file");
    let host = host_over(&scratch.0);
    publish(&host.kernel, "job", "1", &[]);
    ok(&host.kernel, Verb::Sink, "urn:script:job:runs", &[]);
    let runs = scratch.0.join("job").join("runs");
    for filename in ["02.json", "+3.json"] {
        fs::write(runs.join(filename), "a note, not a run").unwrap();
    }
    assert_eq!(host.backend.last_run("job").unwrap().unwrap().id, 1);
    assert_eq!(
        ok(&host.kernel, Verb::Sink, "urn:script:job:runs", &[]).trim(),
        "urn:script:job:run:2"
    );
    for filename in ["02.json", "+3.json"] {
        assert_eq!(
            fs::read_to_string(runs.join(filename)).unwrap(),
            "a note, not a run"
        );
    }
}
