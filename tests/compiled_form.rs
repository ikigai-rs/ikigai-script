//! The compiled form carries a script's source, so it sits behind the READ grant alone, as
//! the source does; a runner still runs the script without it. And what the compiled form
//! and a run record say of the publisher's exclusions is only the part about that script:
//! an exclusion in a family the script holds no grant in narrows nothing it does, so it is
//! the publisher's own policy, not the script's.
//!
//! Each case is run under the narrow grants a host publishes, never root.

mod common;

use std::collections::BTreeSet;

use common::*;
use ikigai_core::Verb;
use ikigai_script::authority::{CAP_READ_PUBLIC, CAP_RUN_PUBLIC};

const PAYROLL: &str = "urn:cap:fs:read:-/srv/payroll";
const INTERNAL: &str = "urn:cap:net:-internal.example";

fn json(text: &str) -> serde_json::Value {
    serde_json::from_str(text).unwrap_or_else(|e| panic!("not JSON ({e}): {text}"))
}

fn strings(value: &serde_json::Value) -> BTreeSet<String> {
    value
        .as_array()
        .unwrap_or_else(|| panic!("not an array: {value}"))
        .iter()
        .map(|v| v.as_str().expect("a string").to_string())
        .collect()
}

fn set(xs: &[&str]) -> BTreeSet<String> {
    xs.iter().map(|s| s.to_string()).collect()
}

#[test]
fn a_runner_without_the_read_grant_is_refused_the_compiled_form_and_still_runs_the_script() {
    let host = host();
    let publisher = cap(&[
        "urn:cap:script:write:secret",
        "urn:cap:lisp",
        "urn:cap:fs:read:/srv",
        PAYROLL,
    ]);
    call(
        &host.kernel,
        &publisher,
        Verb::Sink,
        "urn:script:secret",
        &[
            ("content", "(+ 1 2) ; the secret algorithm"),
            ("requires", "urn:cap:fs:read:/srv"),
        ],
    )
    .unwrap();
    let runner = cap(&["urn:cap:script:run:secret", "urn:cap:lisp"]);
    denied(call(
        &host.kernel,
        &runner,
        Verb::Source,
        "urn:script:secret",
        &[],
    ));
    let message = denied(call(
        &host.kernel,
        &runner,
        Verb::Source,
        "urn:script:secret:compiled",
        &[],
    ));
    assert!(
        message.contains("urn:cap:script:read:") && !message.contains("the secret algorithm"),
        "{message}"
    );
    // The run reads its program without the caller reading it.
    assert_eq!(
        call(
            &host.kernel,
            &runner,
            Verb::Source,
            "urn:script:secret:result",
            &[]
        )
        .unwrap(),
        "3"
    );
    // The positive half: the script's reader reads the compiled form.
    let reader = cap(&["urn:cap:script:read:secret"]);
    let compiled = json(
        &call(
            &host.kernel,
            &reader,
            Verb::Source,
            "urn:script:secret:compiled",
            &[],
        )
        .unwrap(),
    );
    assert_eq!(compiled["program"], "(+ 1 2) ; the secret algorithm");
}

#[test]
fn the_public_run_grant_alone_does_not_read_a_public_scripts_compiled_form() {
    let host = host();
    let publisher = cap(&["urn:cap:script:write:open", "urn:cap:lisp", PAYROLL]);
    call(
        &host.kernel,
        &publisher,
        Verb::Sink,
        "urn:script:open",
        &[("content", "(+ 1 2) ; private text"), ("public", "true")],
    )
    .unwrap();
    let anonymous = cap(&[CAP_RUN_PUBLIC, "urn:cap:lisp"]);
    assert_eq!(
        call(
            &host.kernel,
            &anonymous,
            Verb::Source,
            "urn:script:open:result",
            &[]
        )
        .unwrap(),
        "3"
    );
    denied(call(
        &host.kernel,
        &anonymous,
        Verb::Source,
        "urn:script:open",
        &[],
    ));
    denied(call(
        &host.kernel,
        &anonymous,
        Verb::Source,
        "urn:script:open:compiled",
        &[],
    ));
    // The public READ grant reads it, as it reads the source.
    let reader = cap(&[CAP_READ_PUBLIC]);
    let compiled = json(
        &call(
            &host.kernel,
            &reader,
            Verb::Source,
            "urn:script:open:compiled",
            &[],
        )
        .unwrap(),
    );
    assert_eq!(compiled["program"], "(+ 1 2) ; private text");
}

#[test]
fn the_compiled_form_keeps_only_the_exclusions_about_its_script() {
    let host = host();
    let publisher = cap(&[
        "urn:cap:script:write:files",
        "urn:cap:script:write:sum",
        "urn:cap:lisp",
        "urn:cap:fs:read:/srv",
        PAYROLL,
        INTERNAL,
    ]);
    // A script that reads files keeps the file exclusion, which narrows what it reads, and
    // not the network one.
    call(
        &host.kernel,
        &publisher,
        Verb::Sink,
        "urn:script:files",
        &[("content", "(+ 1 2)"), ("requires", "urn:cap:fs:read:/srv")],
    )
    .unwrap();
    // A script that touches neither keeps neither.
    call(
        &host.kernel,
        &publisher,
        Verb::Sink,
        "urn:script:sum",
        &[("content", "(+ 1 2)")],
    )
    .unwrap();
    let reader = cap(&["urn:cap:script:read:files", "urn:cap:script:read:sum"]);
    let compiled = |name: &str| {
        json(
            &call(
                &host.kernel,
                &reader,
                Verb::Source,
                &format!("urn:script:{name}:compiled"),
                &[],
            )
            .unwrap(),
        )
    };
    assert_eq!(strings(&compiled("files")["exclusions"]), set(&[PAYROLL]));
    assert_eq!(strings(&compiled("sum")["exclusions"]), BTreeSet::new());
}

#[test]
fn a_run_record_keeps_only_the_exclusions_about_its_script() {
    let host = host();
    let publisher = cap(&[
        "urn:cap:script:write:files",
        "urn:cap:lisp",
        "urn:cap:fs:read:/srv",
        PAYROLL,
        INTERNAL,
    ]);
    call(
        &host.kernel,
        &publisher,
        Verb::Sink,
        "urn:script:files",
        &[
            ("content", "(source \"urn:test:whoami\")"),
            ("requires", "urn:cap:fs:read:/srv"),
        ],
    )
    .unwrap();
    // The runner holds an exclusion of its own, in a family the script never touches.
    let mail = "urn:cap:mail:-boss@example.com";
    let runner = cap(&[
        "urn:cap:script:run:files",
        "urn:cap:lisp",
        "urn:cap:fs:read:/srv",
        mail,
    ]);
    let record = call(
        &host.kernel,
        &runner,
        Verb::Sink,
        "urn:script:files:runs",
        &[("content", "")],
    )
    .unwrap();
    let record = record.trim();
    // What the run held, seen from the far side: unchanged, every exclusion included.
    let record_json = json(
        &call(
            &host.kernel,
            &runner,
            Verb::Source,
            record,
            &[("as", "application/json")],
        )
        .unwrap(),
    );
    let held: BTreeSet<String> = record_json["result"]
        .as_str()
        .expect("a recorded result")
        .lines()
        .map(str::to_string)
        .collect();
    for scope in [PAYROLL, INTERNAL, mail] {
        assert!(held.contains(scope), "the run held {held:?}");
    }
    // What the record says it held: the grants, and only the exclusions about them.
    assert_eq!(
        strings(&record_json["capability"]),
        set(&["urn:cap:fs:read:/srv", "urn:cap:lisp", PAYROLL])
    );
    // The plain face's capability line says the same (its result is the script's own
    // output, which lists everything the run held, so only that line is read).
    let plain = call(
        &host.kernel,
        &runner,
        Verb::Source,
        record,
        &[("as", "text/plain")],
    )
    .unwrap();
    let line = plain
        .lines()
        .find_map(|l| l.trim_start().strip_prefix("capability:"))
        .unwrap_or_else(|| panic!("no capability line: {plain}"));
    let listed: BTreeSet<String> = line.split_whitespace().map(str::to_string).collect();
    assert_eq!(
        listed,
        set(&["urn:cap:fs:read:/srv", "urn:cap:lisp", PAYROLL])
    );
}
