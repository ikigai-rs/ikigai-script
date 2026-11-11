//! A run for effects is recorded with an outcome that says what happened: one that fails
//! keeps the error's own kind, and one whose caller stops waiting is not left `running`.
//!
//! The evaluator here is a stand-in bound at `urn:lisp:eval`, so each outcome is exact:
//! the program text picks what the "evaluator" does (answer, fail with a given error, or
//! never finish).

mod common;

use std::sync::Arc;
use std::task::{Context, Poll};

use common::{request, TickingClock};
use futures::executor::block_on;
use futures::FutureExt;
use ikigai_core::{
    AsyncFnEndpoint, Capability, Description, EndpointSpace, Error, Exact, Fallback, Iri, Kernel,
    Space, Verb,
};
use ikigai_script::authority::{same_for_all, Ceiling};
use ikigai_script::{Backend, MemoryBackend, Outcome, Run, SpaceConfig};

/// A kernel with the script space and a stand-in evaluator whose answer is its program.
fn host() -> (Kernel, Arc<dyn Backend>) {
    let backend: Arc<dyn Backend> = Arc::new(MemoryBackend::new());
    let scripts = ikigai_script::space(SpaceConfig::new(
        Arc::clone(&backend),
        same_for_all(Ceiling::unbounded()),
    ));
    let eval = AsyncFnEndpoint::new("eval", |inv| {
        Box::pin(async move {
            let target = || Iri::parse("urn:script:deep").unwrap();
            match inv.inline_str("in")? {
                "hang" => futures::future::pending().await,
                "over-budget" => Err(Error::OverBudget {
                    detail: "the store stopped this query at 900 ms".to_string(),
                }),
                "depth" => Err(Error::DepthExceeded {
                    depth: 65,
                    target: target(),
                }),
                "refused" => Err(Error::Refused("the origin answered 401".to_string())),
                "gone" => Err(Error::Gone("the graph was dropped".to_string())),
                other => Ok(ikigai_core::Representation::new(
                    ikigai_core::ReprType::new("text/plain"),
                    other.as_bytes().to_vec(),
                )),
            }
        })
    })
    .with_description(
        Description::new("eval")
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .output("text/plain"),
    );
    let lisp = EndpointSpace::new().bind(Exact::new("urn:lisp:eval"), eval);
    let root = Fallback::new(vec![
        Arc::new(scripts) as Arc<dyn Space>,
        Arc::new(lisp) as Arc<dyn Space>,
    ]);
    let kernel = Kernel::with_meta_renderer(Arc::new(root), Arc::new(ikigai_vocab::TurtleRenderer))
        .with_clock(Arc::new(TickingClock::default()));
    (kernel, backend)
}

fn publish(kernel: &Kernel, name: &str, program: &str) {
    block_on(kernel.issue(
        request(
            Verb::Sink,
            &format!("urn:script:{name}"),
            &[("content", program)],
        ),
        &Capability::root(),
    ))
    .unwrap();
}

fn record(kernel: &Kernel, name: &str, id: u64) -> Run {
    let repr = block_on(kernel.issue(
        request(
            Verb::Source,
            &format!("urn:script:{name}:run:{id}"),
            &[("as", "application/json")],
        ),
        &Capability::root(),
    ))
    .unwrap();
    serde_json::from_slice(&repr.bytes).unwrap()
}

/// Every error a run can end in is recorded under the kind the error itself names, not
/// `other`: a store's `over-budget` (the declared store time, ledger #1384), the kernel's
/// `depth-exceeded` (a script that calls itself), and the rest.
#[test]
fn a_failed_runs_record_keeps_the_errors_own_kind() {
    let (kernel, _) = host();
    for (name, kind) in [
        ("over-budget", "over-budget"),
        ("depth", "depth-exceeded"),
        ("refused", "refused"),
        ("gone", "gone"),
    ] {
        publish(&kernel, name, name);
        let error = block_on(kernel.issue(
            request(Verb::Sink, &format!("urn:script:{name}:runs"), &[]),
            &Capability::root(),
        ))
        .unwrap_err();
        assert_eq!(error.kind(), kind, "the caller's error keeps its type");
        let run = record(&kernel, name, 1);
        assert!(
            matches!(&run.outcome, Outcome::Failed { kind: recorded, .. } if recorded == kind),
            "{name}: the record says {:?}",
            run.outcome
        );
        assert!(
            run.render().contains(&format!("failed ({kind})")),
            "{}",
            run.render()
        );
    }
}

/// A run whose caller stops waiting (an HTTP client that disconnects, a host's timeout:
/// either drops the request's future) is recorded as failed, not left `running` forever.
#[test]
fn a_run_its_caller_stopped_waiting_for_is_recorded_as_cancelled() {
    let (kernel, backend) = host();
    publish(&kernel, "slow", "hang");
    {
        let root = Capability::root();
        let mut run =
            Box::pin(kernel.issue(request(Verb::Sink, "urn:script:slow:runs", &[]), &root));
        let waker = futures::task::noop_waker();
        let mut context = Context::from_waker(&waker);
        // Polled until the run is recorded as started and its evaluator is waiting.
        for _ in 0..64 {
            assert!(matches!(run.poll_unpin(&mut context), Poll::Pending));
            if backend.run("slow", 1).unwrap().is_some() {
                break;
            }
        }
        let started = backend
            .run("slow", 1)
            .unwrap()
            .expect("the run was recorded");
        assert_eq!(started.outcome, Outcome::Running);
        // …and dropped, as a host drops a request nobody waits for any more.
    }
    let run = record(&kernel, "slow", 1);
    match &run.outcome {
        Outcome::Failed { kind, message } => {
            assert_eq!(kind, "cancelled");
            assert!(message.contains("urn:script:slow"), "{message}");
        }
        other => panic!("a dropped run is recorded as {other:?}"),
    }
    assert!(
        run.render().contains("failed (cancelled)"),
        "{}",
        run.render()
    );
    // The next run is still the next number, and one that finishes is recorded as it ends.
    publish(&kernel, "slow", "done");
    block_on(kernel.issue(
        request(Verb::Sink, "urn:script:slow:runs", &[]),
        &Capability::root(),
    ))
    .unwrap();
    assert_eq!(record(&kernel, "slow", 2).outcome, Outcome::Ok);
    assert!(matches!(
        record(&kernel, "slow", 1).outcome,
        Outcome::Failed { .. }
    ));
}

#[test]
fn a_run_number_has_only_one_spelling() {
    let (kernel, _) = host();
    publish(&kernel, "job", "done");
    common::ok(&kernel, Verb::Sink, "urn:script:job:runs", &[]);
    assert_eq!(record(&kernel, "job", 1).id, 1);
    let mut accepted = Vec::new();
    for spelling in [
        "01",
        "+1",
        "001",
        "+01",
        "-1",
        "00",
        "+0",
        "18446744073709551616",
    ] {
        let iri = format!("urn:script:job:run:{spelling}");
        let source = common::call(&kernel, &Capability::root(), Verb::Source, &iri, &[]);
        if !matches!(source, Err(Error::InvalidArgument { .. })) {
            accepted.push(format!("{spelling}: {source:?}"));
        }
        let exists = common::ok(&kernel, Verb::Exists, &iri, &[]);
        if exists != "false\n" {
            accepted.push(format!("Exists {spelling}: {exists:?}"));
        }
    }
    assert!(
        accepted.is_empty(),
        "noncanonical run numbers: {accepted:#?}"
    );
    // Zero and the largest u64 are canonical numbers, though neither was allocated.
    for spelling in ["0", "18446744073709551615"] {
        let iri = format!("urn:script:job:run:{spelling}");
        assert!(matches!(
            common::call(&kernel, &Capability::root(), Verb::Source, &iri, &[]),
            Err(Error::NotFound(_))
        ));
        assert_eq!(common::ok(&kernel, Verb::Exists, &iri, &[]), "false\n");
    }
    assert_eq!(
        common::ok(&kernel, Verb::Exists, "urn:script:job:run:1", &[]),
        "true\n"
    );
}
