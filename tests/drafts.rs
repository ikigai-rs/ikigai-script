//! Draft privacy (ledger #952, part 1): a draft is visible only to its author until it is
//! published. To anyone else holding the script's read (or run) grant it is ABSENT, and
//! told so exactly as a name nobody wrote is, so a draft's existence leaks no more than its
//! text does.
//!
//! The author is the principal the writer's CAPABILITY names (ledger #1077): the host's door
//! mints `urn:cap:principal:<iri>` with `Capability::with_principal`, and these tests mint it
//! the same way. Alice and Bob hold the SAME grants and differ only in the principal minted
//! into them, which is the case where a cached answer could be served to the wrong one, and
//! the reason the cache keys on the whole capability.

mod common;

use common::*;
use ikigai_core::{Capability, Error, Kernel, Verb};
use ikigai_script::authority::{same_for_all, Ceiling, ANONYMOUS};
use ikigai_script::{Catalog, MemoryBackend};

/// `capability` as the door hands it to `who`.
fn minted(who: &str, capability: &Capability) -> Capability {
    capability
        .with_principal(who)
        .expect("a principal a door can mint")
}

/// Resolve as `who`: under `capability` with `who` minted into it.
fn call_as(
    kernel: &Kernel,
    who: &str,
    capability: &Capability,
    verb: Verb,
    iri: &str,
    args: &[(&str, &str)],
) -> std::result::Result<String, Error> {
    call(kernel, &minted(who, capability), verb, iri, args)
}

const ALICE: &str = "urn:test:person:alice";
const BOB: &str = "urn:test:person:bob";

/// What both people hold: the SAME grants, so only the principal their door minted tells
/// them apart.
fn editor(name: &str) -> Capability {
    cap(&[
        &format!("urn:cap:script:write:{name}"),
        &format!("urn:cap:script:read:{name}"),
        &format!("urn:cap:script:run:{name}"),
        "urn:cap:lisp",
    ])
}

fn stamped() -> Host {
    host_with(
        std::sync::Arc::new(MemoryBackend::new()),
        same_for_all(Ceiling::unbounded()),
    )
}

fn not_found(result: std::result::Result<String, Error>) -> String {
    match result {
        Err(Error::NotFound(message)) => message,
        other => panic!("expected a typed NotFound, got {other:?}"),
    }
}

#[test]
fn a_draft_is_visible_to_its_author_and_absent_to_every_other_reader() {
    let host = stamped();
    let k = &host.kernel;
    let who = editor("plan");
    call_as(
        k,
        ALICE,
        &who,
        Verb::Sink,
        "urn:script:plan",
        &[("content", "(+ 1 2)"), ("state", "draft")],
    )
    .unwrap();

    // The author reads it, twice (a cached answer, if there were one, would be hers).
    for _ in 0..2 {
        let source = call_as(k, ALICE, &who, Verb::Source, "urn:script:plan", &[]);
        assert_eq!(source.unwrap(), "(+ 1 2)");
        let exists = call_as(k, ALICE, &who, Verb::Exists, "urn:script:plan", &[]);
        assert_eq!(exists.unwrap(), "true\n");
    }
    // Bob holds the same capability and learns nothing, not even that it exists: exactly
    // what he is told about a name nobody wrote.
    let hidden = not_found(call_as(k, BOB, &who, Verb::Source, "urn:script:plan", &[]));
    let absent = not_found(call_as(
        k,
        BOB,
        &editor("nothing"),
        Verb::Source,
        "urn:script:nothing",
        &[],
    ));
    assert_eq!(hidden, absent.replace("nothing", "plan"));
    for _ in 0..2 {
        let exists = call_as(k, BOB, &who, Verb::Exists, "urn:script:plan", &[]);
        assert_eq!(exists.unwrap(), "false\n");
        let json = call_as(
            k,
            BOB,
            &who,
            Verb::Source,
            "urn:script:plan",
            &[("as", "application/json")],
        );
        not_found(json);
    }
    // And the author still sees it after Bob asked (no cached "absent" served to her).
    let exists = call_as(k, ALICE, &who, Verb::Exists, "urn:script:plan", &[]);
    assert_eq!(exists.unwrap(), "true\n");

    // Published, it is every reader's.
    call_as(
        k,
        ALICE,
        &who,
        Verb::Sink,
        "urn:script:plan",
        &[("content", "(+ 1 2)")],
    )
    .unwrap();
    let source = call_as(k, BOB, &who, Verb::Source, "urn:script:plan", &[]);
    assert_eq!(source.unwrap(), "(+ 1 2)");
}

#[test]
fn a_version_never_published_stays_its_authors_after_the_head_moves_on() {
    let host = stamped();
    let k = &host.kernel;
    let who = editor("notes");
    let published = call_as(
        k,
        ALICE,
        &who,
        Verb::Sink,
        "urn:script:notes",
        &[("content", "1")],
    )
    .unwrap();
    let draft = call_as(
        k,
        BOB,
        &who,
        Verb::Sink,
        "urn:script:notes",
        &[("content", "2"), ("state", "draft")],
    )
    .unwrap();
    // While the head is Bob's draft, Alice (who published the version before it) is not
    // its author.
    not_found(call_as(
        k,
        ALICE,
        &who,
        Verb::Source,
        "urn:script:notes",
        &[],
    ));
    call_as(
        k,
        ALICE,
        &who,
        Verb::Sink,
        "urn:script:notes",
        &[("content", "3")],
    )
    .unwrap();

    let (published, draft) = (published.trim(), draft.trim());
    // The published version stays every reader's; the draft that was never published stays
    // Bob's, though the head has moved past it and its digest is in the history.
    for reader in [ALICE, BOB] {
        let v = call_as(k, reader, &who, Verb::Source, published, &[]);
        assert_eq!(v.unwrap(), "1");
    }
    assert_eq!(
        call_as(k, BOB, &who, Verb::Source, draft, &[]).unwrap(),
        "2"
    );
    assert_eq!(
        call_as(k, BOB, &who, Verb::Exists, draft, &[]).unwrap(),
        "true\n"
    );
    not_found(call_as(k, ALICE, &who, Verb::Source, draft, &[]));
    assert_eq!(
        call_as(k, ALICE, &who, Verb::Exists, draft, &[]).unwrap(),
        "false\n"
    );
}

#[test]
fn retiring_a_draft_does_not_publish_it() {
    let host = stamped();
    let k = &host.kernel;
    let who = cap(&[
        "urn:cap:script:write:wip",
        "urn:cap:script:read:wip",
        "urn:cap:script:delete:wip",
        "urn:cap:lisp",
    ]);
    call_as(
        k,
        ALICE,
        &who,
        Verb::Sink,
        "urn:script:wip",
        &[("content", "(+ 1 1)"), ("state", "draft")],
    )
    .unwrap();
    call_as(k, BOB, &who, Verb::Delete, "urn:script:wip", &[]).unwrap();
    not_found(call_as(k, BOB, &who, Verb::Source, "urn:script:wip", &[]));
    let record = call_as(
        k,
        ALICE,
        &who,
        Verb::Source,
        "urn:script:wip",
        &[("as", "application/json")],
    )
    .unwrap();
    assert!(record.contains("\"retired\""), "{record}");
}

#[test]
fn a_runner_who_is_not_the_author_cannot_read_a_drafts_compiled_form() {
    let host = stamped();
    let k = &host.kernel;
    let who = editor("job");
    call_as(
        k,
        ALICE,
        &who,
        Verb::Sink,
        "urn:script:job",
        &[("content", "(+ 2 2)"), ("state", "draft")],
    )
    .unwrap();
    let runner = cap(&["urn:cap:script:run:job", "urn:cap:lisp"]);
    // The compiled form carries the program: absent to Bob, the author's to Alice.
    not_found(call_as(
        k,
        BOB,
        &runner,
        Verb::Source,
        "urn:script:job:compiled",
        &[],
    ));
    call_as(
        k,
        ALICE,
        &runner,
        Verb::Source,
        "urn:script:job:compiled",
        &[],
    )
    .unwrap();
    // So a run is absent to Bob, and refused for its state to Alice; nothing evaluates.
    not_found(call_as(
        k,
        BOB,
        &runner,
        Verb::Source,
        "urn:script:job:result",
        &[],
    ));
    not_found(call_as(
        k,
        BOB,
        &runner,
        Verb::Sink,
        "urn:script:job:runs",
        &[],
    ));
    match call_as(
        k,
        ALICE,
        &runner,
        Verb::Source,
        "urn:script:job:result",
        &[],
    ) {
        Err(Error::Conflict(message)) => assert!(message.contains("draft"), "{message}"),
        other => panic!("expected Conflict, got {other:?}"),
    }
    assert_eq!(host.evals(), 0);
}

#[test]
fn the_catalog_lists_a_draft_to_its_author_alone() {
    let host = stamped();
    let k = &host.kernel;
    let both = cap(&[
        "urn:cap:script:write:a",
        "urn:cap:script:write:b",
        "urn:cap:script:read:a",
        "urn:cap:script:read:b",
        "urn:cap:lisp",
    ]);
    call_as(
        k,
        ALICE,
        &both,
        Verb::Sink,
        "urn:script:a",
        &[("content", "1")],
    )
    .unwrap();
    call_as(
        k,
        ALICE,
        &both,
        Verb::Sink,
        "urn:script:b",
        &[("content", "2"), ("state", "draft")],
    )
    .unwrap();
    let names = |who: &str| -> Vec<String> {
        let text = call_as(
            k,
            who,
            &both,
            Verb::Source,
            "urn:script:catalog",
            &[("as", "application/json")],
        )
        .unwrap();
        let catalog: Catalog = serde_json::from_str(&text).unwrap();
        catalog.scripts.into_iter().map(|e| e.name).collect()
    };
    assert_eq!(names(ALICE), ["a", "b"]);
    assert_eq!(names(BOB), ["a"]);
}

#[test]
fn an_unstamped_or_anonymous_principal_is_nobodys_author() {
    // A capability that names no principal cannot be told apart from any other, so no
    // caller holding one can be shown to be a draft's author: the draft is root's alone, and
    // the refusal says why.
    let host = host();
    let k = &host.kernel;
    let who = editor("x");
    call(
        k,
        &who,
        Verb::Sink,
        "urn:script:x",
        &[("content", "1"), ("state", "draft")],
    )
    .unwrap();
    let message = not_found(call(k, &who, Verb::Source, "urn:script:x", &[]));
    assert!(message.contains("names no principal"), "{message}");
    assert_eq!(ok(k, Verb::Source, "urn:script:x", &[]), "1");

    // Two anonymous callers are not one person.
    let host = stamped();
    let k = &host.kernel;
    call_as(
        k,
        ANONYMOUS,
        &who,
        Verb::Sink,
        "urn:script:x",
        &[("content", "1"), ("state", "draft")],
    )
    .unwrap();
    not_found(call_as(
        k,
        ANONYMOUS,
        &who,
        Verb::Source,
        "urn:script:x",
        &[],
    ));
}

#[test]
fn a_private_drafts_contract_says_nothing_its_text_does() {
    // Meta is answered from the description, to anyone who can reach the door, so a
    // SPARQL draft's own contract (its parameters, its comment) would publish its text. A
    // draft never published wears the template's contract instead.
    let host = sparql_host_with(
        ikigai_script::sparql::SparqlDoor::store(),
        same_for_all(Ceiling::unbounded()),
    );
    let k = &host.kernel;
    // Root names no principal, so the author holds what the query needs and no more.
    let author = cap(&["urn:cap:script:write:q", "urn:cap:store:read:graph:urn:g:a"]);
    let query = "# The secret plan.\n# @param who xsd:string\n\
                 SELECT ?s FROM <urn:g:a> WHERE { ?s ?p ?who }";
    call_as(
        k,
        ALICE,
        &author,
        Verb::Sink,
        "urn:script:q",
        &[
            ("content", query),
            ("language", "sparql"),
            ("state", "draft"),
        ],
    )
    .unwrap();
    let meta = |k: &Kernel| {
        call(
            k,
            &Capability::root(),
            Verb::Meta,
            "urn:script:q:result",
            &[],
        )
        .unwrap()
    };
    let contract = meta(k);
    assert!(!contract.contains("secret"), "{contract}");
    assert!(!contract.contains("\"who\""), "{contract}");
    assert_eq!(contract, meta_of_nothing(k));
    // Published, the query is its own entry again.
    call_as(
        k,
        ALICE,
        &author,
        Verb::Sink,
        "urn:script:q",
        &[("content", query), ("language", "sparql")],
    )
    .unwrap();
    assert!(meta(k).contains("secret"));
}

fn meta_of_nothing(k: &Kernel) -> String {
    call(
        k,
        &Capability::root(),
        Verb::Meta,
        "urn:script:never:result",
        &[],
    )
    .unwrap()
}

/// ★ Ledger #1077: the author's answers are CACHED now, and the cache is partitioned by the
/// principal the capability carries, so alice's cached draft is never served to bob though
/// the rest of their capabilities are identical, and bob's cached "absent" is never served
/// to alice. Before 0.2.0 the principal came from a stamper the cache key could not see, so
/// neither could be cached at all.
#[test]
fn alices_cached_draft_is_never_bobs_answer() {
    let host = stamped();
    let k = &host.kernel;
    let grants = editor("plan");
    let (alice, bob) = (minted(ALICE, &grants), minted(BOB, &grants));
    let draft = call(
        k,
        &alice,
        Verb::Sink,
        "urn:script:plan",
        &[("content", "(+ 1 2)"), ("state", "draft")],
    )
    .unwrap();
    let draft = draft.trim().to_string();
    let compiled = "urn:script:plan:compiled".to_string();
    let reads: Vec<(Verb, String)> = vec![
        (Verb::Source, "urn:script:plan".to_string()),
        (Verb::Exists, "urn:script:plan".to_string()),
        (Verb::Source, draft.clone()),
        (Verb::Exists, draft.clone()),
        (Verb::Source, compiled),
    ];
    for (verb, iri) in &reads {
        let cached = |who: &Capability| k.is_cached(&request(*verb, iri, &[]), who);
        let first = call(k, &alice, *verb, iri, &[]).unwrap();
        assert!(
            cached(&alice),
            "{verb:?} {iri}: the author's answer is cached"
        );
        assert!(
            !cached(&bob),
            "{verb:?} {iri}: and only under her capability"
        );
        // Bob asks after her answer is cached, and is told what a reader of nothing is.
        match call(k, &bob, *verb, iri, &[]) {
            Ok(answer) => assert_eq!(answer, "false\n", "{verb:?} {iri}: served {answer:?}"),
            Err(error) => assert!(
                matches!(error, Error::NotFound(_)),
                "{verb:?} {iri}: {error}"
            ),
        }
        // And her answer is still hers, from the cache, after bob's.
        assert!(cached(&alice), "{verb:?} {iri}");
        assert_eq!(
            call(k, &alice, *verb, iri, &[]).unwrap(),
            first,
            "{verb:?} {iri}"
        );
    }
    // Published, both see it, and the publish cut every cached answer above.
    call(
        k,
        &alice,
        Verb::Sink,
        "urn:script:plan",
        &[("content", "(+ 1 2)")],
    )
    .unwrap();
    for (verb, iri) in &reads {
        assert!(
            !k.is_cached(&request(*verb, iri, &[]), &alice),
            "{verb:?} {iri}"
        );
    }
    assert_eq!(call(k, &bob, Verb::Source, &draft, &[]).unwrap(), "(+ 1 2)");
    assert_eq!(
        call(k, &bob, Verb::Exists, "urn:script:plan", &[]).unwrap(),
        "true\n"
    );
}
