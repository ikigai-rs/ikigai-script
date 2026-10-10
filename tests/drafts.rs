//! Draft privacy (ledger #952, part 1): a draft is visible only to its author until it is
//! published. To anyone else holding the script's read (or run) grant it is ABSENT, and
//! told so exactly as a name nobody wrote is, so a draft's existence leaks no more than its
//! text does.
//!
//! The author is the principal the HOST stamps (`SpaceConfig::principal`), the same value a
//! publish records as the script's publisher. These tests stamp it from a door that knows
//! who is calling independently of the capability, as a host's authenticated door does, so
//! two people holding the SAME capability are two principals: the case where a cached
//! answer could be served to the wrong one.

mod common;

use std::sync::{Arc, Mutex};

use common::*;
use ikigai_core::{Capability, Error, Kernel, Verb};
use ikigai_script::authority::{same_for_all, Ceiling, PrincipalStamper, ANONYMOUS};
use ikigai_script::{Catalog, MemoryBackend};

/// Who the door says is calling, set by each test before each call.
#[derive(Clone, Default)]
struct Door(Arc<Mutex<String>>);

impl Door {
    fn stamper(&self) -> PrincipalStamper {
        let who = Arc::clone(&self.0);
        Arc::new(move |_inv| who.lock().unwrap().clone())
    }

    fn call(
        &self,
        kernel: &Kernel,
        who: &str,
        capability: &Capability,
        verb: Verb,
        iri: &str,
        args: &[(&str, &str)],
    ) -> std::result::Result<String, Error> {
        *self.0.lock().unwrap() = who.to_string();
        call(kernel, capability, verb, iri, args)
    }
}

const ALICE: &str = "urn:test:person:alice";
const BOB: &str = "urn:test:person:bob";

/// What both people hold: the SAME capability, so only the door tells them apart.
fn editor(name: &str) -> Capability {
    cap(&[
        &format!("urn:cap:script:write:{name}"),
        &format!("urn:cap:script:read:{name}"),
        &format!("urn:cap:script:run:{name}"),
        "urn:cap:lisp",
    ])
}

fn stamped() -> (Host, Door) {
    let door = Door::default();
    let host = host_with(
        Arc::new(MemoryBackend::new()),
        same_for_all(Ceiling::unbounded()),
        Some(door.stamper()),
    );
    (host, door)
}

fn not_found(result: std::result::Result<String, Error>) -> String {
    match result {
        Err(Error::NotFound(message)) => message,
        other => panic!("expected a typed NotFound, got {other:?}"),
    }
}

#[test]
fn a_draft_is_visible_to_its_author_and_absent_to_every_other_reader() {
    let (host, door) = stamped();
    let k = &host.kernel;
    let who = editor("plan");
    door.call(
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
        let source = door.call(k, ALICE, &who, Verb::Source, "urn:script:plan", &[]);
        assert_eq!(source.unwrap(), "(+ 1 2)");
        let exists = door.call(k, ALICE, &who, Verb::Exists, "urn:script:plan", &[]);
        assert_eq!(exists.unwrap(), "true\n");
    }
    // Bob holds the same capability and learns nothing, not even that it exists: exactly
    // what he is told about a name nobody wrote.
    let hidden = not_found(door.call(k, BOB, &who, Verb::Source, "urn:script:plan", &[]));
    let absent = not_found(door.call(
        k,
        BOB,
        &editor("nothing"),
        Verb::Source,
        "urn:script:nothing",
        &[],
    ));
    assert_eq!(hidden, absent.replace("nothing", "plan"));
    for _ in 0..2 {
        let exists = door.call(k, BOB, &who, Verb::Exists, "urn:script:plan", &[]);
        assert_eq!(exists.unwrap(), "false\n");
        let json = door.call(
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
    let exists = door.call(k, ALICE, &who, Verb::Exists, "urn:script:plan", &[]);
    assert_eq!(exists.unwrap(), "true\n");

    // Published, it is every reader's.
    door.call(
        k,
        ALICE,
        &who,
        Verb::Sink,
        "urn:script:plan",
        &[("content", "(+ 1 2)")],
    )
    .unwrap();
    let source = door.call(k, BOB, &who, Verb::Source, "urn:script:plan", &[]);
    assert_eq!(source.unwrap(), "(+ 1 2)");
}

#[test]
fn a_version_never_published_stays_its_authors_after_the_head_moves_on() {
    let (host, door) = stamped();
    let k = &host.kernel;
    let who = editor("notes");
    let published = door
        .call(
            k,
            ALICE,
            &who,
            Verb::Sink,
            "urn:script:notes",
            &[("content", "1")],
        )
        .unwrap();
    let draft = door
        .call(
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
    not_found(door.call(k, ALICE, &who, Verb::Source, "urn:script:notes", &[]));
    door.call(
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
        let v = door.call(k, reader, &who, Verb::Source, published, &[]);
        assert_eq!(v.unwrap(), "1");
    }
    assert_eq!(
        door.call(k, BOB, &who, Verb::Source, draft, &[]).unwrap(),
        "2"
    );
    assert_eq!(
        door.call(k, BOB, &who, Verb::Exists, draft, &[]).unwrap(),
        "true\n"
    );
    not_found(door.call(k, ALICE, &who, Verb::Source, draft, &[]));
    assert_eq!(
        door.call(k, ALICE, &who, Verb::Exists, draft, &[]).unwrap(),
        "false\n"
    );
}

#[test]
fn retiring_a_draft_does_not_publish_it() {
    let (host, door) = stamped();
    let k = &host.kernel;
    let who = cap(&[
        "urn:cap:script:write:wip",
        "urn:cap:script:read:wip",
        "urn:cap:script:delete:wip",
        "urn:cap:lisp",
    ]);
    door.call(
        k,
        ALICE,
        &who,
        Verb::Sink,
        "urn:script:wip",
        &[("content", "(+ 1 1)"), ("state", "draft")],
    )
    .unwrap();
    door.call(k, BOB, &who, Verb::Delete, "urn:script:wip", &[])
        .unwrap();
    not_found(door.call(k, BOB, &who, Verb::Source, "urn:script:wip", &[]));
    let record = door
        .call(
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
    let (host, door) = stamped();
    let k = &host.kernel;
    let who = editor("job");
    door.call(
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
    not_found(door.call(
        k,
        BOB,
        &runner,
        Verb::Source,
        "urn:script:job:compiled",
        &[],
    ));
    door.call(
        k,
        ALICE,
        &runner,
        Verb::Source,
        "urn:script:job:compiled",
        &[],
    )
    .unwrap();
    // So a run is absent to Bob, and refused for its state to Alice; nothing evaluates.
    not_found(door.call(k, BOB, &runner, Verb::Source, "urn:script:job:result", &[]));
    not_found(door.call(k, BOB, &runner, Verb::Sink, "urn:script:job:runs", &[]));
    match door.call(
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
    let (host, door) = stamped();
    let k = &host.kernel;
    let both = cap(&[
        "urn:cap:script:write:a",
        "urn:cap:script:write:b",
        "urn:cap:script:read:a",
        "urn:cap:script:read:b",
        "urn:cap:lisp",
    ]);
    door.call(
        k,
        ALICE,
        &both,
        Verb::Sink,
        "urn:script:a",
        &[("content", "1")],
    )
    .unwrap();
    door.call(
        k,
        ALICE,
        &both,
        Verb::Sink,
        "urn:script:b",
        &[("content", "2"), ("state", "draft")],
    )
    .unwrap();
    let names = |who: &str| -> Vec<String> {
        let text = door
            .call(
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
    // A host that stamps nothing cannot tell its callers apart, so no caller can be shown to
    // be a draft's author: the draft is root's alone, and the refusal says why.
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
    assert!(message.contains("stamps no principal"), "{message}");
    assert_eq!(ok(k, Verb::Source, "urn:script:x", &[]), "1");

    // Two anonymous callers are not one person.
    let (host, door) = stamped();
    let k = &host.kernel;
    door.call(
        k,
        ANONYMOUS,
        &who,
        Verb::Sink,
        "urn:script:x",
        &[("content", "1"), ("state", "draft")],
    )
    .unwrap();
    not_found(door.call(k, ANONYMOUS, &who, Verb::Source, "urn:script:x", &[]));
}

#[test]
fn a_private_drafts_contract_says_nothing_its_text_does() {
    // Meta is answered from the description, to anyone who can reach the door, so a
    // SPARQL draft's own contract (its parameters, its comment) would publish its text. A
    // draft never published wears the template's contract instead.
    let door = Door::default();
    let host = sparql_host_with(
        ikigai_script::sparql::SparqlDoor::store(),
        same_for_all(Ceiling::unbounded()),
        Some(door.stamper()),
    );
    let k = &host.kernel;
    let query = "# The secret plan.\n# @param who xsd:string\n\
                 SELECT ?s FROM <urn:g:a> WHERE { ?s ?p ?who }";
    door.call(
        k,
        ALICE,
        &Capability::root(),
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
    door.call(
        k,
        ALICE,
        &Capability::root(),
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
