# Accessibility

What `ikigai-script` emits that people read, the rules that output follows, how it is tested,
and how to report a barrier. It is a host library: it keeps scripts as resources
(`urn:script:*`) and answers with text, JSON and Turtle, and a host decides how a person sees
them. It is not a conformance claim. Adapted from the
[ACCESSIBILITY.md template](https://github.com/mgifford/ACCESSIBILITY.md) (MIT).

| Field | Value |
|---|---|
| Target | WCAG 2.2 Level AA, for any page that presents this output; this repository writes text only (plain text, JSON, Turtle), no HTML or SVG |
| Status | Evaluation in progress. No conformance claim. |
| Owner | the maintainers of this repository |
| Report a barrier | [a GitHub issue](https://github.com/ikigai-rs/ikigai-script/issues/new?labels=accessibility) with the `accessibility` label; anything security-sensitive through [private vulnerability reporting](https://github.com/ikigai-rs/ikigai-script/security/advisories/new) |
| Last reviewed | 2026-11-12 |

## What it emits that people read

- **Documentation**: `README.md`, `AGENTS.md`, this file and the Rust API documentation,
  read on GitHub, in an editor or through a documentation host.

- **The plain faces** (`text/plain`, the default, `src/endpoints.rs` and `src/model.rs`): a
  script's source, a run record (`Run::render`: labeled lines `script:`, `version:`,
  `principal:`, `started:`, `ended:`, `outcome:`, `capability:`, then the result), the catalog
  (one line per script: its IRI, state, `public`, version and last run), the new version's or
  run's IRI after a write, `retired …`, and `true` or `false` for an existence check.
- **Refusals and errors**, mostly in `src/endpoints.rs`, with more in `src/plan.rs`,
  `src/limits.rs`, `src/backend.rs` and `src/name.rs`: a missing grant (naming the grant, and
  the forms a grant takes), a draft or retired script asked to run (and how to publish it), a
  version or script that does not exist, a write that lost a race (`read it again and retry`),
  a face not served (listing the ones that are), a parameter that is not the script's (listing
  the ones that are), a SPARQL text or plan out of bounds, and a plan that does not validate.
- **The JSON records** (`"schema": 1`) and the **graph face** (`src/graph.rs`, Turtle) of the
  catalog and runs, for programs more than people.
- **The doors' self-descriptions**: the summaries of every door and argument, which a host shows
  in its catalog, help or tool list.

Not this repository's: a script's text and its result (the author's, and the language's), and a
failed run's message, which is the language runner's own (`ikigai-lisp` and Steel for Lisp, the
SPARQL engine, a plan's steps), recorded as it came; the words around an error (`Error`'s
`Display`, from `ikigai-core`); and any page, terminal or tool that shows these. This repository
has no binary, so it writes nothing to a terminal.

## The rules that output follows

- A refusal names the script it is about (`urn:script:{name}`) and, where there is one, what to
  do: the grant to hold, `publish it (state=published) to run it`, `read it again and retry`,
  the faces or parameters that are accepted.
- A face that is not served is refused, never substituted.
- The plain run record labels every field with a word, states its outcome in words (`running`,
  `ok`, `failed (<kind>): <message>`), marks a result cut to the recorded size `(truncated)`, and
  says `unstamped (the kernel has no clock)` rather than inventing a time. Times are
  `xsd:dateTime` in UTC.
- The catalog marks a record it cannot read `BROKEN:` with the reason, and an empty catalog
  says `no scripts this capability may read`.
- Repository-owned plain-text labels add no color, terminal control codes or markup.
  Script source, results and runner messages can contain author-supplied text; a host must
  decide how to present it.

## How it is tested

Every named check has a result: Pass, Fail or Blocked, with evidence. A Pass covers only
its stated assertions, not overall accessibility. Unrun checks remain Blocked.

The Pass rows below were run on 2026-11-12 against unchanged main at
[`33516745dd4c0863f0a6c4339b5d51991f9ca5cd`](https://github.com/ikigai-rs/ikigai-script/commit/33516745dd4c0863f0a6c4339b5d51991f9ca5cd),
using Cargo 1.99.1 and rustc 1.99.1 on macOS. The command
`cargo test --test refusals --test lifecycle --test run_records --lib` passed 63 tests;
`cargo test --doc` passed 26 doctests. These checks run again through `cargo test --workspace`
in [CI](.github/workflows/ci.yml). They assert text and behavior, not usability in a host.

| Check | Result | Evidence |
|---|---|---|
| Refusal wording for drafts, grants, parameters and graph-free queries | Pass | `cargo test --test refusals --test lifecycle --test run_records --lib`, tools and date above. All 8 tests in `tests/refusals.rs` passed, including: `a_sparql_drafts_author_is_told_it_is_a_draft_not_that_lisp_is_missing`, `a_drafts_other_readers_are_told_it_is_absent_and_the_run_gate_still_holds`, `a_drafts_hint_names_a_door_that_takes_its_language`, `a_draft_is_reported_before_the_run_grant_it_will_also_need`, `a_namespaced_scripts_contract_says_what_its_run_gate_is_and_why`, `a_query_that_reads_no_graph_is_refused_saying_why` and `a_reserved_parameter_name_is_refused_naming_every_reserved_name`. Checks their specific messages and authority behavior; not all refusals or comprehension. |
| Successful run and retirement wording | Pass | Same command, tools and date. `tests/lifecycle.rs`: `a_run_for_effects_is_recorded` asserts `outcome:    ok`; `a_retired_script_is_readable_and_never_runs` asserts `retired urn:script:old`. Does not check every field's presentation. |
| Failed and cancelled run wording | Pass | Same command, tools and date. `tests/run_records.rs`: `a_failed_runs_record_keeps_the_errors_own_kind` asserts `failed (<kind>)` for its four supplied error kinds; `a_run_its_caller_stopped_waiting_for_is_recorded_as_cancelled` asserts `failed (cancelled)` and that the message names the script. Does not evaluate runner messages for readability. |
| Result truncation at a character boundary | Pass | Same command, tools and date. `src/model.rs`: `model::tests::truncation_respects_characters` checks the byte limit preserves a UTF-8 character boundary. Does not test whether the truncation notice explains enough. |
| UTC timestamp and missing-clock wording | Pass | `cargo test --doc`, tools and date above. The `model::when` doctest in `src/model.rs` asserts two UTC timestamps and `unstamped (the kernel has no clock)`. Does not test how a host announces dates. |
| Other messages, catalog notices and door descriptions | Blocked | No comprehensive wording or usability check was run. Existing selected assertions do not establish that every message names its subject, gives a useful next step or reads clearly. |
| Documentation accessibility | Blocked | No rendered documentation or manual reading evaluation was run in GitHub, an editor or a documentation host. Rust doctests check code examples, not accessible presentation. |
| Historical source review of known limitations | Blocked | The previous record reports source reading on 2026-10-31, not testing. CI does not repeat that review; it is context, not a current Pass. See the limitations below. |
| Browser presentation, zoom, reflow and contrast | Blocked | No browser evaluation was run. This library supplies no HTML or SVG interface; a host presenting its text, JSON or Turtle needs evaluation in its own interface. |
| Manual keyboard | Blocked | No person performed a keyboard pass in a host presenting this output; no interactive host session was available for this update. |
| Automated accessibility checker | Blocked | No axe or other automated accessibility checker was run; no rendered host interface or browser checker was configured for this update. Rust tests are not accessibility checkers. |
| Screen reader | Blocked | No screen reader was used on this output; no screen reader and host session was available for this update. |
| Screen magnifier | Blocked | No screen magnifier was used on this output; no magnifier and host session was available for this update. |
| Speech input | Blocked | No speech-input software was used on this output; no speech-input and host session was available for this update. |
| Switch access | Blocked | No switch-access software was used on this output; no switch-access and host session was available for this update. |
| Braille display | Blocked | No braille display was used on this output; no braille display and host session was available for this update. |

## Known limitations

The previous record listed these limitations from source reading on 2026-10-31, not
assistive technology testing. They are not evidence of conformance:

- A failed run's message is recorded as the language runner wrote it, so its limits are this
  output's too. The 2026-10-31 review noted Lisp errors without a script line number;
  source-location guidance has not been evaluated across current runner messages.
- A failed plan validation joins reported problems with `; `, placing constraint or shape
  identifiers and the focus node before the message. It adds no line breaks between problems;
  the host and report messages determine how that text wraps.
- `(truncated)` does not say how much of the result was kept or the size it was cut to.
- The directory backend's errors (`src/backend/dir.rs`) name the store's host path, which is the
  host's own configuration, not something the person running a script chose.

## Contributing

Read this file before changing any output listed above: a plain face, a refusal's words or a
door's description. Keep meaning in words, name the script a message is about, and say what to
do. In the pull request's Accessibility section, give every named check a row in a
`Check | Result | Evidence` table with Pass, Fail or Blocked. Include the test or command,
tool and version used, or why it could not run. Keep unrun checks Blocked, including each
assistive technology nobody used; do not omit them. A historical run that CI does not repeat
stays Blocked with its date. State what each Pass covers and does not cover.

## Reporting a barrier

[Open an issue](https://github.com/ikigai-rs/ikigai-script/issues/new?labels=accessibility) with
the `accessibility` label (the link sets it when GitHub lets you add labels; otherwise a
maintainer adds it): what you were doing, what happened, and any assistive technology you use,
if you are comfortable sharing it. Anything security-sensitive goes through
[private vulnerability reporting](https://github.com/ikigai-rs/ikigai-script/security/advisories/new).
**We acknowledge a report within 7 days**, and promise nothing further.

## Change history

| Date | Change |
|---|---|
| 2026-10-31 | First version. |
| 2026-11-12 | Recorded current main test results and explicitly blocked unrun checks; clarified scope and contribution evidence. |
