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
| Last reviewed | 2026-10-31 |

## What it emits that people read

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
- No color, no terminal control codes and no markup are written.

## How it is tested

- `tests/refusals.rs`: `a_sparql_drafts_author_is_told_it_is_a_draft_not_that_lisp_is_missing`,
  `a_drafts_other_readers_are_told_it_is_absent_and_the_run_gate_still_holds`,
  `a_drafts_hint_names_a_door_that_takes_its_language`,
  `a_draft_is_reported_before_the_run_grant_it_will_also_need`,
  `a_namespaced_scripts_contract_says_what_its_run_gate_is_and_why`,
  `a_query_that_reads_no_graph_is_refused_saying_why` and
  `a_reserved_parameter_name_is_refused_naming_every_reserved_name` pin what those refusals say.
- `tests/lifecycle.rs`: `a_run_for_effects_is_recorded` pins `outcome:    ok` in the run record,
  and `a_retired_script_is_readable_and_never_runs` pins `retired urn:script:…`.
- The doctest on `model::when` pins the time format; a unit test in `src/model.rs` pins that a
  cut result is cut on a character boundary.

The other messages are followed by reading and not tested. **No automated accessibility checker,
browser or assistive technology has been used on this output.**

## Known limitations

Found by reading the source on 2026-10-31, not by testing:

- A failed run's message is recorded as the language runner wrote it, so its limits are this
  output's too: a Lisp error, for example, names no line of the script.
- A plan that does not validate is refused with every problem on one line, joined by `; `, each
  naming a SHACL constraint and a node by IRI before the message.
- `(truncated)` does not say how much of the result was kept or the size it was cut to.
- The directory backend's errors (`src/backend.rs`) name the store's host path, which is the
  host's own configuration, not something the person running a script chose.

## Contributing

Read this file before changing any output listed above: a plain face, a refusal's words or a
door's description. Keep meaning in words, name the script a message is about, and say what to
do. Say in the pull request what was tested, with what, and what was not.

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
