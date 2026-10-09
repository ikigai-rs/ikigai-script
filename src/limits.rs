// COPIED from ikigai-store `src/limits.rs` at commit 1cf3fa0 (ikigai-store 0.2.7; the file is
// unchanged since 6abf030, ikigai-rs/ikigai-store PR #16, ledger #915), for ledger #954, and kept
// byte-for-byte except where marked `COPY:` below, so a later shared limits crate can replace
// this copy and ikigai-sparql's (ikigai-linkeddata, ledger #962) mechanically. ikigai-script does
// not depend on ikigai-store for this: the store links an evaluator (oxigraph's spareval and
// sparopt), and this crate's whole point is that it never evaluates a query in-process. Diff
// the copies before editing any of them.

//! Bounds on caller-supplied SPARQL, checked before the parser sees a byte (ledger #915).
//!
//! oxigraph's SPARQL parser (`spargebra`, a `peg` grammar) and its evaluator (`sparopt`,
//! `spareval`) are **recursive**, so a query's shape is a claim on the stack of whatever
//! thread parses it. Running out is not an error a caller gets back: Rust aborts the
//! **whole process** on a stack overflow, on any thread. `SELECT * WHERE { FILTER(((…1…))) }`
//! with ~1000 parentheses took down a host through its HTTP door, and the anonymous grant
//! held the read authority that reached the parse.
//!
//! Two layers, because neither is enough alone:
//!
//! 1. **[`check_sparql`] refuses, never truncates.** A query or update over
//!    [`MAX_SPARQL_BYTES`], or that nests deeper than [`MAX_SPARQL_NESTING`] — brackets,
//!    and runs of the one prefix operator spargebra recurses on, `!` — is refused with a
//!    typed `InvalidArgument` naming the bound, before anything is parsed. Those are the
//!    cheapest ways to recurse (ONE byte a level; ~2.3 KiB of stack a level for a bracket
//!    in a release build), so this is the check that turns a 3 KB query that killed a host
//!    into a refusal.
//! 2. **[`on_sparql_stack`] runs the parse AND the evaluation on a thread whose stack is
//!    sized from the query's length.** Nesting is not the only recursion: measured on a
//!    2 MiB thread in a release build, 1,879 triple patterns, 2,087 `FILTER`s, a 2,086-way
//!    `||` or 3,283 `+` terms all overflow — and those are shapes a generated query can
//!    legitimately have, so no lexical bound can refuse them without refusing real work.
//!    What bounds them is the byte bound times the stack each byte can cost, and the thread
//!    is where that budget lives: [`STACK_PER_BYTE`] per byte above a [`STACK_BASE`] floor.
//!    A thread's stack is reserved address space, committed only as it is touched, so an
//!    ordinary query costs the spawn and nothing else.
//!
//! ⚠ **The second layer is a RELEASE-build guarantee.** A debug build spends ~20–50× the
//! stack per level (a 2 MiB thread holds 47 `+` terms when evaluating, unoptimized), so a
//! debug host can still be overflowed by a long enough operator chain inside the byte bound.
//! The bracket bound holds in both: a debug build at [`MAX_SPARQL_NESTING`] of the costliest
//! bracket (`STR(` calls, ~60 KiB a level) needs ~4 MiB, well inside [`STACK_BASE`].
//!
//! ⚠ **And on wasm there is no thread**: [`on_sparql_stack`] runs inline there, so only the
//! first layer applies, on whatever stack the host gave the module.
//!
//! ⚠ **Neither layer bounds TIME.** The evaluator is quadratic in an operator chain's
//! length: 40,000 `||1` terms (120 KB) take ~30 s of a core in a release build and 80,000
//! more than two minutes, and long property paths, long BGPs and deeply nested collections
//! are slow well before they are deep. This module is about the stack — an abort takes
//! down every request at once — and leaves a query budget to the host.
//!
//! # The scan is exact about what it skips, and that took an automaton
//!
//! The obvious scan — count `(`, `{`, `[`, skipping strings, `<IRI>`s and `#` comments —
//! is **wrong in a way an attacker can use**, because SPARQL's lexing of `<` depends on
//! where the parser is: in a triple pattern `<…>` is an IRI, but in an expression `?a<…`
//! is a less-than. spargebra accepts `<` + anything-but-`>` + `>` as an IRI only where an
//! IRI is allowed and the text inside is a valid IRI; elsewhere it is an operator, and the
//! "IRI" is code. So `( ?a<'> ) ' && ( ?a<'> ) ' && (…` reads to a skip-the-IRI scan as one
//! level, while the parser sees `(?a < "> ) " && (?a < "> ) " && (…` — a string it opens
//! INSIDE what the scan skipped — and nests once per repetition. A `#` inside such a token
//! does the same with a comment.
//!
//! So the scan follows **every reading** the grammar allows, as a small set of branches, and
//! refuses on the deepest. At a `<` it forks: an IRI (when the text up to the next `>` could
//! be one), a `<<` triple-term opener (when one follows), and a less-than — the last only
//! when the innermost open bracket is `(`, because every SPARQL expression sits directly
//! inside parentheses, so that is the only place a less-than can occur. Branches in the
//! same lexical state with the same open brackets are merged, so an ordinary query runs as
//! one branch and the whole scan stays linear. A closer pops only the opener it matches, so
//! no reading can be made to look shallower than it is; and a query that keeps more than
//! [`MAX_SCAN_BRANCHES`] readings alive at once is refused as too ambiguous to bound.
//!
//! ⚠ One more reading lives OUTSIDE the grammar: spargebra's `standard-unicode-escaping`
//! feature rewrites `\uXXXX` and `\UXXXXXXXX` anywhere in the text **before** tokenizing,
//! so `\u0028` is a `(`. oxigraph does not enable it, but feature unification is global and
//! a sibling could; when the text contains such an escape, the scan also runs over the
//! unescaped text and refuses on either.

use ikigai_core::{Error, Result};

/// The most bytes a SPARQL query or update may carry: **1 MiB**.
///
/// Generous on purpose. The largest legitimate queries in the ecosystem are FLAT — a
/// `VALUES` list of every open item in a ledger is ~51 bytes an item, so this holds about
/// 20,000 of them, and `VALUES` and `INSERT DATA` recurse not at all (measured to 40,000
/// entries on a 2 MiB thread). What this bounds is the stack [`on_sparql_stack`] may need.
pub const MAX_SPARQL_BYTES: usize = 1 << 20;

/// The deepest a SPARQL query or update may nest `(`, `{`, `[` and `<<` — with a run of `!`
/// counting one level for each — **64**.
///
/// The deepest legitimate query in the ecosystem's tests and stored queries nests about 5
/// (a scan of ~700 of them, 2026-10-09). On a 2 MiB thread oxigraph 0.5.11's parser
/// overflows at ~180 levels of `(`/`{` in a debug build and ~850 in release, and at 34
/// (debug) or 426 (release) levels of function calls, the costliest bracket per level. 64 is
/// an order of magnitude above real use, and the parse runs on [`on_sparql_stack`], where a
/// debug build at this bound needs ~4 MiB of the [`STACK_BASE`] it gets.
pub const MAX_SPARQL_NESTING: usize = 64;

/// How many simultaneous readings the scan follows before refusing the text as too
/// ambiguous to bound. An ordinary query keeps one; it takes a `<` inside parentheses
/// followed by text that could be an IRI containing `'`, `#` or a bracket to make two.
pub const MAX_SCAN_BRANCHES: usize = 64;

/// The stack every SPARQL thread gets before the per-byte share: 16 MiB.
pub const STACK_BASE: usize = 16 << 20;

/// The stack reserved per byte of query, above [`STACK_BASE`]: 512 bytes.
///
/// The worst cost measured per byte in a release build, for the shapes the nesting bound
/// does not refuse, is ~370 (a property path of one-letter prefixed names, `:a/:a/…`), then
/// ~335 (`1||1||…`) and ~320 (`1+1+…`); ~260 for a `UNION` chain. 512 covers the worst with
/// margin, so a query at [`MAX_SPARQL_BYTES`] gets a 528 MiB thread — reserved, and touched
/// only as deep as the query actually recurses. (A run of `!` would cost ~650 a byte at
/// scale, which is why it counts as nesting instead.) `tests/sparql_stack_measure.rs`
/// re-measures all of these.
pub const STACK_PER_BYTE: usize = 512;

/// Refuse a SPARQL query or update that exceeds [`MAX_SPARQL_BYTES`] or nests deeper than
/// [`MAX_SPARQL_NESTING`], naming the argument `arg` and the bound. Never truncates.
///
/// Every door in this crate that parses caller text calls this first. It is public so a
/// host with its own SPARQL face over oxigraph can apply the same bound; that host must
/// still parse on a big enough stack (see [`on_sparql_stack`]).
///
/// ```
/// // COPY: this crate's path.
/// use ikigai_script::limits::{check_sparql, MAX_SPARQL_NESTING};
///
/// assert!(check_sparql("SELECT * WHERE { ?s ?p ?o FILTER((1)) }", "query").is_ok());
/// let deep = format!("SELECT * WHERE {{ FILTER({}1{}) }}", "(".repeat(100), ")".repeat(100));
/// let refusal = check_sparql(&deep, "query").unwrap_err().to_string();
/// assert!(refusal.contains("`query`") && refusal.contains(&MAX_SPARQL_NESTING.to_string()));
/// // Brackets in a string, an IRI or a comment are not nesting.
/// let quoted = format!("SELECT * WHERE {{ ?s ?p \"{}\" }} # {}", "(".repeat(100), "[".repeat(100));
/// assert!(check_sparql(&quoted, "query").is_ok());
/// ```
pub fn check_sparql(text: &str, arg: &str) -> Result<()> {
    if text.len() > MAX_SPARQL_BYTES {
        return Err(Error::InvalidArgument {
            name: arg.to_string(),
            detail: format!(
                "this SPARQL text is {} bytes, and this store refuses any over {MAX_SPARQL_BYTES} \
                 (MAX_SPARQL_BYTES) before parsing it: the parser and evaluator are recursive, \
                 and the bound is what keeps the stack a query can claim finite. Split the \
                 work into several requests",
                text.len()
            ),
        });
    }
    let depth = deepest(text.as_bytes()).map_err(|ambiguous| refuse_ambiguous(arg, ambiguous))?;
    let depth = match unescaped(text) {
        Some(unescaped) => depth.max(
            deepest(unescaped.as_bytes()).map_err(|ambiguous| refuse_ambiguous(arg, ambiguous))?,
        ),
        None => depth,
    };
    if depth > MAX_SPARQL_NESTING {
        return Err(Error::InvalidArgument {
            name: arg.to_string(),
            detail: format!(
                "this SPARQL text nests its brackets deeper than {MAX_SPARQL_NESTING} \
                 (MAX_SPARQL_NESTING), counting `(`, `{{`, `[`, `<<` and each `!` of a run, \
                 outside strings, IRIs and comments. It is refused before parsing because the parser recurses once \
                 per level and a stack overflow aborts the whole host, not one request. Real \
                 queries nest well under 10; flatten this one"
            ),
        });
    }
    Ok(())
}

fn refuse_ambiguous(arg: &str, readings: usize) -> Error {
    Error::InvalidArgument {
        name: arg.to_string(),
        detail: format!(
            "this SPARQL text can be read more than {readings} ways at once (MAX_SCAN_BRANCHES): \
             a `<` inside parentheses is either an IRI or a less-than, and this text keeps too \
             many of those readings open for its nesting to be bounded before parsing. Put a \
             space after a less-than `<`, or write IRIs containing `'`, `#` or brackets with a \
             PREFIX"
        ),
    }
}

/// Run `work` — a parse and everything that evaluates what it parsed — on a thread whose
/// stack is sized for `text` (see [`STACK_BASE`] and [`STACK_PER_BYTE`]), and wait for it.
///
/// A panic on that thread is resumed on this one, so the caller sees what it would have
/// seen inline. A thread that cannot be spawned (the address space or the platform refused
/// a stack this size) is a transient [`Error::Unavailable`], never a fallback to running
/// inline — inline is the overflow this exists to prevent. On wasm there are no threads,
/// and `work` runs inline.
pub fn on_sparql_stack<T, F>(text: &str, work: F) -> Result<T>
where
    T: Send,
    F: FnOnce() -> Result<T> + Send,
{
    #[cfg(not(target_family = "wasm"))]
    {
        let stack = STACK_BASE.saturating_add(text.len().saturating_mul(STACK_PER_BYTE));
        std::thread::scope(|scope| {
            let handle = std::thread::Builder::new()
                // COPY: named for this crate, so a crash report names the right one.
                .name("ikigai-script-sparql".to_string())
                .stack_size(stack)
                .spawn_scoped(scope, work)
                .map_err(|e| {
                    Error::Unavailable(format!(
                        "could not start a {} MiB thread to parse this SPARQL text on: {e}",
                        stack >> 20
                    ))
                })?;
            match handle.join() {
                Ok(result) => result,
                Err(panic) => std::panic::resume_unwind(panic),
            }
        })
    }
    #[cfg(target_family = "wasm")]
    {
        let _ = text;
        work()
    }
}

/// The text with spargebra's `standard-unicode-escaping` applied, or `None` when it has no
/// `\u` / `\U` escape and would be unchanged.
fn unescaped(text: &str) -> Option<String> {
    if !text.contains("\\u") && !text.contains("\\U") {
        return None;
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('\\') {
        out.push_str(&rest[..at]);
        let after = &rest[at + 1..];
        let width = match after.as_bytes().first() {
            Some(b'u') => 4,
            Some(b'U') => 8,
            _ => 0,
        };
        let decoded = (width > 0)
            .then(|| after.get(1..=width))
            .flatten()
            .and_then(|hex| u32::from_str_radix(hex, 16).ok())
            .and_then(char::from_u32);
        match decoded {
            Some(c) => {
                out.push(c);
                rest = &after[1 + width..];
            }
            None => {
                out.push('\\');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    Some(out)
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Lex {
    Code,
    Comment,
    /// A string literal opened by `quote`; `long` for the triple-quoted forms.
    Str {
        quote: u8,
        long: bool,
    },
    /// Inside a `<…>` read as an IRI, until the `>`.
    Iri,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Reading {
    lex: Lex,
    /// Bytes still to pass over without reading them (an escape's second byte, the rest of
    /// a `'''`, the second `<` of `<<`).
    skip: u8,
    /// The open brackets, innermost last; `<` stands for `<<`.
    open: Vec<u8>,
    /// The last byte of code read, whitespace and comments aside — enough to know whether
    /// what came before a `<` could have been a less-than's left operand.
    last: u8,
    /// The `!`s in the run being read. spargebra parses `!!!x` as nesting — the one prefix
    /// operator it recurses on (`-`, `+` and a path's `^` do not repeat) — so a run counts
    /// toward the depth like brackets do, for as long as it lasts.
    bangs: usize,
}

/// The deepest any reading of `text` nests, stopping early once one passes the bound.
/// `Err(n)` when more than `n` readings were alive at once.
fn deepest(text: &[u8]) -> std::result::Result<usize, usize> {
    let mut readings = vec![Reading {
        lex: Lex::Code,
        skip: 0,
        open: Vec::new(),
        last: b'(',
        bangs: 0,
    }];
    let mut forks: Vec<Reading> = Vec::new();
    let mut deepest = 0;
    for (at, &byte) in text.iter().enumerate() {
        for reading in readings.iter_mut() {
            step(reading, text, at, byte, &mut forks);
        }
        if !forks.is_empty() {
            readings.append(&mut forks);
        }
        if readings.len() > 1 {
            readings.sort_unstable();
            readings.dedup();
            if readings.len() > MAX_SCAN_BRANCHES {
                return Err(MAX_SCAN_BRANCHES);
            }
        }
        for reading in &readings {
            deepest = deepest.max(reading.open.len() + reading.bangs);
        }
        if deepest > MAX_SPARQL_NESTING {
            break;
        }
    }
    Ok(deepest)
}

fn step(reading: &mut Reading, text: &[u8], at: usize, byte: u8, forks: &mut Vec<Reading>) {
    if reading.skip > 0 {
        reading.skip -= 1;
        return;
    }
    let next = |n: usize| text.get(at + n).copied();
    match reading.lex {
        Lex::Comment => {
            if byte == b'\n' || byte == b'\r' {
                reading.lex = Lex::Code;
            }
        }
        Lex::Iri => {
            if byte == b'>' {
                reading.lex = Lex::Code;
            }
        }
        Lex::Str { quote, long } => match byte {
            b'\\' => reading.skip = 1,
            // A short string cannot hold a line break; spargebra fails there, and reading
            // on as code can only count more, never less.
            b'\n' | b'\r' if !long => reading.lex = Lex::Code,
            b if b == quote && !long => reading.lex = Lex::Code,
            b if b == quote && next(1) == Some(quote) && next(2) == Some(quote) => {
                reading.lex = Lex::Code;
                reading.skip = 2;
            }
            _ => {}
        },
        Lex::Code => {
            match byte {
                // A comment inside a run does not end it.
                b if b <= b' ' || b == b'#' => {}
                b'!' if next(1) != Some(b'=') => reading.bangs += 1,
                _ => reading.bangs = 0,
            }
            code(reading, text, at, byte, forks);
        }
    }
}

fn code(reading: &mut Reading, text: &[u8], at: usize, byte: u8, forks: &mut Vec<Reading>) {
    let next = |n: usize| text.get(at + n).copied();
    match byte {
        b if b <= b' ' => {}
        b'#' => reading.lex = Lex::Comment,
        // A prefixed name's `\(`, `\#`, `\'`… escapes one character into the name, and a
        // name is an operand whatever the character was.
        b'\\' => {
            reading.skip = 1;
            reading.last = b'a';
        }
        b'\'' | b'"' => {
            let long = next(1) == Some(byte) && next(2) == Some(byte);
            reading.lex = Lex::Str { quote: byte, long };
            reading.last = byte;
            if long {
                reading.skip = 2;
            }
        }
        b'(' | b'{' | b'[' => {
            reading.open.push(byte);
            reading.last = byte;
        }
        b')' => close(reading, b'('),
        b'}' => close(reading, b'{'),
        b']' => close(reading, b'['),
        b'>' if next(1) == Some(b'>') && reading.open.last() == Some(&b'<') => {
            reading.open.pop();
            reading.skip = 1;
            reading.last = byte;
        }
        b'<' => {
            // Every reading the grammar allows at a `<`. This one becomes the first
            // that applies; the rest are pushed as forks.
            let mut alternatives: Vec<Reading> = Vec::with_capacity(3);
            if could_be_iri(text, at) {
                alternatives.push(Reading {
                    lex: Lex::Iri,
                    skip: 0,
                    open: reading.open.clone(),
                    last: b'>',
                    bangs: 0,
                });
            }
            if next(1) == Some(b'<') {
                let mut open = reading.open.clone();
                open.push(b'<');
                alternatives.push(Reading {
                    lex: Lex::Code,
                    skip: 1,
                    open,
                    last: b'<',
                    bangs: 0,
                });
            }
            // A less-than (or `<=`) needs an expression — and every SPARQL expression
            // sits directly inside `(` — and a left operand before it. With no other
            // reading left, keep this one anyway: the parser fails here, and reading on
            // can only count more.
            let less_than = reading.open.last() == Some(&b'(')
                && !NEVER_ENDS_AN_OPERAND.contains(&reading.last);
            if less_than || alternatives.is_empty() {
                let mut operator = reading.clone();
                operator.last = b'<';
                alternatives.push(operator);
            }
            let mut alternatives = alternatives.into_iter();
            if let Some(first) = alternatives.next() {
                *reading = first;
            }
            forks.extend(alternatives);
        }
        _ => reading.last = byte,
    }
}

/// Bytes after which no operand has just ended, so a `<` that follows cannot be a
/// less-than. Deliberately short — `-` and `.` are left out because a prefixed name can end
/// in one, and a byte left out only adds a reading.
const NEVER_ENDS_AN_OPERAND: &[u8] = b"(,=!&|+*/^<";

/// Pop the innermost bracket if `opener` is what it is. A closer that does not match is
/// one the parser fails on in this reading, so it closes nothing — never lowering the count.
fn close(reading: &mut Reading, opener: u8) {
    if reading.open.last() == Some(&opener) {
        reading.open.pop();
    }
    reading.last = b')';
}

/// Whether the `<` at `at` could open an IRI: spargebra takes `<` + anything but `>` + `>`
/// and keeps it only if the inside parses as an IRI, which no IRI does with whitespace, a
/// control character, `<`, `"`, `{` or `}` in it. Erring towards "could" is the safe
/// direction — it only adds a reading. The look-ahead stops at the first such byte, so the
/// scan stays linear.
fn could_be_iri(text: &[u8], at: usize) -> bool {
    for &byte in &text[at + 1..] {
        match byte {
            b'>' => return true,
            b if b <= b' ' => return false,
            b'<' | b'"' | b'{' | b'}' => return false,
            _ => {}
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn depth(text: &str) -> usize {
        deepest(text.as_bytes()).unwrap()
    }

    #[test]
    fn brackets_of_every_kind_count_and_close_only_what_they_match() {
        assert_eq!(depth("SELECT * WHERE { ?s ?p ?o }"), 1);
        assert_eq!(depth("SELECT * WHERE { { [ <urn:p> ( 1 ) ] } }"), 4);
        // A closer of the wrong kind closes nothing: it cannot be used to look shallower.
        assert_eq!(depth("( ] ( ] ( ] ("), 4);
        assert_eq!(depth(") ) ) ( ( ("), 3);
    }

    #[test]
    fn strings_iris_and_comments_hide_brackets() {
        assert_eq!(depth(r#"{ ?s ?p "(((([[[[{{{{" }"#), 1);
        assert_eq!(depth(r"{ ?s ?p '(((' }"), 1);
        assert_eq!(depth(r#"{ ?s ?p """((( " "" ((( """ }"#), 1);
        assert_eq!(depth("{ ?s ?p '''((( ' '' ((('''}"), 1);
        assert_eq!(depth(r#"{ ?s ?p "\"(((" }"#), 1);
        assert_eq!(depth("{ ?s <http://x/a(b(c(d> ?o }"), 1);
        assert_eq!(depth("{ # ((((((\n ?s ?p ?o }"), 1);
        assert_eq!(depth("{ # ((((((\r ?s ?p ?o }"), 1);
        // A prefixed name's escaped bracket is part of the name.
        assert_eq!(depth(r"{ ?s ex:a\(\(\( ?o }"), 1);
    }

    #[test]
    fn a_less_than_reading_is_followed_where_an_expression_can_be() {
        // Inside `(`, `<…>` may be a less-than whose "IRI" is code: the scan counts both.
        let attack = "SELECT * WHERE { FILTER(?a<(((((1)))))>0) }";
        assert_eq!(depth(attack), 2 + 5);
        // A string opened INSIDE what an IRI reading would skip.
        let phase = format!(
            "SELECT * WHERE {{ FILTER({}1) }}",
            "( ?a<'> ) ' && ".repeat(20)
        );
        assert!(depth(&phase) >= 20, "{}", depth(&phase));
        // A comment opened inside one, hiding the closers on the rest of the line.
        let comment =
            "SELECT * WHERE { FILTER(\n".to_string() + &"(( ?a<#> )) ?a < \n".repeat(10) + "1) }";
        assert!(depth(&comment) >= 10, "{}", depth(&comment));
        // After an operator there is no left operand, so `<…>` is an IRI there too.
        assert_eq!(
            depth("SELECT * WHERE { FILTER(?o != <urn:x:((((((> && ?o = <urn:y#(>) }"),
            2
        );
        assert_eq!(
            depth("SELECT * WHERE { FILTER(\"a\"^^<urn:t((((> = ?o) }"),
            2
        );
        // …but a name ending in an escaped bracket is an operand, so not after one.
        assert_eq!(
            depth("SELECT * WHERE { FILTER(ex:a\\(<urn:x((((>) }"),
            2 + 4
        );
        // Outside `(`, `<…>` can only be an IRI, so a `#` or `(` in one opens nothing.
        let triple =
            "SELECT * WHERE {\n".to_string() + &"{ ?s <http://x/v#p> ?o }\n".repeat(200) + "}";
        assert_eq!(depth(&triple), 2);
    }

    #[test]
    fn a_run_of_not_nests_and_not_equal_does_not() {
        let run = format!("SELECT * WHERE {{ FILTER({}true) }}", "! #c\n!".repeat(30));
        assert_eq!(depth(&run), 2 + 60);
        assert_eq!(
            depth("SELECT * WHERE { FILTER(?a != ?b && !?c && !(!?d)) }"),
            2 + 2
        );
        // A path's `!` does not recurse, but counting it costs one level, never more.
        assert_eq!(depth("SELECT * WHERE { ?s !<urn:p> ?o }"), 2);
    }

    #[test]
    fn triple_terms_nest_and_the_unescaped_reading_is_scanned_too() {
        assert_eq!(depth("{ << << ?s ?p ?o >> ?q ?r >> ?x ?y }"), 3);
        let escaped = format!(
            "SELECT * WHERE {{ FILTER({}1{}) }}",
            r"\u0028".repeat(100),
            r"\u0029".repeat(100)
        );
        assert!(depth(&escaped) < MAX_SPARQL_NESTING);
        assert!(check_sparql(&escaped, "query").is_err());
    }

    #[test]
    fn the_bound_is_the_number_the_integration_tests_restate() {
        // COPY: kept from the source, where `tests/sparql_nesting.rs` must compile against an
        // older release and so restates 64; here `tests/sparql.rs` restates it for the same
        // reason (an integration test reads the bound as a reader would).
        assert_eq!(MAX_SPARQL_NESTING, 64);
    }

    #[test]
    fn the_bounds_refuse_by_name_and_admit_at_the_bound() {
        let at = format!(
            "SELECT * WHERE {{ FILTER({}1{}) }}",
            "(".repeat(MAX_SPARQL_NESTING - 2),
            ")".repeat(MAX_SPARQL_NESTING - 2)
        );
        assert_eq!(depth(&at), MAX_SPARQL_NESTING);
        check_sparql(&at, "query").unwrap();
        let over = at.replacen('(', "((", 1).replacen(')', "))", 1);
        let err = check_sparql(&over, "content").unwrap_err();
        assert!(
            matches!(&err, Error::InvalidArgument { name, .. } if name == "content"),
            "{err}"
        );
        let big = format!(
            "SELECT * WHERE {{ VALUES ?x {{ {} }} }}",
            "1 ".repeat(MAX_SPARQL_BYTES / 2)
        );
        let err = check_sparql(&big, "query").unwrap_err().to_string();
        assert!(err.contains("MAX_SPARQL_BYTES"), "{err}");
    }
}
