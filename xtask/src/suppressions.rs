// SPDX-License-Identifier: MIT OR Apache-2.0
//! Lint suppressions, counted by a lexer rather than by a pattern (review of PR #121, M-02).
//!
//! **Why this exists.** `cargo clippy -- -D warnings` cannot fail on a warning that was never
//! reported, and `#![allow(warnings)]` reports none. The gate against that was a `grep` in
//! `scripts/ci.sh`, and three rounds of review walked past it:
//!
//! - the first matched only `allow(dead_code` and `allow(unused`;
//! - the second matched anywhere on a line, counting prose as a suppression, and recorded file
//!   names rather than counts, so a second one in a listed file was free;
//! - the third allowed whitespace between the attribute's tokens. Rust also allows *comments*
//!   there, so `#![allow /* reviewer gap */ (warnings)]` compiled, survived `cargo fmt --check`
//!   and every clippy run, and left the gate printing `none added`.
//!
//! Each repair closed one spelling. The defect was deciding what Rust means from one line of text.
//! A lexer decides instead, and tokenisation drops comments and whitespace entirely.
//!
//! **What it counts.** Any attribute whose brackets contain the identifier `allow` or `expect`, at
//! any depth — so `#[cfg_attr(test, allow(unused))]` too, and not the word in a comment, string or
//! doc comment, none of which is an identifier.
//!
//! **What it does not.** A lint relaxed in a manifest, so `[lints]` tables are checked here as
//! well. `RUSTFLAGS` and `--cap-lints` are outside the repository; CI sets neither.

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use std::path::Path;
use std::str::FromStr;

/// The suppressions this repository is known to carry, by path and count.
///
/// A count rather than a file name: a second suppression added to an already-listed file used to be
/// free. Both of these are a crate-root or item `allow(dead_code)` over test support code.
const RECORDED: [(&str, usize); 2] = [
    ("crates/certimining-log/tests/common/mod.rs", 1),
    ("xtask/src/spec.rs", 1),
];

/// Every tracked file matching a pathspec, as repository-relative paths.
fn tracked(root: &Path, pathspec: &str) -> Vec<String> {
    let out = std::process::Command::new("git")
        .args(["ls-files", "-z", pathspec])
        .current_dir(root)
        .output()
        .expect("git ls-files");
    assert!(
        out.status.success(),
        "git ls-files {pathspec} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .expect("git ls-files is utf-8")
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Whether a token stream contains `allow` or `expect` as an identifier, at any depth.
fn relaxes_a_lint(stream: TokenStream) -> bool {
    stream.into_iter().any(|tree| match tree {
        TokenTree::Ident(ident) => {
            let name = ident.to_string();
            name == "allow" || name == "expect"
        }
        TokenTree::Group(group) => relaxes_a_lint(group.stream()),
        _ => false,
    })
}

/// Counts attributes that relax a lint, descending into every group.
///
/// An attribute is `#`, an optional `!`, then a bracketed group. Tokenisation has already removed
/// whatever a writer put between those three, which is the whole point of reading it this way.
fn count(stream: TokenStream, found: &mut usize) {
    let trees: Vec<TokenTree> = stream.into_iter().collect();
    let mut i = 0;
    while i < trees.len() {
        if let TokenTree::Punct(punct) = &trees[i] {
            if punct.as_char() == '#' {
                let mut j = i + 1;
                if let Some(TokenTree::Punct(bang)) = trees.get(j) {
                    if bang.as_char() == '!' {
                        j += 1;
                    }
                }
                if let Some(TokenTree::Group(group)) = trees.get(j) {
                    if group.delimiter() == Delimiter::Bracket {
                        if relaxes_a_lint(group.stream()) {
                            *found += 1;
                        }
                        // The attribute's own tokens are not searched again for nested attributes:
                        // an `allow` inside it has been counted, and counting it twice would make
                        // the recorded number depend on how the attribute is spelled, which is the
                        // property this module exists to remove.
                        i = j + 1;
                        continue;
                    }
                }
            }
        }
        if let TokenTree::Group(group) = &trees[i] {
            count(group.stream(), found);
        }
        i += 1;
    }
}

/// Suppressions in one file, by tokenising it.
fn in_file(root: &Path, path: &str) -> usize {
    let text = std::fs::read_to_string(root.join(path))
        .unwrap_or_else(|e| panic!("{path} is tracked and unreadable: {e}"));
    // A file that does not lex is a file whose contents this check cannot account for, which is a
    // failure rather than a zero. `cargo check` would reject it anyway; this says so first.
    let stream = TokenStream::from_str(&text).unwrap_or_else(|e| {
        panic!("{path} does not tokenise, so its suppressions cannot be counted: {e}")
    });
    let mut found = 0;
    count(stream, &mut found);
    found
}

/// Any lint a manifest sets to `allow`, which no attribute check would ever see.
fn manifest_relaxations(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for path in tracked(root, "*Cargo.toml") {
        let text = std::fs::read_to_string(root.join(&path))
            .unwrap_or_else(|e| panic!("{path} is tracked and unreadable: {e}"));
        let mut in_lints = false;
        for (number_of, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.starts_with('[') {
                in_lints = line.starts_with("[lints");
                continue;
            }
            if in_lints && line.contains("\"allow\"") {
                out.push(format!("{path} line {}: {line}", number_of + 1));
            }
        }
    }
    out
}

/// Fails if the suppressions present disagree with `RECORDED`, in either direction.
pub fn check_suppressions(root: &Path) {
    let mut wrong: Vec<String> = Vec::new();
    let mut present: Vec<(String, usize)> = Vec::new();

    for path in tracked(root, "*.rs") {
        let found = in_file(root, &path);
        if found > 0 {
            present.push((path, found));
        }
    }

    for (path, found) in &present {
        match RECORDED.iter().find(|(p, _)| p == path) {
            None => wrong.push(format!("{path} carries {found} and is not recorded")),
            Some((_, expected)) if expected != found => wrong.push(format!(
                "{path} carries {found}, and {expected} is recorded"
            )),
            Some(_) => {}
        }
    }
    for (path, expected) in RECORDED {
        if !present.iter().any(|(p, _)| p == path) {
            wrong.push(format!(
                "{path} is recorded as carrying {expected} and carries none, so the record is stale"
            ));
        }
    }
    wrong.extend(
        manifest_relaxations(root)
            .into_iter()
            .map(|line| format!("a manifest relaxes a lint, which no attribute carries: {line}")),
    );

    assert!(
        wrong.is_empty(),
        "lint suppressions disagree with the recorded set:\n  {}\n\n\
         Every suppression in the repository is recorded in xtask/src/suppressions.rs by path and \
         count. `cargo clippy -- -D warnings` cannot fail on a warning that was never reported, so \
         an unrecorded suppression is a gate that passes by reporting nothing.",
        wrong.join("\n  ")
    );

    let total: usize = present.iter().map(|(_, n)| n).sum();
    println!(
        "suppressions: {total} in {} file(s), each recorded, counted by tokenising every tracked \
         .rs file; no manifest relaxes a lint",
        present.len()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn count_in(source: &str) -> usize {
        let mut found = 0;
        count(TokenStream::from_str(source).expect("lexes"), &mut found);
        found
    }

    #[test]
    fn the_plain_spellings_are_counted() {
        assert_eq!(count_in("#![allow(warnings)] fn f() {}"), 1);
        assert_eq!(count_in("#[allow(dead_code)] fn f() {}"), 1);
        assert_eq!(count_in("fn f() { #[allow(unused)] let x = 1; }"), 1);
    }

    /// The three spellings three rounds of review used, and the one that got through.
    #[test]
    fn whitespace_and_comments_are_not_spellings() {
        assert_eq!(count_in("#![allow (warnings)] fn f() {}"), 1, "whitespace");
        assert_eq!(
            count_in("#![allow /* reviewer gap */ (warnings)] fn f() {}"),
            1,
            "a block comment between the attribute's tokens — the spelling that passed the grep, \
             rustfmt, clippy and the whole checks group"
        );
        assert_eq!(
            count_in(
                "# /* a */ ! /* b */ [ /* c */ allow /* d */ ( /* e */ warnings ) ] fn f() {}"
            ),
            1,
            "a comment in every gap Rust admits"
        );
        assert_eq!(
            count_in("#![\n    allow(\n        warnings\n    )\n] fn f() {}"),
            1,
            "spread over five lines, which no single-line pattern can see at all"
        );
    }

    /// Runs a tool over `source` on stdin; returns whether it accepted it and what it emitted.
    ///
    /// A missing tool panics rather than skipping: a test that does nothing when its subject is
    /// absent reports what its acceptance predicate rewards, which is this module's own defect.
    fn fed_to(program: &str, args: &[&str], source: &str) -> (bool, String) {
        use std::io::Write as _;
        use std::process::{Command, Stdio};
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| {
                panic!("{program} must be on PATH or this test establishes nothing: {e}")
            });
        child
            .stdin
            .take()
            .expect("stdin was piped")
            .write_all(source.as_bytes())
            .expect("the source is small enough to write in one go");
        let out = child.wait_with_output().expect("the tool exits");
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
        )
    }

    /// **The spelling is real Rust, proved rather than asserted (H-43, #131).**
    ///
    /// The tests above show the counter sees it. They do not show `rustc` compiles it or `rustfmt`
    /// leaves it alone — the half that made the old grep dangerous, since a spelling no tool
    /// accepts is not a bypass.
    ///
    /// Not a fixture file: a tracked `.rs` carrying a live suppression must appear in `RECORDED`,
    /// where a real one could hide behind it. Fed on stdin instead, so nothing is tracked.
    #[test]
    fn the_spelling_that_defeated_the_grep_is_real_rust() {
        const SOURCE: &str = "#![allow /* reviewer gap */ (warnings)]\n";

        assert_eq!(count_in(SOURCE), 1, "this gate counts it");

        let (formatted_ok, formatted) = fed_to(
            "rustfmt",
            &["--emit", "stdout", "--edition", "2021"],
            SOURCE,
        );
        assert!(
            formatted_ok,
            "rustfmt rejected the spelling, so `cargo fmt --check` was never the gate it passed"
        );
        assert!(
            formatted.contains("allow") && formatted.contains("reviewer gap"),
            "rustfmt returned it unchanged, comment and all, so a file carrying it survives \
             `cargo fmt --all --check`: {formatted:?}"
        );

        let metadata = std::env::temp_dir().join(format!(
            "certimining-suppressions-{}-{:?}.rmeta",
            std::process::id(),
            std::thread::current().id()
        ));
        let (compiled, _) = fed_to(
            "rustc",
            &[
                "--edition",
                "2021",
                "--crate-type",
                "lib",
                "--emit",
                "metadata",
                "-o",
                metadata.to_str().expect("a utf-8 temp path"),
                "-",
            ],
            SOURCE,
        );
        let _ = std::fs::remove_file(&metadata);
        assert!(
            compiled,
            "rustc rejected the spelling, so it was never a suppression anything could hide behind"
        );
    }

    /// The control: a spelling neither tool accepts is not evidence of anything.
    #[test]
    fn the_probe_can_tell_rust_from_nonsense() {
        let (ok, _) = fed_to(
            "rustfmt",
            &["--emit", "stdout", "--edition", "2021"],
            "#![allow /* unterminated (warnings)]\n",
        );
        assert!(
            !ok,
            "rustfmt accepted an unterminated comment, so it accepts anything"
        );
    }

    #[test]
    fn a_relaxation_reached_through_cfg_attr_is_counted() {
        assert_eq!(count_in("#[cfg_attr(test, allow(unused))] fn f() {}"), 1);
    }

    #[test]
    fn expect_is_a_suppression_too() {
        assert_eq!(count_in("#[expect(dead_code)] fn f() {}"), 1);
    }

    /// The word, where it is not an identifier in an attribute.
    #[test]
    fn prose_and_strings_are_not_suppressions() {
        assert_eq!(count_in("// #![allow(warnings)] fn f() {}"), 0, "a comment");
        assert_eq!(
            count_in("/// Mentions `#![allow(warnings)]`.\nfn f() {}"),
            0,
            "a doc comment, which tokenises to #[doc = \"…\"] and carries no identifier"
        );
        assert_eq!(
            count_in("#[doc = \"allow(warnings)\"] fn f() {}"),
            0,
            "a string literal is not an identifier"
        );
        assert_eq!(count_in("let allow = 1;"), 0, "a binding named allow");
        assert_eq!(
            count_in("#[cfg(feature = \"expect\")] fn f() {}"),
            0,
            "a feature named expect"
        );
    }

    #[test]
    fn two_suppressions_in_one_file_count_as_two() {
        assert_eq!(
            count_in("#![allow(warnings)]\n#[allow(dead_code)]\nfn f() {}"),
            2
        );
    }

    #[test]
    fn deny_and_warn_are_not_suppressions() {
        assert_eq!(count_in("#![deny(warnings)] fn f() {}"), 0);
        assert_eq!(count_in("#![warn(missing_docs)] fn f() {}"), 0);
        assert_eq!(count_in("#![forbid(unsafe_code)] fn f() {}"), 0);
    }
}
