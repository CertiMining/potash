// SPDX-License-Identifier: MIT OR Apache-2.0
//! Lint suppressions, counted by a lexer rather than by a pattern (review of PR #121, M-02).
//!
//! **Why this exists.** `cargo clippy -- -D warnings` only fails on warnings that are reported, and
//! `#![allow(warnings)]` in a tracked file reports none. The gate against that lived in
//! `scripts/ci.sh` as a `grep`, and three rounds of review walked past it in three different
//! spellings:
//!
//! - the first pattern matched only `allow(dead_code` and `allow(unused`, so `#![allow(warnings)]`
//!   was free;
//! - the second matched the text anywhere on a line, so a comment mentioning a suppression counted
//!   as one, and it recorded file names rather than counts, so a second suppression in a listed file
//!   was free;
//! - the third accepted whitespace between the attribute's tokens, because `#![allow (warnings)]`
//!   had slipped past the second — and Rust also accepts *comments* between those tokens, so
//!   `#![allow /* reviewer gap */ (warnings)]` slipped past the third. It compiled, `cargo fmt
//!   --check` accepted it, every clippy invocation in the `checks` group passed, and the gate
//!   printed `2 recorded, counts match, none added`.
//!
//! Each repair narrowed the gap by one spelling. The defect was never the spelling: it was deciding
//! what Rust means by looking at one line of text. A lexer decides it instead. Comments and
//! whitespace do not survive tokenisation, so neither is a spelling any more.
//!
//! **What it counts.** Every attribute — `#[…]` or `#![…]` — whose brackets contain the identifier
//! `allow` or `expect` at any depth. That reaches `#[allow(dead_code)]`, `#![allow(warnings)]`,
//! `#[cfg_attr(test, allow(unused))]` and `#[expect(dead_code)]` alike, and it does not reach the
//! word in a comment, in a string, or in a doc comment, because none of those is an identifier.
//!
//! **What it does not.** A lint relaxed in a manifest is a suppression this file would never see, so
//! `[lints]` tables are checked here too, for any lint set to `allow`. `RUSTFLAGS` and
//! `--cap-lints` are outside the repository and outside this check; CI sets neither.

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
