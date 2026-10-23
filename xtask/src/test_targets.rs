// SPDX-License-Identifier: MIT OR Apache-2.0
//! Every test target in the workspace, against the groups `scripts/ci.sh` actually runs
//! (H-62, issue #230).
//!
//! **Why this exists.** `ci.sh` names what it runs, target by target. That is deliberate and right
//! for the ones it names — `anchor_status` runs in `kat01-onchain` because it needs a compiled
//! program, and the cluster harnesses are excluded because every test in them is `#[ignore]`d. The
//! cost is that **adding a target reaches no gate until somebody remembers**, and remembering is what
//! this repository stopped relying on after H-36. Two targets were found unreached on 22 October:
//!
//! - `confirm-anchor-b`'s unit tests. Every `cargo test` line passes explicit `--test` targets, and
//!   that excludes `--bin` ones, so four tests beside a binary's own logic ran nowhere.
//! - `program_addresses`, whose two offline tests had been unreached for as long as V-P-12 existed.
//!   One of them is the regression test for §2.4 printing the PDA seeds in the wrong order — the
//!   remedy for a defect that shipped, itself never exercised.
//!
//! **Enumeration comes from `cargo metadata`, not from the filesystem.** A target is declared two
//! ways: discovered from `tests/*.rs`, or named in an explicit `[[test]]` or `[[bin]]` block.
//! `benches/band.rs` and `benches/thresholds.rs` are the second kind and sit at their crate's root,
//! so a sweep of `tests/*.rs` never sees them — the hand sweep that found the two targets above
//! called `band.rs` a bench and was wrong about it. Asking cargo removes the question.
//!
//! **What counts as run.** One of three things, and the third is the honest form of "this needs a
//! cluster":
//!
//! 1. the target is named by a `--test` or `--bin` flag in `scripts/ci.sh`; or
//! 2. its package is run wholesale, by a `cargo test -p <package>` carrying no target flag, which
//!    runs every target the package has; or
//! 3. **every** `#[test]` in its source carries `#[ignore]`.
//!
//! **Condition 3 is decided by tokenising**, for the reason `check-suppressions` records: deciding
//! what Rust means from a line of text failed there four times — a substring, then a match anywhere
//! on a line, then whitespace between an attribute's tokens, then a raw identifier's rendering.
//! Counting `#[test]` occurrences against `#[ignore]` occurrences would pass a file with two ignored
//! tests and two live ones. An attribute run belongs to one item and is contiguous, so this reads the
//! run and asks whether it holds both.
//!
//! A case found while demonstrating the gate rather than while writing it: `correlation.rs`'s own
//! module documentation says its test is "`#[ignore]`d and behind the `cluster` feature". A gate
//! counting occurrences would read that sentence as an ignore and the file would hold two for one
//! test. The lexer turns a doc comment into `#[doc = "…"]`, so the word is a string literal and not
//! an identifier, and it is not counted. That is the same distinction `check-suppressions` needed.
//!
//! **What it does not do.** It reads `scripts/ci.sh` and not the workflows, because every job there
//! calls this script and `scripts/ci.sh all` is the pipeline verbatim (D-09). A target run only by a
//! workflow step that bypassed the script would be invisible here, and nothing does that today.

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use std::collections::BTreeSet;
use std::path::Path;

/// One test or bin target, as cargo reports it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Target {
    package: String,
    kind: String,
    name: String,
    src: String,
}

/// Every `test` and `bin` target of every workspace member.
fn targets(root: &Path) -> Vec<Target> {
    let out = std::process::Command::new("cargo")
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .current_dir(root)
        .output()
        .expect("cargo metadata");
    assert!(
        out.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("cargo metadata is JSON");
    let mut found = Vec::new();
    for pkg in json["packages"].as_array().expect("packages") {
        let package = pkg["name"].as_str().expect("a package name").to_string();
        for target in pkg["targets"].as_array().expect("targets") {
            let name = target["name"].as_str().expect("a target name").to_string();
            let src = target["src_path"]
                .as_str()
                .expect("a source path")
                .to_string();
            for kind in target["kind"].as_array().expect("a kind") {
                let kind = kind.as_str().unwrap_or_default();
                if kind == "test" || kind == "bin" {
                    found.push(Target {
                        package: package.clone(),
                        kind: kind.to_string(),
                        name: name.clone(),
                        src: src.clone(),
                    });
                }
            }
        }
    }
    found.sort();
    found
}

/// What `scripts/ci.sh` runs: packages tested wholesale, and targets named by flag.
#[derive(Debug, Default)]
struct Covered {
    wholesale: BTreeSet<String>,
    named: BTreeSet<String>,
}

/// Reads the script's `cargo test` invocations.
///
/// Line continuations are joined first, because one invocation is written across two lines and a
/// per-line reader would see neither half whole.
fn covered(script: &str) -> Covered {
    let joined = script.replace("\\\n", " ");
    let mut out = Covered::default();
    for line in joined.lines() {
        let line = line.trim();
        if line.starts_with('#') || !line.contains("cargo test") {
            continue;
        }
        let words: Vec<&str> = line.split_whitespace().collect();
        let mut packages = Vec::new();
        let mut names = Vec::new();
        let mut i = 0;
        while i < words.len() {
            match words[i] {
                "-p" | "--package" => {
                    if let Some(p) = words.get(i + 1) {
                        packages.push(p.trim_matches('"').to_string());
                    }
                    i += 2;
                }
                "--test" | "--bin" | "--bench" | "--example" => {
                    if let Some(n) = words.get(i + 1) {
                        names.push(n.trim_matches('"').to_string());
                    }
                    i += 2;
                }
                _ => i += 1,
            }
        }
        for n in &names {
            out.named.insert(n.clone());
        }
        // No target flag means every target of the package, which is what covers a whole crate.
        if names.is_empty() {
            for p in packages {
                out.wholesale.insert(p);
            }
        }
    }
    out
}

/// Every identifier inside an attribute, at any depth, with a raw identifier's `r#` removed.
///
/// The prefix matters: `Ident::to_string` renders `r#test` as `r#test`, and comparing the rendering
/// is the mistake `check-suppressions` made on its fourth attempt.
fn idents(stream: TokenStream, into: &mut BTreeSet<String>) {
    for tree in stream {
        match tree {
            TokenTree::Ident(ident) => {
                let text = ident.to_string();
                into.insert(text.strip_prefix("r#").unwrap_or(&text).to_string());
            }
            TokenTree::Group(group) => idents(group.stream(), into),
            _ => {}
        }
    }
}

/// Counts the `#[test]` functions in a source, and how many of them also carry `#[ignore]`.
fn count(stream: TokenStream, tests: &mut usize, ignored: &mut usize) {
    let trees: Vec<TokenTree> = stream.into_iter().collect();
    let mut i = 0;
    while i < trees.len() {
        // An attribute run: consecutive `#[…]` or `#![…]` groups, which belong to one item.
        if matches!(&trees[i], TokenTree::Punct(p) if p.as_char() == '#') {
            let mut names = BTreeSet::new();
            let mut j = i;
            loop {
                let hash = matches!(trees.get(j), Some(TokenTree::Punct(p)) if p.as_char() == '#');
                if !hash {
                    break;
                }
                let mut k = j + 1;
                if matches!(trees.get(k), Some(TokenTree::Punct(p)) if p.as_char() == '!') {
                    k += 1;
                }
                match trees.get(k) {
                    Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Bracket => {
                        idents(g.stream(), &mut names);
                        j = k + 1;
                    }
                    _ => break,
                }
            }
            if j > i {
                if names.contains("test") {
                    *tests += 1;
                    if names.contains("ignore") {
                        *ignored += 1;
                    }
                }
                i = j;
                continue;
            }
        }
        // A brace group is a module or function body, and a test can be inside either.
        if let TokenTree::Group(group) = &trees[i] {
            if group.delimiter() == Delimiter::Brace {
                count(group.stream(), tests, ignored);
            }
        }
        i += 1;
    }
}

/// `(tests, ignored)` for one source file.
fn tests_in(path: &Path) -> (usize, usize) {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let stream: TokenStream = text
        .parse()
        .unwrap_or_else(|e| panic!("{} does not tokenise: {e}", path.display()));
    let mut tests = 0;
    let mut ignored = 0;
    count(stream, &mut tests, &mut ignored);
    (tests, ignored)
}

pub fn check_test_targets(root: &Path) {
    let script = std::fs::read_to_string(root.join("scripts/ci.sh")).expect("scripts/ci.sh");
    let runs = covered(&script);
    let all = targets(root);

    let mut problems = Vec::new();
    let mut by_name = 0usize;
    let mut by_package = 0usize;
    let mut by_ignore = 0usize;
    for target in &all {
        if runs.named.contains(&target.name) {
            by_name += 1;
            continue;
        }
        if runs.wholesale.contains(&target.package) {
            by_package += 1;
            continue;
        }
        let rel = target
            .src
            .strip_prefix(&format!("{}/", root.display()))
            .unwrap_or(&target.src);
        let (tests, ignored) = tests_in(Path::new(&target.src));
        if tests == ignored {
            by_ignore += 1;
            continue;
        }
        problems.push(format!(
            "  {} {} ({}) — {} of its {} test(s) carry #[ignore], and no CI group names it",
            target.kind, target.name, rel, ignored, tests
        ));
    }

    if !problems.is_empty() {
        eprintln!(
            "test-targets: {} target(s) are run by nothing:",
            problems.len()
        );
        for p in &problems {
            eprintln!("{p}");
        }
        eprintln!(
            "\nA target reaches a gate by being named in scripts/ci.sh with --test or --bin, by its \
             package being run wholesale with `cargo test -p <package>` and no target flag, or by \
             every #[test] in it carrying #[ignore]. A test nobody runs is the same thing as no test."
        );
        std::process::exit(1);
    }

    println!(
        "test-targets: {} test and bin target(s) across {} package(s), all run — {} named in \
         scripts/ci.sh, {} by their package being run wholesale, {} wholly #[ignore]d",
        all.len(),
        all.iter()
            .map(|t| &t.package)
            .collect::<BTreeSet<_>>()
            .len(),
        by_name,
        by_package,
        by_ignore
    );
    println!(
        "test-targets: enumerated from `cargo metadata`, so an explicit [[test]] block at a crate's \
         root counts as well as a file under tests/. This says every target reaches a group, not \
         that the group's assertions are any good."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counted(src: &str) -> (usize, usize) {
        let mut tests = 0;
        let mut ignored = 0;
        count(src.parse().expect("tokenises"), &mut tests, &mut ignored);
        (tests, ignored)
    }

    /// **The case a count of occurrences would pass.** Two ignored and two live is not "all
    /// ignored", and comparing `#[test]` occurrences against `#[ignore]` occurrences would make it
    /// look like it was.
    #[test]
    fn some_ignored_and_some_live_is_not_all_ignored() {
        let (tests, ignored) = counted(
            r#"
            #[test] #[ignore] fn a() {}
            #[test] fn b() {}
            #[test] #[ignore = "needs a cluster"] fn c() {}
            #[test] fn d() {}
            "#,
        );
        assert_eq!((tests, ignored), (4, 2));
        assert_ne!(tests, ignored, "this file must not read as wholly ignored");
    }

    /// A cluster harness: every test ignored, which is the honest form of "this needs a network".
    #[test]
    fn every_test_ignored_reads_as_wholly_ignored() {
        let (tests, ignored) = counted(
            r#"
            #[test]
            #[ignore = "needs devnet"]
            fn a() {}

            #[ignore]
            #[test]
            fn b() {}
            "#,
        );
        assert_eq!(
            (tests, ignored),
            (2, 2),
            "order within the run must not matter"
        );
    }

    /// **Comments between an attribute's tokens.** `check-suppressions` was defeated by exactly this
    /// before it tokenised: the lexer drops comments, so the run is still one run.
    #[test]
    fn a_comment_between_the_attributes_does_not_split_the_run() {
        assert_eq!(
            counted("#[test] /* reviewer gap */ #[ignore] fn a() {}"),
            (1, 1)
        );
    }

    /// A raw identifier renders as `r#ignore`, and comparing the rendering is how the fourth version
    /// of `check-suppressions` was still wrong.
    #[test]
    fn a_raw_identifier_is_read_as_the_identifier_it_spells() {
        assert_eq!(counted("#[test] #[r#ignore] fn a() {}"), (1, 1));
    }

    /// Tests live inside `mod tests { … }`, so the walk has to enter brace groups.
    #[test]
    fn a_test_inside_a_module_is_counted() {
        assert_eq!(
            counted("mod outer { mod inner { #[test] fn a() {} #[test] #[ignore] fn b() {} } }"),
            (2, 1)
        );
    }

    /// A file with no tests at all — a binary that has none yet — is vacuously wholly ignored, and
    /// gains cover the moment it grows one.
    #[test]
    fn a_source_with_no_tests_is_vacuously_covered() {
        assert_eq!(counted("fn main() { println!(\"hello\"); }"), (0, 0));
    }

    /// A target flag names a target; a `-p` with no target flag covers the whole package. Both are
    /// read off the real script's shapes, including the invocation written across two lines.
    #[test]
    fn the_script_is_read_for_both_shapes_of_coverage() {
        let runs = covered(
            r#"
  check "test core, default" cargo test -p certimining-core
  check "test client" cargo test -p certimining-client --test fetch --test schedule
  check "address vector" cargo test -p certimining-client --test program_addresses
  check "confirm-anchor-b" cargo test -p certimining-client --features ots --bin confirm-anchor-b
  check "property counts" \
    env PROPTEST_CASES=10000 cargo test -p certimining-core --test state_props p02 -- --exact
  # check "commented out" cargo test -p certimining-log --test batcher
"#,
        );
        assert!(
            runs.wholesale.contains("certimining-core"),
            "a -p with no target flag"
        );
        assert!(
            !runs.wholesale.contains("certimining-client"),
            "a -p with target flags covers those targets and not the package"
        );
        assert!(runs.named.contains("fetch") && runs.named.contains("schedule"));
        assert!(runs.named.contains("program_addresses"));
        assert!(
            runs.named.contains("confirm-anchor-b"),
            "a --bin target counts"
        );
        assert!(
            runs.named.contains("state_props"),
            "the continued line is read whole"
        );
        assert!(
            !runs.named.contains("batcher"),
            "a commented-out invocation runs nothing"
        );
    }
}
