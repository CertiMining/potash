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
//! **A library target is covered per feature set, which is H-63 (issue #240).** This read only
//! `test` and `bin` kinds, so a `lib` — where the `#[cfg(test)] mod tests` of every crate lives —
//! was outside what it inspected, and `certimining-client`'s seventy-three unit tests reached no
//! group at all: the whole of `bitcoin.rs`, including the proof-of-work floor of H-57 and the
//! canonical-difficulty check of H-59. The remedies for filed defects were sitting in a target CI
//! did not name, and the gate written to find exactly that could not see them.
//!
//! The feature dimension is the part that needed deciding. A library is not one body of code:
//! `#[cfg(feature = "ots")] pub mod bitcoin;` compiles forty more tests, so "the lib target is run"
//! is not a yes or a no. A gate satisfied by the `--features ots` line would call that package
//! covered while the build a plain `cargo test` produces went unrun; one satisfied by a plain run
//! would call it covered while `bitcoin.rs` did. So **each feature set carrying live tests has to be
//! named by a run that enables it, and the default build by a run that adds no features**, and the
//! gate prints the sets it requires whether it passes or fails.
//!
//! Which sets those are is read from the module tree, not declared here: the walk follows `mod`
//! declarations from the library root and carries each `#[cfg(feature = "…")]` down, so a feature
//! added tomorrow is demanded tomorrow. A `cfg` operator it cannot reduce to "these features must be
//! on" — `any(…)`, `not(…)` — is refused rather than guessed at, and a `mod` that resolves to no
//! file is reported rather than skipped, because a walk that stops early under-counts and
//! under-counting is the direction that lets a gate pass.
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
//!
//! **A test written in shell is not a cargo target, which is H-96 (issue #301).** Enumeration from
//! `cargo metadata` is what makes the sweep above complete, and it is also the reason this gate
//! could not see `scripts/release-qualify-test.sh` — 132 lines holding `release-qualify.sh`'s
//! fail-closed boundary in place, run by nothing from the day it was committed. That is the third
//! kind of test this gate has been blind to: `--bin` targets were outside it until H-62, `lib`
//! targets until H-63, and a shell script is outside `cargo metadata` altogether rather than by
//! oversight.
//!
//! So there is a second enumeration, from the filesystem, and it demands by **convention**: a script
//! under `scripts/` whose name ends `-test.sh` is a test, and some line of `scripts/ci.sh` has to
//! name it. The convention is what separates a test from the operational scripts beside it —
//! `deploy-devnet.sh`, `upgrade-devnet.sh`, `devnet-anchoring-cycle.sh`, `mainnet-bootstrap.sh`,
//! `cluster-fault-injection.sh`, `anchor-repo.sh`, `merge-ready.sh` and `release-qualify.sh` itself
//! write to clusters or produce releases, and requiring CI to run them would be wrong. A rule
//! separates them; an allowlist of their names would have to be maintained and would go stale.
//!
//! **The limit, stated rather than left to be discovered.** A test in shell that does not follow the
//! convention escapes the demand, exactly as a cargo target outside `cargo metadata` would. The gate
//! therefore also prints every `scripts/*.sh` that no `ci.sh` line names, as information and not as a
//! verdict, so a misnamed test is visible to a reader even where it is not failed on.
//!

/// Every shell script under `scripts/`, by basename, sorted.
///
/// From the filesystem because there is no manifest to ask: `cargo metadata` knows nothing about
/// these. A read error is a panic rather than an empty list, for the reason H-78 records — a gate
/// that treats a failed observation as an absence reports the value its own failure produces.
fn shell_scripts(root: &Path) -> Vec<String> {
    let dir = root.join("scripts");
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) => panic!("{}: {e}", dir.display()),
    };
    let mut out = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => panic!("{}: {e}", dir.display()),
        };
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(".sh") {
            out.push(name);
        }
    }
    out.sort();
    out
}

/// Whether some line of `scripts/ci.sh` names this script **in a position that runs it**.
///
/// **Comments are stripped first, and that is the whole substance of this function.** The first
/// version searched the file's text, and the comment block introducing the new `checks` line — which
/// explains the fix by naming `release-qualify.sh` in prose — was enough to make the gate call that
/// script named. So a comment mentioning `release-qualify-test.sh` would have satisfied the demand
/// below while nothing ran it: this gate would have been the thing it was written to catch, an
/// instrument whose failed observation maps onto the value its predicate rewards.
///
/// A line whose first non-whitespace character is `#` is a comment and contributes nothing. On every
/// other line, text from the first ` #` onward is dropped as a trailing comment. That heuristic can
/// over-strip — a `#` inside a quoted string ends the line early — and over-stripping can only
/// withhold a match, which fails the demand. Under-stripping is what lets prose satisfy a gate, so
/// the error is taken in the direction that complains.
///
/// Substring rather than word match, which the basenames in use make unambiguous: no script's name
/// is a substring of another's, since `release-qualify-test.sh` does not contain the string
/// `release-qualify.sh` — the character after `qualify` is a hyphen, not a dot.
fn named_in_ci(script_text: &str, basename: &str) -> bool {
    script_text.lines().any(|line| {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            return false;
        }
        let code = match trimmed.find(" #") {
            Some(at) => trimmed.get(..at).unwrap_or(""),
            None => trimmed,
        };
        code.contains(basename)
    })
}

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// One test or bin target, as cargo reports it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Target {
    package: String,
    kind: String,
    name: String,
    src: String,
}

/// Every `test`, `bin` and `lib` target of every workspace member.
///
/// **`lib` was missing and that is H-63 (issue #240).** A `lib` target carries unit tests too — the
/// `#[cfg(test)] mod tests` inside `src/` — and this enumerated only `test` and `bin`, so it could
/// not report a library nobody runs. It found two unreached targets and said nothing about
/// `certimining-client`'s library, whose sixty-nine unit tests no group ran: the whole of
/// `bitcoin.rs`, including the proof-of-work floor of H-57 and the canonical-difficulty check of
/// H-59. The gate's own wording was scoped honestly, so it did not overclaim; it was incomplete.
///
/// `test = false` in a `[lib]` block means cargo builds no test harness for it, so there is nothing
/// to run and nothing to require.
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
                // `lib`, `rlib` and `proc-macro` all name the one library target; cargo reports the
                // crate types, so the kind is matched on what it means rather than on one spelling.
                let is_lib = matches!(kind, "lib" | "rlib" | "proc-macro");
                let harness = target["test"].as_bool().unwrap_or(true);
                if is_lib && !harness {
                    continue;
                }
                if kind == "test" || kind == "bin" || is_lib {
                    found.push(Target {
                        package: package.clone(),
                        kind: if is_lib {
                            "lib".to_string()
                        } else {
                            kind.to_string()
                        },
                        name: name.clone(),
                        src: src.clone(),
                    });
                }
            }
        }
    }
    found.sort();
    // A library with several crate types — `certimining-checkpoint` is `cdylib` and `lib` — is
    // reported once per type and is one target.
    found.dedup();
    found
}

/// What `scripts/ci.sh` runs: packages tested wholesale, and targets named by flag.
#[derive(Debug, Default)]
struct Covered {
    wholesale: BTreeSet<String>,
    named: BTreeSet<String>,
    /// Every invocation, kept whole because a library's coverage is a question about **which feature
    /// set** ran it, which the two sets above cannot answer (H-63, issue #240).
    invocations: Vec<Invocation>,
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
        let mut call = Invocation::default();
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
                "--lib" => {
                    call.lib = true;
                    i += 1;
                }
                "--all-features" => {
                    call.all_features = true;
                    i += 1;
                }
                "--features" => {
                    if let Some(list) = words.get(i + 1) {
                        for f in list.trim_matches('"').split(&[',', ' '][..]) {
                            if !f.is_empty() {
                                call.features.insert(f.to_string());
                            }
                        }
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
        if names.is_empty() && !call.lib {
            for p in &packages {
                out.wholesale.insert(p.clone());
            }
            call.every_target = true;
        }
        call.packages = packages;
        out.invocations.push(call);
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

/// Whether an attribute run marks a `#[test]`, and whether that test also carries `#[ignore]`.
///
/// **The attribute's own name, not an identifier anywhere inside it (H-63, issue #240).** Reading
/// idents at depth was right for `#[ignore]` and wrong for `#[test]`: `#[cfg(test)]` contains the
/// ident `test` and marks no test at all — it is the gate on the module every unit test lives in. So
/// a depth read counted one phantom test per `#[cfg(test)] mod tests`, which is once per source file
/// in a library. It reported 38 live tests in `certimining-client`'s default build where `cargo test
/// --lib` runs 33, and one apiece in `certimining-core` and `certimining-log`, which have none.
///
/// It never made this gate pass when it should have failed — an inflated count only moves a target
/// away from the "wholly #[ignore]d" condition — but a figure printed beside a demand is a figure a
/// reader will check.
///
/// `#[ignore]` is still read at depth, because `#[cfg_attr(miri, ignore = "…")]` is how this
/// repository ignores a test under Miri and that has to keep counting as one.
fn marks(attrs: &[TokenStream]) -> (bool, bool) {
    let mut is_test = false;
    let mut is_ignore = false;
    for attr in attrs {
        let name = attr.clone().into_iter().find_map(|tree| match tree {
            TokenTree::Ident(id) => {
                let text = id.to_string();
                Some(text.strip_prefix("r#").unwrap_or(&text).to_string())
            }
            _ => None,
        });
        match name.as_deref() {
            Some("test") => is_test = true,
            Some("ignore") => is_ignore = true,
            Some("cfg_attr") => {
                let mut deep = BTreeSet::new();
                idents(attr.clone(), &mut deep);
                if deep.contains("ignore") {
                    is_ignore = true;
                }
            }
            _ => {}
        }
    }
    (is_test, is_ignore)
}

/// Counts the `#[test]` functions in a source, and how many of them also carry `#[ignore]`.
fn count(stream: TokenStream, tests: &mut usize, ignored: &mut usize) {
    let trees: Vec<TokenTree> = stream.into_iter().collect();
    let mut i = 0;
    while i < trees.len() {
        // An attribute run: consecutive `#[…]` or `#![…]` groups, which belong to one item.
        if matches!(&trees[i], TokenTree::Punct(p) if p.as_char() == '#') {
            let mut attrs = Vec::new();
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
                        attrs.push(g.stream());
                        j = k + 1;
                    }
                    _ => break,
                }
            }
            if j > i {
                let (is_test, is_ignore) = marks(&attrs);
                if is_test {
                    *tests += 1;
                    if is_ignore {
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

// ------------------------------------------------------- H-63 (issue #240): the library targets

/// Where a module's external submodules live.
///
/// Rust's rule: `lib.rs`, `main.rs` and any `mod.rs` own the directory they sit in, and every other
/// file owns a directory named after itself. Getting this wrong would stop the walk early, and a walk
/// that stops early reports fewer tests than exist — the direction that makes a gate pass when it
/// should not. A `mod` that resolves to no file is reported rather than skipped for the same reason.
fn module_dir(src: &Path) -> PathBuf {
    let parent = src.parent().unwrap_or(Path::new(".")).to_path_buf();
    match src.file_stem().and_then(|s| s.to_str()) {
        Some("lib") | Some("main") | Some("mod") => parent,
        Some(stem) => parent.join(stem),
        None => parent,
    }
}

/// The features a `#[cfg(…)]` attribute requires, or the operator this gate cannot read.
///
/// **It refuses rather than guesses.** `any(…)` and `not(…)` do not reduce to "these features must
/// be on": collecting their features would demand a CI run nothing needs, and dropping them would let
/// tests hide behind a cfg the gate had quietly ignored. Neither appears in this workspace, and if one
/// does this says so instead of being wrong in silence.
///
/// `#[cfg(test)]` carries no feature and `#[cfg_attr(…)]` is not a cfg, so both yield nothing.
fn cfg_features(stream: TokenStream) -> Result<BTreeSet<String>, String> {
    let trees: Vec<TokenTree> = stream.into_iter().collect();
    let mut out = BTreeSet::new();
    let Some(TokenTree::Ident(head)) = trees.first() else {
        return Ok(out);
    };
    if *head != "cfg" {
        return Ok(out);
    }
    let Some(TokenTree::Group(group)) = trees.get(1) else {
        return Ok(out);
    };
    collect_cfg(group.stream(), &mut out)?;
    Ok(out)
}

fn collect_cfg(stream: TokenStream, out: &mut BTreeSet<String>) -> Result<(), String> {
    let trees: Vec<TokenTree> = stream.into_iter().collect();
    let mut i = 0;
    while i < trees.len() {
        if let TokenTree::Ident(id) = &trees[i] {
            if *id == "any" || *id == "not" {
                return Err(id.to_string());
            }
            if *id == "all" {
                if let Some(TokenTree::Group(g)) = trees.get(i + 1) {
                    collect_cfg(g.stream(), out)?;
                    i += 2;
                    continue;
                }
            }
            if *id == "feature"
                && matches!(trees.get(i + 1), Some(TokenTree::Punct(p)) if p.as_char() == '=')
            {
                if let Some(TokenTree::Literal(lit)) = trees.get(i + 2) {
                    let text = lit.to_string();
                    out.insert(text.trim_matches('"').to_string());
                    i += 3;
                    continue;
                }
            }
        }
        i += 1;
    }
    Ok(())
}

/// What a library's `#[test]`s cost to compile: `(tests, ignored)` against the feature set needed.
///
/// The empty key is what a plain `cargo test` reaches; `{"ots"}` is what only `--features ots` does.
/// Keys combine, so a gated module inside a gated module needs both features.
#[derive(Default)]
struct LibTests {
    by_features: BTreeMap<BTreeSet<String>, (usize, usize)>,
    unreadable: Vec<String>,
}

fn lib_tests(src: &Path) -> LibTests {
    let mut found = LibTests::default();
    walk_file(src, &BTreeSet::new(), &mut found);
    found
}

fn walk_file(src: &Path, features: &BTreeSet<String>, found: &mut LibTests) {
    let text = match std::fs::read_to_string(src) {
        Ok(text) => text,
        Err(e) => {
            found.unreadable.push(format!("{}: {e}", src.display()));
            return;
        }
    };
    let stream: TokenStream = match text.parse() {
        Ok(stream) => stream,
        Err(e) => {
            found
                .unreadable
                .push(format!("{} does not tokenise: {e}", src.display()));
            return;
        }
    };
    let trees: Vec<TokenTree> = stream.into_iter().collect();
    let dir = module_dir(src);
    walk_items(&trees, features, &dir, src, found);
}

/// The same attribute-run reading `count` does, carrying the cfg features down the module tree.
fn walk_items(
    trees: &[TokenTree],
    features: &BTreeSet<String>,
    dir: &Path,
    owner: &Path,
    found: &mut LibTests,
) {
    let mut i = 0;
    while i < trees.len() {
        if matches!(trees.get(i), Some(TokenTree::Punct(p)) if p.as_char() == '#') {
            let mut attrs = Vec::new();
            let mut gated = features.clone();
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
                        attrs.push(g.stream());
                        match cfg_features(g.stream()) {
                            Ok(f) => gated.extend(f),
                            Err(which) => found.unreadable.push(format!(
                                "{}: cfg({which}(…)) is an operator this gate does not read",
                                owner.display()
                            )),
                        }
                        j = k + 1;
                    }
                    _ => break,
                }
            }
            if j > i {
                let (is_test, is_ignore) = marks(&attrs);
                if is_test {
                    let entry = found.by_features.entry(gated.clone()).or_insert((0, 0));
                    entry.0 = entry.0.saturating_add(1);
                    if is_ignore {
                        entry.1 = entry.1.saturating_add(1);
                    }
                }
                i = consume_item(trees, j, &gated, dir, owner, found);
                continue;
            }
        }
        i = consume_item(trees, i, features, dir, owner, found);
    }
}

/// Steps over one item, descending into it: a module by file, a module written inline, or any body.
///
/// **Visibility is skipped first, and leaving that out was a real defect.** The first version looked
/// for `mod` immediately after the attribute run, so `#[cfg(feature = "ots")] pub mod bitcoin;` fell
/// through the module branch entirely: the module was then walked with the *enclosing* feature set
/// and its thirty-six tests were counted as compiling by default. The gate reported 79 live tests
/// under `default features` where the build has 33, which is a gate reading more coverage into a
/// run than the run performs.
fn consume_item(
    trees: &[TokenTree],
    i: usize,
    features: &BTreeSet<String>,
    dir: &Path,
    owner: &Path,
    found: &mut LibTests,
) -> usize {
    // `pub`, `pub(crate)`, `pub(super)` — the keyword and an optional restriction in parentheses.
    let mut at = i;
    if matches!(trees.get(at), Some(TokenTree::Ident(id)) if *id == "pub") {
        at = at.saturating_add(1);
        if matches!(trees.get(at), Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Parenthesis)
        {
            at = at.saturating_add(1);
        }
    }
    if let (Some(TokenTree::Ident(keyword)), Some(TokenTree::Ident(name))) =
        (trees.get(at), trees.get(at + 1))
    {
        if *keyword == "mod" {
            match trees.get(at + 2) {
                Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Brace => {
                    let inner: Vec<TokenTree> = g.stream().into_iter().collect();
                    walk_items(&inner, features, dir, owner, found);
                    return at.saturating_add(3);
                }
                Some(TokenTree::Punct(p)) if p.as_char() == ';' => {
                    let rendered = name.to_string();
                    let name = rendered.strip_prefix("r#").unwrap_or(&rendered);
                    let flat = dir.join(format!("{name}.rs"));
                    let nested = dir.join(name).join("mod.rs");
                    if flat.is_file() {
                        walk_file(&flat, features, found);
                    } else if nested.is_file() {
                        walk_file(&nested, features, found);
                    } else {
                        found.unreadable.push(format!(
                            "{}: `mod {name};` resolves to neither {} nor {}",
                            owner.display(),
                            flat.display(),
                            nested.display()
                        ));
                    }
                    return at.saturating_add(3);
                }
                _ => {}
            }
        }
    }
    if let Some(TokenTree::Group(g)) = trees.get(i) {
        if g.delimiter() == Delimiter::Brace {
            let inner: Vec<TokenTree> = g.stream().into_iter().collect();
            walk_items(&inner, features, dir, owner, found);
        }
    }
    i.saturating_add(1)
}

/// One `cargo test` invocation, as far as a library's coverage needs to read it.
#[derive(Debug, Clone, Default)]
struct Invocation {
    packages: Vec<String>,
    /// No `--test`, `--bin` or `--lib` flag, so every target of the package runs.
    every_target: bool,
    lib: bool,
    features: BTreeSet<String>,
    all_features: bool,
}

impl Invocation {
    fn runs_lib_of(&self, package: &str) -> bool {
        self.packages.iter().any(|p| p == package) && (self.every_target || self.lib)
    }

    fn enables(&self, wanted: &BTreeSet<String>) -> bool {
        self.all_features || wanted.iter().all(|f| self.features.contains(f))
    }

    /// Adds no features, which is the build a plain `cargo test` produces.
    fn baseline(&self) -> bool {
        !self.all_features && self.features.is_empty()
    }
}

/// How a feature set reads in a message: the empty one is the default build.
fn feature_label(features: &BTreeSet<String>) -> String {
    if features.is_empty() {
        "default features".to_string()
    } else {
        format!(
            "--features {}",
            features.iter().cloned().collect::<Vec<_>>().join(",")
        )
    }
}

/// What a library's coverage requires, and which of those requirements `scripts/ci.sh` does not meet.
#[derive(Debug, Default, PartialEq, Eq)]
struct LibCoverage {
    /// One entry per feature set that compiles live tests, for the gate to state.
    required: Vec<String>,
    problems: Vec<String>,
}

/// **A library is covered per feature set, not once (H-63, issue #240).** Its unit tests are not one
/// body of code: `#[cfg(feature = "ots")] pub mod bitcoin;` compiles forty more of them, so "the lib
/// target is run" is not a yes or a no. A gate satisfied by the `--features ots` line would call
/// `certimining-client` covered while the build a plain `cargo test` produces went unrun, and one
/// satisfied by a plain run would call it covered while `bitcoin.rs` did.
///
/// So each feature set carrying live tests has to be named by a run that enables it, and the default
/// build has to be named by a run that adds no features at all.
fn lib_coverage(target: &Target, found: &LibTests, runs: &Covered, root: &Path) -> LibCoverage {
    let mut out = LibCoverage::default();
    for why in &found.unreadable {
        out.problems.push(format!(
            "  lib {} — this gate could not read its module tree, so it cannot say what runs it: \
             {why}",
            target.name
        ));
    }
    let rel = target
        .src
        .strip_prefix(&format!("{}/", root.display()))
        .unwrap_or(&target.src);
    for (features, (tests, ignored)) in &found.by_features {
        // Every test ignored is the same answer condition 3 gives a test target: nothing to run.
        if tests == ignored {
            continue;
        }
        let live = tests.saturating_sub(*ignored);
        let label = feature_label(features);
        out.required.push(format!("{label} ({live})"));
        let satisfied = runs.invocations.iter().any(|call| {
            call.runs_lib_of(&target.package)
                && if features.is_empty() {
                    call.baseline()
                } else {
                    call.enables(features)
                }
        });
        if !satisfied {
            out.problems.push(format!(
                "  lib {} ({rel}) — {live} live test(s) compile under `{label}` and no cargo test \
                 line in scripts/ci.sh runs that library at that feature set",
                target.name
            ));
        }
    }
    out
}

pub fn check_test_targets(root: &Path) {
    let script = std::fs::read_to_string(root.join("scripts/ci.sh")).expect("scripts/ci.sh");
    let runs = covered(&script);
    let all = targets(root);

    let mut problems = Vec::new();
    let mut by_name = 0usize;
    let mut by_package = 0usize;
    let mut by_ignore = 0usize;
    // Library targets are a different question — which **feature set** ran them — and are below.
    let mut libs = Vec::new();
    for target in &all {
        if target.kind == "lib" {
            libs.push(target);
            continue;
        }
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

    // **A library is covered per feature set, not once (H-63, issue #240).** Its unit tests are not
    // one body of code: `#[cfg(feature = "ots")] pub mod bitcoin;` compiles thirty-six more of them,
    // so "the lib target is run" is not yes or no. A gate satisfied by the `--features ots` line
    // would call `certimining-client` covered while the build a plain `cargo test` produces went
    // unrun, and a gate satisfied by a plain run would call it covered while `bitcoin.rs` did.
    //
    // So each feature set that compiles tests of its own has to be named by a run that enables it,
    // and the default build has to be named by a run that adds no features at all.
    let mut required: Vec<(String, Vec<String>)> = Vec::new();
    let mut lib_sets = 0usize;
    for target in &libs {
        let found = lib_tests(Path::new(&target.src));
        let coverage = lib_coverage(target, &found, &runs, root);
        lib_sets = lib_sets.saturating_add(coverage.required.len());
        if !coverage.required.is_empty() {
            required.push((target.package.clone(), coverage.required));
        }
        problems.extend(coverage.problems);
    }

    // **Stated before anything is judged.** A library's coverage depends on which feature sets carry
    // tests, and that is the part a reader cannot check by looking at `ci.sh` alone — so it is
    // printed whether the gate passes or fails, and a failure can be read against it.
    for (package, sets) in &required {
        println!(
            "test-targets: {package}'s library needs a run at {} — live test counts in brackets",
            sets.join(" and ")
        );
    }

    // **The second enumeration: tests written in shell (H-96, issue #301).** `cargo metadata` cannot
    // see these, which is why `release-qualify-test.sh` was run by nothing from the day it was
    // committed. The demand is by convention — a name ending `-test.sh` is a test — so that the
    // operational scripts beside it are separated by a rule rather than by a list that would go
    // stale.
    let scripts = shell_scripts(root);
    let mut shell_run = 0usize;
    let mut shell_unnamed = Vec::new();
    for name in &scripts {
        let named = named_in_ci(&script, name);
        if name.ends_with("-test.sh") {
            if named {
                shell_run = shell_run.saturating_add(1);
            } else {
                problems.push(format!(
                    "  shell test scripts/{name} — its name ends -test.sh, so it is a test, and no \
                     line of scripts/ci.sh names it"
                ));
            }
        } else if !named {
            shell_unnamed.push(name.clone());
        }
    }

    // **Information, not a verdict.** These are the scripts no CI line names and the convention does
    // not claim are tests: they deploy, upgrade, operate a cluster or cut a release, and CI running
    // them would be wrong. Printed so that a test misnamed out of the demand above is still visible
    // to a reader, which is the one way this rule can be wrong.
    if !shell_unnamed.is_empty() {
        println!(
            "test-targets: {} shell script(s) under scripts/ are named by no ci.sh line and are not \
             tests by the -test.sh convention — {}. If one of these is a test, it is outside the \
             demand above and should be renamed.",
            shell_unnamed.len(),
            shell_unnamed.join(", ")
        );
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
             every #[test] in it carrying #[ignore]. A library reaches one per feature set: a run \
             with no --features for the default build, and a run enabling each feature that gates \
             tests of its own. A test nobody runs is the same thing as no test."
        );
        std::process::exit(1);
    }

    println!(
        "test-targets: {} test, bin and lib target(s) across {} package(s), all run — {} named in \
         scripts/ci.sh, {} by their package being run wholesale, {} wholly #[ignore]d, and {} \
         library feature set(s). Plus {} shell test(s) under scripts/, each named by a ci.sh line \
         (H-96).",
        all.len(),
        all.iter()
            .map(|t| &t.package)
            .collect::<BTreeSet<_>>()
            .len(),
        by_name,
        by_package,
        by_ignore,
        lib_sets,
        shell_run
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

    // ------------------------------------------------- H-63 (issue #240): the library targets

    /// **`#[cfg(test)]` is not a test**, and reading idents at depth said it was. That attribute
    /// gates the module every unit test lives in, so a depth read scored one phantom test per source
    /// file — 38 where the build runs 33, and one apiece in two libraries that have none.
    #[test]
    fn cfg_test_is_not_a_test() {
        assert_eq!(
            counted("#[cfg(test)] mod tests { #[test] fn a() {} }"),
            (1, 0),
            "the module gate is not a test; the function inside it is"
        );
        assert_eq!(
            counted("#[cfg(test)] mod tests { fn helper() {} }"),
            (0, 0),
            "a module of helpers holds no tests"
        );
    }

    /// And the depth read that was right stays right: this is how the suite ignores under Miri.
    #[test]
    fn cfg_attr_miri_ignore_still_reads_as_ignored() {
        assert_eq!(
            counted(r#"#[test] #[cfg_attr(miri, ignore = "too slow")] fn a() {}"#),
            (1, 1)
        );
    }

    fn features_of(attr: &str) -> Result<BTreeSet<String>, String> {
        let stream: TokenStream = attr.parse().expect("tokenises");
        cfg_features(stream)
    }

    #[test]
    fn a_cfg_names_the_features_it_requires() {
        assert_eq!(
            features_of(r#"cfg(feature = "ots")"#),
            Ok(BTreeSet::from(["ots".to_string()]))
        );
        assert_eq!(
            features_of(r#"cfg(all(feature = "ots", feature = "cluster"))"#),
            Ok(BTreeSet::from(["cluster".to_string(), "ots".to_string()])),
            "all() requires both"
        );
        assert_eq!(features_of("cfg(test)"), Ok(BTreeSet::new()), "no feature");
        assert_eq!(
            features_of(r#"cfg_attr(miri, ignore = "slow")"#),
            Ok(BTreeSet::new()),
            "cfg_attr is not a cfg"
        );
    }

    /// **Refused rather than guessed.** `any(…)` does not reduce to "these features must be on":
    /// demanding them would ask for a run nothing needs, and dropping them would let tests hide
    /// behind a cfg the gate had quietly ignored.
    #[test]
    fn a_cfg_operator_this_gate_cannot_read_is_refused() {
        assert_eq!(
            features_of(r#"cfg(any(feature = "a", feature = "b"))"#),
            Err("any".to_string())
        );
        assert_eq!(
            features_of(r#"cfg(not(feature = "a"))"#),
            Err("not".to_string())
        );
    }

    /// Rust's own rule. A wrong answer here stops the walk early, and a walk that stops early reports
    /// fewer tests than exist — the direction that makes a gate pass when it should not.
    #[test]
    fn module_dir_follows_rusts_own_rule() {
        assert_eq!(module_dir(Path::new("/w/src/lib.rs")), Path::new("/w/src"));
        assert_eq!(
            module_dir(Path::new("/w/src/a/mod.rs")),
            Path::new("/w/src/a")
        );
        assert_eq!(
            module_dir(Path::new("/w/src/anchor.rs")),
            Path::new("/w/src/anchor"),
            "a plain file owns a directory named after itself"
        );
    }

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("certimining-h63-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        dir
    }

    /// **The defect this walk shipped with for one run.** The first version looked for `mod`
    /// immediately after the attribute, so `#[cfg(feature = "ots")] pub mod bitcoin;` missed the
    /// module branch: the module was walked with the *enclosing* feature set and its tests were
    /// counted as compiling by default.
    #[test]
    fn visibility_between_the_attribute_and_the_mod_does_not_lose_the_gate() {
        let dir = scratch("visibility");
        std::fs::write(
            dir.join("lib.rs"),
            "#[cfg(feature = \"ots\")]\npub mod gated;\nmod plain;\n",
        )
        .expect("write");
        std::fs::write(
            dir.join("gated.rs"),
            "#[test] fn a() {}\n#[test] fn b() {}\n",
        )
        .expect("write");
        std::fs::write(dir.join("plain.rs"), "#[test] fn c() {}\n").expect("write");

        let found = lib_tests(&dir.join("lib.rs"));
        assert!(found.unreadable.is_empty(), "{:?}", found.unreadable);
        assert_eq!(
            found.by_features.get(&BTreeSet::new()),
            Some(&(1usize, 0usize)),
            "only the ungated module compiles by default"
        );
        assert_eq!(
            found.by_features.get(&BTreeSet::from(["ots".to_string()])),
            Some(&(2usize, 0usize)),
            "the gated module's tests belong to its feature"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A module that resolves to no file is reported, never skipped: skipping would under-count.
    #[test]
    fn a_module_resolving_to_no_file_is_reported() {
        let dir = scratch("missing");
        std::fs::write(dir.join("lib.rs"), "mod absent;\n").expect("write");
        let found = lib_tests(&dir.join("lib.rs"));
        assert_eq!(found.unreadable.len(), 1, "{:?}", found.unreadable);
        assert!(found.unreadable[0].contains("absent"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **`--lib` is not a wholesale package run, and reading it as one weakened the gate.** When the
    /// `client lib` line landed, `covered` saw a `cargo test -p certimining-client` carrying no
    /// `--test` or `--bin` flag and recorded the whole package as run wholesale — so every test and
    /// bin target in it counted as covered by a line that runs only the library. Seven targets were
    /// being credited to it.
    #[test]
    fn a_lib_flag_is_not_a_wholesale_package_run() {
        let runs = covered("  check \"x\" cargo test -p certimining-client --features ots --lib\n");
        assert!(
            !runs.wholesale.contains("certimining-client"),
            "a --lib run covers the library and nothing else"
        );
        let call = &runs.invocations[0];
        assert!(call.lib && !call.every_target);
        assert!(call.runs_lib_of("certimining-client"));
        assert!(call.enables(&BTreeSet::from(["ots".to_string()])));
        assert!(!call.baseline(), "it adds a feature");
    }

    #[test]
    fn a_bare_package_run_is_wholesale_and_is_the_baseline() {
        let runs = covered("  check \"x\" cargo test -p certimining-core\n");
        assert!(runs.wholesale.contains("certimining-core"));
        let call = &runs.invocations[0];
        assert!(call.every_target && call.baseline());
        assert!(call.runs_lib_of("certimining-core"));
        assert!(
            !call.enables(&BTreeSet::from(["solana".to_string()])),
            "a bare run enables no named feature"
        );
    }

    #[test]
    fn all_features_enables_every_set() {
        let runs = covered("  check \"x\" cargo test -p certimining-core --all-features\n");
        let call = &runs.invocations[0];
        assert!(call.enables(&BTreeSet::from(["solana".to_string()])));
        assert!(!call.baseline(), "--all-features is not the default build");
    }

    /// **The acceptance condition issue #240 names.** It asserts the gate *fails* when the line is
    /// removed, rather than asserting it passes on a tree where the line is present — a gate that
    /// only ever passes is the defect this repository keeps filing. Both halves run against the
    /// committed `scripts/ci.sh` and the committed library, not a fixture.
    #[test]
    fn removing_the_default_feature_line_makes_the_gate_name_the_library() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask sits beside the workspace root");
        let script = std::fs::read_to_string(root.join("scripts/ci.sh")).expect("scripts/ci.sh");
        let src = root.join("crates/certimining-client/src/lib.rs");
        let target = Target {
            package: "certimining-client".to_string(),
            kind: "lib".to_string(),
            name: "certimining_client".to_string(),
            src: src.display().to_string(),
        };
        let found = lib_tests(&src);
        assert!(found.unreadable.is_empty(), "{:?}", found.unreadable);

        let whole = lib_coverage(&target, &found, &covered(&script), root);
        assert!(
            whole.problems.is_empty(),
            "as committed, both feature sets are named: {:?}",
            whole.problems
        );
        assert_eq!(
            whole.required.len(),
            2,
            "the default build and --features ots: {:?}",
            whole.required
        );

        let without: String = script
            .lines()
            .filter(|line| !line.contains("cargo test -p certimining-client --lib"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_ne!(without, script, "the line this removes must exist");
        let gap = lib_coverage(&target, &found, &covered(&without), root);
        assert_eq!(
            gap.problems.len(),
            1,
            "exactly the default build goes unrun: {:?}",
            gap.problems
        );
        assert!(
            gap.problems[0].contains("default features"),
            "{}",
            gap.problems[0]
        );
        assert!(
            !gap.problems[0].contains("--features ots"),
            "the ots line still covers its own set: {}",
            gap.problems[0]
        );
    }

    /// **The defect this gate shipped with for one run, and the reason `named_in_ci` strips
    /// comments.** The first version searched `ci.sh`'s text. The comment block introducing the new
    /// `checks` line names `release-qualify.sh` in prose while explaining the fix, and that alone was
    /// enough to make the gate report the script as named. A comment naming a `-test.sh` script would
    /// therefore have satisfied the demand with nothing running it — this gate would have become the
    /// thing it exists to catch.
    #[test]
    fn a_comment_naming_a_script_does_not_make_it_run() {
        let script = "# check \"release qualification\" bash scripts/release-qualify-test.sh\n";
        assert!(
            !named_in_ci(script, "release-qualify-test.sh"),
            "a commented-out line runs nothing"
        );
    }

    /// The same in its trailing form, which is the one that reads like working code.
    #[test]
    fn a_trailing_comment_naming_a_script_does_not_make_it_run() {
        let script = "  check \"formatting\" cargo fmt --check # unlike scripts/foo-test.sh\n";
        assert!(
            !named_in_ci(script, "foo-test.sh"),
            "the name appears only after the comment marker"
        );
    }

    /// And the positive case, so the two above are not passing because nothing ever matches.
    #[test]
    fn a_check_line_naming_a_script_makes_it_run() {
        let script = "  check \"release qualification controls\" bash scripts/foo-test.sh\n";
        assert!(named_in_ci(script, "foo-test.sh"));
    }

    /// **Against the committed files rather than a fixture**, for the reason the H-63 test beside it
    /// gives: the claim is about this repository's `ci.sh`, and a fixture would only restate the
    /// function. Deleting the `checks` line fails here as well as in the gate.
    #[test]
    fn the_committed_ci_script_runs_every_committed_shell_test() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("the workspace root is xtask's parent")
            .to_path_buf();
        let script = std::fs::read_to_string(root.join("scripts/ci.sh")).expect("scripts/ci.sh");
        let scripts = shell_scripts(&root);
        assert!(
            scripts.iter().any(|n| n == "release-qualify-test.sh"),
            "the enumeration must see the one shell test there is: {scripts:?}"
        );
        for name in scripts.iter().filter(|n| n.ends_with("-test.sh")) {
            assert!(
                named_in_ci(&script, name),
                "scripts/{name} is a test by the -test.sh convention and no ci.sh line runs it"
            );
        }
    }

    /// The operational scripts must stay outside the demand. This pins the separation as a rule, so
    /// that a future `deploy-devnet.sh` rename into `-test.sh` is a deliberate act and not a drift.
    #[test]
    fn the_operational_scripts_are_not_demanded_to_run_in_ci() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("the workspace root is xtask's parent")
            .to_path_buf();
        let scripts = shell_scripts(&root);
        for name in [
            "deploy-devnet.sh",
            "upgrade-devnet.sh",
            "devnet-anchoring-cycle.sh",
            "mainnet-bootstrap.sh",
            "cluster-fault-injection.sh",
            "release-qualify.sh",
        ] {
            assert!(
                scripts.iter().any(|n| n == name),
                "scripts/{name} is expected to exist"
            );
            assert!(
                !name.ends_with("-test.sh"),
                "scripts/{name} writes to a cluster or cuts a release and must not be demanded of CI"
            );
        }
    }
}
