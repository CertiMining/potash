// SPDX-License-Identifier: MIT OR Apache-2.0
//! Status statements about the worker and the regression band, against what the code does (#254).
//!
//! **What happened.** Nine sentences across eight files said the OpenTimestamps worker did not exist,
//! or that `bench-band` reported drift `without failing on it`. Each was true when written and false
//! 23 October 2026: `anchor-b-worker` was committed on 20 October, `batcher-handoff` on 22 October,
//! and H-47 restored the band's failure on the same day. They were found by reading files one at a
//! time, which is why five survived the first pass — `README.md` denied the worker on a head where
//! `docs/DECISIONS.md` already recorded that denial as superseded, and `benches/src/lib.rs` held the
//! band's old behaviour four files away from three that had just been corrected.
//!
//! **Why no existing gate reaches it.** `scripts/claim-check.sh` greps for §4.6's banned phrasings and
//! for concept nouns against an allowlist; a status sentence is neither. `xtask check-citations` pins a
//! document against the specification text it cites, and these sentences cite a *decision* — D-117,
//! H-47 — rather than an invariant. D-117's own amendment spelled out the contradiction in
//! `docs/DECISIONS.md` for nine days while `README.md` kept the sentence it contradicted, because
//! nothing compared the two.
//!
//! **What this is.** A list of constructions that were true before a dated head and are false after
//! it. Every occurrence must be recorded below with the reason it is still correct — a changelog entry
//! describing its own version, or a decision recording what a sentence used to say. An exemption
//! matching nothing fails as well: a record nobody re-checks is how the next one rots, which
//! `check-suppressions` was already written to catch in its own domain.
//!
//! **What it does not do, said rather than discovered.** It cannot tell whether a *new* sentence is
//! true. It says that nine known-false constructions do not come back, which is the whole of its
//! claim. It also skips its own source, because the list has to be written somewhere and a needle
//! quoted in the list is indistinguishable from a needle used in prose.
//!
//! An exemption covers *every* occurrence of its needle in its file, so a second sentence added to an
//! exempted file is covered without being read. Both exempted files are the decision record and the
//! specification's changelog, where an entry describes the version that made it and nothing current is
//! asserted; a reader-facing status sentence does not belong in either, and `check-citations` already
//! holds the specification's cited text to its digest.

use std::path::Path;

/// A construction that was true before a dated head and is false after it.
struct Stale {
    /// Matched case-insensitively, so the list is written in lower case.
    needle: &'static str,
    /// What made it false. Printed with the offending line.
    why: &'static str,
}

const STALE: [Stale; 9] = [
    Stale {
        needle: "no worker exists",
        why: "anchor-b-worker was committed on 20 Oct 2026 (D-117's amendment, H-13)",
    },
    Stale {
        needle: "no opentimestamps worker",
        why: "anchor-b-worker was committed on 20 Oct 2026 (D-117's amendment, H-13)",
    },
    Stale {
        needle: "worker does not exist",
        why: "anchor-b-worker was committed on 20 Oct 2026 (D-117's amendment, H-13)",
    },
    Stale {
        needle: "cannot fail at all",
        why: "a class is compared against a baseline taken on it since H-61, so a faster class fails on regression",
    },
    Stale {
        needle: "cannot fail the comparison",
        why: "a class is compared against a baseline taken on it since H-61, so a faster class fails on regression",
    },
    Stale {
        needle: "does not fail on it",
        why: "bench-band fails on drift past its band since H-47, 22 Oct 2026",
    },
    Stale {
        needle: "without failing on it",
        why: "bench-band fails on drift past its band since H-47, 22 Oct 2026",
    },
    Stale {
        needle: "is report-only",
        why: "bench-band fails on drift past its band since H-47, 22 Oct 2026",
    },
    Stale {
        needle: "regression gate exists",
        why: "D-144 took bench-band out of all and out of ci.yml on 1 Nov 2026, so CI gates no wall-clock measure; §4.4a records it",
    },
];

/// **A fixture in this module may not spell a needle bare (H-87).** The gate reads its own source
/// outside the two lists, so a test string stating a needle is a statement in a scanned file. Tests
/// needing a bare needle build it with `concat!`, which costs nothing at runtime and keeps the file
/// honest. That is the price of not excluding the whole file, and it is the cheaper side.
///
/// An occurrence that is correct where it stands.
///
/// **It records how many, because covering "every occurrence" fails open (H-79, #278).** The
/// exemption used to be keyed on path and needle alone, so a *new* false sentence added to an
/// exempt file inherited the exemption and the gate stayed green. A count turns the exemption into
/// a statement about a known text rather than a licence for that file.
struct Exempt {
    path: &'static str,
    needle: &'static str,
    /// The normalized sentence this records, which is what makes the exemption non-fungible.
    ///
    /// **It used to be a count, and a count is substitutable (H-102, issue #311).** An exemption
    /// named `(path, needle)` and how many bare occurrences it expected, so replacing an exempt
    /// historical occurrence with a live false one left the count intact and the gate green. Naming
    /// the sentence means a different occurrence is a different exemption, and editing the sentence
    /// retires the one that covered it — which is the review the exemption stands in for.
    sentence: &'static str,
    why: &'static str,
}

const EXEMPT: [Exempt; 4] = [
    Exempt {
        path: "docs/DECISIONS.md",
        needle: "no worker exists",
        sentence: "The sentence here read \"no worker exists\" and was true until that head",
        why: "D-117's amendment quotes the sentence it superseded. **This is the occurrence H-79 (#278) added the quotation-mark arm for**, and it is recorded here instead as of D-145: a quotation reviewed once and named, rather than any quotation skipped from its punctuation",
    },
    Exempt {
        path: "docs/DECISIONS.md",
        needle: "no worker exists",
        sentence: "present tense while the amendment below said no worker exists; the amendment was correct and this sentence was not",
        why: "D-117's amendment records the sentence it superseded, which is how it records the change",
    },
    Exempt {
        path: "docs/TCU-02_CertiMining_Anchored_Log_v0.1.md",
        needle: "does not fail on it",
        sentence: "it records and reports drift and does not fail on it, so no wall-clock regression gate exists",
        why: "the same v0.2.3 changelog entry as below, describing that version. **Invisible to this gate until H-102 (#311)**: the source wraps the phrase across a line break, so it appeared zero times in any single line and the prefilter never saw it — a live occurrence hidden by the defect, not a mutation",
    },
    Exempt {
        path: "docs/TCU-02_CertiMining_Anchored_Log_v0.1.md",
        needle: "regression gate exists",
        sentence: "fail on it, so no wall-clock regression gate exists until calibration restores the assertion",
        why: "the v0.2.3 changelog entry describes that version, where no gate existed; v0.2.12's entry and §4.4a carry the current account",
    },
];

/// This module's own path. Only the two lists above are skipped in it, not the whole file.
///
/// **Skipping the file hid anything written in it (H-78, #277).** The lists have to be written
/// somewhere and a needle quoted in a list is indistinguishable from a needle used in prose, which
/// is the whole of the reason; it is not a reason to stop reading the other three hundred lines. An
/// ordinary refactor that moved documentation into this file used to inherit the exclusion.
const OWN_PATH: &str = "xtask/src/status.rs";

/// Whether a line of this module's own source is inside one of the two lists, or its test module.
///
/// **The test module is excluded as of H-102 (issue #311), and narrowly.** The adversarial fixtures
/// that gate exists for have to contain the banned phrases — a test that a wrapped claim is caught
/// must write a wrapped claim — and a needle in a fixture is not a sentence a reader meets. This is
/// the same reasoning as the two lists above it, and the same limit: one block of one file, not the
/// file. H-78 (#277) is the cost of the broad version, where an ordinary refactor that moved
/// documentation into this file inherited the exclusion.
fn inside_a_list(path: &str, text: &str, number: usize) -> bool {
    if path != OWN_PATH {
        return false;
    }
    // Everything from `#[cfg(test)]` to the end of the file is fixtures.
    if let Some(tests_at) = text
        .lines()
        .position(|line| line.trim_start().starts_with("#[cfg(test)]"))
    {
        if number >= tests_at {
            return true;
        }
    }
    let mut depth = 0usize;
    for (at, line) in text.lines().enumerate() {
        if line.starts_with("const STALE:") || line.starts_with("const EXEMPT:") {
            depth = 1;
        } else if depth > 0 && line.starts_with("];") {
            if at == number {
                return true;
            }
            depth = 0;
        }
        if at == number {
            return depth > 0;
        }
    }
    false
}

/// Whether the match at `at` is delimited by a backtick on both sides.
///
/// **A needle named is not a needle used (H-79, #278).** A code span says "these characters" rather
/// than making a claim, so `` `no worker exists` `` in prose about the phrase is not an assertion
/// about the worker.
///
/// **It tests the two characters around the match, not a count on the line (H-87).** The first
/// version counted quotes before the match and called the needle named when the count was odd. A
/// Rust raw string opens with `r#"`, so that quote made the count even and a genuinely quoted needle
/// read as a bare claim — which is how a test added in #286 turned `main` red. A phrase delimited by
/// a character is delimited by it, and asking that directly has no parity to get wrong.
///
/// **The quotation-mark arm is gone (D-145, owner's ruling of 2 November 2026).** H-79 added it for
/// a real case: a sentence saying that `no worker exists` *became false* is true and should not be
/// condemned. But a delimiter cannot tell that sentence from one asserting `no worker exists` as the
/// current state, which is the same two characters doing the opposite job.
///
/// **Both phrases above are code spans, and that is this rule applied to the prose introducing it.**
/// When this module names a banned phrase it is talking about the characters, so it marks them as
/// characters. Quoting them instead would be making the claim, which is now exactly what the gate
/// says it is. The 1 November audit found that as M-01. A
/// quotation is now recorded as an exemption naming its sentence and its reason, which is a record
/// of a reviewed occurrence rather than a guess from punctuation. A backtick stays, because a code
/// span is about the characters by construction and has no second reading.
fn is_named_not_used(line: &str, at: usize, needle_len: usize) -> bool {
    let opened = line[..at].chars().next_back();
    let closed = line[at + needle_len..].chars().next();
    matches!((opened, closed), (Some('`'), Some('`')))
}

/// Every file a reader could meet: tracked, plus untracked and not ignored.
///
/// Both halves matter. A gate that sees only committed files cannot see the sentence arriving in the
/// working tree, which is the one case where telling somebody costs nothing — `claim-check.sh` found
/// that out on a brand-new README and the same reasoning applies here.
fn surface(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for args in [
        ["ls-files", "-z"].as_slice(),
        ["ls-files", "-z", "-o", "--exclude-standard"].as_slice(),
    ] {
        let git = std::process::Command::new("git")
            .args(args)
            .current_dir(root)
            .output()
            .expect("git ls-files");
        assert!(
            git.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&git.stderr)
        );
        out.extend(
            String::from_utf8(git.stdout)
                .expect("git ls-files is utf-8")
                .split('\0')
                .filter(|s| !s.is_empty())
                .map(str::to_string),
        );
    }
    out.sort();
    out.dedup();
    out
}

/// Whether an exemption covers this occurrence of `needle` in `path`.
///
/// Matched on the sentence the occurrence sits in, not on the file it sits in. A substring match
/// rather than equality, so the recorded sentence may be the clause a reader would quote rather than
/// the whole paragraph; it still has to be *this* clause.
fn exempted(path: &str, needle: &str, context: &str) -> Option<&'static Exempt> {
    EXEMPT
        .iter()
        .find(|e| e.path == path && e.needle == needle && context.contains(e.sentence))
}

/// One paragraph of a file: the line it starts on, and its text as a reader meets it.
///
/// **This is the bypass M-01 of the 1 November audit found, and it was in the prefilter rather than
/// the scan.** `check-status` lowercased the whole file to decide whether a needle was present at
/// all, and that text still carries its newlines — so `no worker\nexists`, which is ordinary
/// Markdown wrapping and renders as one sentence, failed the prefilter and the per-line scan below it
/// never ran. The audit put exactly that into a copy of `README.md` and the gate exited 0, still
/// reporting "0 unrecorded".
///
/// Inline markup is stripped for the same reason: `**no** worker exists` and `[no worker
/// exists](x)` are the sentence a reader reads, and a gate that matches the source characters reads
/// something nobody wrote.
fn paragraphs(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut current: Vec<&str> = Vec::new();
    let mut start = 0usize;
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            if !current.is_empty() {
                out.push((start, normalize(&current.join(" "))));
                current.clear();
            }
            continue;
        }
        if current.is_empty() {
            start = index;
        }
        current.push(line);
    }
    if !current.is_empty() {
        out.push((start, normalize(&current.join(" "))));
    }
    out
}

/// Markdown inline markup removed, and runs of whitespace collapsed.
///
/// Emphasis and link syntax only. A code span keeps its backticks, because `is_named_not_used` below
/// reads them to tell a needle named from a needle used, and dropping them here would take that
/// distinction away from it.
fn normalize(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            // `**bold**` and `*emphasis*` and `_emphasis_`: the markers, not the words.
            '*' | '_' => {}
            // `[text](url)` keeps the text. The target is left where it is: it cannot create a
            // match that the prose does not contain, and it cannot break one, so removing it would
            // be more parsing for no gain.
            '[' | ']' => {}
            _ => out.push(c),
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// What the gate found: lines no exemption covers, and exemptions that matched nothing.
fn findings(root: &Path) -> (Vec<String>, Vec<String>, usize) {
    let mut unrecorded = Vec::new();
    let mut problems = Vec::new();
    let mut seen = vec![0usize; EXEMPT.len()];
    let mut covered = 0usize;

    for path in surface(root) {
        // **A file that cannot be read is reported, not skipped (H-78, #277).** Every read error
        // used to take the same branch as success, so a sentence in a submodule, behind a
        // permission, or in a file holding one non-UTF-8 byte was indistinguishable from no
        // sentence at all. Bytes are decoded lossily, which costs nothing on text and means a
        // binary file is scanned and finds nothing rather than being waved through.
        let bytes = match std::fs::read(root.join(&path)) {
            Ok(b) => b,
            Err(err) => {
                problems.push(format!(
                    "{path} could not be read, so nothing is known about it: {err}"
                ));
                continue;
            }
        };
        let text = String::from_utf8_lossy(&bytes);
        // **Paragraphs, not physical lines, for Markdown (H-102, issue #311).** Both the prefilter
        // and the scan used raw file text, so a needle broken across a line break — ordinary
        // Markdown wrapping, one sentence to a reader — matched neither.
        //
        // **Markdown only, and the reason is not convenience.** Normalizing joins wrapped lines and
        // strips emphasis, which is what a renderer does to Markdown and is nothing a Rust or shell
        // file does. Applied to source it would mangle code — `paras[0].1` reads as `paras0.1` —
        // and, worse, removing characters can join text that the file does not actually put
        // together, which is a gate inventing a sentence rather than finding one. Source files keep
        // the line scan.
        //
        // **What that leaves, said rather than discovered later:** a banned claim wrapped across two
        // lines of a comment in a `.rs` or `.sh` file is still invisible here. The audit's finding
        // was Markdown and the gate's own subject is the reader-facing surface, so this closes that
        // and does not pretend to close the other.
        let units: Vec<(usize, String)> = if path.ends_with(".md") {
            paragraphs(&text)
        } else {
            text.lines()
                .enumerate()
                .map(|(n, l)| (n, l.to_string()))
                .collect()
        };
        let lower = units
            .iter()
            .map(|(_, p)| p.to_lowercase())
            .collect::<Vec<_>>()
            .join("\n");
        for stale in &STALE {
            if !lower.contains(stale.needle) {
                continue;
            }
            for (number, line) in units.iter().map(|(n, p)| (*n, p.as_str())) {
                if inside_a_list(&path, &text, number) {
                    continue;
                }
                let lowered = line.to_lowercase();
                let mut from = 0;
                while let Some(found) = lowered[from..].find(stale.needle) {
                    let at = from + found;
                    from = at + stale.needle.len();
                    if is_named_not_used(line, at, stale.needle.len()) {
                        continue;
                    }
                    match exempted(&path, stale.needle, line) {
                        Some(e) => {
                            let index = EXEMPT
                                .iter()
                                .position(|x| std::ptr::eq(x, e))
                                .expect("in EXEMPT");
                            seen[index] += 1;
                            covered += 1;
                        }
                        None => unrecorded.push(format!(
                            "{path}:{} says \"{}\", and {}\n             {}",
                            number + 1,
                            stale.needle,
                            stale.why,
                            line.trim()
                        )),
                    }
                }
            }
        }
    }

    // **An exemption that matches nothing is stale (H-79, #278; identity narrowed in H-102, #311).**
    // It used to state a count, and a count is substitutable: a live false claim could take an
    // exempt occurrence's place with the number intact. The exemption now names its sentence, so
    // matching nothing means that sentence is gone and the exemption with it. Matching more than
    // once is no longer a problem by itself — one sentence cannot arrive twice without being the
    // same sentence, which is what was reviewed.
    for (at, e) in EXEMPT.iter().enumerate() {
        if seen[at] > 0 {
            continue;
        }
        problems.push(format!(
            "{} no longer carries the sentence this exemption records, so the exemption is stale: \"{}\" — {}",
            e.path, e.sentence, e.why
        ));
    }

    (unrecorded, problems, covered)
}

/// The gate. Fails on an unrecorded occurrence and on an exemption that matched nothing.
pub fn check_status(root: &Path) {
    let (unrecorded, problems, covered) = findings(root);
    let mut failed = false;

    if !unrecorded.is_empty() {
        eprintln!(
            "status: {} statement(s) contradict what the code does (#254):",
            unrecorded.len()
        );
        for line in &unrecorded {
            eprintln!("  {line}");
        }
        eprintln!(
            "         If one is correct where it stands, add it to EXEMPT in {OWN_PATH} with the reason."
        );
        failed = true;
    }

    if !problems.is_empty() {
        eprintln!("status: {} exemption or read problem(s):", problems.len());
        for line in &problems {
            eprintln!("  {line}");
        }
        failed = true;
    }

    assert!(!failed, "status: the gate above failed");

    println!(
        "status: {} construction(s) checked across the reader-facing surface, {covered} recorded \
         occurrence(s), 0 unrecorded, 0 stale exemptions",
        STALE.len()
    );
    println!(
        "status: this says nine known-false sentences have not come back, not that any current \
         sentence is true — that is a judgement no grep reaches"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The list is matched case-insensitively against a lowercased line, so an upper-case needle
    /// could never match and would be a gate that looks at nothing.
    #[test]
    fn every_needle_is_lower_case() {
        for stale in &STALE {
            assert_eq!(
                stale.needle,
                stale.needle.to_lowercase(),
                "needle {:?} is not lower case",
                stale.needle
            );
        }
        for e in &EXEMPT {
            assert_eq!(
                e.needle,
                e.needle.to_lowercase(),
                "exemption {:?}",
                e.needle
            );
        }
    }

    /// An exemption whose needle is not in the list exempts nothing and hides a typo.
    #[test]
    fn every_exemption_names_a_needle_the_gate_checks() {
        for e in &EXEMPT {
            assert!(
                STALE.iter().any(|s| s.needle == e.needle),
                "exemption for {} names {:?}, which is not in STALE",
                e.path,
                e.needle
            );
        }
    }

    /// Two exemptions recording the same sentence would let the second rot unnoticed, because the
    /// first marks it used.
    ///
    /// **The pair is no longer the identity (H-102, #311).** `(path, needle)` was, so one file could
    /// carry only one exempt occurrence of a phrase — and `docs/DECISIONS.md` legitimately carries
    /// two of `no worker exists`, one quoted and one in prose, which is why D-145 needed a second
    /// entry rather than a looser first one.
    #[test]
    fn no_two_exemptions_record_the_same_sentence() {
        for (at, e) in EXEMPT.iter().enumerate() {
            for other in &EXEMPT[at + 1..] {
                assert!(
                    !(e.path == other.path
                        && e.needle == other.needle
                        && e.sentence == other.sentence),
                    "{} records {:?} twice for {:?}",
                    e.path,
                    e.sentence,
                    e.needle
                );
            }
        }
    }

    /// Every needle carries a reason, printed beside the line it was found on. An empty one makes a
    /// failure that says only that something matched.
    #[test]
    fn every_entry_gives_a_reason() {
        for stale in &STALE {
            assert!(
                !stale.why.trim().is_empty(),
                "{:?} has no reason",
                stale.needle
            );
        }
        for e in &EXEMPT {
            assert!(!e.why.trim().is_empty(), "{} has no reason", e.path);
        }
    }

    /// H-79 (#278). A sentence that names a needle in order to say it became false is true, and
    /// the gate used to condemn it.
    #[test]
    fn a_needle_named_in_a_code_span_is_not_a_claim() {
        let span = "The needle `no worker exists` is in the list.";
        let at = span.find("no worker exists").expect("present");
        assert!(is_named_not_used(span, at, "no worker exists".len()));

        // **And quotation marks are no longer a reason (D-145).** This assertion was the opposite
        // until 2 November 2026: H-79 (#278) read the quotes as naming rather than using, and the
        // 1 November audit found that a present-tense claim in quotes passed on the same reading.
        let quoted = r#"The sentence "no worker exists" became false on 20 October 2026."#;
        let at = quoted.find("no worker exists").expect("present");
        assert!(
            !is_named_not_used(quoted, at, "no worker exists".len()),
            "true though this sentence is, the gate cannot tell it from the claim; it is recorded \
             as an exemption naming it instead"
        );
    }

    /// The same needle written bare is the claim itself, and still fails.
    #[test]
    fn a_needle_used_bare_is_a_claim() {
        // Spelled in two pieces so this module's own source does not state the claim: the
        // gate reads its own file now, and a fixture spelling a needle bare is a sentence
        // in a scanned file.
        let line = concat!("No worker ", "exists in this repository.");
        let at = line
            .to_lowercase()
            .find("no worker exists")
            .expect("present");
        assert!(!is_named_not_used(line, at, "no worker exists".len()));
    }

    /// H-87. The first version counted delimiters before the match and called the needle named when
    /// the count was odd, so a Rust raw string's `r#"` flipped the parity and a named needle read as
    /// a claim. That is how a test added in #286 turned `main` red.
    ///
    /// The parity is gone and the two adjacent characters are asked directly, which has nothing to
    /// get wrong. Carried on the backtick, since D-145 removed the quotation-mark arm; the property
    /// under test is that surrounding source syntax cannot change the verdict.
    #[test]
    fn source_syntax_around_a_code_span_does_not_change_the_verdict() {
        let line = r##"        let line = r#"The needle `no worker exists` is in the list."#;"##;
        let at = line.find("no worker exists").expect("present");
        assert!(is_named_not_used(line, at, "no worker exists".len()));
    }

    /// H-78 (#277). Only the two lists are skipped in this module, not every line of it. The old
    /// exclusion was the whole file, so anything written here was invisible.
    #[test]
    fn only_the_two_lists_are_skipped_in_this_module() {
        let text = "a\nconst STALE: [Stale; 1] = [\n    needle,\n];\nb\n";
        assert!(
            !inside_a_list(OWN_PATH, text, 0),
            "line above the list is read"
        );
        assert!(
            inside_a_list(OWN_PATH, text, 2),
            "a line in the list is skipped"
        );
        assert!(
            !inside_a_list(OWN_PATH, text, 4),
            "line below the list is read"
        );
        assert!(
            !inside_a_list("docs/performance.md", text, 2),
            "no other file has lists to skip"
        );
    }

    /// H-79 (#278), as the identity it has now. An exemption that records nothing cannot fail open.
    ///
    /// The count this used to assert was the thing H-102 (#311) removed: a count is substitutable,
    /// and a non-empty sentence is not. `every_exemption_records_a_sentence_containing_its_needle`
    /// below carries the other half, that the sentence and the needle agree.
    #[test]
    fn every_exemption_records_a_sentence() {
        for e in &EXEMPT {
            assert!(
                !e.sentence.trim().is_empty(),
                "{} records no sentence for {:?}, so it would cover every occurrence",
                e.path,
                e.needle
            );
        }
    }

    /// **The bypass, as the audit wrote it (H-102, issue #311).**
    ///
    /// Ordinary Markdown wrapping. The rendered sentence restores a banned claim, and the old gate
    /// saw nothing: its prefilter searched raw file text, where the phrase does not occur, so the
    /// per-line scan under it never ran.
    #[test]
    fn a_claim_wrapped_across_a_line_break_is_one_sentence() {
        let doc = "Current status: no worker\nexists in this repository.\n";
        assert!(
            !doc.to_lowercase().contains("no worker exists"),
            "the raw text does not contain it, which is why the old prefilter passed"
        );
        let paras = paragraphs(doc);
        assert_eq!(paras.len(), 1);
        assert!(
            paras[0].1.to_lowercase().contains("no worker exists"),
            "normalized, it is the sentence a reader meets: {:?}",
            paras[0].1
        );
    }

    /// Inline markup is the same bypass with different characters.
    #[test]
    fn emphasis_and_link_markup_do_not_hide_a_claim() {
        for doc in [
            "**no** worker exists here.\n",
            "_no worker exists_ here.\n",
            "[no worker exists](https://example.invalid/x) here.\n",
            "*no worker\nexists* here.\n",
        ] {
            let paras = paragraphs(doc);
            assert!(
                paras[0].1.to_lowercase().contains("no worker exists"),
                "markup must not hide it: {doc:?} normalized to {:?}",
                paras[0].1
            );
        }
    }

    /// A blank line ends a paragraph, so two sentences are not spliced into one claim that neither
    /// of them makes. The gate must not invent a match either.
    #[test]
    fn a_blank_line_separates_paragraphs_so_no_claim_is_invented() {
        let doc = "Something about no worker\n\nexists in this repository.\n";
        let paras = paragraphs(doc);
        assert_eq!(paras.len(), 2, "a blank line ends the paragraph");
        assert!(
            !paras
                .iter()
                .any(|(_, p)| p.to_lowercase().contains("no worker exists")),
            "nothing here says it, so nothing may be reported: {paras:?}"
        );
    }

    /// The line a finding reports is the paragraph's first, not the file's.
    #[test]
    fn a_paragraph_reports_the_line_it_starts_on() {
        let doc = "one\n\ntwo\nthree\n\nfour\n";
        assert_eq!(
            paragraphs(doc).iter().map(|(n, _)| *n).collect::<Vec<_>>(),
            vec![0, 2, 5]
        );
    }

    /// **An exemption is no longer substitutable (H-102, issue #311).**
    ///
    /// It named `(path, needle)` and a count, so a live false claim could take an exempt historical
    /// occurrence's place with the number intact and the gate stayed green. It names the sentence
    /// now, so a different occurrence is not covered.
    #[test]
    fn an_exemption_covers_its_own_sentence_and_no_other() {
        let e = &EXEMPT[1];
        assert!(
            exempted(e.path, e.needle, e.sentence).is_some(),
            "the sentence it records is covered"
        );
        assert!(
            exempted(
                e.path,
                e.needle,
                "Current status: no wall-clock regression gate exists."
            )
            .is_none(),
            "a different sentence using the same needle in the same file is not covered"
        );
        assert!(
            exempted("README.md", e.needle, e.sentence).is_none(),
            "and the same sentence in another file is not covered either"
        );
    }

    /// Every exemption records a sentence that actually contains its needle.
    ///
    /// Without this the pair could drift into an exemption that can never match, which the stale
    /// check would report — but only after someone edited the document. This catches it at the list.
    #[test]
    fn every_exemption_records_a_sentence_containing_its_needle() {
        for e in &EXEMPT {
            assert!(
                e.sentence.to_lowercase().contains(e.needle),
                "exemption for {:?} records a sentence that does not contain it: {:?}",
                e.needle,
                e.sentence
            );
        }
    }

    /// **A quoted banned claim is a claim (D-145, owner's ruling of 2 November 2026).**
    ///
    /// The quotation-mark arm used to skip this, so a present-tense assertion passed on its
    /// punctuation. The 1 November audit found it as M-01. A legitimate quotation is recorded as an
    /// exemption naming its sentence instead — `EXEMPT[0]` is the occurrence H-79 (#278) added the
    /// arm for, now carried that way.
    #[test]
    fn a_quoted_banned_claim_is_no_longer_excused_by_its_quotation_marks() {
        let line = "Current status: \"no worker exists\".";
        let at = line.find("no worker exists").expect("present");
        assert!(
            !is_named_not_used(line, at, "no worker exists".len()),
            "a quotation mark is not a reason: this sentence asserts the claim"
        );
    }

    /// And a code span still is a reason, because it has no second reading.
    #[test]
    fn a_backticked_needle_is_still_a_phrase_and_not_a_claim() {
        let line = "The phrase `no worker exists` names nine sentences this gate bans.";
        let at = line.find("no worker exists").expect("present");
        assert!(
            is_named_not_used(line, at, "no worker exists".len()),
            "a code span says `these characters`, which is not an assertion about the worker"
        );
    }

    /// The reversal is not partial: no other delimiter was ever a reason, and none becomes one.
    #[test]
    fn no_delimiter_other_than_a_backtick_excuses_a_claim() {
        let needle = "no worker exists";
        for (open, close) in [('"', '"'), ('\'', '\''), ('(', ')'), ('*', '*'), ('_', '_')] {
            let line = format!("Status: {open}{needle}{close}.");
            let at = line.find(needle).expect("present");
            assert!(
                !is_named_not_used(&line, at, needle.len()),
                "{open}{close} must not excuse it"
            );
        }
    }

    /// **The test-module exclusion is narrow, which is the whole of H-78's lesson (#277).**
    ///
    /// Skipping the file hid anything written anywhere in it. This skips the fixtures and the two
    /// lists; the prose above them is read like any other file's, so documentation moved into this
    /// module does not inherit an exclusion.
    #[test]
    fn the_exclusion_covers_the_fixtures_and_the_lists_and_nothing_else() {
        let own = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/status.rs");
        let text = match std::fs::read_to_string(&own) {
            Ok(text) => text,
            Err(e) => panic!("{}: {e}", own.display()),
        };
        let lines: Vec<&str> = text.lines().collect();

        let tests_at = lines
            .iter()
            .position(|l| l.trim_start().starts_with("#[cfg(test)]"))
            .expect("this module has a test block");
        assert!(
            inside_a_list(OWN_PATH, &text, tests_at),
            "the fixtures are excluded"
        );
        assert!(
            inside_a_list(OWN_PATH, &text, lines.len().saturating_sub(1)),
            "to the end of the file"
        );

        let doc_line = lines
            .iter()
            .position(|l| l.starts_with("//! "))
            .expect("this module has module documentation");
        assert!(
            !inside_a_list(OWN_PATH, &text, doc_line),
            "but the module's own documentation is read, so a claim written there is caught"
        );
        assert!(
            !inside_a_list("README.md", &text, tests_at),
            "and no other file is excluded at any line"
        );
    }
}
