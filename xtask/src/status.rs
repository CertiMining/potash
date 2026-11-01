// SPDX-License-Identifier: MIT OR Apache-2.0
//! Status statements about the worker and the regression band, against what the code does (#254).
//!
//! **What happened.** Nine sentences across eight files said the OpenTimestamps worker did not exist,
//! or that `bench-band` reported drift "without failing on it". Each was true when written and false
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

/// An occurrence that is correct where it stands.
///
/// **It records how many, because covering "every occurrence" fails open (H-79, #278).** The
/// exemption used to be keyed on path and needle alone, so a *new* false sentence added to an
/// exempt file inherited the exemption and the gate stayed green. A count turns the exemption into
/// a statement about a known text rather than a licence for that file.
struct Exempt {
    path: &'static str,
    needle: &'static str,
    /// Bare occurrences this records. One more is a new claim, not this one.
    occurrences: usize,
    why: &'static str,
}

const EXEMPT: [Exempt; 2] = [
    Exempt {
        path: "docs/DECISIONS.md",
        needle: "no worker exists",
        occurrences: 1,
        why: "D-117's amendment quotes the sentence it superseded, which is how it records the change",
    },
    Exempt {
        path: "docs/TCU-02_CertiMining_Anchored_Log_v0.1.md",
        needle: "regression gate exists",
        occurrences: 1,
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

/// Whether a line of this module's own source is inside one of the two lists.
fn inside_a_list(path: &str, text: &str, number: usize) -> bool {
    if path != OWN_PATH {
        return false;
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

/// Whether the match at `at` sits inside a quoted or backticked span on its line.
///
/// **A needle named is not a needle used (H-79, #278).** `The sentence "no worker exists" became
/// false on 20 October 2026` is true, and the gate used to condemn it. Prose that means the claim
/// writes it bare, which is what every real occurrence in this repository does.
fn is_named_not_used(line: &str, at: usize) -> bool {
    let before = &line[..at];
    before.matches('"').count() % 2 == 1 || before.matches('`').count() % 2 == 1
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

/// Whether an exemption covers an occurrence of `needle` in `path`.
fn exempted(path: &str, needle: &str) -> Option<&'static Exempt> {
    EXEMPT.iter().find(|e| e.path == path && e.needle == needle)
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
        let lower = text.to_lowercase();
        for stale in &STALE {
            if !lower.contains(stale.needle) {
                continue;
            }
            for (number, line) in text.lines().enumerate() {
                if inside_a_list(&path, &text, number) {
                    continue;
                }
                let lowered = line.to_lowercase();
                let mut from = 0;
                while let Some(found) = lowered[from..].find(stale.needle) {
                    let at = from + found;
                    from = at + stale.needle.len();
                    if is_named_not_used(line, at) {
                        continue;
                    }
                    match exempted(&path, stale.needle) {
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

    // An exemption states how many bare occurrences it covers. Fewer means it records nothing;
    // more means a sentence arrived that nobody looked at (H-79, #278).
    for (at, e) in EXEMPT.iter().enumerate() {
        if seen[at] == e.occurrences {
            continue;
        }
        problems.push(format!(
            "{} has {} bare occurrence(s) of \"{}\" and this exemption records {}: {}",
            e.path, seen[at], e.needle, e.occurrences, e.why
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

    /// Two exemptions for one (path, needle) would let the second rot unnoticed, because the first
    /// marks the pair used.
    #[test]
    fn no_two_exemptions_cover_the_same_pair() {
        for (at, e) in EXEMPT.iter().enumerate() {
            for other in &EXEMPT[at + 1..] {
                assert!(
                    !(e.path == other.path && e.needle == other.needle),
                    "{} is exempted twice for {:?}",
                    e.path,
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
    fn a_needle_named_in_quotes_or_backticks_is_not_a_claim() {
        let line = r#"The sentence "no worker exists" became false on 20 October 2026."#;
        let at = line.find("no worker exists").expect("present");
        assert!(is_named_not_used(line, at));

        let span = "The needle `no worker exists` is in the list.";
        let at = span.find("no worker exists").expect("present");
        assert!(is_named_not_used(span, at));
    }

    /// The same needle written bare is the claim itself, and still fails.
    #[test]
    fn a_needle_used_bare_is_a_claim() {
        let line = "No worker exists in this repository.";
        let at = line
            .to_lowercase()
            .find("no worker exists")
            .expect("present");
        assert!(!is_named_not_used(line, at));
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

    /// H-79 (#278). An exemption that records nothing cannot fail open on a count of zero.
    #[test]
    fn every_exemption_records_how_many_it_covers() {
        for e in &EXEMPT {
            assert!(
                e.occurrences > 0,
                "{} records no occurrence of {:?}",
                e.path,
                e.needle
            );
        }
    }
}
