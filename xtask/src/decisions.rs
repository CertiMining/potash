// SPDX-License-Identifier: MIT OR Apache-2.0
//! Decision identifiers, which have to name one decision each (#256, audit finding L-01).
//!
//! **What happened.** `docs/DECISIONS.md` carries D-99, D-100, D-101 and D-103 twice each, with
//! byte-identical bodies, and reserves D-131 in one block before settling it in the next. A reference
//! reading "per D-103" therefore names two headings. Nothing noticed, because nothing counted them.
//!
//! It is not only a tidiness problem. On 31 October 2026 three open pull requests — #258, #259 and
//! #260 — each added a decision numbered **D-142**, which `main` had just taken for something else.
//! All three conflicted on this file at once, and the collision was found by a merge rather than by a
//! gate, after the number had already been written into fifteen places across eleven files on each
//! branch. A gate on uniqueness fails on the branch that introduces the second D-142, while it is
//! still one heading and no references exist.
//!
//! **What this is.** Two assertions over the parsed file. Every `## D-nnn` heading appears once, and
//! every `Superseded by` / `Supersedes` / `Amends` / `Amended by` link names a heading that exists.
//!
//! The five existing duplicates are listed below rather than fixed here, because resolving them edits
//! the decision record and that is the owner's to rule on (#256's second and third criteria). Each is
//! recorded with what it is, so the list is a classification and not a mute allowlist. A listed entry
//! that has stopped being a duplicate fails too: once the record is corrected, this gate is what says
//! the entry can go.
//!
//! **What it does not do.** It says each identifier names one heading, not that the heading says
//! anything true, and not that a reference elsewhere in the repository points at the right decision.
//! `check-citations` holds cited *specification* text to its digest; nothing does that for decisions.

use std::collections::BTreeMap;
use std::path::Path;

/// One decision heading and the text under it, up to the next heading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// One-based line of the heading.
    pub line: usize,
    pub id: String,
    pub body: String,
}

/// An identifier used by more than one heading.
#[derive(Debug, PartialEq, Eq)]
pub struct Duplicate {
    pub id: String,
    pub lines: Vec<usize>,
    /// Whether every body under the identifier is the same text.
    pub identical: bool,
}

/// A duplicate that exists on `main` and whose resolution is the owner's to rule on.
///
/// **Admission matches the recorded shape, not the identifier (H-81, #280).** It used to compare
/// `id` alone, so a third body under `D-99` \u{2014} a different decision, not the recorded pair \u{2014} was
/// admitted and the gate went on printing that the identifier was used twice. `kind` was recorded
/// and never read. An entry here now says how many headings it covers and whether their bodies are
/// the same text, and anything else under that identifier is a new duplicate.
struct Known {
    id: &'static str,
    /// How many headings this records. A further one is not this duplicate.
    headings: usize,
    /// Whether every body under the identifier is the same text.
    identical: bool,
    /// What it is, from the inventory #256's first criterion asks for.
    kind: &'static str,
}

impl Known {
    /// Whether an observed duplicate is the one this entry records.
    fn covers(&self, d: &Duplicate) -> bool {
        self.id == d.id && self.headings == d.lines.len() && self.identical == d.identical
    }
}

const KNOWN: [Known; 5] = [
    Known {
        id: "D-99",
        headings: 2,
        identical: true,
        kind: "exact duplicate, both bodies byte-identical",
    },
    Known {
        id: "D-100",
        headings: 2,
        identical: true,
        kind: "exact duplicate, both bodies byte-identical",
    },
    Known {
        id: "D-101",
        headings: 2,
        identical: true,
        kind: "exact duplicate, both bodies byte-identical",
    },
    Known {
        id: "D-103",
        headings: 2,
        identical: true,
        kind: "exact duplicate, both bodies byte-identical",
    },
    Known {
        id: "D-131",
        headings: 2,
        identical: false,
        kind: "reserved, then reused: a reservation block followed by the settled decision",
    },
];

/// Every decision heading in order, with the text under each.
pub fn parse(text: &str) -> Vec<Entry> {
    let lines: Vec<&str> = text.split('\n').collect();
    let heads: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| !heading_ids(l).is_empty())
        .map(|(i, _)| i)
        .collect();
    heads
        .iter()
        .enumerate()
        .flat_map(|(n, &at)| {
            let end = heads.get(n + 1).copied().unwrap_or(lines.len());
            let body = lines[at + 1..end].join("\n").trim().to_string();
            // A heading naming two identifiers is two entries over one body, so each identifier is
            // counted (H-80, #279).
            heading_ids(lines[at])
                .into_iter()
                .map(move |id| Entry {
                    line: at + 1,
                    id,
                    body: body.clone(),
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Every identifier a heading names. `## D-123 \u{b7} anything` yields `D-123`, and
/// `## D-102 and D-119 \u{b7} anything` yields both.
///
/// **It used to yield only the first, and that hid a real duplicate (H-80, #279).** The heading
/// `## D-102 and D-119 \u{b7} INV-PRIM-01 is scoped to this system's own digests` was read as D-102
/// alone, so the separate `## D-119` heading further down was the only one counted and the gate
/// reported a record it had not finished reading. Only the label is scanned \u{2014} the text before the
/// separator \u{2014} because a subject may mention other decisions without naming itself one of them.
///
/// The separator is now required rather than a bare space, which is what the old comment claimed
/// and the old code did not check: `## D-123 ` with nothing after it was accepted as a heading with
/// no decision under it. All 145 headings on `main` carry it.
fn heading_ids(line: &str) -> Vec<String> {
    let Some(rest) = line.strip_prefix("## D-") else {
        return Vec::new();
    };
    let Some((label, _)) = rest.split_once('\u{b7}') else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for id in scan_ids(&format!("D-{label}")) {
        if !out.contains(&id) {
            out.push(id);
        }
    }
    out
}

/// Every `D-<digits>` in a string, in order of appearance, outside code spans.
///
/// **A code span is not a reference.** A record that documents a mistaken citation has to be able
/// to name the identifier that was wrong without the gate reading it as a fresh claim that the
/// decision exists. Writing it between backticks says "these characters", and prose that means a
/// decision writes it bare, which is what every real reference in this file does.
fn scan_ids(text: &str) -> Vec<String> {
    let text: String = {
        let mut kept = String::with_capacity(text.len());
        let mut in_span = false;
        for ch in text.chars() {
            if ch == '`' {
                in_span = !in_span;
                kept.push(' ');
            } else {
                kept.push(if in_span { ' ' } else { ch });
            }
        }
        kept
    };
    let text = text.as_str();
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut at = 0;
    while let Some(found) = text[at..].find("D-") {
        let start = at + found + 2;
        // `AD-12` is not an identifier: the marker has to begin a word.
        let preceded_by_word = start >= 3
            && bytes
                .get(start - 3)
                .is_some_and(|b| b.is_ascii_alphanumeric());
        let digits: String = text[start..]
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        if !digits.is_empty() && !preceded_by_word {
            out.push(format!("D-{digits}"));
        }
        at = start;
    }
    out
}

/// Identifiers used by more than one heading, in numeric order.
pub fn duplicates(entries: &[Entry]) -> Vec<Duplicate> {
    let mut by_id: BTreeMap<&str, Vec<&Entry>> = BTreeMap::new();
    for e in entries {
        by_id.entry(&e.id).or_default().push(e);
    }
    let mut out: Vec<Duplicate> = by_id
        .into_iter()
        .filter(|(_, v)| v.len() > 1)
        .map(|(id, v)| Duplicate {
            id: id.to_string(),
            lines: v.iter().map(|e| e.line).collect(),
            identical: v.iter().all(|e| e.body == v[0].body),
        })
        .collect();
    out.sort_by_key(|d| number(&d.id));
    out
}

/// The numeric part, for ordering. A malformed identifier never reaches here: `heading_id` built it.
fn number(id: &str) -> u32 {
    id[2..].parse().expect("heading_id produced the digits")
}

/// Identifiers mentioned in the record that no heading defines, as (identifier, line).
///
/// **It used to read four link verbs only, and that passed a reference to a decision that has
/// never existed (H-82, #281).** D-142 cited "D-185's rule"; the numbering has never passed D-144,
/// the rule is D-18's, and the number was the line D-18 states it on. An ordinary mention was not
/// one of the four forms, so the gate reported no dangling links. Every `D-<digits>` in the file is
/// now resolved.
///
/// Identifiers are compared by number, because the headings are zero-padded (`## D-03`) and prose
/// is not (`D-8`). Comparing the text would have made every unpadded mention dangle.
///
/// `EXTERNAL` holds the two the file itself says live elsewhere.
pub fn dangling(text: &str, entries: &[Entry]) -> Vec<(String, usize)> {
    let defined: Vec<u32> = entries.iter().map(|e| number(&e.id)).collect();
    let mut out = Vec::new();
    for (at, line) in text.split('\n').enumerate() {
        for id in scan_ids(line) {
            let n = number(&id);
            if defined.contains(&n) || EXTERNAL.contains(&n) {
                continue;
            }
            out.push((id, at + 1));
        }
    }
    out
}

/// Identifiers recorded outside this file. The first line of `docs/DECISIONS.md` says so: the
/// record is "numbered from D-03", and D-01 and D-02 are in Appendix B of the specification.
const EXTERNAL: [u32; 2] = [1, 2];

/// The gate. Fails on an unlisted duplicate, a dangling link, and a listed entry that is no longer a
/// duplicate.
pub fn check_decisions(root: &Path) {
    let path = root.join("docs/DECISIONS.md");
    let text = std::fs::read_to_string(&path).expect("docs/DECISIONS.md can be read");
    let entries = parse(&text);
    let dups = duplicates(&entries);
    let dangles = dangling(&text, &entries);
    let mut failed = false;

    for d in &dups {
        if KNOWN.iter().any(|k| k.covers(d)) {
            continue;
        }
        if !failed {
            eprintln!("decisions: an identifier names more than one decision (#256):");
            failed = true;
        }
        eprintln!(
            "  {} is used by {} headings, at lines {:?}, with {} bodies.",
            d.id,
            d.lines.len(),
            d.lines,
            if d.identical {
                "identical"
            } else {
                "DIFFERENT"
            }
        );
        if !d.identical {
            eprintln!(
                "         Different bodies under one number is a collision: two decisions were \
                 numbered independently and one has to be renumbered before any reference to it is \
                 written."
            );
        }
    }

    if !dangles.is_empty() {
        eprintln!("decisions: {} link(s) name no decision:", dangles.len());
        for (id, line) in &dangles {
            eprintln!("  docs/DECISIONS.md:{line} links {id}, which has no heading.");
        }
        failed = true;
    }

    for k in &KNOWN {
        if !dups.iter().any(|d| d.id == k.id) {
            eprintln!(
                "decisions: {} is listed as a known duplicate ({}) and is not one any more. \
                 Remove it from KNOWN in xtask/src/decisions.rs.",
                k.id, k.kind
            );
            failed = true;
        }
    }

    assert!(!failed, "decisions: the gate above failed");

    println!(
        "decisions: {} decision(s), {} identifier(s) used twice, all {} of them the duplicates #256 \
         records; {} structured link(s), none dangling",
        entries.len(),
        dups.len(),
        KNOWN.len(),
        text.matches("Amends D-").count()
            + text.matches("Superseded by D-").count()
            + text.matches("Supersedes D-").count()
            + text.matches("Amended by D-").count()
    );
    for k in &KNOWN {
        println!("decisions:   {} — {}", k.id, k.kind);
    }
    println!(
        "decisions: this says each identifier names one heading, not that the heading is right, and \
         not that a reference elsewhere points at the decision it means"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXACT_DUPLICATE: &str = "\
## D-7 · A thing
**Date:** today

## D-7 · A thing
**Date:** today
";

    const RESERVED_THEN_REUSED: &str = "\
## D-9 · This entry is reserved
**Status:** reserved

## D-9 · Fuzzing is cargo-fuzz
**Status:** settled
";

    const BROKEN_LINK: &str = "\
## D-1 · A thing
Amends D-404
";

    /// #256's negative test for an exact duplicate.
    #[test]
    fn an_exact_duplicate_is_found_and_reported_as_identical() {
        let dups = duplicates(&parse(EXACT_DUPLICATE));
        assert_eq!(dups.len(), 1, "{dups:?}");
        assert_eq!(dups[0].id, "D-7");
        assert_eq!(dups[0].lines, vec![1, 4]);
        assert!(dups[0].identical, "the bodies are the same text");
    }

    /// #256's negative test for a reserved-then-reused identifier. It must not read as an exact
    /// duplicate, because the remedy is different: one block is a placeholder, not a second decision.
    #[test]
    fn a_reserved_then_reused_identifier_is_found_and_reported_as_different() {
        let dups = duplicates(&parse(RESERVED_THEN_REUSED));
        assert_eq!(dups.len(), 1, "{dups:?}");
        assert_eq!(dups[0].id, "D-9");
        assert!(
            !dups[0].identical,
            "a reservation is not the decision that replaced it"
        );
    }

    /// #256's negative test for a broken supersession link.
    #[test]
    fn a_link_to_a_decision_that_does_not_exist_is_found() {
        let entries = parse(BROKEN_LINK);
        assert_eq!(
            dangling(BROKEN_LINK, &entries),
            vec![("D-404".to_string(), 2)]
        );
    }

    /// A link to a decision that does exist is not reported, or the gate would fail on every file.
    #[test]
    fn a_link_to_a_decision_that_exists_is_not_reported() {
        let text = "## D-1 · A thing\nAmends D-2\n\n## D-2 · Another\nbody\n";
        let entries = parse(text);
        assert!(dangling(text, &entries).is_empty());
    }

    /// The collision that prompted this: two branches numbering different decisions the same. It has
    /// to read as DIFFERENT, because that is the case where a renumber is owed.
    #[test]
    fn two_different_decisions_under_one_number_read_as_a_collision() {
        let text = "## D-142 · Advisory exceptions\nmine\n\n## D-142 · Split-host cycle\ntheirs\n";
        let dups = duplicates(&parse(text));
        assert_eq!(dups.len(), 1);
        assert!(!dups[0].identical, "a collision, not a duplicate");
    }

    /// Prose mentioning a decision, and a deeper heading, are not decision headings.
    #[test]
    fn only_a_second_level_heading_with_a_subject_counts() {
        let text = "### D-5 · deeper\nx\n\nsee D-6 for this\n\n## D-7\n\n## D-8 · real\ny\n";
        let entries = parse(text);
        let ids: Vec<&str> = entries.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, vec!["D-8"], "only the one heading with a subject");
    }

    /// Duplicates come back in numeric order, not the lexicographic order a string sort would give.
    #[test]
    fn duplicates_are_ordered_numerically() {
        let text = "## D-100 · a\nx\n\n## D-100 · a\nx\n\n## D-9 · b\ny\n\n## D-9 · b\ny\n";
        let ids: Vec<String> = duplicates(&parse(text)).into_iter().map(|d| d.id).collect();
        assert_eq!(ids, vec!["D-9".to_string(), "D-100".to_string()]);
    }

    /// Every listed entry names a real classification, so the printed inventory cannot be blank.
    #[test]
    fn every_known_entry_is_classified() {
        for k in &KNOWN {
            assert!(!k.kind.trim().is_empty(), "{} has no classification", k.id);
            assert!(k.id.starts_with("D-"), "{} is not a decision id", k.id);
        }
    }

    /// H-80 (#279). The heading `## D-102 and D-119 \u{b7} \u{2026}` named two decisions and the gate saw
    /// one, so the second `## D-119` further down was never a duplicate to it.
    #[test]
    fn a_heading_naming_two_identifiers_yields_both() {
        let text = "## D-102 and D-119 \u{b7} a\nx\n\n## D-119 \u{b7} b\ny\n";
        let ids: Vec<String> = parse(text).into_iter().map(|e| e.id).collect();
        assert_eq!(ids, vec!["D-102", "D-119", "D-119"]);
        let dups: Vec<String> = duplicates(&parse(text)).into_iter().map(|d| d.id).collect();
        assert_eq!(dups, vec!["D-119".to_string()]);
    }

    /// A heading needs its separator. The old code checked for a space and the comment claimed a
    /// separator, so `## D-123 ` counted as a decision with nothing under it (H-80, #279).
    #[test]
    fn a_heading_with_no_subject_is_not_a_decision() {
        assert!(heading_ids("## D-123 ").is_empty());
        assert!(heading_ids("## D-123").is_empty());
        assert_eq!(heading_ids("## D-123 \u{b7} a subject"), vec!["D-123"]);
    }

    /// H-81 (#280). A known duplicate is admitted on its recorded shape. A third body under the
    /// same identifier is a different duplicate and has to be reported.
    #[test]
    fn a_third_body_under_a_known_identifier_is_not_the_known_duplicate() {
        let two = "## D-99 \u{b7} a\nx\n\n## D-99 \u{b7} a\nx\n";
        let three = "## D-99 \u{b7} a\nx\n\n## D-99 \u{b7} a\nx\n\n## D-99 \u{b7} different\nz\n";
        let known = KNOWN
            .iter()
            .find(|k| k.id == "D-99")
            .expect("D-99 is listed");
        let d2 = duplicates(&parse(two))
            .into_iter()
            .next()
            .expect("a duplicate");
        let d3 = duplicates(&parse(three))
            .into_iter()
            .next()
            .expect("a duplicate");
        assert!(known.covers(&d2), "the recorded pair is admitted");
        assert!(
            !known.covers(&d3),
            "a third, differing body is not the recorded pair"
        );
    }

    /// H-82 (#281). Every mention resolves, not only four link verbs, and the comparison is by
    /// number because headings are zero-padded and prose is not.
    #[test]
    fn an_ordinary_mention_of_a_decision_that_does_not_exist_dangles() {
        let text = "## D-08 \u{b7} a\nSee D-8's rule and D-999's rule.\n";
        let entries = parse(text);
        let out: Vec<String> = dangling(text, &entries)
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        assert_eq!(
            out,
            vec!["D-999".to_string()],
            "D-8 is D-08 unpadded, D-999 is nothing"
        );
    }

    /// A record that documents a mistaken citation names the wrong identifier in a code span, and
    /// that is text rather than a reference (H-82, #281).
    #[test]
    fn an_identifier_in_a_code_span_is_not_a_reference() {
        let text = "## D-03 \u{b7} a\nThis entry cited `D-185`, which does not exist.\n";
        assert!(dangling(text, &parse(text)).is_empty());
        let bare = "## D-03 \u{b7} a\nThis entry cites D-185.\n";
        assert_eq!(dangling(bare, &parse(bare)).len(), 1);
    }

    /// D-01 and D-02 are recorded in the specification's Appendix B, which the first line of the
    /// record states. They are references, not dangling ones.
    #[test]
    fn the_two_decisions_recorded_in_the_specification_do_not_dangle() {
        let text = "## D-03 \u{b7} a\nD-01 and D-02 are in Appendix B.\n";
        assert!(dangling(text, &parse(text)).is_empty());
    }
}
