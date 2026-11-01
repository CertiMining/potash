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
struct Known {
    id: &'static str,
    /// What it is, from the inventory #256's first criterion asks for.
    kind: &'static str,
}

const KNOWN: [Known; 5] = [
    Known {
        id: "D-99",
        kind: "exact duplicate, both bodies byte-identical",
    },
    Known {
        id: "D-100",
        kind: "exact duplicate, both bodies byte-identical",
    },
    Known {
        id: "D-101",
        kind: "exact duplicate, both bodies byte-identical",
    },
    Known {
        id: "D-103",
        kind: "exact duplicate, both bodies byte-identical",
    },
    Known {
        id: "D-131",
        kind: "reserved, then reused: a reservation block followed by the settled decision",
    },
];

/// Every decision heading in order, with the text under each.
pub fn parse(text: &str) -> Vec<Entry> {
    let lines: Vec<&str> = text.split('\n').collect();
    let heads: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| heading_id(l).is_some())
        .map(|(i, _)| i)
        .collect();
    heads
        .iter()
        .enumerate()
        .map(|(n, &at)| {
            let end = heads.get(n + 1).copied().unwrap_or(lines.len());
            Entry {
                line: at + 1,
                id: heading_id(lines[at]).expect("filtered above"),
                body: lines[at + 1..end].join("\n").trim().to_string(),
            }
        })
        .collect()
}

/// `## D-123 · anything` yields `D-123`. A deeper heading is not a decision, and neither is prose
/// that merely mentions one, which is why the marker and the separator are both required.
fn heading_id(line: &str) -> Option<String> {
    let rest = line.strip_prefix("## D-")?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return None;
    }
    // A heading names its subject after a separator. `## D-99` alone would be a heading with no
    // decision under it, and is refused rather than silently counted.
    let after = &rest[digits.len()..];
    if !after.starts_with(' ') {
        return None;
    }
    Some(format!("D-{digits}"))
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

/// Structured links naming an identifier no heading defines, as (link target, line).
pub fn dangling(text: &str, entries: &[Entry]) -> Vec<(String, usize)> {
    let defined: Vec<&str> = entries.iter().map(|e| e.id.as_str()).collect();
    let mut out = Vec::new();
    for (at, line) in text.split('\n').enumerate() {
        for verb in ["Superseded by", "Supersedes", "Amends", "Amended by"] {
            let mut from = 0;
            while let Some(found) = line[from..].find(verb) {
                let start = from + found + verb.len();
                if let Some(id) = link_target(&line[start..]) {
                    if !defined.contains(&id.as_str()) {
                        out.push((id, at + 1));
                    }
                }
                from = start;
            }
        }
    }
    out
}

/// ` D-123` immediately after a link verb.
fn link_target(rest: &str) -> Option<String> {
    let rest = rest.strip_prefix(' ')?.strip_prefix("D-")?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    (!digits.is_empty()).then(|| format!("D-{digits}"))
}

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
        if KNOWN.iter().any(|k| k.id == d.id) {
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
}
