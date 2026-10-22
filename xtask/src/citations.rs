// SPDX-License-Identifier: MIT OR Apache-2.0
//! Documents that cite an invariant, against the specification's text for it (H-46, issue #143).
//!
//! **What happened.** `docs/promises.md` said a gap in the on-chain epoch sequence is evidence of
//! batcher failure, which INV-ANCH-02 required a client to surface. v0.2.0 corrected the
//! specification to say there is no such gap: `publish_checkpoint` accepts only `last_epoch + 1`, so
//! the range is contiguous by construction, and an invariant requiring a detector for an unreachable
//! condition was itself a defect. The document kept the superseded wording and was found by a person
//! reading the file, not by a gate.
//!
//! `scripts/claim-check.sh` could not catch it: that greps for banned phrasings and for concept nouns
//! against an allowlist. A sentence permissible in isolation, and wrong only because the
//! specification now says the opposite, is invisible to it.
//!
//! **What this is.** The third candidate the issue listed — record, per amendment, which documents
//! cite the amended identifier and make the amending change confront them — turned from process into
//! a gate. `docs/CITED-INVARIANTS.sha256` records, for every invariant cited outside the
//! specification, the digest of the specification's paragraph defining it and the documents that cite
//! it. Amending that paragraph changes the digest, which fails this check and names the documents to
//! re-read. Re-recording the manifest is the deliberate act of saying they were read.
//!
//! **What it does not establish.** That a citing sentence is *correct* — only that nobody has changed
//! the text under it without looking. A document can cite an unchanged invariant and still say
//! something false about it, which is a judgement no digest reaches.
//!
//! **Where the boundary of "its text" is.** The paragraph beginning `**INV-…**` and ending at the next
//! blank line. Some definitions continue past it: INV-PRIM-01's does. Those continuations are outside
//! the digest, so an amendment confined to one would not fail this. The headline sentence is what a
//! citation usually rests on, and a rule a reader can apply by eye is worth more here than one that
//! guesses where a definition ends.

use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const SPEC: &str = "docs/TCU-02_CertiMining_Anchored_Log_v0.1.md";
const MANIFEST: &str = "docs/CITED-INVARIANTS.sha256";

/// Reads an `INV-FAMILY-NN` starting at `at`, or `None` if one does not start there.
fn identifier_at(text: &str, at: usize) -> Option<String> {
    let rest = text.get(at..)?;
    let tail = rest.strip_prefix("INV-")?;
    let family: String = tail.chars().take_while(char::is_ascii_uppercase).collect();
    if family.is_empty() {
        return None;
    }
    let after = tail.get(family.len()..)?.strip_prefix('-')?;
    let number: String = after.chars().take_while(char::is_ascii_digit).collect();
    if number.is_empty() {
        return None;
    }
    Some(format!("INV-{family}-{number}"))
}

/// Every `INV-` identifier appearing in `text`.
fn cited_in(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut at = 0usize;
    while let Some(rest) = text.get(at..) {
        let Some(hit) = rest.find("INV-") else { break };
        let start = at.saturating_add(hit);
        if let Some(ident) = identifier_at(text, start) {
            out.insert(ident);
        }
        at = start.saturating_add(4);
    }
    out
}

/// Each invariant the specification defines, and the digest of the paragraph defining it.
///
/// A definition opens a line with `**INV-…` and runs to the next blank line.
fn defined_in(spec: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut offset = 0usize;
    for line in spec.split_inclusive('\n') {
        if let Some(after) = line.strip_prefix("**") {
            if let Some(ident) = identifier_at(after, 0) {
                let end = spec
                    .get(offset..)
                    .and_then(|rest| rest.find("\n\n"))
                    .map(|i| offset.saturating_add(i))
                    .unwrap_or(spec.len());
                if let Some(paragraph) = spec.get(offset..end) {
                    out.insert(ident, format!("{:x}", Sha256::digest(paragraph.as_bytes())));
                }
            }
        }
        offset = offset.saturating_add(line.len());
    }
    out
}

/// Every Markdown file that may cite an invariant: everything but the specification and the archive.
fn documents(root: &Path) -> Vec<(String, String)> {
    let out = std::process::Command::new("git")
        .args(["ls-files", "-z", "*.md"])
        .current_dir(root)
        .output()
        .expect("git ls-files");
    assert!(out.status.success(), "git ls-files *.md failed");
    String::from_utf8(out.stdout)
        .expect("git ls-files is utf-8")
        .split('\0')
        .filter(|s| !s.is_empty())
        .filter(|s| *s != SPEC && *s != "docs/DECISIONS.md" && *s != MANIFEST)
        .map(|s| {
            let text = std::fs::read_to_string(root.join(s)).unwrap_or_default();
            (s.to_string(), text)
        })
        .collect()
}

/// What the repository cites right now: identifier, the specification's digest for it, and who cites it.
fn observed(root: &Path) -> (BTreeMap<String, String>, BTreeMap<String, BTreeSet<String>>) {
    let spec = std::fs::read_to_string(root.join(SPEC)).unwrap_or_else(|e| panic!("{SPEC}: {e}"));
    let defined = defined_in(&spec);
    let mut citers: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (name, text) in documents(root) {
        for ident in cited_in(&text) {
            citers.entry(ident).or_default().insert(name.clone());
        }
    }
    (defined, citers)
}

/// The manifest as text, so the generator and the check agree on one format.
pub fn render(root: &Path) -> String {
    let (defined, citers) = observed(root);
    let mut out = String::new();
    for (ident, who) in &citers {
        let digest = match defined.get(ident) {
            Some(d) => d,
            None => continue,
        };
        out.push_str(digest);
        out.push_str("  ");
        out.push_str(ident);
        out.push_str("  ");
        out.push_str(&who.iter().cloned().collect::<Vec<_>>().join(" "));
        out.push('\n');
    }
    out
}

/// Fails on every way the repository and the manifest disagree, naming the documents to re-read.
pub fn check_citations(root: &Path) {
    let (defined, citers) = observed(root);
    let recorded =
        std::fs::read_to_string(root.join(MANIFEST)).unwrap_or_else(|e| panic!("{MANIFEST}: {e}"));

    let mut manifest: BTreeMap<String, (String, BTreeSet<String>)> = BTreeMap::new();
    for line in recorded.lines().filter(|l| !l.trim().is_empty()) {
        let mut parts = line.split("  ");
        let (Some(digest), Some(ident), Some(who)) = (parts.next(), parts.next(), parts.next())
        else {
            panic!("{MANIFEST}: malformed line {line:?}");
        };
        manifest.insert(
            ident.to_string(),
            (
                digest.to_string(),
                who.split_whitespace().map(str::to_string).collect(),
            ),
        );
    }
    assert!(
        !manifest.is_empty(),
        "{MANIFEST} records nothing, so this check would pass on any specification at all"
    );

    let mut problems: Vec<String> = Vec::new();

    for (ident, who) in &citers {
        let Some(current) = defined.get(ident) else {
            problems.push(format!(
                "{ident} is cited by {} and the specification defines no such invariant",
                who.iter().cloned().collect::<Vec<_>>().join(", ")
            ));
            continue;
        };
        match manifest.get(ident) {
            None => problems.push(format!(
                "{ident} is cited by {} and is not in {MANIFEST}. Regenerate it, which records that \
                 those documents were read against the specification's current text.",
                who.iter().cloned().collect::<Vec<_>>().join(", ")
            )),
            Some((recorded_digest, recorded_who)) => {
                if recorded_digest != current {
                    problems.push(format!(
                        "{ident}'s paragraph in the specification has changed since {MANIFEST} was \
                         written. These documents cite it and have to be read against the new text: \
                         {}",
                        who.iter().cloned().collect::<Vec<_>>().join(", ")
                    ));
                }
                if recorded_who != who {
                    let added: Vec<_> = who.difference(recorded_who).cloned().collect();
                    let gone: Vec<_> = recorded_who.difference(who).cloned().collect();
                    problems.push(format!(
                        "{ident}'s citers have changed: {}{}{}",
                        if added.is_empty() {
                            String::new()
                        } else {
                            format!("{} now cites it", added.join(", "))
                        },
                        if added.is_empty() || gone.is_empty() {
                            ""
                        } else {
                            "; "
                        },
                        if gone.is_empty() {
                            String::new()
                        } else {
                            format!("{} no longer does", gone.join(", "))
                        }
                    ));
                }
            }
        }
    }

    for ident in manifest.keys() {
        if !citers.contains_key(ident) {
            problems.push(format!(
                "{MANIFEST} records {ident} and nothing cites it any more, so the entry is dead"
            ));
        }
    }

    if problems.is_empty() {
        println!(
            "citations: {} invariant(s) cited outside the specification, each against the text it \
             was read at",
            manifest.len()
        );
        println!(
            "citations: this says nobody changed the text under a citation, not that the citing \
             sentence is right — that is a judgement no digest reaches"
        );
        return;
    }
    for p in &problems {
        eprintln!("citations: {p}");
    }
    eprintln!(
        "citations: {} disagreement(s). `cargo xtask gen-citations` re-records the manifest, and \
         doing so is the statement that the documents above were read.",
        problems.len()
    );
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_identifier_is_read_only_where_one_starts() {
        assert_eq!(
            identifier_at("INV-ANCH-02", 0).as_deref(),
            Some("INV-ANCH-02")
        );
        assert_eq!(
            identifier_at("see INV-TREE-05 above", 4).as_deref(),
            Some("INV-TREE-05")
        );
        assert_eq!(identifier_at("INV-", 0), None, "a family is required");
        assert_eq!(identifier_at("INV-ANCH-", 0), None, "a number is required");
        assert_eq!(identifier_at("XINV-ANCH-02", 0), None);
    }

    #[test]
    fn citations_are_found_once_each_however_often_they_appear() {
        let found = cited_in("INV-ANCH-01 and INV-ANCH-01 again, plus INV-TREE-02.");
        assert_eq!(found.len(), 2);
        assert!(found.contains("INV-ANCH-01") && found.contains("INV-TREE-02"));
    }

    #[test]
    fn a_definition_is_its_paragraph_and_stops_at_the_blank_line() {
        let spec = "intro\n\n**INV-X-01.** The first line.\nStill the first paragraph.\n\nSomething else.\n";
        let defined = defined_in(spec);
        assert_eq!(defined.len(), 1);
        let only = defined.values().next().expect("one definition");
        let expected = format!(
            "{:x}",
            Sha256::digest("**INV-X-01.** The first line.\nStill the first paragraph.".as_bytes())
        );
        assert_eq!(
            only, &expected,
            "the digest covers the paragraph and not the text after the blank line"
        );
    }

    /// **The case this exists for.** Amending the text changes the digest.
    #[test]
    fn amending_an_invariants_text_changes_its_digest() {
        let before = defined_in("**INV-X-01.** The sequence may contain a gap.\n\n");
        let after = defined_in("**INV-X-01.** The sequence is contiguous by construction.\n\n");
        assert_ne!(
            before.get("INV-X-01"),
            after.get("INV-X-01"),
            "a corrected invariant has to read as changed, or nothing re-reads the documents citing it"
        );
    }

    #[test]
    fn the_repository_agrees_with_its_own_manifest() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("the workspace root is xtask's parent");
        let rendered = render(root);
        let recorded = std::fs::read_to_string(root.join(MANIFEST))
            .unwrap_or_else(|e| panic!("{MANIFEST}: {e}"));
        assert_eq!(
            rendered, recorded,
            "the committed manifest is not what the repository renders; run `cargo xtask gen-citations`"
        );
    }
}
