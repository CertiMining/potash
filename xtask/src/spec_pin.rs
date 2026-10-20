// SPDX-License-Identifier: MIT OR Apache-2.0
//! The specification pin in `ts/README.md`, checked against the specification (H-48, issue #163).
//!
//! **Why this exists.** E-11's verifier was written from TCU-02 alone, so which TCU-02 is the whole
//! of what its findings are about. `ts/README.md` pins that: a version, a SHA-256 and a line count.
//!
//! The pin exists because an earlier one named a hash no committed version of the specification has
//! ever had — a pin a reader cannot resolve, which that file records about itself. Nothing checked
//! the replacement either. It has been correct since only because it was recomputed by hand on each
//! amendment, which is correctness by diligence rather than by construction, and diligence is what
//! the rest of this repository stopped relying on after H-36.
//!
//! **What it refuses to do is pass quietly.** A pin that cannot be found is a failure here, not a
//! clean run: rewording the sentence would otherwise disable the check and report success, which is
//! the defect this repository keeps filing.

use sha2::{Digest, Sha256};
use std::path::Path;

/// Where the specification lives. One place, so a rename fails loudly rather than being searched for.
const SPEC: &str = "docs/TCU-02_CertiMining_Anchored_Log_v0.1.md";

/// The sentence the pin is written in. Matched literally, so a rewrite is a failure rather than a
/// silent miss.
const ANCHOR: &str = "The specification as committed today is ";

/// What `ts/README.md` claims about the specification.
#[derive(Debug, PartialEq, Eq)]
pub struct Pin {
    pub version: String,
    pub sha256: String,
    pub lines: usize,
}

/// Collapses every run of whitespace to one space, so a sentence wrapped across lines reads as one.
fn flatten(markdown: &str) -> String {
    markdown.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Reads the pin out of `ts/README.md`'s text.
///
/// Every failure names what it could not find. A pin half-read is not a pin.
pub fn pin_from(markdown: &str) -> Result<Pin, String> {
    let flat = flatten(markdown);
    let at = flat
        .find(ANCHOR)
        .ok_or_else(|| format!("ts/README.md no longer contains the sentence {ANCHOR:?}, so the pin cannot be read and nothing about it is checked"))?;
    let rest = flat
        .get(at.saturating_add(ANCHOR.len())..)
        .ok_or("the pin sentence is at the end of the file with nothing after it")?;

    // **v0.2.3**, SHA-256 `<64 hex>`, 854 lines.
    let version = rest
        .strip_prefix("**")
        .and_then(|r| r.split_once("**"))
        .map(|(v, _)| v.to_string())
        .ok_or("the pin's version is not in bold where the sentence puts it")?;

    let sha256 = rest
        .split_once("SHA-256 `")
        .and_then(|(_, r)| r.split_once('`'))
        .map(|(h, _)| h.to_string())
        .ok_or("the pin carries no SHA-256 in backticks")?;
    if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "the pin's SHA-256 is {sha256:?}, which is not 64 hex characters"
        ));
    }

    let lines = rest
        .split_once("`, ")
        .and_then(|(_, r)| r.split_once(" lines"))
        .and_then(|(n, _)| n.replace(',', "").parse::<usize>().ok())
        .ok_or("the pin carries no line count before the word \"lines\"")?;

    Ok(Pin {
        version,
        sha256,
        lines,
    })
}

/// The specification's own version line, which is its third line.
fn version_of(spec: &str) -> Result<String, String> {
    let line = spec
        .lines()
        .find(|l| l.starts_with("**Version "))
        .ok_or("the specification carries no line beginning \"**Version \"")?;
    let rest = line
        .strip_prefix("**Version ")
        .ok_or("the version line lost its prefix between finding it and reading it")?;
    let number = rest
        .split_whitespace()
        .next()
        .ok_or("the version line names no version")?;
    Ok(format!("v{number}"))
}

/// Adds a problem for every way the pin and the specification disagree.
pub fn check_spec_pin(root: &Path, problems: &mut Vec<String>) {
    let readme = match std::fs::read_to_string(root.join("ts/README.md")) {
        Ok(text) => text,
        Err(e) => {
            problems.push(format!("ts/README.md: {e}"));
            return;
        }
    };
    let spec = match std::fs::read_to_string(root.join(SPEC)) {
        Ok(text) => text,
        Err(e) => {
            problems.push(format!("{SPEC}: {e}"));
            return;
        }
    };

    let pin = match pin_from(&readme) {
        Ok(pin) => pin,
        Err(e) => {
            problems.push(e);
            return;
        }
    };

    let actual_sha = format!("{:x}", Sha256::digest(spec.as_bytes()));
    if pin.sha256 != actual_sha {
        problems.push(format!(
            "ts/README.md pins SHA-256 {} and {SPEC} hashes to {actual_sha}",
            pin.sha256
        ));
    }

    let actual_lines = spec.lines().count();
    if pin.lines != actual_lines {
        problems.push(format!(
            "ts/README.md pins {} lines and {SPEC} has {actual_lines}",
            pin.lines
        ));
    }

    match version_of(&spec) {
        Ok(actual) if actual != pin.version => problems.push(format!(
            "ts/README.md pins {} and {SPEC} says {actual}",
            pin.version
        )),
        Ok(_) => {}
        Err(e) => problems.push(format!("{SPEC}: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "The specification as\ncommitted today is **v0.2.3**, SHA-256 \
                        `8b83556ffd6b080f4ff39ed97e5649ea98fee09f8e299d01a74ccccfeabdf86c`,\n\
                        854 lines. v0.2.1 added V-P-13.";

    #[test]
    fn the_pin_reads_across_the_line_breaks_it_is_wrapped_at() {
        assert_eq!(
            pin_from(GOOD),
            Ok(Pin {
                version: "v0.2.3".into(),
                sha256: "8b83556ffd6b080f4ff39ed97e5649ea98fee09f8e299d01a74ccccfeabdf86c".into(),
                lines: 854,
            }),
            "the sentence wraps in the file, so the reader has to flatten it rather than match a line"
        );
    }

    /// **The failure that matters.** A check that reports success on a document it could not read is
    /// the defect this module exists against.
    #[test]
    fn a_missing_pin_is_a_failure_and_not_a_clean_run() {
        let reworded = "The spec committed today is v0.2.3 with hash abc.";
        let problem = pin_from(reworded).expect_err("a reworded pin must not parse");
        assert!(
            problem.contains("no longer contains the sentence"),
            "the failure has to say the sentence moved, or a reader will look for a hash mismatch \
             that is not there: {problem}"
        );
    }

    #[test]
    fn a_pin_missing_any_of_its_three_parts_is_refused() {
        for (missing, text) in [
            (
                "version",
                "The specification as committed today is v0.2.3, SHA-256 `aa`, 1 lines.",
            ),
            (
                "hash",
                "The specification as committed today is **v0.2.3**, 854 lines.",
            ),
            (
                "line count",
                "The specification as committed today is **v0.2.3**, SHA-256 \
                 `8b83556ffd6b080f4ff39ed97e5649ea98fee09f8e299d01a74ccccfeabdf86c`.",
            ),
        ] {
            assert!(
                pin_from(text).is_err(),
                "a pin with no {missing} parsed instead of being refused"
            );
        }
    }

    #[test]
    fn a_hash_that_is_not_64_hex_characters_is_refused() {
        let short = GOOD.replace(
            "8b83556ffd6b080f4ff39ed97e5649ea98fee09f8e299d01a74ccccfeabdf86c",
            "8b83556f",
        );
        assert!(pin_from(&short).is_err(), "a short hash is not a hash");
    }

    #[test]
    fn the_repository_pin_matches_the_specification() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("the workspace root is xtask's parent");
        let mut problems = Vec::new();
        check_spec_pin(root, &mut problems);
        assert!(
            problems.is_empty(),
            "the committed pin disagrees with the committed specification: {problems:?}"
        );
    }

    #[test]
    fn the_version_line_is_read_from_the_specification_itself() {
        assert_eq!(
            version_of("# T\n\n**Version 0.2.3 · Supersedes TCU-01**\n"),
            Ok("v0.2.3".into())
        );
        assert!(version_of("# T\n\nno version here\n").is_err());
    }
}
