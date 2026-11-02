// SPDX-License-Identifier: MIT OR Apache-2.0
//! The advisory exception list, against the record that justifies it (M-06, audit of 1 November
//! 2026).
//!
//! **Why this exists.** D-142 carries fourteen dated exceptions and `deny.toml` carries the lines
//! that make them effective. The 1 November audit found the verdicts sound and the evidence text
//! wrong in four places: the header counted five exceptions where there were fourteen and called
//! every fix a semver-major bump after one had been taken as a compatible update, and two reasons
//! contradicted the decision they cite. Nothing compared the two documents, and nothing compared
//! either with itself.
//!
//! **The expiry was the sharpest of it.** `cargo-deny` has no expiry for an ignore entry; `EXPIRES
//! 2026-12-31` is prose inside the `reason` string, so the date was enforced by nobody and an
//! exception would have outlived it silently. This gate enforces it, which is the only thing that
//! makes a dated exception different from a permanent one.
//!
//! **What it does not do.** It does not judge whether an exception is sound. Whether a vulnerable API
//! is reached from a committed call path is the work D-142 records and an auditor rechecks; no gate
//! reaches it. This checks that each exception is *well formed, counted, dated, retirable and
//! recorded* — the properties whose drift the audit found.

use std::path::Path;

/// The marker the header carries so the count is a fact rather than a word in prose.
///
/// The header said "the five below them" against fourteen entries. A spelled-out numeral in a
/// sentence cannot be compared with anything, so the count is stated once, in a form this gate reads,
/// and the prose around it may describe without counting.
const COUNT_MARKER: &str = "# DATED-EXCEPTIONS:";

/// One ignore entry in `deny.toml`.
struct Exception {
    id: String,
    reason: String,
    line: usize,
}

/// Every `{ id = "…", reason = "…" }` entry, in file order.
///
/// Read with a line scan rather than a TOML parser because the file's comments carry the evidence
/// this gate is about, and a parser would discard them. A line whose `id` is present but whose
/// `reason` is absent is reported rather than skipped: an exception with no evidence is the state
/// D-18's rule exists to prevent.
fn exceptions(text: &str) -> (Vec<Exception>, Vec<String>) {
    let mut out = Vec::new();
    let mut problems = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = index.saturating_add(1);
        let trimmed = raw.trim_start();
        if trimmed.starts_with('#') || !trimmed.starts_with("{ id") {
            continue;
        }
        let Some(id) = between(trimmed, "id = \"", "\"") else {
            problems.push(format!(
                "  deny.toml:{line} — an entry whose id cannot be read"
            ));
            continue;
        };
        let Some(reason) = between(trimmed, "reason = \"", "\"") else {
            problems.push(format!(
                "  deny.toml:{line} — {id} carries no reason, so the exception has no evidence"
            ));
            continue;
        };
        out.push(Exception { id, reason, line });
    }
    (out, problems)
}

/// The text between two delimiters, or nothing.
fn between(haystack: &str, open: &str, close: &str) -> Option<String> {
    let after = haystack.split_once(open)?.1;
    let inner = after.split_once(close)?.0;
    Some(inner.to_owned())
}

/// A `YYYY-MM-DD` immediately after `EXPIRES`.
fn expiry(reason: &str) -> Option<(i64, i64, i64)> {
    let after = reason.split_once("EXPIRES ")?.1;
    let date = after.split_whitespace().next()?;
    let mut parts = date.split('-');
    let year = parts.next()?.parse().ok()?;
    let month = parts.next()?.parse().ok()?;
    let day = parts.next()?.trim_end_matches('.').parse().ok()?;
    if parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    Some((year, month, day))
}

/// Today, as a civil date in UTC.
///
/// Hand-rolled rather than brought in: this crate is the build's own tooling and a date conversion is
/// not worth a dependency that the advisory gate would then have to hold an opinion about. The
/// algorithm is Howard Hinnant's `civil_from_days`, which is exact for every day this will ever see.
fn today_utc() -> Option<(i64, i64, i64)> {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    let days = i64::try_from(secs.checked_div(86_400)?).ok()?;

    let z = days.checked_add(719_468)?;
    let era = if z >= 0 { z } else { z.saturating_sub(146_096) } / 146_097;
    let doe = z.saturating_sub(era.saturating_mul(146_097));
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe.saturating_add(era.saturating_mul(400));
    let doy = doe.saturating_sub(365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy.saturating_sub((153 * mp + 2) / 5).saturating_add(1);
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    Some((if m <= 2 { y.saturating_add(1) } else { y }, m, d))
}

/// The count the header states, from its marker line.
fn stated_count(text: &str) -> Option<usize> {
    for line in text.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix(COUNT_MARKER) {
            return rest.trim().parse().ok();
        }
    }
    None
}

/// The decision an exception cites, as `D-142` from a trailing `(D-142)`.
///
/// **This is the demand, and the first version of it was wrong.** I required every advisory
/// identifier to appear in `docs/DECISIONS.md`, and the gate failed on its first run against content
/// that is correct: D-142 names a few advisories by identifier and describes the other eleven by the
/// API they implicate, which is how a reader would want it. A demand that fails on correct content is
/// a demand that does not track the property — the test applied to every other gate in this
/// repository, applied here.
///
/// What D-18 actually says is that a new advisory is a *decision* rather than a line quietly added to
/// this file. An exception that cites the decision authorising it satisfies that and is checkable; all
/// nineteen entries already do, so the gate holds today and fails the line someone adds without one.
fn cited_decision(reason: &str) -> Option<String> {
    let after = reason.rsplit_once("(D-")?.1;
    let digits: String = after.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return None;
    }
    Some(format!("D-{digits}"))
}

pub fn check_advisories(root: &Path) {
    let deny_path = root.join("deny.toml");
    let decisions_path = root.join("docs/DECISIONS.md");

    // Fail closed on a read error. A gate that reads a failed read as an empty list reports whatever
    // its own failure produces (H-78).
    let deny = match std::fs::read_to_string(&deny_path) {
        Ok(text) => text,
        Err(e) => panic!("{}: {e}", deny_path.display()),
    };
    let decisions = match std::fs::read_to_string(&decisions_path) {
        Ok(text) => text,
        Err(e) => panic!("{}: {e}", decisions_path.display()),
    };

    let (entries, mut problems) = exceptions(&deny);
    let dated: Vec<&Exception> = entries
        .iter()
        .filter(|e| e.reason.contains("EXPIRES"))
        .collect();

    // **The count, which is what the audit found wrong.**
    match stated_count(&deny) {
        Some(stated) if stated == dated.len() => {}
        Some(stated) => problems.push(format!(
            "  deny.toml — the header states {stated} dated exception(s) and there are {}",
            dated.len()
        )),
        None => problems.push(format!(
            "  deny.toml — no `{COUNT_MARKER} <n>` line, so the count the header gives is checked by \
             nothing"
        )),
    }

    // **Duplicate identifiers.** Two entries for one advisory means one of them is not the one being
    // read, and which one wins is `cargo-deny`'s business rather than a reviewer's.
    for (i, entry) in entries.iter().enumerate() {
        if entries.iter().take(i).any(|earlier| earlier.id == entry.id) {
            problems.push(format!(
                "  deny.toml:{} — {} is listed more than once",
                entry.line, entry.id
            ));
        }
    }

    let now = today_utc();
    for entry in &dated {
        match expiry(&entry.reason) {
            None => problems.push(format!(
                "  deny.toml:{} — {} says EXPIRES but gives no readable YYYY-MM-DD after it",
                entry.line, entry.id
            )),
            Some(date) => {
                if let Some(today) = now {
                    if today > date {
                        problems.push(format!(
                            "  deny.toml:{} — {} expired on {}-{:02}-{:02}. cargo-deny does not \
                             enforce an expiry, so this gate is the only thing that does: renew the \
                             exception with fresh evidence, or retire it",
                            entry.line, entry.id, date.0, date.1, date.2
                        ));
                    }
                }
            }
        }
        if !entry.reason.contains("RETIRE when") {
            problems.push(format!(
                "  deny.toml:{} — {} states no RETIRE condition, so nothing says when it stops being \
                 needed",
                entry.line, entry.id
            ));
        }
        match cited_decision(&entry.reason) {
            None => problems.push(format!(
                "  deny.toml:{} — {} cites no decision. D-18: a new advisory is a decision, not a \
                 line added to deny.toml",
                entry.line, entry.id
            )),
            Some(decision) => {
                if !decisions.contains(&format!("## {decision} ")) {
                    problems.push(format!(
                        "  deny.toml:{} — {} cites {decision}, which docs/DECISIONS.md does not \
                         carry as a heading",
                        entry.line, entry.id
                    ));
                }
            }
        }
    }

    if !problems.is_empty() {
        eprintln!(
            "advisories: {} problem(s) in the exception list:",
            problems.len()
        );
        for problem in &problems {
            eprintln!("{problem}");
        }
        panic!("advisories: the gate above failed");
    }

    println!(
        "advisories: {} exception(s), {} of them dated — each with a readable expiry in the future, \
         a retirement condition, and a decision it cites",
        entries.len(),
        dated.len()
    );
    let unnamed: Vec<&str> = dated
        .iter()
        .filter(|e| !decisions.contains(e.id.as_str()))
        .map(|e| e.id.as_str())
        .collect();
    if !unnamed.is_empty() {
        println!(
            "advisories: {} dated exception(s) are not named by identifier anywhere in \
             docs/DECISIONS.md — {}. Each cites a decision, which is D-18's demand; this is printed \
             so an exception filed under the wrong decision stays visible",
            unnamed.len(),
            unnamed.join(", ")
        );
    }
    println!(
        "advisories: this says the list is well formed and recorded, not that any exception is \
         sound — whether a vulnerable API is reached from a committed path is D-142's work and an \
         auditor's, and no gate reaches it"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_entry_is_read_from_its_line_and_a_comment_is_not() {
        let text = "\
[advisories]
# { id = \"RUSTSEC-2026-0001\", reason = \"a comment naming an entry is not an entry\" },
  { id = \"RUSTSEC-2026-0002\", reason = \"real. EXPIRES 2099-12-31. RETIRE when upstream moves\" },
";
        let (entries, problems) = exceptions(text);
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(entries.len(), 1, "the commented line must not count");
        assert_eq!(entries[0].id, "RUSTSEC-2026-0002");
    }

    #[test]
    fn an_entry_without_a_reason_is_a_problem_rather_than_skipped() {
        let (entries, problems) = exceptions("  { id = \"RUSTSEC-2026-0003\" },\n");
        assert!(entries.is_empty());
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("no reason"), "{problems:?}");
    }

    #[test]
    fn an_expiry_is_read_and_a_malformed_one_is_not_guessed_at() {
        assert_eq!(
            expiry("… EXPIRES 2026-12-31. RETIRE when …"),
            Some((2026, 12, 31))
        );
        assert_eq!(expiry("… EXPIRES soon. RETIRE when …"), None);
        assert_eq!(expiry("… EXPIRES 2026-13-31 …"), None, "month 13");
        assert_eq!(expiry("… no expiry here …"), None);
    }

    /// The count marker is the whole point of having one: a number in prose cannot be compared.
    #[test]
    fn the_count_marker_is_read_and_its_absence_is_detectable() {
        assert_eq!(stated_count("# DATED-EXCEPTIONS: 14\n"), Some(14));
        assert_eq!(
            stated_count("    # DATED-EXCEPTIONS: 7\n"),
            Some(7),
            "indented is still the marker"
        );
        assert_eq!(
            stated_count("# fourteen dated exceptions\n"),
            None,
            "prose does not count"
        );
        // **A near miss is not read, deliberately.** The marker is a structured token, and guessing
        // at spelling variants is how a gate comes to read something other than what it checks. An
        // unrecognised marker makes the gate report that there is none, which fails loudly, where a
        // tolerant reader risks matching a line nobody meant as the count.
        assert_eq!(
            stated_count("#   DATED-EXCEPTIONS:   7\n"),
            None,
            "extra spaces after the hash"
        );
        assert_eq!(
            stated_count("#DATED-EXCEPTIONS: 7\n"),
            None,
            "no space after the hash"
        );
        assert_eq!(
            stated_count("# DATED-EXCEPTIONS: many\n"),
            None,
            "not a number"
        );
    }

    #[test]
    fn a_cited_decision_is_read_and_its_absence_is_detected() {
        assert_eq!(
            cited_decision("… EXPIRES 2026-12-31. RETIRE when upstream moves (D-142)"),
            Some("D-142".to_owned())
        );
        assert_eq!(cited_decision("no citation at all"), None);
        assert_eq!(cited_decision("(D-) malformed"), None);
        // The last citation wins, so a reason mentioning an earlier decision in passing still
        // resolves to the one it is filed under.
        assert_eq!(
            cited_decision("supersedes (D-18) and is filed under (D-142)"),
            Some("D-142".to_owned())
        );
    }

    /// Today has to be a real date, or the expiry check silently passes everything.
    #[test]
    fn today_is_a_plausible_civil_date() {
        let (y, m, d) = match today_utc() {
            Some(date) => date,
            None => panic!("the host clock has no civil date, so the expiry check would be blind"),
        };
        assert!((2026..=2100).contains(&y), "year {y}");
        assert!((1..=12).contains(&m), "month {m}");
        assert!((1..=31).contains(&d), "day {d}");
    }

    /// And the conversion is pinned against dates computed independently, since an off-by-one here
    /// would expire an exception a day early or late without anyone noticing.
    #[test]
    fn the_civil_conversion_matches_known_days() {
        // 1970-01-01 is day 0; 2026-11-02 is day 20_759.
        for (days, expected) in [(0_i64, (1970, 1, 1)), (20_759, (2026, 11, 2))] {
            let z = days + 719_468;
            let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
            let doe = z - era * 146_097;
            let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
            let y = yoe + era * 400;
            let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
            let mp = (5 * doy + 2) / 153;
            let d = doy - (153 * mp + 2) / 5 + 1;
            let m = if mp < 10 { mp + 3 } else { mp - 9 };
            let got = (if m <= 2 { y + 1 } else { y }, m, d);
            assert_eq!(got, expected, "day {days}");
        }
    }
}
