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

/// The only identifiers D-18 permits to carry no expiry, as a closed list (M-10, issue #331).
///
/// **Why a list and not a shape test.** The gate enforced its controls over the entries whose reason
/// already said `EXPIRES`, so an entry that simply omitted the word avoided every one of them: the
/// audit added a new `RUSTSEC-2099-9999` with no expiry, no retirement condition and no decision, and
/// the gate exited 0 reporting twenty exceptions of which fourteen were dated. Classifying by what an
/// entry happens to say lets the entry choose its own class.
///
/// These five are `unmaintained` advisories reached only through `litesvm`, the test runtime, and
/// never shipped. Adding a sixth is a decision, which is D-18's whole point, and it has to be made
/// here rather than in `deny.toml`.
const UNDATED_BY_D18: [&str; 5] = [
    "RUSTSEC-2024-0436",
    "RUSTSEC-2025-0161",
    "RUSTSEC-2021-0139",
    "RUSTSEC-2024-0388",
    "RUSTSEC-2025-0141",
];

/// The header line stating how many exceptions there are in total.
const TOTAL_MARKER: &str = "# EXCEPTIONS:";

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
    // **Inside the array, every line is an entry or a problem (M-10, issue #331).** The scan skipped
    // anything not starting with `{ id`, so a valid TOML entry written another way — `{id =`, or one
    // spread over two lines — was read by `cargo-deny` and by nothing here. Tracking the array's
    // bounds costs two comparisons and turns a silent skip into a refusal.
    let mut inside = false;
    for (index, raw) in text.lines().enumerate() {
        let line = index.saturating_add(1);
        let trimmed = raw.trim_start();
        if !inside {
            inside = trimmed.starts_with("ignore = [");
            continue;
        }
        if trimmed.starts_with(']') {
            inside = false;
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if !trimmed.starts_with("{ id") {
            problems.push(format!(
                "  deny.toml:{line} — inside the ignore array and not an entry this gate can read: \
                 {trimmed:?}. cargo-deny may still honour it, so it cannot be skipped here"
            ));
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
    marked_count(text, COUNT_MARKER)
}

/// Entries that belong to neither class, and allowlisted identifiers the file no longer holds.
///
/// **A seam, because the classification had no test without one (M-10, issue #331).** The check lived
/// inside `check_advisories`, which reads the real `deny.toml` and panics, so no unit test could hand
/// it a synthetic entry — and CI only ever runs it against the clean file. Removing the check would
/// have gone unnoticed by every test, which is the shape of the defect this is fixing.
///
/// An entry that is not dated must be one of D-18's five. Otherwise a new exception enters the
/// dependency policy with no expiry, no retirement condition and no decision: the governance failure
/// the gate exists to prevent, and the one the 2 November audit walked straight through.
fn unclassified(entries: &[Exception]) -> Vec<String> {
    let mut problems = Vec::new();
    for entry in entries {
        if entry.reason.contains("EXPIRES") || UNDATED_BY_D18.contains(&entry.id.as_str()) {
            continue;
        }
        problems.push(format!(
            "  deny.toml:{} — {} carries no EXPIRES and is not one of D-18's five undated \
             unmaintained exceptions. A new advisory is a decision: date it with a retirement \
             condition and a decision it cites, or record the decision that adds it to \
             UNDATED_BY_D18",
            entry.line, entry.id
        ));
    }
    // An allowlist naming something the file no longer holds is a record nobody re-checked, which is
    // the same defect in the other direction.
    for id in UNDATED_BY_D18 {
        if !entries.iter().any(|e| e.id == id) {
            problems.push(format!(
                "  deny.toml — {id} is permitted to be undated and is no longer listed, so the \
                 allowlist is stale"
            ));
        }
    }
    problems
}

/// The number a named header marker states, or nothing.
///
/// Two markers now, because checking only the dated subset let an undated entry be added with no
/// evidence change anywhere (M-10, issue #331). `# DATED-EXCEPTIONS:` is not a prefix of
/// `# EXCEPTIONS:`, so neither marker reads the other's line.
fn marked_count(text: &str, marker: &str) -> Option<usize> {
    for line in text.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix(marker) {
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

    problems.extend(unclassified(&entries));

    // **The total, not only the dated subset.** The dated count alone meant an undated entry could
    // be added with no corresponding evidence change anywhere.
    match marked_count(&deny, TOTAL_MARKER) {
        Some(stated) if stated == entries.len() => {}
        Some(stated) => problems.push(format!(
            "  deny.toml — the header states {stated} exception(s) in total and there are {}",
            entries.len()
        )),
        None => problems.push(format!(
            "  deny.toml — no `{TOTAL_MARKER} <n>` line, so the total is checked by nothing"
        )),
    }

    // **The dated count, which is what the 1 November audit found wrong.**
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

    /// The fixtures below carry `ignore = [` and its `]`, which they did not before M-10 (issue
    /// #331). The scan now reads entries only inside that array, so a fixture without it describes a
    /// file shape `deny.toml` never has — and both of these fixtures had exactly that shape.
    #[test]
    fn an_entry_is_read_from_its_line_and_a_comment_is_not() {
        let text = "\
[advisories]
ignore = [
# { id = \"RUSTSEC-2026-0001\", reason = \"a comment naming an entry is not an entry\" },
  { id = \"RUSTSEC-2026-0002\", reason = \"real. EXPIRES 2099-12-31. RETIRE when upstream moves\" },
]
";
        let (entries, problems) = exceptions(text);
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(entries.len(), 1, "the commented line must not count");
        assert_eq!(entries[0].id, "RUSTSEC-2026-0002");
    }

    #[test]
    fn an_entry_without_a_reason_is_a_problem_rather_than_skipped() {
        let (entries, problems) = exceptions("ignore = [\n  { id = \"RUSTSEC-2026-0003\" },\n]\n");
        assert!(entries.is_empty());
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("no reason"), "{problems:?}");
    }

    /// **An entry the scan cannot read is refused, not skipped (M-10, issue #331).** The scan passed
    /// over anything not starting with `{ id`, so a valid TOML entry written another way was honoured
    /// by cargo-deny and read by nothing here.
    #[test]
    fn a_line_inside_the_array_that_is_not_an_entry_is_a_problem() {
        let text = "ignore = [\n  {id = \"RUSTSEC-2026-0004\", reason = \"no space\"},\n]\n";
        let (entries, problems) = exceptions(text);
        assert!(entries.is_empty());
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            problems[0].contains("not an entry this gate can read"),
            "{problems:?}"
        );
    }

    /// And the array's own punctuation is not an entry, or every file would report two problems.
    #[test]
    fn the_arrays_brackets_and_blank_lines_are_not_entries() {
        let text = "# a header\nignore = [\n\n  # a note\n]\n[bans]\nmulti = \"deny\"\n";
        let (entries, problems) = exceptions(text);
        assert_eq!(entries.len(), 0, "nothing in that text is an entry");
        assert!(problems.is_empty(), "{problems:?}");
    }

    /// **The five undated identifiers are a closed list, and it is the real one.** A sixth undated
    /// entry is what the 2 November audit added to pass the gate; the classification below is what
    /// refuses it, and this pins the list the classification reads against `deny.toml` itself so the
    /// two cannot drift.
    #[test]
    fn every_undated_identifier_in_deny_toml_is_one_of_d18s_five() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .map(std::path::Path::to_path_buf);
        let root = match root {
            Some(r) => r,
            None => panic!("the workspace root is the manifest's parent"),
        };
        let deny = match std::fs::read_to_string(root.join("deny.toml")) {
            Ok(text) => text,
            Err(e) => panic!("deny.toml: {e}"),
        };
        let (entries, problems) = exceptions(&deny);
        assert!(problems.is_empty(), "{problems:?}");
        let undated: Vec<&str> = entries
            .iter()
            .filter(|e| !e.reason.contains("EXPIRES"))
            .map(|e| e.id.as_str())
            .collect();
        assert_eq!(
            undated.len(),
            UNDATED_BY_D18.len(),
            "deny.toml holds {} undated exception(s) and D-18 permits {}: {undated:?}",
            undated.len(),
            UNDATED_BY_D18.len()
        );
        for id in &undated {
            assert!(
                UNDATED_BY_D18.contains(id),
                "{id} carries no expiry and is not one of D-18's five"
            );
        }
    }

    /// Both counts are read, and neither marker reads the other's line.
    #[test]
    fn the_total_and_dated_markers_are_separate() {
        let text = "# EXCEPTIONS: 19\n# DATED-EXCEPTIONS: 14\n";
        assert_eq!(marked_count(text, TOTAL_MARKER), Some(19));
        assert_eq!(stated_count(text), Some(14));
        assert_eq!(
            marked_count("# DATED-EXCEPTIONS: 14\n", TOTAL_MARKER),
            None,
            "the dated marker is not the total marker"
        );
    }

    /// **The audit's mutation, as a test (M-10, issue #331).** A new undated entry with no expiry,
    /// no retirement condition and no decision is what passed the gate at `98bf09c`.
    #[test]
    fn a_new_undated_entry_is_refused() {
        let entries = vec![
            Exception {
                id: "RUSTSEC-2099-9999".to_string(),
                reason: "new vulnerability exception without an expiry".to_string(),
                line: 38,
            },
            Exception {
                id: UNDATED_BY_D18[0].to_string(),
                reason: "unmaintained; reached only through litesvm (D-18)".to_string(),
                line: 32,
            },
        ];
        let problems = unclassified(&entries);
        let refusal = problems
            .iter()
            .filter(|p| p.contains("RUSTSEC-2099-9999"))
            .count();
        assert_eq!(
            refusal, 1,
            "the new undated entry must be refused: {problems:?}"
        );
        assert!(
            !problems.iter().any(|p| p.contains(UNDATED_BY_D18[0])),
            "one of D-18's five is permitted to be undated: {problems:?}"
        );
    }

    /// A dated entry is classified whether or not it is on the allowlist.
    #[test]
    fn a_dated_entry_needs_no_allowlist_entry() {
        let entries = vec![Exception {
            id: "RUSTSEC-2026-1234".to_string(),
            reason: "reached. EXPIRES 2099-12-31. RETIRE when upstream moves (D-142)".to_string(),
            line: 40,
        }];
        let problems = unclassified(&entries);
        assert!(
            !problems.iter().any(|p| p.contains("RUSTSEC-2026-1234")),
            "{problems:?}"
        );
    }

    /// And an allowlisted identifier the file no longer holds is reported, so the list cannot rot.
    #[test]
    fn an_allowlisted_identifier_that_is_gone_is_reported() {
        let problems = unclassified(&[]);
        assert_eq!(
            problems.len(),
            UNDATED_BY_D18.len(),
            "every missing allowlist entry is named: {problems:?}"
        );
        assert!(
            problems.iter().all(|p| p.contains("allowlist is stale")),
            "{problems:?}"
        );
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
