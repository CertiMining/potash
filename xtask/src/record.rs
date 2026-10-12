// SPDX-License-Identifier: MIT OR Apache-2.0
//! The deployment record, checked against the files it describes (H-36).
//!
//! **Why this exists.** On 7 October three statements about the announced deployment were false at the
//! same commit, and each had been true when it was written. The README said anchor B had completed
//! five cycles while the chain held nine. `docs/anchoring.md` said every attached receipt was epochs
//! 20723 to 20727 and that 20728's was neither committed nor attached, when 20728 through 20730 were
//! both — and that sentence was itself the correction of an earlier overstatement. The cadence
//! paragraph said the cadence had been missed twice and caught up each time, two days after a third
//! miss. Nothing edited any of them. The sequence advanced underneath them.
//!
//! A hand-kept record of a live deployment is wrong by default after any cycle, and the direction is
//! not predictable: two of those three understated and one overstated. So the parts a machine can
//! check are checked here.
//!
//! **What this covers.** Only what is in the repository: the committed receipts, the two tables in
//! `docs/anchoring.md`, and the count the README states in prose. Every receipt digest is recomputed
//! from the committed bytes, so a row cannot name a digest the file does not produce.
//!
//! **What it does not.** It never reads the chain, so it cannot tell you the record is *current* —
//! only that it is internally consistent. A table that is complete, correct and two epochs behind
//! passes here. `scripts/live-values-from-chain.py` is what compares against the chain, and it reads
//! values rather than prose.

use certimining_core::{Hasher, NativeKeccak, TAG_RCPT};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

/// One row of the epoch table: what anchors the deployment claims for an epoch.
#[derive(Debug)]
struct EpochRow {
    epoch: u64,
    receipt: Option<String>,
    status: String,
}

/// One row of the receipt table: a committed file, its size, its hash, and the digest on chain.
#[derive(Debug)]
struct ReceiptRow {
    epoch: u64,
    path: String,
    bytes: usize,
    sha256: String,
    digest: String,
}

/// Splits a markdown table row into its cells, with the surrounding pipes and whitespace gone.
fn cells(line: &str) -> Vec<String> {
    line.trim()
        .trim_start_matches('|')
        .trim_end_matches('|')
        .split('|')
        .map(|c| c.trim().trim_matches('`').trim().to_string())
        .collect()
}

/// `1,459` and `1459` both mean the same number of bytes; the tables are written for a reader.
fn number(cell: &str) -> Option<usize> {
    cell.replace(',', "").parse().ok()
}

/// Reads both tables out of `docs/anchoring.md` by their column count and their first cell.
///
/// Matching on shape rather than on a heading means a table that moves in the document is still
/// found, and a row added to the wrong table is caught by the checks below rather than silently
/// parsed as the other kind.
/// The epoch table's header, cell for cell, lowercased.
const EPOCH_HEADER: [&str; 6] = [
    "epoch",
    "root",
    "anchor a, slot",
    "anchor b",
    "receipt",
    "status",
];

/// The receipt table's header, cell for cell, lowercased.
const RECEIPT_HEADER: [&str; 5] = [
    "epoch",
    "receipt",
    "bytes",
    "sha256 of the file",
    "digest attached on chain",
];

/// A table's own furniture: the header, and the `|---|---|` rule under it.
///
/// **Recognised by the whole header, not by its first cell (review of PR #121, M-01).** This used to
/// return true for any row whose first cell was `epoch` under case folding, so changing the live row
/// for 20736 from `20736` to `Epoch` turned that row into furniture. It left the table; the thirteen
/// `dual` rows above it were still contiguous; `check-record` printed `13 epoch rows` where it had
/// printed 14 and exited 0.
///
/// A row that calls itself the header and is believed is the same defect as a row that calls itself
/// `epoch-20735` and is skipped — the one the malformed-row report below exists for — reached through
/// the one line that still mapped an unreadable epoch onto "not a data row". Both headers are now
/// matched entire, so a row can only be furniture by being the furniture. If a header is ever
/// reworded, every row in that table is reported as malformed, which is loud and is the right
/// direction: a table this cannot find is a table it cannot check.
fn is_furniture(cells: &[String]) -> bool {
    let header = |expected: &[&str]| {
        cells.len() == expected.len()
            && cells
                .iter()
                .zip(expected)
                .all(|(c, e)| c.eq_ignore_ascii_case(e))
    };
    header(&EPOCH_HEADER)
        || header(&RECEIPT_HEADER)
        || cells
            .iter()
            .all(|c| !c.is_empty() && c.chars().all(|ch| ch == '-' || ch == ':'))
}

/// **A row that does not parse is reported, not skipped (review of da87ce5, M-01).**
///
/// Both of these used to `continue`: an epoch cell that is not a number, and a byte count that is
/// not one. A review changed `20735` to `epoch-20735` and the row left the table as far as every
/// check downstream was concerned, while `check-record` exited 0 — the same shape this module was
/// written against, in the module written against it.
///
/// A line beginning with `|` in a five- or six-cell table is a row unless it is the header or the
/// rule beneath it. If it is a row, it owes a readable epoch, and a receipt row owes a readable
/// size.
fn parse(markdown: &str) -> (Vec<EpochRow>, Vec<ReceiptRow>, Vec<String>) {
    let mut epochs = Vec::new();
    let mut receipts = Vec::new();
    let mut malformed = Vec::new();
    for (number_of, line) in markdown.lines().enumerate() {
        if !line.trim_start().starts_with('|') {
            continue;
        }
        let c = cells(line);
        if !matches!(c.len(), 5 | 6) || is_furniture(&c) {
            continue;
        }
        let Some(epoch) = c.first().and_then(|f| f.parse::<u64>().ok()) else {
            malformed.push(format!(
                "docs/anchoring.md line {}: {:?} is not an epoch, and the row is in a table whose \
                 rows are checked, so it would have left the table unnoticed",
                number_of + 1,
                c.first().cloned().unwrap_or_default()
            ));
            continue;
        };
        match c.len() {
            // Epoch | Root | Anchor A, slot | Anchor B | Receipt | Status
            6 => epochs.push(EpochRow {
                epoch,
                receipt: (!c[4].starts_with('*')).then(|| c[4].clone()),
                status: c[5].clone(),
            }),
            // Epoch | Receipt | Bytes | sha256 of the file | Digest attached on chain
            5 => match number(&c[2]) {
                Some(bytes) => receipts.push(ReceiptRow {
                    epoch,
                    path: c[1].clone(),
                    bytes,
                    sha256: c[3].clone(),
                    digest: c[4].clone(),
                }),
                None => malformed.push(format!(
                    "docs/anchoring.md line {}: epoch {epoch}'s receipt row gives its size as {:?}, \
                     which is not a number of bytes",
                    number_of + 1,
                    c[2]
                )),
            },
            _ => {}
        }
    }
    (epochs, receipts, malformed)
}

/// §2.5's receipt digest: `Keccak256(TAG_RCPT ‖ len(receipt) ‖ receipt)`, the length a little-endian
/// `u16`. The same construction `certimining-client` attaches, transcribed here so a row is checked
/// against the document rather than against the code that wrote it.
fn receipt_digest(receipt: &[u8]) -> Option<String> {
    let len = u16::try_from(receipt.len()).ok()?;
    let mut preimage = Vec::with_capacity(receipt.len() + 10);
    preimage.extend_from_slice(&TAG_RCPT);
    preimage.extend_from_slice(&len.to_le_bytes());
    preimage.extend_from_slice(receipt);
    let d = NativeKeccak::hashv(&[&preimage]);
    Some(format!(
        "0x{}",
        d.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ))
}

/// Checks the record against the files, and exits non-zero naming every disagreement.
/// Collapses runs of whitespace so a claim that wraps across lines is still one sentence.
fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The text between `after` and `until`, if both are present in that order.
fn between<'a>(haystack: &'a str, after: &str, until: &str) -> Option<&'a str> {
    let start = haystack.find(after)? + after.len();
    let rest = &haystack[start..];
    let end = rest.find(until)?;
    Some(&rest[..end])
}

/// The days a publication was owed and did not come, derived from the chain's own timestamps.
///
/// **Derived, not transcribed (H-42, #127).** Two counts in `docs/anchoring.md` were wrong on
/// 12 October and nothing here could have said so: this function read the README's cycle count
/// against the `dual` rows and no other prose at all. The cadence paragraph claimed three misses and
/// named the first three, having been stale since day 20735 — a day, a miss, and then another of
/// each. The README said four. Both were written by hand and neither was checked.
///
/// `LIVE-VALUES.txt` holds every epoch's `published_unix`, and
/// `scripts/live-values-from-chain.py` fails closed unless that list holds every value the chain
/// carries, so the timestamps here are reconciled against devnet by a different gate than this one.
/// An epoch whose publication landed on a later UTC day than its own number was paid late, which is
/// what both documents mean by a missed day.
///
/// The log's first epoch is excluded, as both documents say and for the reason they give: a log's
/// first publishable epoch is its `start_epoch`, and that day had already turned before the program
/// existed. Excluding it by position rather than by number means the carve-out does not need
/// editing when the log is older.
fn missed_days(root: &Path) -> Result<Vec<u64>, String> {
    let listing = std::fs::read_to_string(root.join("LIVE-VALUES.txt"))
        .map_err(|e| format!("LIVE-VALUES.txt: {e}"))?;
    late_epochs(&listing)
}

/// The derivation itself, over the text of the list, so it can be tested without a repository.
fn late_epochs(listing: &str) -> Result<Vec<u64>, String> {
    let mut published: BTreeMap<u64, i64> = BTreeMap::new();
    for line in listing.lines() {
        let Some((value, what)) = line.split_once("  ") else {
            continue;
        };
        let Some(epoch) = what.trim().strip_prefix("published unix timestamp, epoch ") else {
            continue;
        };
        let (Ok(epoch), Ok(unix)) = (epoch.trim().parse::<u64>(), value.trim().parse::<i64>())
        else {
            continue;
        };
        published.insert(epoch, unix);
    }
    if published.is_empty() {
        return Err(
            "LIVE-VALUES.txt holds no publication timestamps, so the cadence claims in the README \
             and docs/anchoring.md rest on nothing this check can read"
                .to_string(),
        );
    }
    let first = *published.keys().next().expect("not empty");
    Ok(published
        .iter()
        .filter(|(epoch, unix)| {
            **epoch != first && u64::try_from(**unix / 86_400).is_ok_and(|day| day > **epoch)
        })
        .map(|(epoch, _)| *epoch)
        .collect())
}

/// The cadence claims in both documents, against the days the chain says were missed.
fn check_cadence(root: &Path, readme: &str, anchoring: &str, problems: &mut Vec<String>) {
    let missed = match missed_days(root) {
        Ok(missed) => missed,
        Err(why) => {
            problems.push(why);
            return;
        }
    };
    let spelled: Vec<String> = missed.iter().map(u64::to_string).collect();
    let chain = format!("{} ({})", missed.len(), spelled.join(", "));

    let readme_line = one_line(readme);
    match between(&readme_line, "has also already been missed ", " times").and_then(word_to_number)
    {
        Some(n) if n == missed.len() => {}
        Some(n) => problems.push(format!(
            "the README says the cadence has been missed {n} times and the publication timestamps \
             say {chain}"
        )),
        None => problems.push(
            "the README no longer says how many times the cadence has been missed, so nothing \
             checks it"
                .to_string(),
        ),
    }

    match between(&readme_line, "nothing published on day ", " —") {
        Some(list) => {
            let named: Vec<String> = list
                .split(|c: char| !c.is_ascii_digit())
                .filter(|t| !t.is_empty())
                .map(str::to_string)
                .collect();
            if named != spelled {
                problems.push(format!(
                    "the README names days {} as missed and the publication timestamps say {chain}",
                    named.join(", ")
                ));
            }
        }
        None => problems.push(
            "the README no longer names the days the cadence was missed, so nothing checks them"
                .to_string(),
        ),
    }

    let anchoring_line = one_line(anchoring);
    match between(&anchoring_line, "A day has been missed ", " times").and_then(word_to_number) {
        Some(n) if n == missed.len() => {}
        Some(n) => problems.push(format!(
            "docs/anchoring.md says a day has been missed {n} times and the publication timestamps \
             say {chain}"
        )),
        None => problems.push(
            "docs/anchoring.md no longer says how many times a day has been missed, so nothing \
             checks it"
                .to_string(),
        ),
    }

    match between(&anchoring_line, "and all ", " were paid the day after").and_then(word_to_number)
    {
        Some(n) if n == missed.len() => {}
        Some(n) => problems.push(format!(
            "docs/anchoring.md says all {n} missed days were paid and the publication timestamps \
             say {chain}"
        )),
        None => problems.push(
            "docs/anchoring.md no longer says every missed day was paid, so nothing checks it"
                .to_string(),
        ),
    }
}

pub fn check_record(root: &Path) {
    let anchoring =
        std::fs::read_to_string(root.join("docs/anchoring.md")).expect("docs/anchoring.md");
    let readme = std::fs::read_to_string(root.join("README.md")).expect("README.md");
    let (epoch_rows, receipt_rows, malformed) = parse(&anchoring);

    let mut problems: Vec<String> = malformed;
    // The cadence claims in both documents, against the days the chain says were missed (H-42).
    check_cadence(root, &readme, &anchoring, &mut problems);

    if epoch_rows.is_empty() || receipt_rows.is_empty() {
        // A parser that silently matches nothing reports a clean record for a document it never read,
        // which is the failure this whole module exists to stop.
        problems.push(format!(
            "parsed {} epoch rows and {} receipt rows out of docs/anchoring.md; the tables moved or \
             changed shape and this check was reading nothing",
            epoch_rows.len(),
            receipt_rows.len()
        ));
    }

    // Every committed receipt file, by the epoch its name carries.
    let dir = root.join("anchors/epochs");
    let mut committed: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let Some(stem) = name.strip_suffix(".ots") else {
                continue;
            };
            let Ok(epoch) = stem.parse::<u64>() else {
                continue;
            };
            committed.insert(
                epoch,
                std::fs::read(entry.path()).expect("a committed receipt"),
            );
        }
    }

    // 1. Every committed receipt has a row, and every row names a file that exists.
    for epoch in committed.keys() {
        if !receipt_rows.iter().any(|r| r.epoch == *epoch) {
            problems.push(format!(
                "anchors/epochs/{epoch}.ots is committed and the receipt table has no row for it"
            ));
        }
    }
    for row in &receipt_rows {
        if !committed.contains_key(&row.epoch) {
            problems.push(format!(
                "the receipt table has a row for epoch {} and {} is not committed",
                row.epoch, row.path
            ));
        }
    }

    // 2. Every epoch named by a committed receipt or a receipt row appears in the epoch table.
    //    Without this the three sets agree pairwise and contradict each other as a whole: a review
    //    supplied receipts for epochs 1 and 3 and epoch rows for 1 and 2, and this passed.
    let in_epoch_table: BTreeMap<u64, &EpochRow> =
        epoch_rows.iter().map(|r| (r.epoch, r)).collect();
    for epoch in committed.keys() {
        if !in_epoch_table.contains_key(epoch) {
            problems.push(format!(
                "anchors/epochs/{epoch}.ots is committed and the epoch table has no row for epoch {epoch}"
            ));
        }
    }
    for row in &receipt_rows {
        if !in_epoch_table.contains_key(&row.epoch) {
            problems.push(format!(
                "the receipt table has a row for epoch {} and the epoch table does not",
                row.epoch
            ));
        }
    }

    // 3. Every path either table prints is the path that epoch's receipt actually has. The rows were
    //    keyed by epoch alone, so a row could name `anchors/epochs/99999.ots`, or a file that does
    //    not exist, and still be checked against the right bytes and pass.
    for row in &receipt_rows {
        let owed = format!("anchors/epochs/{}.ots", row.epoch);
        if row.path != owed {
            problems.push(format!(
                "the receipt table's row for epoch {} names {} and that epoch's receipt is {owed}",
                row.epoch, row.path
            ));
        }
    }
    for row in &epoch_rows {
        match (&row.receipt, row.status.as_str()) {
            (Some(path), _) => {
                let owed = format!("anchors/epochs/{}.ots", row.epoch);
                if *path != owed {
                    problems.push(format!(
                        "epoch {}'s row names {path} and that epoch's receipt is {owed}",
                        row.epoch
                    ));
                }
            }
            // A `single` row that names a receipt is a row mid-edit: the status says anchor B has
            // not attached and the cell says which file it attached.
            (None, "single") => {}
            (None, _) => {}
        }
    }
    for row in &epoch_rows {
        if row.status == "single" && row.receipt.is_some() {
            problems.push(format!(
                "epoch {} reads single and its row names a receipt; one of the two is stale",
                row.epoch
            ));
        }
    }

    // 4. Each row's byte count, sha256 and attached digest are what the committed file produces.
    for row in &receipt_rows {
        let Some(bytes) = committed.get(&row.epoch) else {
            continue;
        };
        if bytes.len() != row.bytes {
            problems.push(format!(
                "epoch {}: the receipt table says {} bytes and the file is {}",
                row.epoch,
                row.bytes,
                bytes.len()
            ));
        }
        let sha = format!("{:x}", Sha256::digest(bytes));
        if sha != row.sha256 {
            problems.push(format!(
                "epoch {}: the receipt table's sha256 is {} and the file hashes to {sha}",
                row.epoch, row.sha256
            ));
        }
        match receipt_digest(bytes) {
            Some(d) if d == row.digest => {}
            Some(d) => problems.push(format!(
                "epoch {}: the receipt table says the digest attached on chain is {} and the \
                 committed bytes produce {d}",
                row.epoch, row.digest
            )),
            None => problems.push(format!(
                "epoch {}: the committed receipt is longer than u16::MAX and cannot be digested",
                row.epoch
            )),
        }
    }

    // 5. `dual` owes a committed receipt; `single` owes none. This is the pair that went wrong in both
    //    directions on 7 October, in prose, while the table beside it was right.
    for row in &epoch_rows {
        match row.status.as_str() {
            "dual" => {
                if row.receipt.is_none() {
                    problems.push(format!(
                        "epoch {} reads dual and the epoch table names no receipt for it",
                        row.epoch
                    ));
                }
                if !committed.contains_key(&row.epoch) {
                    problems.push(format!(
                        "epoch {} reads dual and anchors/epochs/{}.ots is not committed",
                        row.epoch, row.epoch
                    ));
                }
            }
            "single" => {
                if committed.contains_key(&row.epoch) {
                    problems.push(format!(
                        "epoch {} reads single and a receipt for it is committed; a committed \
                         receipt is the upgraded form and the row is stale",
                        row.epoch
                    ));
                }
            }
            other => problems.push(format!(
                "epoch {} has status {other:?}, which is neither single nor dual",
                row.epoch
            )),
        }
    }

    // 6. INV-ANCH-02: the published range runs unbroken, so the table's epochs are contiguous.
    let mut listed: Vec<u64> = epoch_rows.iter().map(|r| r.epoch).collect();
    listed.sort_unstable();
    for pair in listed.windows(2) {
        if pair[1] != pair[0] + 1 {
            problems.push(format!(
                "the epoch table jumps from {} to {}; INV-ANCH-02 makes the published range unbroken",
                pair[0], pair[1]
            ));
        }
    }

    // 7. The count the README states in prose, against the rows. This is the one that was wrong: the
    //    README said five while the table held nine, for two days.
    let dual = epoch_rows.iter().filter(|r| r.status == "dual").count();
    let claimed = readme
        .split("Anchor B has completed **")
        .nth(1)
        .and_then(|rest| rest.split("**").next())
        .map(str::to_string);
    match claimed.as_deref().map(word_to_number) {
        Some(Some(n)) if n == dual => {}
        Some(Some(n)) => problems.push(format!(
            "the README says anchor B has completed {n} cycles and the epoch table holds {dual} dual rows"
        )),
        Some(None) => problems.push(format!(
            "the README's cycle count is {:?}, which this check cannot read as a number; spell it or \
             teach this function the word",
            claimed.unwrap_or_default()
        )),
        None => problems.push(
            "the README no longer says how many cycles anchor B has completed, so nothing checks it"
                .to_string(),
        ),
    }

    if problems.is_empty() {
        println!(
            "record: {} committed receipts, {} epoch rows ({dual} dual), every digest recomputed from \
             the committed bytes; the README's count matches the table, and both documents' cadence \
             claims match the publication timestamps",
            committed.len(),
            epoch_rows.len()
        );
        println!(
            "record: this compares the repository against itself and never reads the chain, so it \
             cannot say the record is current — only that it does not contradict itself"
        );
        return;
    }
    for p in &problems {
        eprintln!("record: {p}");
    }
    eprintln!(
        "record: {} disagreement(s) between the record and the files",
        problems.len()
    );
    std::process::exit(1);
}

/// The README spells its count, so the check reads the word rather than demanding a digit.
fn word_to_number(word: &str) -> Option<usize> {
    const WORDS: [&str; 21] = [
        "zero",
        "one",
        "two",
        "three",
        "four",
        "five",
        "six",
        "seven",
        "eight",
        "nine",
        "ten",
        "eleven",
        "twelve",
        "thirteen",
        "fourteen",
        "fifteen",
        "sixteen",
        "seventeen",
        "eighteen",
        "nineteen",
        "twenty",
    ];
    let w = word.trim().to_ascii_lowercase();
    WORDS
        .iter()
        .position(|c| *c == w)
        .or_else(|| w.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The epoch table as `docs/anchoring.md` writes it, with two rows.
    const TABLE: &str = "\
| Epoch | Root | Anchor A, slot | Anchor B | Receipt | Status |
|---|---|---|---|---|---|
| 20734 | `0x11…11` | 1 | block 1 | `anchors/epochs/20734.ots` | `dual` |
| 20735 | `0x22…22` | 2 | *pending* | *not yet committed* | `single` |
";

    #[test]
    fn the_control_parses_both_rows_and_reports_nothing() {
        let (epochs, receipts, malformed) = parse(TABLE);
        assert_eq!(epochs.len(), 2, "both data rows are rows");
        assert!(receipts.is_empty(), "this table is not the receipt table");
        assert!(malformed.is_empty(), "nothing in the control is malformed");
    }

    /// The mutation a review of `da87ce5` used: an epoch cell that is not a number.
    #[test]
    fn an_unreadable_epoch_is_reported_not_skipped() {
        let (epochs, _, malformed) = parse(&TABLE.replace("| 20735 |", "| epoch-20735 |"));
        assert_eq!(epochs.len(), 1);
        assert_eq!(malformed.len(), 1, "the row is reported, not dropped");
        assert!(malformed[0].contains("epoch-20735"), "{:?}", malformed);
    }

    /// The mutation a review of PR #121 used: a data row that spells its epoch `Epoch`.
    ///
    /// Before the header was matched entire this row became furniture and the count silently fell
    /// from 14 to 13 against the real table, with `check-record` exiting 0.
    #[test]
    fn a_data_row_calling_itself_the_header_is_reported() {
        let (epochs, _, malformed) = parse(&TABLE.replace("| 20735 |", "| Epoch |"));
        assert_eq!(epochs.len(), 1, "the mutated row is not a row");
        assert_eq!(malformed.len(), 1, "but it is reported rather than skipped");
        assert!(malformed[0].contains("Epoch"), "{:?}", malformed);
    }

    /// H-42's derivation: an epoch published on a later UTC day than its own number was paid late.
    const LISTING: &str = "\
# a comment, and a blank line follow

1790476800  published unix timestamp, epoch 20723
1790563200  published unix timestamp, epoch 20724
1790736000  published unix timestamp, epoch 20726
1790822400  published unix timestamp, epoch 20727
0xdeadbeef  something that is not a timestamp, epoch 99999
";

    #[test]
    fn an_epoch_published_on_a_later_day_is_late() {
        // 20723 -> day 20723 on the nose, 20724 -> 20724, 20726 -> day 20726, 20727 -> 20727.
        assert_eq!(late_epochs(LISTING).unwrap(), Vec::<u64>::new());
    }

    #[test]
    fn a_day_late_is_reported_and_the_first_epoch_is_not() {
        // Move 20726 a day later, and 20723 — the first — a day later too.
        let moved = LISTING
            .replace(
                "1790736000  published unix timestamp, epoch 20726",
                "1790822400  published unix timestamp, epoch 20726",
            )
            .replace(
                "1790476800  published unix timestamp, epoch 20723",
                "1790563200  published unix timestamp, epoch 20723",
            );
        assert_eq!(
            late_epochs(&moved).unwrap(),
            vec![20726],
            "the log's first epoch is excluded by position, as both documents say"
        );
    }

    #[test]
    fn a_listing_with_no_timestamps_is_a_failure_not_an_empty_answer() {
        let err = late_epochs("# nothing here\n").unwrap_err();
        assert!(err.contains("no publication timestamps"), "{err}");
    }

    #[test]
    fn a_claim_that_wraps_across_lines_is_still_one_sentence() {
        let wrapped = "has also already been missed five\n  times \u{2014} nothing published on day 1, 2 \u{2014}";
        let line = one_line(wrapped);
        assert_eq!(
            between(&line, "has also already been missed ", " times"),
            Some("five")
        );
        assert_eq!(
            between(&line, "nothing published on day ", " \u{2014}"),
            Some("1, 2")
        );
    }

    /// A row of six cells whose first is `epoch` but which is not the header.
    #[test]
    fn only_the_whole_header_is_furniture() {
        let real: Vec<String> = EPOCH_HEADER.iter().map(|c| c.to_string()).collect();
        assert!(is_furniture(&real), "the header is furniture");
        let mut impostor = real.clone();
        impostor[3] = "Anchor Z".to_string();
        assert!(
            !is_furniture(&impostor),
            "a row that is not the header is not furniture, whatever its first cell says"
        );
    }

    /// The headers this module matches are the headers the document carries.
    ///
    /// A reworded header would make every row of that table malformed. That is loud rather than
    /// silent, but it is still a break, and this is the test that fails first and says why.
    #[test]
    fn the_documents_headers_are_the_ones_matched() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("the workspace root is xtask's parent");
        let markdown = std::fs::read_to_string(root.join("docs/anchoring.md"))
            .expect("docs/anchoring.md is in the repository");
        for header in [&EPOCH_HEADER[..], &RECEIPT_HEADER[..]] {
            let row = format!("| {} |", header.join(" | "));
            assert!(
                markdown.to_lowercase().contains(&row),
                "docs/anchoring.md no longer carries the header this module matches: {row}"
            );
        }
    }
}
