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
fn parse(markdown: &str) -> (Vec<EpochRow>, Vec<ReceiptRow>) {
    let mut epochs = Vec::new();
    let mut receipts = Vec::new();
    for line in markdown.lines() {
        if !line.trim_start().starts_with('|') {
            continue;
        }
        let c = cells(line);
        let Some(epoch) = c.first().and_then(|f| f.parse::<u64>().ok()) else {
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
            5 => {
                if let Some(bytes) = number(&c[2]) {
                    receipts.push(ReceiptRow {
                        epoch,
                        path: c[1].clone(),
                        bytes,
                        sha256: c[3].clone(),
                        digest: c[4].clone(),
                    });
                }
            }
            _ => {}
        }
    }
    (epochs, receipts)
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
pub fn check_record(root: &Path) {
    let anchoring =
        std::fs::read_to_string(root.join("docs/anchoring.md")).expect("docs/anchoring.md");
    let readme = std::fs::read_to_string(root.join("README.md")).expect("README.md");
    let (epoch_rows, receipt_rows) = parse(&anchoring);

    let mut problems: Vec<String> = Vec::new();

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

    // 2. Each row's byte count, sha256 and attached digest are what the committed file produces.
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

    // 3. `dual` owes a committed receipt; `single` owes none. This is the pair that went wrong in both
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

    // 4. INV-ANCH-02: the published range runs unbroken, so the table's epochs are contiguous.
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

    // 5. The count the README states in prose, against the rows. This is the one that was wrong: the
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
             the committed bytes; the README's count matches the table",
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
