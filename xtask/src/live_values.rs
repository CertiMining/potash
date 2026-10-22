// SPDX-License-Identifier: MIT OR Apache-2.0
//! The rule that no synthetic artifact carries a value from a live deployment (owner, 28 Sep 2026).
//!
//! **Why this exists.** E-14's demo fixture carried the announced log's real transaction signature
//! and slot beside a root built for the demo and published nowhere — and the two were not even from
//! the same publication. It asserted an anchoring that never happened. Fabricated provenance is the
//! worst defect this repository can hold and the kind an author cannot see in their own work, and a
//! rule living only in judgement is the rule that failed.
//!
//! **What it checks.** Every file a generator is about to write is scanned for each value in
//! `LIVE-VALUES.txt`, and generation fails on a match unless the exact pair is recorded in
//! `LIVE-VALUES.exempt`. Matching is case-insensitive, so a base58 string that collides only under
//! case folding would fail generation — a false positive, which is the safe direction, and loud.
//!
//! **What it covers.** 32-byte values, base58 identifiers, and decimals of five digits or more.
//! Block heights are uncovered.
//!
//! **Decimals match on digit boundaries since H-20** (issue #60). They were substrings, so a listed
//! slot `504985662` also matched the unrelated `15049856620` and a six-digit floor was needed to keep
//! the gate from firing on counters and lengths. The long shapes keep substring matching on purpose:
//! a 64-character digest does not collide by accident, and boundaries there would lose the case the
//! gate most needs, a listed root pasted inside a longer hex blob.
//!
//! The floor is now about entropy rather than matching. Bumps stay out because one of 256
//! possibilities carries no provenance — finding `255` in a file is evidence of nothing — and not
//! because `255` is short. Epoch day indices became listable with the floor at five; whether to list
//! them is a legitimacy question the exemption list answers, since a synthetic artifact may be
//! legitimately about a real epoch.
//!
//! **What neither half asked (H-26).** The rule is unqualified, and these checks covered only the
//! *announced* deployment. The superseded ids were listed; nothing derived from them was, though
//! they still own 2 and 213 devnet accounts. One in a fixture passed both halves: no value to match
//! statically, and the chain reader never asked them anything.
//!
//! **Listing the addresses did not list the values (review of PR #121, H-01).** The repair above
//! listed all 215 addresses and called the gap closed. A review decoded those accounts — 213
//! checkpoints, 2 LogConfigs — and found 640 values inside them that nothing had asked for: 213
//! roots, 213 slots, 213 timestamps, one receipt digest. One of those roots in a fuzz target left
//! this gate exiting 0 and printing that the surface held no listed value, true only because the
//! list did not hold it. Asking about addresses and reporting on values is the substitution the
//! paragraph above describes, made by its own repair.
//!
//! All 640 are listed now, with the two deployments' 434 signatures, their ProgramData addresses
//! and deploy slots. Two travelled the other way: `0xabab…abab` and `0x3333…3333` are this
//! repository's placeholder constants, which `tests/devnet.rs` published to the 24 September
//! program. Listed anyway — narrowing the rule is the owner's call — with the 23 files that
//! legitimately carry them named in `LIVE-VALUES.exempt` by exact path.
//!
//! `scripts/live-values-from-chain.py` now asks every deployment named in `ANNOUNCED_PROGRAM_ID`
//! and `SUPERSEDED_PROGRAM_IDS`. Enumerate-once rested on a superseded program's accounts not
//! growing, which is true and was never the problem: nothing had enumerated what they held.
//!
//! An earlier version of this paragraph said slot numbers were deliberately uncovered, which the
//! decimal support contradicts. H-34 recorded that paragraph as still stale; it had already been
//! corrected by then, and this sentence says so rather than leaving the next reader to check.
//!
//! **Each entry is validated against the class it declares (H-34).** The list names what every value
//! is, and nothing read it: an entry was accepted if it resembled hex, base58 or a decimal, whichever
//! matched, and none of the three was checked properly. A reviewer listed thirty-two capital `O`
//! characters as a program id and `18446744073709551616` as a slot, and both passed the whole static
//! gate. The description now decides which check runs.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// One value that exists on chain.
struct LiveValue {
    value: String,
    lower: String,
    what: String,
    /// Whether a match has to stand alone as a number rather than sit inside one (H-20, #60).
    ///
    /// **Substring matching makes a low-entropy value unlistable.** A listed slot `504985662` is
    /// also a substring of the unrelated `15049856620`, so listing it would fire on text that has
    /// nothing to do with the deployment. That is why the list carried a six-digit floor and why
    /// epoch day indices were review-enforced rather than gate-enforced.
    ///
    /// Only decimals need it. A 64-character hex digest or a base58 signature does not collide by
    /// accident, and requiring boundaries there would *lose* matches: a listed root pasted inside a
    /// longer hex blob is exactly the case the gate must still catch. So the long, high-entropy
    /// shapes keep substring matching and the short ones gain boundaries.
    on_number_boundaries: bool,
    /// Every spelling of this value a file could carry, lowercased.
    ///
    /// **`0x` is the list's convention, not part of the value (found while repairing H-01).** The
    /// match required the prefix, so the same bytes spelled bare went straight through: a real root
    /// from the 25 September deployment, pasted into a fuzz target without it, left the gate at
    /// exit 0. Three committed files already carried a listed digest that way, unseen.
    needles: Vec<String>,
}

/// Removes the digit separator a number may carry, so `20_723` reads as the number it is.
///
/// **This was a live escape, found while listing the epochs (H-20).** Rust, JavaScript and Python all
/// allow `_` between digits, and the gate did not: `crates/certimining-client/tests/program_addresses.rs`
/// derives the announced deployment's checkpoint address for `20_723`, and a search for `20723` went
/// straight past it. One of the twenty-seven uses of a live epoch index in the synthetic surface was
/// spelled that way and was invisible — the same shape of hole as the `0x` prefix that once let a real
/// root through when it was pasted bare.
///
/// Only a separator **between two digits** is removed, which is what makes this safe: `20_723` is the
/// number 20723 in each of those languages, while `slot_20723` keeps its underscore because a letter
/// sits on one side of it.
fn strip_digit_separators(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    for (i, c) in text.char_indices() {
        if c == '_' {
            let before = i.checked_sub(1).and_then(|j| bytes.get(j));
            let after = bytes.get(i.saturating_add(1));
            if before.is_some_and(u8::is_ascii_digit) && after.is_some_and(u8::is_ascii_digit) {
                continue;
            }
        }
        out.push(c);
    }
    out
}

/// How many times `needle` occurs in `haystack` standing alone as a number.
///
/// **The boundary is a hexadecimal digit, not a decimal one, and that is what makes epochs
/// listable.** Rejecting only decimal neighbours still leaves a five-digit number matching inside a
/// hex blob: `a20751b` is not the epoch 20751, and nothing in the file holding it is about that epoch.
/// Measured over the synthetic surface, the decimal rule produced **twenty-six** such false positives
/// across five committed files, twenty-one of them in the Keccak known-answer vectors — which is
/// exactly the collision the owner's 3 October ruling predicted when it left these values
/// review-enforced.
///
/// Hex digits either side are rejected and other letters are not, so `504985662` still matches in
/// `slot504985662` and in `"slot": 504985662,`, which is what a looser boundary is for. It must not
/// match inside `15049856620`, and a decimal digit is a hex digit, so that case is covered twice over.
fn occurrences_as_a_number(haystack: &str, needle: &str) -> usize {
    if needle.is_empty() {
        return 0;
    }
    let bytes = haystack.as_bytes();
    let hex = |b: &u8| b.is_ascii_digit() || (b'a'..=b'f').contains(b);
    let mut found = 0usize;
    let mut from = 0usize;
    while let Some(rest) = haystack.get(from..) {
        let Some(hit) = rest.find(needle) else {
            break;
        };
        let at = from.saturating_add(hit);
        let end = at.saturating_add(needle.len());
        let before = at.checked_sub(1).and_then(|i| bytes.get(i));
        if before.is_some_and(hex) || bytes.get(end).is_some_and(hex) {
            from = at.saturating_add(1);
            continue;
        }
        found = found.saturating_add(1);
        from = end;
    }
    found
}

/// How many times a file carries this value, by the rule its declared shape sets.
///
/// **The bare spelling is the one counted, and counting any other would double.** For a hex entry the
/// list's `0x` is a convention rather than part of the value, so `needles` holds both spellings and
/// every occurrence of either contains the bare form exactly once. Counting that form counts both
/// spellings without counting either twice.
fn occurrences(v: &LiveValue, lower: &str, without_separators: &str) -> usize {
    let Some(needle) = v.needles.last() else {
        return 0;
    };
    if v.on_number_boundaries {
        occurrences_as_a_number(without_separators, needle)
    } else {
        lower.matches(needle.as_str()).count()
    }
}

fn repo_file(root: &Path, name: &str) -> String {
    let path = root.join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn live_values(root: &Path) -> Vec<LiveValue> {
    let mut out = Vec::new();
    for line in repo_file(root, "LIVE-VALUES.txt").lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (value, what) = line
            .split_once("  ")
            .unwrap_or_else(|| panic!("LIVE-VALUES.txt: no description on {line:?}"));
        let lower = value.trim().to_lowercase();
        let mut needles = vec![lower.clone()];
        if let Some(bare) = lower.strip_prefix("0x") {
            needles.push(bare.to_string());
        }
        out.push(LiveValue {
            value: value.trim().to_string(),
            lower,
            what: what.trim().to_string(),
            // Decimals need boundaries; the long, high-entropy shapes must keep substring matching
            // so a value pasted inside a longer string is still caught (H-20).
            on_number_boundaries: matches!(
                declared_shape(what.trim()),
                Shape::Slot | Shape::UnixTimestamp | Shape::Epoch
            ),
            needles,
        });
    }
    assert!(!out.is_empty(), "LIVE-VALUES.txt lists nothing");
    out
}

/// `(file, value)` to the number of occurrences allowed, because the artifact's subject *is* the
/// deployment.
///
/// **The count is the per-occurrence half of H-20 (issue #60).** An exemption used to be a pair, so
/// one entry blanketed every occurrence in the file and a second use could appear beneath it in
/// silence. `LIVE-VALUES.txt` carried a hand-written block of counts beside the gate for the values
/// the list could not hold, checked by `check_recorded_short_values`; now that epoch day indices are
/// listed, the count belongs in the gate, and an entry says how many times the artifact may name the
/// value rather than that it may.
fn exemptions(root: &Path) -> BTreeMap<(String, String), usize> {
    let mut out = BTreeMap::new();
    for line in repo_file(root, "LIVE-VALUES.exempt").lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(4, "  ");
        let file = parts
            .next()
            .unwrap_or_else(|| panic!("LIVE-VALUES.exempt: no file on {line:?}"))
            .trim();
        let value = parts
            .next()
            .unwrap_or_else(|| panic!("LIVE-VALUES.exempt: no value on {line:?}"))
            .trim();
        let count = parts
            .next()
            .unwrap_or_else(|| {
                panic!("LIVE-VALUES.exempt: no occurrence count on {line:?}; the format is file, value, count, reason")
            })
            .trim();
        let count: usize = count.parse().unwrap_or_else(|_| {
            panic!("LIVE-VALUES.exempt: {count:?} is not an occurrence count on {line:?}")
        });
        assert!(
            count > 0,
            "LIVE-VALUES.exempt: {line:?} exempts nothing; a line that permits no occurrence should \
             be deleted, and the gate says so rather than passing it"
        );
        assert!(
            parts.next().is_some(),
            "LIVE-VALUES.exempt: no reason on {line:?}; an exemption without one is a hole"
        );
        out.insert((file.to_string(), value.to_lowercase()), count);
    }
    out
}

/// Fails generation if a file carries a live value it is not recorded as being about.
///
/// `files` is what the generator is about to write: the name it will be written under, and its text.
pub fn refuse_live_values(root: &Path, files: &[(String, String)]) {
    let found = offences(root, files);
    assert!(
        found.is_empty(),
        "a generated artifact carries a value that exists on chain:\n{}\n\n\
         No value from a live deployment appears in a synthetic artifact, fixture or page constant \
         (owner, 28 Sep 2026). If the artifact's subject really is the announced deployment, record \
         the pair in LIVE-VALUES.exempt with the reason; if it merely looked more concrete for \
         carrying one, that is the defect this rule exists for.",
        found.join("\n")
    );
}

/// Every `(file, value)` pair in `files` that the rule refuses, as the lines a reader would see.
///
/// Separate from the assertion so that `prove_the_gate_detects` can ask the detector a question and
/// read its answer. A gate whose detection has never been exercised is a gate that reports what its
/// acceptance predicate rewards, which is the defect this whole module keeps finding in itself.
fn offences(root: &Path, files: &[(String, String)]) -> Vec<String> {
    let values = live_values(root);
    let allowed = exemptions(root);
    let mut found: Vec<String> = Vec::new();

    for (name, text) in files {
        let lower = text.to_lowercase();
        let without_separators = strip_digit_separators(&lower);
        for v in &values {
            let carried = occurrences(v, &lower, &without_separators);
            if carried == 0 {
                continue;
            }
            // **The exact path, and nothing else (H-25 review, H3).** A basename was accepted too,
            // so that an exemption written for a generated file kept working when the tree walk
            // found it under a path. One exemption for `(allowed.json, value)` therefore exempted
            // that value in every other `allowed.json` anywhere in the surface — a review passed two
            // different files through one entry. Both callers now key by the artifact's destination
            // in the repository, so one spelling is enough and it is the specific one.
            match allowed.get(&(name.clone(), v.lower.clone())) {
                Some(&permitted) if permitted == carried => continue,
                // **A recorded count that no longer describes the file is the failure this adds.**
                // The artifact may legitimately name the value, and it now names it a different
                // number of times, which is a use nobody recorded. Re-count it deliberately.
                Some(&permitted) => found.push(format!(
                    "  {name} carries {} ({}) {carried} time(s) and LIVE-VALUES.exempt permits {permitted}",
                    v.value, v.what
                )),
                None => found.push(format!(
                    "  {name} carries {} ({}) {carried} time(s)",
                    v.value, v.what
                )),
            }
        }
    }

    found
}

/// One root the 25 September deployment still stores, taken from the list rather than hardcoded.
fn a_superseded_root(root: &Path) -> String {
    for line in repo_file(root, "LIVE-VALUES.txt").lines() {
        let Some((value, what)) = line.split_once("  ") else {
            continue;
        };
        if what.contains("root stored in the account") && what.contains("superseded") {
            return value.trim().to_string();
        }
    }
    panic!(
        "LIVE-VALUES.txt holds no root from a superseded deployment. Either the list lost 213 \
         values or the description changed; this check cannot prove it detects anything without one."
    );
}

/// Proves the gate refuses a live value in each directory of the surface, before trusting a pass.
///
/// **Asked for by the review of PR #121 (H-01).** The gate reported 111 clean files while a real
/// superseded root sat in `fuzz/fuzz_targets/fuzz_apply.rs`: the list did not hold it, and "no
/// match" and "nothing to match with" print the same sentence. H-25 was the same shape — that
/// directory was not walked at all.
///
/// So a pass means nothing alone. This refuses a listed value in every directory, and accepts the
/// same file without one — both directions, since refusing everything is as useless as refusing
/// nothing.
fn prove_the_gate_detects(root: &Path) {
    let value = a_superseded_root(root);
    for dir in SYNTHETIC_SURFACE {
        let name = format!("{dir}/a-file-no-generator-writes.json");
        let carrying = vec![(name.clone(), format!("{{\"root\": \"{value}\"}}"))];
        let offended = offences(root, &carrying);
        assert!(
            offended.iter().any(|line| line.contains(&name)),
            "the gate did not refuse {value} in {name}, so a pass over {dir} means nothing: {offended:?}"
        );
        let clean = vec![(name.clone(), "{\"root\": \"0x00\"}".to_string())];
        assert!(
            offences(root, &clean).is_empty(),
            "the gate refused a file holding no live value, so its refusals carry no information"
        );
    }
    println!(
        "live-values: the gate was shown to refuse a live root in each of the {} directories of the \
         surface, and to accept the same file without one",
        SYNTHETIC_SURFACE.len()
    );
}

/// The list's own integrity: a value that is not what it claims to be would exempt nothing and catch
/// nothing. Checked at generation so a malformed list fails loudly rather than passing everything.
/// The short live values the rule permits, each checked against the file that is supposed to hold it
/// (H-27).
///
/// The owner made these review-enforced on 4 Oct 2026: a short live value may appear only where the
/// artifact's subject is the announced deployment, and only if the use is recorded in
/// `LIVE-VALUES.txt` by file, value and occurrence.
///
/// **What is left here after H-20 is the values no list can hold**, and it is a smaller set than it
/// was. Epoch day indices have gone: 212 of them are listed and the gate counts their occurrences, so
/// the record for them moved into `LIVE-VALUES.exempt` where it is enforced rather than read. What
/// remains is a PDA bump, which is one of 256 possibilities, and the single checkpoint the 24
/// September deployment holds at epoch `1`. Finding either in a file is evidence of nothing, and
/// listing one would refuse the whole corpus.
///
/// **A checklist nobody verifies goes stale the first time somebody edits one of those files.** The
/// record claims `vectors/V-P-12.json` holds `255` three times. If a fourth use appears, the count is
/// wrong and the reviewer reading it is misled in the safe-looking direction. So the counts are
/// checked here: not that the value is permitted, which is a judgement, but that the record describes
/// the tree.
fn check_recorded_short_values(root: &Path) {
    let listing = repo_file(root, "LIVE-VALUES.txt");
    let mut checked = 0usize;
    for line in listing.lines() {
        // `#   <path>  <value>  <count>  <why>` — the recorded block, and only it.
        let Some(rest) = line.strip_prefix("#   ") else {
            continue;
        };
        let mut parts = rest.split_whitespace();
        let (Some(path), Some(value), Some(count)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        if !path.contains('/') || !value.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let Ok(expected) = count.parse::<usize>() else {
            continue;
        };
        let body = repo_file(root, path);
        let found = body.matches(value).count();
        assert_eq!(
            found, expected,
            "LIVE-VALUES.txt records {value} appearing {expected} time(s) in {path} and it appears \
             {found}. The short-value rule is enforced by a reader against that record, so a record \
             that does not describe the tree is worse than none."
        );
        checked += 1;
    }
    assert!(
        checked > 0,
        "LIVE-VALUES.txt records no short live values; if the carve-out is gone the check should go \
         with it, and if it is not, the record is missing"
    );
    println!("live-values: {checked} recorded short-value uses match the files that hold them");
}

/// Base58 in the alphabet Bitcoin and Solana use, decoded only far enough to know its length.
///
/// The alphabet excludes `0`, `O`, `I` and `l` precisely because they are confusable, and the old
/// check accepted every one of them: a reviewer listed thirty-two capital `O` characters and the
/// gate took it for an address. Decoding is by the schoolbook base-256 accumulation, which is
/// enough to tell a 32-byte key from a 64-byte signature; nothing here needs the bytes themselves.
fn base58_len(s: &str) -> Option<usize> {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut bytes: Vec<u8> = Vec::new();
    for c in s.bytes() {
        let digit = ALPHABET.iter().position(|a| *a == c)?;
        let mut carry = digit;
        for b in bytes.iter_mut().rev() {
            carry += (*b as usize) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    // Each leading `1` is a leading zero byte, which the accumulation above never produces.
    Some(bytes.len() + s.bytes().take_while(|c| *c == b'1').count())
}

/// What an entry's own description says it is. The list names the class of every value it holds, and
/// until H-34 nothing read it: an entry was accepted if it resembled *any* of three shapes, so a
/// signature could be listed with a program id's length and a slot could be any six digits.
#[derive(Debug, PartialEq)]
enum Shape {
    /// `0x` and 64 lowercase nybbles: a 32-byte digest or an address written as bytes.
    Hex32,
    /// A 32-byte base58 identifier: a program id, an address, an authority.
    Base58Key,
    /// A 64-byte base58 transaction signature.
    Base58Signature,
    /// A Solana slot, which is a `u64`.
    Slot,
    /// A unix timestamp, which §2.4 stores as an `i64`.
    UnixTimestamp,
    /// An epoch day index: §1.4's `floor(unix / 86_400)`, and five digits on every deployment there
    /// has been (H-20).
    Epoch,
}

fn declared_shape(what: &str) -> Shape {
    // **First, because every other description names an epoch as well.** "published root, epoch
    // 20723" describes a root; only an entry whose subject is the index itself says "epoch day
    // index", and reading this later would classify every one of them as something else.
    if what.contains("epoch day index") {
        Shape::Epoch
    } else if what.contains("as bytes") || what.contains("digest") || what.contains("root") {
        Shape::Hex32
    } else if what.contains("signature") {
        Shape::Base58Signature
    } else if what.contains("slot") {
        Shape::Slot
    } else if what.contains("timestamp") {
        Shape::UnixTimestamp
    } else {
        Shape::Base58Key
    }
}

/// **Every entry is checked against the shape it declares, not against any of three (H-34).**
///
/// The old check accepted a value resembling hex, base58 or a decimal, whichever matched. It
/// validated none of them properly: hex by its `0x` prefix and length and not its characters, base58
/// by ASCII alphanumeric and so including the four characters the alphabet excludes, and decimals by
/// having six digits and not by fitting the field. Two reviewer probes passed the whole static gate:
/// thirty-two capital `O` characters, and `18446744073709551616`, which is one past `u64::MAX`.
///
/// No committed entry was malformed, so this was a defect in the promise rather than an escape. A
/// list whose integrity check cannot reject a malformed entry is a list nobody is checking.
pub fn check_list_shape(root: &Path) {
    check_recorded_short_values(root);
    for v in live_values(root) {
        let shape = declared_shape(&v.what);
        let wrong = |why: &str| -> String {
            format!(
                "LIVE-VALUES.txt: {:?} is recorded as {:?}, which this list reads as {shape:?}, and {why}",
                v.value, v.what
            )
        };
        match shape {
            Shape::Hex32 => {
                assert!(
                    v.value.len() == 66
                        && v.value.starts_with("0x")
                        && v.value[2..]
                            .bytes()
                            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
                    "{}",
                    wrong("that is `0x` and exactly 64 lowercase hexadecimal characters")
                );
            }
            Shape::Base58Key => {
                assert_eq!(
                    base58_len(&v.value),
                    Some(32),
                    "{}",
                    wrong("that is a base58 identifier decoding to 32 bytes")
                );
            }
            Shape::Base58Signature => {
                assert_eq!(
                    base58_len(&v.value),
                    Some(64),
                    "{}",
                    wrong("that is a base58 signature decoding to 64 bytes")
                );
            }
            Shape::Slot => {
                assert!(
                    v.value.parse::<u64>().is_ok() && !v.value.starts_with('0'),
                    "{}",
                    wrong("that is a slot, which is a `u64` written without a leading zero")
                );
            }
            Shape::Epoch => {
                assert!(
                    v.value.parse::<u64>().is_ok() && !v.value.starts_with('0'),
                    "{}",
                    wrong("that is an epoch day index, which §1.4 makes a `u64` written without a leading zero")
                );
            }
            Shape::UnixTimestamp => {
                // **Signed, because the field is (H-28).** §2.4 stores `published_unix` as an `i64`
                // and `scripts/live-values-from-chain.py` reads it signed, so a negative time is
                // decoded from the chain and reported as missing from a list that could not hold it:
                // the minus sign is not a digit. No list content satisfied both halves of the gate
                // for a value the field admits. Not reachable on the announced deployment, whose
                // clock writes present seconds, but the two halves disagreed about the domain of a
                // field they both claim to cover.
                let digits = v.value.strip_prefix('-').unwrap_or(&v.value);
                assert!(
                    v.value.parse::<i64>().is_ok() && !digits.starts_with('0'),
                    "{}",
                    wrong("that is a publication time, which §2.4 stores as an `i64`")
                );
            }
        }
        // **The floor is five digits since H-20, and it is now about entropy rather than matching.**
        //
        // It was six because the matcher used substrings: a listed `504985662` also matched the
        // unrelated `15049856620`, so a short value could not be listed without firing on text that
        // has nothing to do with the deployment. Decimals now match on number boundaries, and that
        // false positive is gone, which is what lets the 212 epoch day indices be listed and
        // gate-enforced rather than review-enforced.
        //
        // **One live epoch is still under the floor and still cannot be listed.** The program
        // superseded on 24 September holds a single checkpoint, at epoch `1`. A one-digit number is
        // in every file in the corpus, so listing it would refuse everything; it stays
        // review-enforced for the same reason a bump does, which is what it is rather than how it is
        // matched.
        //
        // What boundaries cannot fix is a value that carries no provenance. A checkpoint bump is one
        // of 256 possibilities; `255` appearing in a fixture is evidence of nothing, and listing it
        // would fire on every unrelated `255` in the corpus — the demo page says "255 records" about
        // a tree it built itself. So bumps stay out, by what they are rather than by their length,
        // and `check_recorded_short_values` governs any exception a reviewer records.
        if matches!(shape, Shape::Slot | Shape::UnixTimestamp | Shape::Epoch) {
            // The floor is on the magnitude, not the string: a sign is not a digit, and `-100000`
            // is as specific a thing to search a corpus for as `100000` (H-28).
            let digits = v.value.strip_prefix('-').unwrap_or(&v.value);
            assert!(
                digits.len() >= 5,
                "LIVE-VALUES.txt: {:?} has under five digits, which is too few possibilities to \
                 carry provenance: finding it in a file is evidence of nothing",
                v.value
            );
        }
    }
    // Every exemption must name a value the list actually holds, or it is silently dead.
    let known: BTreeSet<String> = live_values(root).into_iter().map(|v| v.lower).collect();
    for ((file, value), _permitted) in exemptions(root) {
        assert!(
            known.contains(&value),
            "LIVE-VALUES.exempt: {file} exempts {value:?}, which LIVE-VALUES.txt does not list"
        );
    }
}

/// Every file in the synthetic surface, checked the way a generated one is.
///
/// **Why generation alone was not enough.** The rule names three things — synthetic artifacts,
/// fixtures, and **page constants** — and the generator only ever sees the second. A review put a live
/// receipt digest into `demo/app.js` and watched `gen-demo`, the vectors gate and every test pass,
/// because a hand-written page is not something a generator inspects. The gate has to look at the
/// working tree as well as at what it is about to write.
///
/// The surface is named rather than inferred, and a tree-wide scan is still the wrong shape: it would
/// need an allow-list holding `docs/anchoring.md`, `ANNOUNCED_PROGRAM_ID`, `README.md`, the deploy
/// script and the program's own `declare_id!` — every one of which holds live values because its
/// subject is the deployment — and an allow-list that long is a gate that no longer refuses anything.
///
/// **What the named surface missed was the tests (H-25).** It was the demo and the vectors, on the
/// argument that those are synthetic by nature. So are fixtures and constants under `ts/test/` and
/// `crates/*/tests/`, and a review showed the bypass concretely: the already-listed publication slot
/// `504985662`, placed in a constant in `ts/test/units.test.ts`, passed. The discipline was avoidable
/// by choosing where to put a value, which is not a discipline.
///
/// Widening to the test directories cost **two** exemptions, both in `ts/test/units.test.ts`, both
/// for §2.4's derivation check whose whole subject is the announced deployment. The cluster harnesses
/// needed none: they reach the program through `certimining_checkpoint::ID` rather than a literal, so
/// they carry no live value to find. The allow-list the paragraph above warns about did not appear,
/// because what makes an artifact legitimate is its subject, and a test of a derivation has one.
/// What is synthetic by nature: the demo, the vectors, and every test and fixture directory. Not the
/// cluster harnesses' crate root, the deploy script or the documents whose subject is the deployment.
const SYNTHETIC_SURFACE: [&str; 10] = [
    "demo",
    "vectors",
    "ts/test",
    "crates/certimining-core/tests",
    "crates/certimining-log/tests",
    "crates/certimining-client/tests",
    "programs/certimining-checkpoint/tests",
    "programs/core-harness/tests",
    "benches",
    // H-25 widened this to every test directory and missed the one that is not called `tests`. A
    // review placed a listed live slot in `fuzz/fuzz_targets/` and the gate passed it, while the
    // same value was refused in all seven of the others. `fuzz/corpus` and `fuzz/artifacts` are
    // generated inputs rather than authored artifacts and are deliberately not walked: a corpus is
    // libFuzzer's bytes, and a coincidental run of base58 characters there is noise, not a claim.
    "fuzz/fuzz_targets",
];

pub fn check_synthetic_surface(root: &Path) {
    check_list_shape(root);
    prove_the_gate_detects(root);
    let mut files: Vec<(String, String)> = Vec::new();
    // Every directory must contribute. `files.len() > 10` was the old floor, and it would have been
    // met by eight of these nine going missing — a renamed directory is exactly how a surface stops
    // being scanned without anyone noticing, which is the whole of H-25 in one line.
    for dir in SYNTHETIC_SURFACE {
        let before = files.len();
        collect(&root.join(dir), root, &mut files);
        assert!(
            files.len() > before,
            "{dir} contributed no files to the synthetic surface: it was renamed, emptied or moved, \
             and the scan would pass anything it used to hold"
        );
    }
    refuse_live_values(root, &files);
    let allowed = exemptions(root);
    println!(
        "live-values: {} files in the synthetic surface hold no value of the announced deployment, \
         or of the two superseded ones, or of their accounts, or stored inside those accounts — \
         beyond {} recorded occurrence(s) across {} (file, value) pair(s) whose subject is a \
         deployment, each counted against the file",
        files.len(),
        allowed.values().sum::<usize>(),
        allowed.len()
    );
}

/// Everything readable as text under `dir`, keyed by the name the exemption list uses: the file's own
/// name for a generated artifact, and its repository-relative path otherwise.
/// **Every failure here is loud, because a quiet one reads as "carries nothing" (H-09's class).**
///
/// This function had four ways to drop a file silently: a directory it could not open, an entry it
/// could not stat, a file that was not valid UTF-8, and anything whose name began with a dot. A
/// review put a listed live value after one invalid UTF-8 byte and the artifact vanished from the
/// scan while a readable sibling kept the directory's "contributed files" assertion satisfied. A
/// gate that maps "I could not look" onto "there is nothing there" is the defect this repository
/// has named fifteen times.
///
/// So: an unreadable directory or entry panics, and a file is read as **bytes** and searched as
/// bytes. The values are base58 and hex, which are ASCII, so `from_utf8_lossy` preserves every one
/// of them while replacing only the sequences that were never going to match anything.
fn collect(dir: &Path, root: &Path, out: &mut Vec<(String, String)>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| {
        panic!(
            "{}: {e}. A directory in the synthetic surface that cannot be \
             read is not a directory that carries nothing",
            dir.display()
        )
    });
    for entry in entries {
        let entry =
            entry.unwrap_or_else(|e| panic!("{}: an entry could not be read: {e}", dir.display()));
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        // Build output is not committed and is a copy of dependencies that legitimately hold nothing
        // of ours; `node_modules` likewise. `.git` is not part of any artifact. Nothing else is
        // skipped by name: `demo/.gitignore` is tracked, and a dot is not a reason to stop looking.
        if name == "build" || name == "node_modules" || name == "dist" || name == ".git" {
            continue;
        }
        if path.is_dir() {
            collect(&path, root, out);
            continue;
        }
        let bytes = std::fs::read(&path).unwrap_or_else(|e| {
            panic!(
                "{}: {e}. A file that cannot be read is not a file that carries nothing",
                path.display()
            )
        });
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let relative = path
            .strip_prefix(root)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| name.clone());
        // A generated artifact is exempted by its own file name, which is how the generator records
        // it; anything else is exempted by path. Both spellings are offered so an exemption written
        // for a generated file keeps working when the tree is scanned.
        out.push((relative, text));
    }
}

/// Fails if a value the generators use as a placeholder is one a deployment holds (H-45, issue #137).
///
/// **The failure this prevents has already happened once.** `[0x33; 32]` was the vector generator's
/// assessment digest and is also a value a throwaway devnet program holds, published *from* this
/// repository on 24 September. The direction of travel is repository to chain, the opposite of the one
/// the live-value rule guards — but the rule is unqualified, so it fired, and every record vector
/// needed an exemption line. Twenty-four of fifty-four exemptions existed for two constants of that
/// kind.
///
/// H-45 changed the values rather than narrowing the rule, which keeps the gate free of judgement.
/// This is what stops the same thing recurring silently: if a placeholder ever appears in
/// `LIVE-VALUES.txt`, the build goes red and names it, instead of an exemption being added.
///
/// The placeholders are passed in rather than read from a file, so the caller's own constants are
/// what is checked and a renamed constant cannot slip out of the check's view.
pub fn check_placeholders_are_not_live(root: &Path, placeholders: &[(&str, [u8; 32])]) {
    assert!(
        !placeholders.is_empty(),
        "no placeholders were handed to the check, which would pass on any list at all"
    );
    let values = live_values(root);
    let mut clashes = Vec::new();
    for (name, bytes) in placeholders {
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        for v in &values {
            if v.lower == format!("0x{hex}") || v.lower == hex {
                clashes.push(format!(
                    "  {name} is 0x{hex}, which LIVE-VALUES.txt holds as {}",
                    v.what
                ));
            }
        }
    }
    assert!(
        clashes.is_empty(),
        "a generator placeholder is a value a deployment holds:\n{}\n\nChange the placeholder \
         rather than exempting the files that carry it. A placeholder that is also a live value makes \
         every artifact using it need an exemption, which is H-45.",
        clashes.join("\n")
    );
    println!(
        "live-values: {} generator placeholder(s), none of them a value any deployment holds",
        placeholders.len()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The matcher counts; these tests ask whether it found anything, which is the same question.
    fn carries_as_a_number(haystack: &str, needle: &str) -> bool {
        occurrences_as_a_number(&strip_digit_separators(haystack), needle) > 0
    }

    /// **The false positive that made short values unlistable** (H-20, issue #60).
    #[test]
    fn a_listed_decimal_does_not_match_inside_a_longer_number() {
        assert!(
            !carries_as_a_number("15049856620", "504985662"),
            "a slot inside an unrelated longer decimal is not that slot, and treating it as one is \
             why the list carried a six-digit floor"
        );
        assert!(!carries_as_a_number("1504985662", "504985662"));
        assert!(!carries_as_a_number("5049856620", "504985662"));
    }

    /// The control. Without it the test above would pass on a matcher that never matches.
    #[test]
    fn a_listed_decimal_matches_where_it_is_a_number_on_its_own() {
        for carrier in [
            "504985662",
            "\"slot\": 504985662,",
            "slot=504985662",
            "published at 504985662.",
            "[504985662]",
            "504985662 and more text",
        ] {
            assert!(
                carries_as_a_number(carrier, "504985662"),
                "{carrier:?} carries the slot and was not matched"
            );
        }
    }

    /// It has to keep looking after a rejected hit, or one bad occurrence hides a real one.
    #[test]
    fn a_rejected_occurrence_does_not_stop_the_search() {
        assert!(
            carries_as_a_number("15049856620 then 504985662", "504985662"),
            "the first occurrence is inside a longer number and the second is not"
        );
    }

    /// Epoch day indices are five digits, which is what the floor now admits.
    #[test]
    fn a_five_digit_epoch_is_matched_on_its_own_and_not_inside_a_longer_number() {
        assert!(carries_as_a_number("epoch 20739 published", "20739"));
        assert!(!carries_as_a_number("207391", "20739"));
        assert!(!carries_as_a_number("120739", "20739"));
    }

    /// **The long shapes keep substring matching, and that is deliberate.**
    ///
    /// A 64-character digest does not collide by accident, and requiring boundaries would lose the
    /// case the gate most needs: a listed root pasted inside a longer hex blob. The list decides per
    /// value, from its declared shape.
    #[test]
    fn only_decimal_shapes_take_boundaries() {
        for what in ["published slot, epoch 20723", "publication timestamp"] {
            assert!(
                matches!(declared_shape(what), Shape::Slot | Shape::UnixTimestamp),
                "{what:?} should be a decimal shape"
            );
        }
        for what in [
            "published root, epoch 20723",
            "checkpoint address, epoch 20723",
            "co-signature inside a transaction",
            "program id, superseded 24 September, as bytes",
        ] {
            assert!(
                !matches!(declared_shape(what), Shape::Slot | Shape::UnixTimestamp),
                "{what:?} must keep substring matching, or a value inside a longer string escapes"
            );
        }
    }

    /// **The carve-out's own example, fixed.** `LIVE-VALUES.txt` records that a matcher looking for
    /// the bump `255` as a substring finds the curve's name in `Ed25519`. The trailing `1` is a digit,
    /// so boundaries reject it.
    #[test]
    fn the_bump_255_is_not_found_inside_ed25519() {
        assert!(!carries_as_a_number("Ed25519", "255"));
        assert!(!carries_as_a_number("ed25519 signature", "255"));
        assert!(
            carries_as_a_number("bump 255", "255"),
            "the control: a bump written as a number is still found, which is why 255 stays \
             unlistable on entropy rather than on matching"
        );
    }

    /// **The twenty-six false positives, in one assertion** (H-20, issue #60).
    ///
    /// This is why the boundary is a hexadecimal digit rather than a decimal one. A five-digit epoch
    /// index inside a digest is not that epoch, and the decimal rule found twenty-one of them in the
    /// Keccak known-answer vectors alone.
    #[test]
    fn a_five_digit_epoch_inside_a_hex_blob_is_not_that_epoch() {
        assert!(
            !carries_as_a_number("a3f20751bc9d", "20751"),
            "hex digits either side, so this is a digest and not the epoch 20751"
        );
        assert!(!carries_as_a_number(
            "0x6bb7ac8d9543a9b175ebed0af2d643315745104cfc1b96e29097416da83fd867",
            "43315"
        ));
        assert!(
            carries_as_a_number("epoch 20751, published", "20751"),
            "the control: a letter that is not a hex digit, or none at all, still matches"
        );
        assert!(
            carries_as_a_number("slot20723", "20723"),
            "`s` is not a hex digit, so the looser cases a boundary is for still match"
        );
    }

    /// **The spelling that let ten uses through** (H-20, issue #60).
    #[test]
    fn a_digit_separator_does_not_hide_a_number() {
        assert!(
            carries_as_a_number("checkpoint_address(&program_id, 20_723)", "20723"),
            "`20_723` is the number 20723 in Rust, and ten of the fifteen synthetic uses of a live \
             epoch were spelled this way"
        );
        assert_eq!(
            strip_digit_separators("slot_20723 and 20_723"),
            "slot_20723 and 20723",
            "only a separator between two digits goes; an identifier keeps its underscore"
        );
    }

    /// The gate counts occurrences now, because an exemption permits a number of them (H-20).
    #[test]
    fn occurrences_are_counted_and_not_merely_detected() {
        assert_eq!(
            occurrences_as_a_number("20723 then 20723 then 120723", "20723"),
            2,
            "two standalone uses and one inside a longer number"
        );
    }

    /// **A hex value is counted once per occurrence, not once per spelling.**
    ///
    /// `needles` holds `0x…` and the bare form, and every occurrence of the prefixed spelling
    /// contains the bare one, so counting both would report two uses where a file has one — and the
    /// exemption permitting one would fail.
    #[test]
    fn a_hex_value_in_both_spellings_is_counted_once_each() {
        let v = LiveValue {
            value: format!("0x{}", "ab".repeat(32)),
            lower: format!("0x{}", "ab".repeat(32)),
            what: "published root, epoch 20723".to_string(),
            on_number_boundaries: false,
            needles: vec![format!("0x{}", "ab".repeat(32)), "ab".repeat(32)],
        };
        let text = format!("{} and 0x{}", "ab".repeat(32), "ab".repeat(32));
        assert_eq!(
            occurrences(&v, &text, &text),
            2,
            "one bare and one prefixed is two occurrences, not three"
        );
    }

    #[test]
    fn an_empty_needle_matches_nothing() {
        assert!(
            !carries_as_a_number("anything at all", ""),
            "an empty needle is in every string, which would make the gate fire on everything"
        );
    }
}
