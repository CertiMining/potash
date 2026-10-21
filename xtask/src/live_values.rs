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

use std::collections::BTreeSet;
use std::path::Path;

/// One value that exists on chain.
struct LiveValue {
    value: String,
    lower: String,
    what: String,
    /// Whether a match has to fall on digit boundaries (H-20, issue #60).
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
    on_digit_boundaries: bool,
    /// Every spelling of this value a file could carry, lowercased.
    ///
    /// **`0x` is the list's convention, not part of the value (found while repairing H-01).** The
    /// match required the prefix, so the same bytes spelled bare went straight through: a real root
    /// from the 25 September deployment, pasted into a fuzz target without it, left the gate at
    /// exit 0. Three committed files already carried a listed digest that way, unseen.
    needles: Vec<String>,
}

/// Whether `needle` occurs in `haystack` with no digit immediately either side.
///
/// The boundary is digits and not alphanumerics on purpose. `504985662` must not match inside
/// `15049856620`, which is the false positive that made short values unlistable; it must still match
/// in `"slot": 504985662,` and in `slot504985662` if anything ever writes that, because a looser
/// boundary buys nothing here and loses matches.
fn contains_on_digit_boundaries(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let bytes = haystack.as_bytes();
    let mut from = 0usize;
    while let Some(rest) = haystack.get(from..) {
        let Some(hit) = rest.find(needle) else {
            return false;
        };
        let at = from.saturating_add(hit);
        let end = at.saturating_add(needle.len());
        let before_is_digit = at
            .checked_sub(1)
            .and_then(|i| bytes.get(i))
            .is_some_and(u8::is_ascii_digit);
        let after_is_digit = bytes.get(end).is_some_and(u8::is_ascii_digit);
        if !before_is_digit && !after_is_digit {
            return true;
        }
        from = at.saturating_add(1);
    }
    false
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
            on_digit_boundaries: matches!(
                declared_shape(what.trim()),
                Shape::Slot | Shape::UnixTimestamp
            ),
            needles,
        });
    }
    assert!(!out.is_empty(), "LIVE-VALUES.txt lists nothing");
    out
}

/// `(file, value)` pairs that are allowed, because the artifact's subject *is* the deployment.
fn exemptions(root: &Path) -> BTreeSet<(String, String)> {
    let mut out = BTreeSet::new();
    for line in repo_file(root, "LIVE-VALUES.exempt").lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(3, "  ");
        let file = parts
            .next()
            .unwrap_or_else(|| panic!("LIVE-VALUES.exempt: no file on {line:?}"))
            .trim();
        let value = parts
            .next()
            .unwrap_or_else(|| panic!("LIVE-VALUES.exempt: no value on {line:?}"))
            .trim();
        assert!(
            parts.next().is_some(),
            "LIVE-VALUES.exempt: no reason on {line:?}; an exemption without one is a hole"
        );
        out.insert((file.to_string(), value.to_lowercase()));
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
        for v in &values {
            let carried = |n: &String| {
                if v.on_digit_boundaries {
                    contains_on_digit_boundaries(&lower, n)
                } else {
                    lower.contains(n)
                }
            };
            if !v.needles.iter().any(carried) {
                continue;
            }
            // **The exact path, and nothing else (H-25 review, H3).** A basename was accepted too,
            // so that an exemption written for a generated file kept working when the tree walk
            // found it under a path. One exemption for `(allowed.json, value)` therefore exempted
            // that value in every other `allowed.json` anywhere in the surface — a review passed two
            // different files through one entry. Both callers now key by the artifact's destination
            // in the repository, so one spelling is enough and it is the specific one.
            if allowed.contains(&(name.clone(), v.lower.clone())) {
                continue;
            }
            found.push(format!("  {name} carries {} ({})", v.value, v.what));
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
/// Bumps and epoch day indices cannot be matched — five digits and 0-255 collide with unrelated text
/// everywhere, and `255` inside `Ed25519` is the example the list itself gives — so the owner made them
/// review-enforced on 4 Oct 2026: a short live value may appear only where the artifact's subject is
/// the announced deployment, and only if the use is recorded in `LIVE-VALUES.txt` by file, value and
/// occurrence.
///
/// **A checklist nobody verifies goes stale the first time somebody edits one of those files.** The
/// record claims `demo/app.js` holds `20723` once. If a second use appears, the count is wrong and the
/// reviewer reading it is misled in the safe-looking direction. So the counts are checked here: not
/// that the value is permitted, which is a judgement, but that the record describes the tree.
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
}

fn declared_shape(what: &str) -> Shape {
    if what.contains("as bytes") || what.contains("digest") || what.contains("root") {
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
        // has nothing to do with the deployment. Decimals now match on digit boundaries, and that
        // false positive is gone, which is what lets epoch day indices be listed and gate-enforced
        // rather than review-enforced.
        //
        // What boundaries cannot fix is a value that carries no provenance. A checkpoint bump is one
        // of 256 possibilities; `255` appearing in a fixture is evidence of nothing, and listing it
        // would fire on every unrelated `255` in the corpus — the demo page says "255 records" about
        // a tree it built itself. So bumps stay out, by what they are rather than by their length,
        // and `check_recorded_short_values` governs any exception a reviewer records.
        if matches!(shape, Shape::Slot | Shape::UnixTimestamp) {
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
    for (file, value) in exemptions(root) {
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
    println!(
        "live-values: {} files in the synthetic surface carry no value this list holds — the \
         announced deployment, and the two superseded ones, their accounts and what those accounts \
         store",
        files.len()
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

#[cfg(test)]
mod tests {
    use super::*;

    /// **The false positive that made short values unlistable** (H-20, issue #60).
    #[test]
    fn a_listed_decimal_does_not_match_inside_a_longer_number() {
        assert!(
            !contains_on_digit_boundaries("15049856620", "504985662"),
            "a slot inside an unrelated longer decimal is not that slot, and treating it as one is \
             why the list carried a six-digit floor"
        );
        assert!(!contains_on_digit_boundaries("1504985662", "504985662"));
        assert!(!contains_on_digit_boundaries("5049856620", "504985662"));
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
                contains_on_digit_boundaries(carrier, "504985662"),
                "{carrier:?} carries the slot and was not matched"
            );
        }
    }

    /// It has to keep looking after a rejected hit, or one bad occurrence hides a real one.
    #[test]
    fn a_rejected_occurrence_does_not_stop_the_search() {
        assert!(
            contains_on_digit_boundaries("15049856620 then 504985662", "504985662"),
            "the first occurrence is inside a longer number and the second is not"
        );
    }

    /// Epoch day indices are five digits, which is what the floor now admits.
    #[test]
    fn a_five_digit_epoch_is_matched_on_its_own_and_not_inside_a_longer_number() {
        assert!(contains_on_digit_boundaries(
            "epoch 20739 published",
            "20739"
        ));
        assert!(!contains_on_digit_boundaries("207391", "20739"));
        assert!(!contains_on_digit_boundaries("120739", "20739"));
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
        assert!(!contains_on_digit_boundaries("Ed25519", "255"));
        assert!(!contains_on_digit_boundaries("ed25519 signature", "255"));
        assert!(
            contains_on_digit_boundaries("bump 255", "255"),
            "the control: a bump written as a number is still found, which is why 255 stays \
             unlistable on entropy rather than on matching"
        );
    }

    #[test]
    fn an_empty_needle_matches_nothing() {
        assert!(
            !contains_on_digit_boundaries("anything at all", ""),
            "an empty needle is in every string, which would make the gate fire on everything"
        );
    }
}
