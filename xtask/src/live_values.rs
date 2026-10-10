// SPDX-License-Identifier: MIT OR Apache-2.0
//! The rule that no synthetic artifact carries a value from a live deployment (owner, 28 Sep 2026).
//!
//! **Why this exists.** E-14's demo fixture carried the announced log's real transaction signature and
//! slot in its `anchor` block, beside an epoch root that was built for the demo and published nowhere
//! — and the signature and the slot were not even from the same publication. The fixture asserted an
//! anchoring that had never happened. Fabricated provenance is the worst class of defect this
//! repository can hold, and it is the kind an author cannot see in their own work, which is what an
//! independent round is for. A rule that lives only in a person's judgement is the same rule that
//! failed.
//!
//! **What it checks.** Every file a generator is about to write is scanned for each value in
//! `LIVE-VALUES.txt`, and generation fails on a match unless the exact pair is recorded in
//! `LIVE-VALUES.exempt`. Matching is case-insensitive, so a base58 string that collides only under
//! case folding would fail generation — a false positive, which is the safe direction, and loud.
//!
//! **What it covers, and what it does not.** The rule reaches 32-byte values, base58 identifiers and —
//! since a review found a live publication slot beside a fabricated root — decimals of six digits or
//! more, which is what admits a slot or a unix timestamp without firing on every small counter in the
//! corpus. Block heights are still uncovered. Bumps and epoch day indices are excluded by shape rather
//! than by principle: both are short enough that listing them would match unrelated text, so they are
//! review-enforced, and H-20 removes the need for that carve-out.
//!
//! **What neither half asks (H-26).** The rule is unqualified — no value from a live deployment, in
//! any synthetic artifact — and these two checks cover the *announced* deployment. The superseded
//! program ids `HS82CAXg…` and `jzJzgKWM…` are listed, but nothing derived from them is: a review
//! found they still own 2 and 213 accounts on devnet, and none of those addresses is here. Placing
//! one in a fixture passes both halves, because the static gate has no value to match and the chain
//! reader never asks a superseded program what it owns. Supersession does not remove an account from
//! devnet and does not make its provenance synthetic.
//!
//! Closing that means either listing those 215 accounts or narrowing the rule to the announced
//! deployment, and the second is the owner's to decide rather than a tool's. Until then both
//! messages say which deployment they asked, so neither claims more than it checked.
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
        out.push(LiveValue {
            value: value.trim().to_string(),
            lower: value.trim().to_lowercase(),
            what: what.trim().to_string(),
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
    let values = live_values(root);
    let allowed = exemptions(root);
    let mut found: Vec<String> = Vec::new();

    for (name, text) in files {
        let lower = text.to_lowercase();
        for v in &values {
            if !lower.contains(&v.lower) {
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
        // The six-digit floor stays, and it is about matching rather than about shape: a short
        // number is everywhere in a fixture, so listing one would make the gate match text that has
        // nothing to do with the deployment. `check_recorded_short_values` governs the exceptions.
        if matches!(shape, Shape::Slot | Shape::UnixTimestamp) {
            // The floor is on the magnitude, not the string: a sign is not a digit, and `-100000`
            // is as specific a thing to search a corpus for as `100000` (H-28).
            let digits = v.value.strip_prefix('-').unwrap_or(&v.value);
            assert!(
                digits.len() >= 6,
                "LIVE-VALUES.txt: {:?} has under six digits, which would make the gate match counters \
                 and lengths throughout the corpus",
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
        "live-values: {} files in the synthetic surface carry no value this list holds, and this \
         list covers the announced deployment (H-26)",
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
