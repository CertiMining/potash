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
//! An earlier version of this paragraph said slot numbers were deliberately uncovered, which the
//! decimal support contradicts.

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
            // An exemption may be recorded under the artifact's own file name, which is how the
            // generator knows it, or under its repository path, which is how the tree walk does.
            // Either spelling exempts the same file, so a pair written once keeps working whichever
            // side finds it.
            let basename = name.rsplit('/').next().unwrap_or(name).to_string();
            if allowed.contains(&(name.clone(), v.lower.clone()))
                || allowed.contains(&(basename, v.lower.clone()))
            {
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

pub fn check_list_shape(root: &Path) {
    check_recorded_short_values(root);
    for v in live_values(root) {
        let looks_like_hex = v.value.starts_with("0x") && v.value.len() == 66;
        let looks_like_base58 = v.value.len() >= 32
            && v.value.len() <= 88
            && v.value.chars().all(|c| c.is_ascii_alphanumeric());
        // **A third shape, added after a review found the second gap this file has had.** The rule
        // covers "no value from a live deployment", unqualified, and two of a checkpoint's fields are
        // decimal: `published_slot` and `published_unix`. Only hex and base58 were accepted here, so a
        // slot could not be listed even by someone who wanted to — and `demo/test/footprint.test.mjs`
        // carried epoch 20723's real slot beside a fabricated root and a fabricated receipt digest,
        // which is the exact pairing this rule was written for, while both halves of the gate exited 0.
        //
        // Six digits or more, all decimal. The floor is there because short numbers are everywhere in a
        // fixture — lengths, counts, epoch day indices — and listing one would make the gate match text
        // that has nothing to do with the deployment. Epoch numbers are deliberately **not** listed for
        // that reason: a UTC day index is a date, not something the deployment produced, and the demo is
        // legitimately about epoch 20723.
        let looks_like_decimal = v.value.len() >= 6 && v.value.chars().all(|c| c.is_ascii_digit());
        assert!(
            looks_like_hex || looks_like_base58 || looks_like_decimal,
            "LIVE-VALUES.txt: {:?} is not a 32-byte hex value, a base58 identifier, or a decimal of six \
             digits or more, and the rule covers those three shapes",
            v.value
        );
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
/// The surface is named rather than inferred. A tree-wide scan would need an allow-list holding
/// `docs/anchoring.md`, `ANNOUNCED_PROGRAM_ID`, `README.md`, the deploy script, the cluster harnesses
/// and the program's own `declare_id!` — every one of which holds live values because its subject is
/// the deployment — and an allow-list that long is a gate that no longer refuses anything. What is
/// scanned is what is synthetic by nature: the demo and the vectors.
pub fn check_synthetic_surface(root: &Path) {
    check_list_shape(root);
    let mut files: Vec<(String, String)> = Vec::new();
    for dir in ["demo", "vectors"] {
        collect(&root.join(dir), root, &mut files);
    }
    assert!(
        files.len() > 10,
        "the synthetic surface is {} files, which means the walk found nothing and would pass anything",
        files.len()
    );
    refuse_live_values(root, &files);
    println!(
        "live-values: {} files in the synthetic surface carry no value that exists on chain",
        files.len()
    );
}

/// Everything readable as text under `dir`, keyed by the name the exemption list uses: the file's own
/// name for a generated artifact, and its repository-relative path otherwise.
fn collect(dir: &Path, root: &Path, out: &mut Vec<(String, String)>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        // Build output is not committed and is a copy of dependencies that legitimately hold nothing
        // of ours; `node_modules` likewise.
        if name == "build" || name == "node_modules" || name == "dist" || name.starts_with('.') {
            continue;
        }
        if path.is_dir() {
            collect(&path, root, out);
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue; // not text; nothing to read a base58 string out of
        };
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
