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
//! **What it deliberately does not cover.** Slot numbers and block heights are plain integers and a
//! list of them would produce false positives on every counter in the corpus. The rule reaches
//! 32-byte values and base58 identifiers, which is where fabricated provenance is persuasive.

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
pub fn check_list_shape(root: &Path) {
    for v in live_values(root) {
        let looks_like_hex = v.value.starts_with("0x") && v.value.len() == 66;
        let looks_like_base58 = v.value.len() >= 32
            && v.value.len() <= 88
            && v.value.chars().all(|c| c.is_ascii_alphanumeric());
        assert!(
            looks_like_hex || looks_like_base58,
            "LIVE-VALUES.txt: {:?} is neither a 32-byte hex value nor a base58 identifier, and the \
             rule covers those two shapes",
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
