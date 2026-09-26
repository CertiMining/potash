#!/usr/bin/env bash
# The supply-chain gate for the TypeScript verifier (D-93). `cargo deny` reads Cargo.lock and sees no
# npm package, so without this the verifier's dependencies would enter the build ungated while the
# Rust side is held to D-18's standard.
#
# Two checks, both against the committed lock file rather than against whatever npm resolves today:
#   1. advisories, through `npm audit`
#   2. licences, against ts/LICENCES.allow, which is a closed list
#
# A package under an unlisted licence fails the build and reaches a person, which is the behaviour
# D-89 chose for the Rust side and the reason a global allow was refused there.
set -euo pipefail
cd "$(dirname "$0")/.."

TS_DIR="ts"
ALLOW="$TS_DIR/LICENCES.allow"

[ -d "$TS_DIR" ] || { echo "ts-gate: $TS_DIR is missing" >&2; exit 1; }
[ -f "$TS_DIR/package-lock.json" ] || { echo "ts-gate: no committed lock file in $TS_DIR" >&2; exit 1; }
[ -f "$ALLOW" ] || { echo "ts-gate: $ALLOW is missing; the allow list is not optional (D-93)" >&2; exit 1; }

failed=0

# `npm ci` installs exactly the lock file, never a newer resolution, so the tree audited below is the
# tree the build uses.
echo "----- npm ci"
( cd "$TS_DIR" && npm ci --no-audit --no-fund ) || failed=1

echo "----- npm audit"
# Anything at high or critical fails. Moderate and low are reported and do not block, which matches
# the post-deadline hardening rule rather than pretending every advisory is a release blocker.
( cd "$TS_DIR" && npm audit --audit-level=high ) || failed=1

echo "----- licences"
# Every installed package's licence is read from its own package.json and matched against the closed
# list. A package with no licence field at all fails: absence is not permission.
( cd "$TS_DIR" && node --input-type=module -e '
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
const allow = new Set(
  readFileSync("LICENCES.allow", "utf8")
    .split("\n").map(l => l.replace(/#.*$/, "").trim()).filter(Boolean)
);
const bad = [];
const seen = [];
function walk(dir) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (!statSync(path).isDirectory()) continue;
    if (name.startsWith("@")) { walk(path); continue; }
    let pkg;
    try { pkg = JSON.parse(readFileSync(join(path, "package.json"), "utf8")); } catch { continue; }
    const licence = typeof pkg.license === "string" ? pkg.license
      : pkg.license?.type ?? (Array.isArray(pkg.licenses) ? pkg.licenses.map(l => l.type).join(" OR ") : null);
    seen.push(`${pkg.name}@${pkg.version} ${licence ?? "NONE"}`);
    if (!licence || !allow.has(licence)) bad.push(`${pkg.name}@${pkg.version}: ${licence ?? "no licence field"}`);
    const nested = join(path, "node_modules");
    try { if (statSync(nested).isDirectory()) walk(nested); } catch {}
  }
}
try { walk("node_modules"); } catch { console.error("ts-gate: no node_modules; run npm ci first"); process.exit(1); }
for (const line of seen.sort()) console.log("  " + line);
if (bad.length) {
  console.error("\nts-gate: " + bad.length + " package(s) under a licence not on the list (D-93):");
  for (const b of bad) console.error("  " + b);
  console.error("\nAdd it to ts/LICENCES.allow deliberately, having read what it covers, or drop the package.");
  process.exit(1);
}
console.log(`\nts-gate: ${seen.length} packages, every licence on the list`);
') || failed=1

if [ "$failed" -ne 0 ]; then
  echo "ts-gate: FAILED" >&2
  exit 1
fi
echo "ts-gate: advisories ok, licences ok"
