#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# §4.6's claim gate, as a build step (E-15, D-121). No artifact in this repository may claim fraud
# prevention, double-pledge prevention or regulatory compliance, and §4.4's INV-STATE-06a adds that a
# flag is an observation and never a verdict.
#
# Two checks, because one grep cannot do it:
#
#   1. Banned phrasings: constructions a denial never uses, which is why they can be grepped for
#      without exempting anything. The list is not reproduced here — it lives in §4.6 of the
#      specification and is read from there, so there is one copy and changing it is a change to the
#      document an independent reader reads. This script quotes none of them, because it checks itself
#      like every other file and a quoted example would be indistinguishable from a claim.
#
#   2. The bare concept nouns. §0 and §4.6 contain them, because naming a claim is how a document
#      forbids it. Every occurrence must be listed in docs/claim-denials.txt by a SHA-256 of its
#      trimmed line. Editing a denial changes the hash and withdraws the exemption, which is the point:
#      an exemption nobody re-checks is how a claim eventually lands beside a denial.
set -uo pipefail
cd "$(dirname "$0")/.."

SPEC=docs/TCU-02_CertiMining_Anchored_Log_v0.1.md
DENIALS=docs/claim-denials.txt
failed=0

# §4.6's own list of banned phrasings is not a claim and not a denial: it is the list. Its line range
# is computed here so the noun check skips it, rather than the list being recorded as fifteen denials.
fence_range() {
  awk -v s="$SPEC" '
    /^```claim-phrasings-banned$/ { start = NR }
    start && /^```$/ && NR > start { print start "," NR; exit }
  ' "$SPEC"
}

# Drops any hit that falls inside that fence.
outside_the_fence() {
  local range from to
  range="$(fence_range)"
  from="${range%%,*}"
  to="${range##*,}"
  if [ -z "$range" ]; then cat; return; fi
  awk -F: -v spec="$SPEC" -v from="$from" -v to="$to" \
    '!($1 == spec && $2 >= from && $2 <= to)'
}

# Everything a reader could meet. Build output, dependencies and the git directory are not artifacts.
files() {
  # Tracked *and* untracked-but-not-ignored. A gate that only sees committed files cannot see the file
  # a claim arrives in, which a probe found it doing on a brand-new README.
  git ls-files --cached --others --exclude-standard \
    ':!:docs/claim-denials.txt' \
    ':!:LICENSE' ':!:LICENSE-MIT' ':!:LICENSE-APACHE' \
    | grep -E '\.(md|rs|ts|mjs|toml|sh|yml|yaml|json|txt)$' || true
}

echo "----- banned phrasings (§4.6)"
phrasings="$(awk '/^```claim-phrasings-banned$/{flag=1;next}/^```$/{flag=0}flag' "$SPEC")"
if [ -z "$phrasings" ]; then
  echo "claim-check: §4.6 has no claim-phrasings-banned block; the list must live in the specification" >&2
  exit 1
fi
count=0
while IFS= read -r phrase; do
  [ -n "$phrase" ] || continue
  count=$((count + 1))
  # Only §4.6's list block is exempt, not the whole specification. Exempting the file would let a
  # claim added to the document itself pass, which a probe found it doing.
  hits="$(files | xargs grep -inF -- "$phrase" 2>/dev/null | outside_the_fence || true)"
  if [ -n "$hits" ]; then
    echo "claim-check: §4.6 forbids the phrasing \"$phrase\":" >&2
    echo "$hits" >&2
    failed=1
  fi
done <<<"$phrasings"
echo "  $count phrasings checked, from $SPEC"

echo "----- the bare concept nouns, against the pinned allowlist"
# Every line mentioning a banned concept must be a denial recorded in $DENIALS by its own hash.
[ -f "$DENIALS" ] || { echo "claim-check: $DENIALS is missing (D-121)" >&2; exit 1; }

# The hashes present in the repository right now, computed once.
present="$(mktemp)"
trap 'rm -f "$present"' EXIT
listed=0
unlisted=0
while IFS= read -r line; do
  [ -n "$line" ] || continue
  path="${line%%:*}"
  rest="${line#*:}"
  number="${rest%%:*}"
  text="${rest#*:}"
  hash="$(printf '%s' "$text" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | shasum -a 256 | cut -d' ' -f1)"
  printf '%s\n' "$hash" >>"$present"
  if grep -qF "$hash" "$DENIALS"; then
    listed=$((listed + 1))
  else
    echo "claim-check: $path:$number mentions a banned concept and is not a recorded denial." >&2
    echo "             If it is one, add this line to $DENIALS:" >&2
    echo "             $hash  $path" >&2
    unlisted=$((unlisted + 1))
    failed=1
  fi
done < <(files | xargs grep -inE 'fraud|double-pledge|double pledge|regulatory compliance|43-101 complian' 2>/dev/null | outside_the_fence || true)
echo "  $listed recorded denials, $unlisted unrecorded"

# A stale exemption is a defect of its own: it means a denial moved and nobody noticed.
stale=0
while IFS= read -r entry; do
  case "$entry" in ''|\#*) continue ;; esac
  hash="${entry%% *}"
  case "$hash" in *[!0-9a-f]*|'') continue ;; esac
  if ! grep -qxF "$hash" "$present"; then
    echo "claim-check: $DENIALS exempts a line that no longer exists: $hash" >&2
    echo "             Remove it, so the file records what is there rather than what was." >&2
    stale=$((stale + 1))
    failed=1
  fi
done <"$DENIALS"
echo "  $stale stale exemptions"

[ "$failed" -eq 0 ] || { echo "claim-check: FAILED" >&2; exit 1; }
echo "claim-check: no banned phrasing, every banned concept a recorded denial"
