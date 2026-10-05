#!/usr/bin/env bash
# The repository head, timestamped on Bitcoin through OpenTimestamps (E-16).
#
# `anchors/0001-0258f51.txt` was produced by hand in September and nothing recorded how. That is a
# one-shot step on the submission commit with no second chance and no runbook, which is the kind of
# step that goes wrong on the day. This is the same thing as a command.
#
# What it does: writes a manifest naming the commit, its tree, and the digest of the documents a
# counterparty reads, then stamps that manifest. The tree hash already commits to every tracked byte;
# the per-file digests are there so a reader can check one document without reconstructing the tree.
#
# **The commit it names is the parent of the commit that carries it, and that is unavoidable.** The
# manifest cannot contain its own hash, so the anchored commit is the clean head at the time of
# stamping, and committing the manifest produces a child of it. `anchors/0001-0258f51.txt` has the same
# shape. A reader checks out the named commit and recomputes the tree; the anchor commit itself adds
# only the manifest and its receipt.
#
# The receipt it writes carries calendar attestations only. Bitcoin confirmation takes hours, exactly
# as it does for an epoch (D-112), so run `ots upgrade` on the `.ots` before committing it and verify
# it names a block. An unupgraded receipt proves a calendar saw the manifest, which is not the claim.
set -euo pipefail

OTS="${OTS:-$HOME/.local/share/potash/ots-venv/bin/ots}"
root="$(git rev-parse --show-toplevel)"
cd "$root"

# A manifest for a tree you cannot reproduce is not evidence of anything.
if [ -n "$(git status --porcelain)" ]; then
  echo "anchor-repo: the working tree is dirty; the manifest would name a commit that is not what is here" >&2
  git status --short >&2
  exit 1
fi

commit="$(git rev-parse HEAD)"
tree="$(git rev-parse HEAD^{tree})"
short="$(git rev-parse --short=7 HEAD)"

# The next number in sequence, so two anchors cannot share a name.
last="$(find anchors -maxdepth 1 -name '[0-9][0-9][0-9][0-9]-*.txt' -exec basename {} \; \
        | cut -c1-4 | sort -n | tail -1)"
next="$(printf '%04d' $((10#${last:-0} + 1)))"
manifest="anchors/${next}-${short}.txt"

if [ -e "$manifest" ]; then
  echo "anchor-repo: $manifest already exists" >&2
  exit 1
fi

{
  echo "CertiMining/potash - OpenTimestamps anchor manifest ${next}"
  echo "repository https://github.com/CertiMining/potash"
  echo "commit ${commit}"
  echo "tree ${tree}"
  for f in docs/STANDARD-STEPS.md docs/TCU-02_CertiMining_Anchored_Log_v0.1.md docs/DECISIONS.md README.md; do
    [ -f "$f" ] && shasum -a 256 "$f"
  done
} > "$manifest"

echo "----- manifest"
cat "$manifest"

echo "----- stamping"
"$OTS" stamp "$manifest"

echo
echo "anchor-repo: wrote $manifest and $manifest.ots"
echo "             The receipt carries calendar attestations only. Hours from now:"
echo "               $OTS upgrade $manifest.ots"
echo "               $OTS info $manifest.ots | grep -i bitcoin"
echo "             Commit the upgraded receipt, not this one (INV-ANCH-03's reasoning: one shot)."
