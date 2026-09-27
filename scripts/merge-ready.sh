#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Is a branch actually ready to merge? Run this before telling anyone it is.
#
# Written because "ready to merge" was asserted from a green CI run, and the branch carried 783
# vendored dependency files and 30 build outputs into `main` (S9-E11-08). CI was green the whole time,
# because no job looked. A green pipeline says the tests passed; it does not say the branch contains
# what it should.
#
#   scripts/merge-ready.sh [base]      base defaults to origin/main
#
# Exits non-zero on anything a reviewer would object to. It checks the tree, not the tests: run
# `scripts/ci.sh all` for those.
set -uo pipefail
cd "$(dirname "$0")/.."

BASE="${1:-origin/main}"
HEAD_REF="$(git rev-parse --abbrev-ref HEAD)"
failed=0

note() { printf '  %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1" >&2; failed=1; }

echo "merge-ready: $HEAD_REF against $BASE"

echo "----- the working tree is clean"
if [ -n "$(git status --porcelain)" ]; then
  fail "uncommitted changes; what is reviewed must be what is committed"
  git status --short | sed 's/^/        /' >&2
else
  note "clean"
fi

echo "----- nothing that should never be committed"
# Dependency trees, build output, keys, and anything with a secret's shape.
banned="$(git ls-files \
  | grep -E '(^|/)(node_modules|dist|target)/|\.so$|\.ots$|(^|/)\.env|keypair.*\.json$|id_rsa|\.pem$' \
  | grep -v '^anchors/' || true)"
if [ -n "$banned" ]; then
  fail "$(printf '%s' "$banned" | wc -l | tr -d ' ') tracked files that do not belong in a repository:"
  printf '%s\n' "$banned" | head -10 | sed 's/^/        /' >&2
else
  note "no dependency trees, build output or key-shaped files tracked"
fi

echo "----- the diff against $BASE"
if ! git rev-parse --verify -q "$BASE" >/dev/null; then
  fail "$BASE does not exist; fetch first"
else
  added="$(git diff --name-status "$BASE"...HEAD | awk '$1=="A"{print $2}' | wc -l | tr -d ' ')"
  deleted="$(git diff --name-status "$BASE"...HEAD | awk '$1=="D"{print $2}' | wc -l | tr -d ' ')"
  note "$added added, $deleted deleted, $(git rev-list --count "$BASE"..HEAD) commits"
  # A deletion is legitimate and is never silent: it is named so a reader decides rather than discovers.
  if [ "$deleted" != "0" ]; then
    note "deleted files, each of which a reviewer should be told about:"
    git diff --name-status "$BASE"...HEAD | awk '$1=="D"{print "        " $2}' | head -10
  fi
fi

echo "----- the branch is not behind $BASE"
if git rev-parse --verify -q "$BASE" >/dev/null; then
  behind="$(git rev-list --count HEAD.."$BASE")"
  if [ "$behind" != "0" ]; then
    fail "$behind commits behind $BASE; rebase before claiming mergeable"
  else
    note "up to date"
  fi
fi

echo "----- no placeholder left in a document"
placeholders="$(git ls-files '*.md' | xargs grep -nE 'filled at deploy|TBD|TODO|FIXME|PENDING_|XXX' 2>/dev/null \
  | grep -viE 'TODO is|a TODO|`TODO`|TODO,' || true)"
if [ -n "$placeholders" ]; then
  fail "placeholders in prose a reader would read as fact:"
  printf '%s\n' "$placeholders" | head -8 | sed 's/^/        /' >&2
else
  note "none"
fi

echo "----- §4.6's claim gate"
if [ -x scripts/claim-check.sh ]; then
  if scripts/claim-check.sh >/dev/null 2>&1; then note "passes"; else fail "claim-check fails"; fi
else
  note "not on this branch"
fi

if [ "$failed" -ne 0 ]; then
  echo "merge-ready: NOT READY" >&2
  exit 1
fi
echo "merge-ready: the tree is in order. Tests are scripts/ci.sh all, and review is a person."
