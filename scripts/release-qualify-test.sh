#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Structural tests for the release-qualification entry point. The real end-to-end test is a clean-tree
# run of scripts/release-qualify.sh; these checks keep its fail-closed boundary and command plan pinned.
set -uo pipefail
cd "$(dirname "$0")/.."

failed=0
pass() { printf 'ok - %s\n' "$1"; }
fail() { printf 'not ok - %s\n' "$1" >&2; failed=1; }

if bash -n scripts/release-qualify.sh; then pass "release script parses"; else fail "release script parses"; fi

plan="$(scripts/release-qualify.sh --print-plan)"
for required in \
  'scripts/ci.sh all' \
  'cargo test --release -p certimining-log -- --ignored' \
  'scripts/ci.sh thresholds' \
  'scripts/ci.sh bench' \
  'scripts/ci.sh fuzz' \
  'cargo build --release -p certimining-client --features cluster\,ots --bins' \
  'scripts/build-sbf.sh'; do
  if grep -Fq "$required" <<<"$plan"; then pass "plan contains $required"; else fail "plan contains $required"; fi
done

for forbidden in deploy-devnet upgrade-devnet test:net anchor_b_devnet live-values-from-chain; do
  if grep -Fq "$forbidden" <<<"$plan"; then fail "plan excludes $forbidden"; else pass "plan excludes $forbidden"; fi
done

if grep -Fq 'no checks ran and no qualification verdict was produced' <<<"$plan"; then
  pass "plan mode cannot be mistaken for qualification"
else
  fail "plan mode cannot be mistaken for qualification"
fi

fixture="$(mktemp -d)" || exit 1
cleanup() { rm -rf "$fixture"; }
trap cleanup EXIT HUP INT TERM
dirty_fixture="$fixture/dirty"
mkdir -p "$dirty_fixture/scripts"
cp scripts/release-qualify.sh "$dirty_fixture/scripts/release-qualify.sh"
chmod +x "$dirty_fixture/scripts/release-qualify.sh"
(
  cd "$dirty_fixture" || exit 1
  git init -q
  git config user.name release-qualify-test
  git config user.email release-qualify-test@example.invalid
  printf 'clean\n' > tracked.txt
  git add scripts/release-qualify.sh tracked.txt
  git commit -qm 'test fixture'
  printf 'dirty\n' >> tracked.txt
)

dirty_output="$(cd "$dirty_fixture" && scripts/release-qualify.sh 2>&1)"
dirty_code=$?
if [ "$dirty_code" -eq 2 ]; then pass "dirty tree is refused"; else fail "dirty tree is refused with exit 2 (got $dirty_code)"; fi
if grep -Fq 'working tree is not clean' <<<"$dirty_output"; then pass "dirty refusal is explicit"; else fail "dirty refusal is explicit"; fi
if [ ! -e "$dirty_fixture/target/release-qualification" ]; then pass "refusal creates no evidence resembling a run"; else fail "refusal creates no evidence resembling a run"; fi

failure_fixture="$fixture/failure"
mkdir -p "$failure_fixture/scripts" "$failure_fixture/bin"
cp scripts/release-qualify.sh "$failure_fixture/scripts/release-qualify.sh"
chmod +x "$failure_fixture/scripts/release-qualify.sh"
cat > "$failure_fixture/.gitignore" <<'EOF'
/target
EOF
cat > "$failure_fixture/scripts/ci.sh" <<'EOF'
#!/usr/bin/env bash
set -u
echo "fixture ci group: ${1:-missing}"
if [ "${1:-}" = thresholds ]; then exit 7; fi
exit 0
EOF
cat > "$failure_fixture/scripts/build-sbf.sh" <<'EOF'
#!/usr/bin/env bash
set -u
mkdir -p target/deploy
printf 'checkpoint fixture\n' > target/deploy/certimining_checkpoint.so
echo "fixture SBF build deliberately omitted core_harness.so"
EOF
cat > "$failure_fixture/bin/cargo" <<'EOF'
#!/usr/bin/env bash
set -u
echo "fixture cargo $*"
case " $* " in
  *' build --release -p certimining-client --features cluster,ots --bins '*)
    mkdir -p target/release
    for name in anchor-b-worker batcher-handoff confirm-anchor-b; do
      printf '%s fixture\n' "$name" > "target/release/$name"
      chmod +x "target/release/$name"
    done
    ;;
esac
exit 0
EOF
chmod +x "$failure_fixture/scripts/ci.sh" "$failure_fixture/scripts/build-sbf.sh" "$failure_fixture/bin/cargo"
(
  cd "$failure_fixture" || exit 1
  git init -q
  git config user.name release-qualify-test
  git config user.email release-qualify-test@example.invalid
  git add .
  git commit -qm 'failure fixture'
)

failure_output="$(cd "$failure_fixture" && PATH="$failure_fixture/bin:$PATH" scripts/release-qualify.sh 2>&1)"
failure_code=$?
failure_evidence="$(find "$failure_fixture/target/release-qualification" -mindepth 1 -maxdepth 1 -type d -print | head -1)"
if [ "$failure_code" -eq 1 ]; then pass "failed command and missing artifact fail qualification"; else fail "failed command and missing artifact fail qualification (got $failure_code)"; fi
if [ -n "$failure_evidence" ] && grep -Fq 'status=FAILED_OR_UNRESOLVED' "$failure_evidence/summary.txt"; then
  pass "failure bundle carries an explicit unresolved verdict"
else
  fail "failure bundle carries an explicit unresolved verdict"
fi
if [ -n "$failure_evidence" ] && grep -Fq $'thresholds\t' "$failure_evidence/steps.tsv" && grep -Fq $'\t7\t' "$failure_evidence/steps.tsv"; then
  pass "non-zero command exit is recorded"
else
  fail "non-zero command exit is recorded"
fi
if [ -n "$failure_evidence" ] && grep -Fq $'sbf-test-harness\ttarget/deploy/core_harness.so\tUNRESOLVED_MISSING' "$failure_evidence/artifact-status.tsv"; then
  pass "missing artifact is recorded as unresolved"
else
  fail "missing artifact is recorded as unresolved"
fi
if [ -n "$failure_evidence" ] && [ "$(tail -n +2 "$failure_evidence/steps.tsv" | grep -c . | tr -d ' ')" -eq 7 ]; then
  pass "independent steps continue after failure"
else
  fail "independent steps continue after failure"
fi

if [ "$failed" -ne 0 ]; then exit 1; fi
echo "release-qualify-test: every structural control passed"
