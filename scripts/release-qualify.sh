#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# One release-qualification run, one immutable commit, and one evidence bundle. This script performs
# no deployment, upgrade, devnet test, or production transaction. It builds artefacts and exercises
# only the offline/local gates named below.
set -uo pipefail
cd "$(dirname "$0")/.."

usage() {
  cat <<'EOF'
usage: scripts/release-qualify.sh [--help | --print-plan]

With no arguments, require a clean working tree, run every release and manual gate, and write an
evidence bundle under target/release-qualification/. --print-plan prints the exact commands without
running them. No mode skips a check while producing a qualification verdict.
EOF
}

MODE=run
case "${1:-}" in
  "") ;;
  --help|-h) usage; exit 0 ;;
  --print-plan) MODE=plan ;;
  *) usage >&2; exit 2 ;;
esac
[ "$#" -le 1 ] || { usage >&2; exit 2; }

utc_now() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }

quote_command() {
  local arg first=1
  for arg in "$@"; do
    if [ "$first" -eq 0 ]; then printf ' '; fi
    printf '%q' "$arg"
    first=0
  done
}

STEP_NUMBER=0
FAILED=0

run_step() {
  local label="$1" safe log started ended command_code tee_code code
  shift
  if [ "$MODE" = plan ]; then
    printf '%-20s ' "$label"
    quote_command "$@"
    printf '\n'
    return 0
  fi

  STEP_NUMBER=$((STEP_NUMBER + 1))
  safe="$(printf '%s' "$label" | tr -c 'A-Za-z0-9._-' '-')"
  log="$(printf '%s/logs/%02d-%s.log' "$EVIDENCE_DIR" "$STEP_NUMBER" "$safe")"
  started="$(utc_now)"
  {
    printf 'step: %s\nstarted_utc: %s\ncommand: ' "$label" "$started"
    quote_command "$@"
    printf '\n\n'
  } | tee "$log"

  "$@" 2>&1 | tee -a "$log"
  local pipe_status=("${PIPESTATUS[@]}")
  command_code="${pipe_status[0]}"
  tee_code="${pipe_status[1]}"
  code="$command_code"
  if [ "$tee_code" -ne 0 ]; then
    printf 'release-qualify: transcript write failed for %s (tee exit %s)\n' "$label" "$tee_code" >&2
    code=125
  fi
  ended="$(utc_now)"
  {
    printf '\nended_utc: %s\ncommand_exit: %s\ntranscript_exit: %s\nrecorded_exit: %s\n' \
      "$ended" "$command_code" "$tee_code" "$code"
  } | tee -a "$log"
  if ! {
    printf '%s\t%s\t%s\t%s\t%s\t' "$label" "$started" "$ended" "$code" "$log"
    quote_command "$@"
    printf '\n'
  } >> "$STEPS_FILE"; then
    echo "release-qualify: could not record the exit status for $label" >&2
    FAILED=1
  fi
  if [ "$code" -ne 0 ]; then FAILED=1; fi
  return 0
}

release_steps() {
  run_step ci-all scripts/ci.sh all
  run_step privacy-full cargo test --release -p certimining-log -- --ignored
  run_step thresholds scripts/ci.sh thresholds
  run_step benchmark-distributions scripts/ci.sh bench
  run_step fuzz scripts/ci.sh fuzz
  run_step release-binaries cargo build --release -p certimining-client --features cluster,ots --bins
  run_step release-sbf scripts/build-sbf.sh
}

if [ "$MODE" = plan ]; then
  echo "release-qualify: plan only; no checks ran and no qualification verdict was produced."
  release_steps
  exit 0
fi

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "release-qualify: not inside a Git working tree" >&2
  exit 2
fi

REPO_ROOT="$(git rev-parse --show-toplevel)"
CURRENT_ROOT="$(pwd -P)"
REPO_ROOT="$(cd "$REPO_ROOT" && pwd -P)"
if [ "$CURRENT_ROOT" != "$REPO_ROOT" ]; then
  echo "release-qualify: repository root mismatch: script entered $CURRENT_ROOT, Git reports $REPO_ROOT" >&2
  exit 2
fi

if ! DIRTY="$(git status --porcelain=v1 --untracked-files=all)"; then
  echo "release-qualify: Git could not determine whether the working tree is clean" >&2
  exit 2
fi
if [ -n "$DIRTY" ]; then
  echo "release-qualify: working tree is not clean; qualification must describe exactly one commit" >&2
  printf '%s\n' "$DIRTY" >&2
  exit 2
fi

if command -v shasum >/dev/null 2>&1; then
  HASH_TOOL=shasum
elif command -v sha256sum >/dev/null 2>&1; then
  HASH_TOOL=sha256sum
else
  echo "release-qualify: neither shasum nor sha256sum is available; artifact hashes are unresolved" >&2
  exit 2
fi

STARTED_UTC="$(utc_now)"
START_STAMP="$(date -u '+%Y%m%dT%H%M%SZ')"
START_COMMIT="$(git rev-parse --verify HEAD)"
SHORT_COMMIT="$(git rev-parse --short=12 HEAD)"
EVIDENCE_DIR="$REPO_ROOT/target/release-qualification/$START_STAMP-$SHORT_COMMIT"
if [ -e "$EVIDENCE_DIR" ]; then
  echo "release-qualify: evidence directory already exists and will not be overwritten: $EVIDENCE_DIR" >&2
  exit 2
fi
if ! mkdir -p "$EVIDENCE_DIR/logs"; then
  echo "release-qualify: cannot create evidence directory: $EVIDENCE_DIR" >&2
  exit 2
fi
STEPS_FILE="$EVIDENCE_DIR/steps.tsv"
if ! printf 'step\tstarted_utc\tended_utc\texit_code\ttranscript\tcommand\n' > "$STEPS_FILE"; then
  echo "release-qualify: cannot initialize the evidence index: $STEPS_FILE" >&2
  exit 2
fi

interrupt() {
  local signal="$1"
  printf 'status=INTERRUPTED\nsignal=%s\ncommit=%s\nstarted_utc=%s\nended_utc=%s\n' \
    "$signal" "$START_COMMIT" "$STARTED_UTC" "$(utc_now)" > "$EVIDENCE_DIR/summary.txt"
  echo "release-qualify: interrupted by $signal; partial evidence: $EVIDENCE_DIR" >&2
  exit 130
}
trap 'interrupt HUP' HUP
trap 'interrupt INT' INT
trap 'interrupt TERM' TERM

{
  printf 'commit=%s\n' "$START_COMMIT"
  printf 'commit_short=%s\n' "$SHORT_COMMIT"
  printf 'branch=%s\n' "$(git symbolic-ref --short -q HEAD || printf 'DETACHED')"
  printf 'started_utc=%s\n' "$STARTED_UTC"
  printf 'repository=%s\n' "$REPO_ROOT"
  printf 'tree_state=clean\n'
} > "$EVIDENCE_DIR/git.txt" || { echo "release-qualify: could not record Git identity" >&2; exit 2; }

{
  printf 'captured_utc=%s\n' "$(utc_now)"
  printf 'hostname=%s\n' "$(hostname 2>/dev/null || printf 'UNAVAILABLE')"
  printf 'uname='; uname -a 2>&1 || printf 'UNAVAILABLE\n'
  printf 'architecture=%s\n' "$(uname -m 2>/dev/null || printf 'UNAVAILABLE')"
  printf 'logical_cpus=%s\n' "$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null || printf 'UNAVAILABLE')"
  printf 'cpu_model=%s\n' "$(sysctl -n machdep.cpu.brand_string 2>/dev/null || awk -F: '/model name/{sub(/^[[:space:]]*/, "", $2); print $2; exit}' /proc/cpuinfo 2>/dev/null || printf 'UNAVAILABLE')"
  if command -v sw_vers >/dev/null 2>&1; then sw_vers; else printf 'sw_vers=NOT_APPLICABLE\n'; fi
  if [ -r /etc/os-release ]; then cat /etc/os-release; else printf 'os_release=NOT_APPLICABLE\n'; fi
  for name in CI GITHUB_ACTIONS RUNNER_OS RUNNER_ARCH RUNNER_NAME ImageOS ImageVersion; do
    value="$(printenv "$name" 2>/dev/null || true)"
    if [ -n "$value" ]; then printf '%s=%s\n' "$name" "$value"; else printf '%s=UNSET\n' "$name"; fi
  done
  for name in CERTIMINING_DEVNET CERTIMINING_RPC CERTIMINING_MASTER_KEY \
    CERTIMINING_BATCHER_SIGNING_KEY CERTIMINING_BATCHER_KEY SOLANA_URL ANCHOR_PROVIDER_URL; do
    if printenv "$name" >/dev/null 2>&1; then printf '%s=SET_REDACTED\n' "$name"; else printf '%s=UNSET\n' "$name"; fi
  done
} > "$EVIDENCE_DIR/environment.txt" 2>&1 || { echo "release-qualify: could not record environment identity" >&2; exit 2; }

record_tool() {
  local label="$1"
  shift
  printf '\n[%s]\ncommand=' "$label"
  quote_command "$@"
  printf '\n'
  if "$@" 2>&1; then printf 'status=AVAILABLE\n'; else printf 'status=UNAVAILABLE\n'; fi
}

AGAVE_BUILD_SBF="${HOME}/.local/share/potash/agave/v4.2.2/solana-release/bin/cargo-build-sbf"
{
  record_tool bash bash --version
  record_tool git git --version
  record_tool rustc rustc --version --verbose
  record_tool cargo cargo --version --verbose
  record_tool rustup rustup --version
  record_tool miri rustup run nightly-2026-06-16 miri --version
  record_tool cargo-deny cargo deny --version
  record_tool cargo-fuzz cargo fuzz --version
  record_tool node node --version
  record_tool npm npm --version
  record_tool clang clang --version
  record_tool python3 python3 --version
  record_tool hash-tool "$HASH_TOOL" --version
  record_tool cargo-build-sbf "$AGAVE_BUILD_SBF" --version
} > "$EVIDENCE_DIR/tools.txt" 2>&1 || { echo "release-qualify: could not record tool versions" >&2; exit 2; }

{
  echo "network_policy=no deployment, upgrade, devnet test, or transaction-producing command is in the plan"
  echo "CERTIMINING_DEVNET is forced to 0; cluster credentials and endpoints are removed from child commands"
} > "$EVIDENCE_DIR/network-policy.txt" || { echo "release-qualify: could not record network policy" >&2; exit 2; }
export CERTIMINING_DEVNET=0
unset CERTIMINING_RPC CERTIMINING_MASTER_KEY CERTIMINING_BATCHER_SIGNING_KEY \
  CERTIMINING_BATCHER_KEY CERTIMINING_HANDOFFS CERTIMINING_RECEIPTS CERTIMINING_SUBMISSIONS \
  SOLANA_URL ANCHOR_PROVIDER_URL

echo "release-qualify: commit $START_COMMIT"
echo "release-qualify: evidence $EVIDENCE_DIR"
release_steps

ARTIFACT_STATUS="$EVIDENCE_DIR/artifact-status.tsv"
ARTIFACT_HASHES="$EVIDENCE_DIR/artifacts.sha256"
if ! printf 'kind\tpath\tstatus\tbytes\tsha256\n' > "$ARTIFACT_STATUS" || ! : > "$ARTIFACT_HASHES"; then
  echo "release-qualify: cannot initialize artifact evidence" >&2
  FAILED=1
fi

hash_file() {
  if [ "$HASH_TOOL" = shasum ]; then shasum -a 256 "$1" | awk '{print $1}'; else sha256sum "$1" | awk '{print $1}'; fi
}

record_artifact() {
  local kind="$1" path="$2" digest bytes
  if [ ! -f "$path" ]; then
    printf '%s\t%s\tUNRESOLVED_MISSING\t-\t-\n' "$kind" "$path" >> "$ARTIFACT_STATUS"
    echo "release-qualify: required artifact is missing: $path" >&2
    FAILED=1
    return 0
  fi
  digest="$(hash_file "$path")"
  if [ -z "$digest" ]; then
    printf '%s\t%s\tUNRESOLVED_HASH\t-\t-\n' "$kind" "$path" >> "$ARTIFACT_STATUS"
    echo "release-qualify: SHA-256 could not be computed: $path" >&2
    FAILED=1
    return 0
  fi
  bytes="$(wc -c < "$path" | tr -d ' ')"
  printf '%s\t%s\tHASHED\t%s\t%s\n' "$kind" "$path" "$bytes" "$digest" >> "$ARTIFACT_STATUS"
  printf '%s  %s\n' "$digest" "$path" >> "$ARTIFACT_HASHES"
}

record_artifact sbf-program target/deploy/certimining_checkpoint.so
record_artifact sbf-test-harness target/deploy/core_harness.so
record_artifact release-binary target/release/anchor-b-worker
record_artifact release-binary target/release/batcher-handoff
record_artifact release-binary target/release/confirm-anchor-b

if ! END_COMMIT="$(git rev-parse --verify HEAD)"; then
  echo "release-qualify: Git could not resolve HEAD after verification" >&2
  END_COMMIT=UNRESOLVED
  FAILED=1
fi
if ! END_DIRTY="$(git status --porcelain=v1 --untracked-files=all)"; then
  echo "release-qualify: Git could not determine the final working-tree state" >&2
  END_DIRTY=UNRESOLVED
  FAILED=1
fi
if [ "$END_COMMIT" != "$START_COMMIT" ]; then
  echo "release-qualify: HEAD changed during verification: $START_COMMIT -> $END_COMMIT" >&2
  FAILED=1
fi
if [ -n "$END_DIRTY" ]; then
  echo "release-qualify: tracked or untracked working-tree state changed during verification" >&2
  printf '%s\n' "$END_DIRTY" >&2
  FAILED=1
fi

ENDED_UTC="$(utc_now)"
if [ "$FAILED" -eq 0 ]; then STATUS=QUALIFIED; else STATUS=FAILED_OR_UNRESOLVED; fi
{
  printf 'status=%s\n' "$STATUS"
  printf 'commit=%s\n' "$START_COMMIT"
  printf 'started_utc=%s\n' "$STARTED_UTC"
  printf 'ended_utc=%s\n' "$ENDED_UTC"
  printf 'evidence_directory=%s\n' "$EVIDENCE_DIR"
  printf 'step_count=%s\n' "$STEP_NUMBER"
  printf 'artifact_count=%s\n' "$(tail -n +2 "$ARTIFACT_STATUS" | grep -c . | tr -d ' ')"
  printf 'tree_unchanged=%s\n' "$([ "$END_COMMIT" = "$START_COMMIT" ] && [ -z "$END_DIRTY" ] && printf yes || printf no)"
} > "$EVIDENCE_DIR/summary.txt" || {
  echo "release-qualify: final summary could not be written; qualification fails" >&2
  exit 1
}

echo "release-qualify: $STATUS"
echo "release-qualify: evidence $EVIDENCE_DIR"
if [ "$FAILED" -ne 0 ]; then exit 1; fi
