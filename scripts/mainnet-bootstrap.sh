#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Offline qualification and state initialization for a Potash mainnet anchoring worker.
# This script never sends a transaction, changes a Solana CLI URL, or initializes a validator.

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

MAINNET_GENESIS_HASH=5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d
PROGRAM_SO=target/deploy/certimining_checkpoint.so
BOOTSTRAP_TEMP_CHALLENGE=

cleanup() {
  if [[ -n $BOOTSTRAP_TEMP_CHALLENGE ]]; then
    rm -f -- "$BOOTSTRAP_TEMP_CHALLENGE"
  fi
}

trap cleanup EXIT

usage() {
  cat <<'EOF'
usage: scripts/mainnet-bootstrap.sh COMMAND [ARG]

  challenge FILE   Write the exact public challenge the HSM/KMS must sign
  preflight        Verify source, artifact, genesis, identities, payer, and HSM signature
  init DIRECTORY   Run preflight, then create a new public-only node-state manifest

Required public configuration:
  CERTIMINING_PROFILE=mainnet
  CERTIMINING_MAINNET_ACK=offline-preflight-only
  CERTIMINING_GENESIS_HASH
  CERTIMINING_EXPECTED_SBF_SHA256
  CERTIMINING_PROGRAM_ID
  CERTIMINING_DEPLOY_AUTHORITY_ID
  CERTIMINING_WORKER_PAYER_ID
  CERTIMINING_CHECKPOINT_AUTHORITY_ID
  CERTIMINING_BATCHER_KEY
  CERTIMINING_HSM_PROVIDER=pkcs11|kms|secure-enclave

Preflight additionally requires:
  CERTIMINING_WORKER_PAYER       mode-0600 hot fee-payer keypair
  CERTIMINING_HSM_CHALLENGE      challenge file produced by this checkout
  CERTIMINING_HSM_SIGNATURE      64-byte Ed25519 signature as 128 lowercase hex characters

The hardware key remains outside this process. Sign the challenge using reviewed provider tooling.
EOF
}

fail() {
  echo "mainnet-bootstrap: $*" >&2
  exit 2
}

require_clean_tree() {
  if [[ -n $(git status --porcelain --untracked-files=normal) ]]; then
    fail "the working tree is not clean; bootstrap evidence must name committed source"
  fi
}

require_environment() {
  [[ ${CERTIMINING_PROFILE:-} == mainnet ]] ||
    fail "CERTIMINING_PROFILE must be exactly mainnet"
  [[ ${CERTIMINING_MAINNET_ACK:-} == offline-preflight-only ]] ||
    fail "CERTIMINING_MAINNET_ACK must be offline-preflight-only"
  [[ ${CERTIMINING_GENESIS_HASH:-} == "$MAINNET_GENESIS_HASH" ]] ||
    fail "CERTIMINING_GENESIS_HASH is not the pinned Solana mainnet genesis hash"
  [[ -n ${CERTIMINING_PROGRAM_ID:-} ]] || fail "CERTIMINING_PROGRAM_ID is not set"
  [[ -n ${CERTIMINING_DEPLOY_AUTHORITY_ID:-} ]] ||
    fail "CERTIMINING_DEPLOY_AUTHORITY_ID is not set"
  [[ -n ${CERTIMINING_WORKER_PAYER_ID:-} ]] ||
    fail "CERTIMINING_WORKER_PAYER_ID is not set"
  [[ -n ${CERTIMINING_CHECKPOINT_AUTHORITY_ID:-} ]] ||
    fail "CERTIMINING_CHECKPOINT_AUTHORITY_ID is not set"
  [[ -n ${CERTIMINING_BATCHER_KEY:-} ]] || fail "CERTIMINING_BATCHER_KEY is not set"
  case ${CERTIMINING_HSM_PROVIDER:-} in
    pkcs11|kms|secure-enclave) ;;
    *) fail "CERTIMINING_HSM_PROVIDER must be pkcs11, kms, or secure-enclave" ;;
  esac
}

hash_file() {
  local file=$1
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
  else
    fail "neither sha256sum nor shasum is available"
  fi
}

artifact_hash() {
  [[ -f $PROGRAM_SO ]] || fail "$PROGRAM_SO is absent; run scripts/build-sbf.sh"
  local actual
  actual=$(hash_file "$PROGRAM_SO")
  [[ ${CERTIMINING_EXPECTED_SBF_SHA256:-} =~ ^[0-9a-f]{64}$ ]] ||
    fail "CERTIMINING_EXPECTED_SBF_SHA256 must be 64 lowercase hex characters"
  [[ $actual == "$CERTIMINING_EXPECTED_SBF_SHA256" ]] ||
    fail "$PROGRAM_SO does not match CERTIMINING_EXPECTED_SBF_SHA256"
  printf '%s\n' "$actual"
}

challenge_content() {
  local digest=$1
  local commit
  commit=$(git rev-parse --verify HEAD)
  cat <<EOF
certimining-mainnet-preflight-v1
commit=$commit
artifact_sha256=$digest
genesis_hash=$CERTIMINING_GENESIS_HASH
program_id=${CERTIMINING_PROGRAM_ID:-}
deploy_authority_id=${CERTIMINING_DEPLOY_AUTHORITY_ID:-}
worker_payer_id=${CERTIMINING_WORKER_PAYER_ID:-}
checkpoint_authority_id=${CERTIMINING_CHECKPOINT_AUTHORITY_ID:-}
batcher_key=${CERTIMINING_BATCHER_KEY:-}
hsm_provider=$CERTIMINING_HSM_PROVIDER
EOF
}

write_challenge() {
  local output=$1
  [[ ! -e $output ]] || fail "$output already exists; refusing to overwrite it"
  require_clean_tree
  require_environment
  local digest
  digest=$(artifact_hash)
  umask 077
  challenge_content "$digest" >"$output"
  echo "mainnet-bootstrap: wrote public signing challenge $output"
  echo "mainnet-bootstrap: no transaction was created or submitted"
}

preflight() {
  require_clean_tree
  require_environment
  local digest
  digest=$(artifact_hash)
  [[ -f ${CERTIMINING_HSM_CHALLENGE:-} ]] ||
    fail "CERTIMINING_HSM_CHALLENGE must name a regular challenge file"
  [[ -f ${CERTIMINING_HSM_SIGNATURE:-} ]] ||
    fail "CERTIMINING_HSM_SIGNATURE must name a regular signature file"
  BOOTSTRAP_TEMP_CHALLENGE=$(mktemp "${TMPDIR:-/tmp}/certimining-mainnet-challenge.XXXXXX")
  challenge_content "$digest" >"$BOOTSTRAP_TEMP_CHALLENGE"
  cmp -s "$BOOTSTRAP_TEMP_CHALLENGE" "$CERTIMINING_HSM_CHALLENGE" ||
    fail "CERTIMINING_HSM_CHALLENGE is stale or belongs to another source/artifact/manifest"
  cargo run --quiet --locked --offline -p certimining-client --features cluster \
    --bin anchoring-preflight -- worker-hsm
  rm -f -- "$BOOTSTRAP_TEMP_CHALLENGE"
  BOOTSTRAP_TEMP_CHALLENGE=
  echo "mainnet-bootstrap: offline preflight passed at $(git rev-parse --verify HEAD)"
  echo "mainnet-bootstrap: artifact sha256 $digest"
  echo "mainnet-bootstrap: no transaction was created or submitted"
}

initialize_state() {
  local state_dir=$1
  [[ ! -e $state_dir ]] || fail "$state_dir already exists; refusing to overwrite node state"
  preflight
  local digest commit
  digest=$(artifact_hash)
  commit=$(git rev-parse --verify HEAD)
  umask 077
  mkdir -m 700 "$state_dir"
  cat >"$state_dir/bootstrap-manifest" <<EOF
format=certimining-mainnet-bootstrap-v1
commit=$commit
artifact_sha256=$digest
genesis_hash=$CERTIMINING_GENESIS_HASH
program_id=$CERTIMINING_PROGRAM_ID
deploy_authority_id=$CERTIMINING_DEPLOY_AUTHORITY_ID
worker_payer_id=$CERTIMINING_WORKER_PAYER_ID
checkpoint_authority_id=$CERTIMINING_CHECKPOINT_AUTHORITY_ID
batcher_key=$CERTIMINING_BATCHER_KEY
hsm_provider=$CERTIMINING_HSM_PROVIDER
EOF
  chmod 600 "$state_dir/bootstrap-manifest"
  echo "mainnet-bootstrap: initialized public-only node state at $state_dir"
  echo "mainnet-bootstrap: live deployment and worker startup remain separate human-gated steps"
}

command=${1:-}
case "$command" in
  challenge)
    [[ -n ${2:-} ]] || fail "challenge requires an output file"
    write_challenge "$2"
    ;;
  preflight)
    preflight
    ;;
  init)
    [[ -n ${2:-} ]] || fail "init requires a new state directory"
    initialize_state "$2"
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
