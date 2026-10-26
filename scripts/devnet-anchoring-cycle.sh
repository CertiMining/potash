#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# D-142's bounded operator entry point for staging rehearsal and the devnet split cycle.

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

usage() {
  cat <<'EOF'
usage: scripts/devnet-anchoring-cycle.sh COMMAND [ARG]

  simulate                 Build SBF and run the offline LiteSVM split-cycle rehearsal
  faults                   Run deterministic worker/partition/dropout fault injection
  preflight ROLE           Validate deployment, batcher, or worker separation offline
  batch EPOCH              Preflight the batcher and write its signed handoff
  worker                   Preflight and start the transaction-writing devnet worker
  reconcile EPOCH          Read-only reconciliation of handoff, receipt, and devnet state

Live commands require CERTIMINING_PROFILE=devnet and the exact devnet RPC endpoint.
The worker additionally requires CERTIMINING_LIVE_ACK=devnet-transactions-authorized.
EOF
}

require_devnet() {
  if [[ ${CERTIMINING_PROFILE:-} != devnet ]]; then
    echo "devnet-anchoring-cycle: CERTIMINING_PROFILE must be exactly devnet" >&2
    exit 2
  fi
  if [[ ${CERTIMINING_RPC:-} != https://api.devnet.solana.com ]]; then
    echo "devnet-anchoring-cycle: CERTIMINING_RPC must be https://api.devnet.solana.com" >&2
    exit 2
  fi
}

preflight() {
  local role=${1:?role is required}
  cargo run -p certimining-client --features cluster --bin anchoring-preflight -- "$role"
}

command=${1:-}
case "$command" in
  simulate)
    scripts/build-sbf.sh
    cargo test -p certimining-client --features cluster,ots --test devnet_anchoring_cycle -- --nocapture
    ;;
  faults)
    scripts/cluster-fault-injection.sh
    ;;
  preflight)
    require_devnet
    preflight "${2:-}"
    ;;
  batch)
    require_devnet
    epoch=${2:?batch requires an epoch}
    preflight batcher
    CERTIMINING_EPOCH="$epoch" \
      cargo run -p certimining-client --features cluster,ots --bin batcher-handoff
    ;;
  worker)
    require_devnet
    preflight worker
    if [[ ${CERTIMINING_LIVE_ACK:-} != devnet-transactions-authorized ]]; then
      echo "devnet-anchoring-cycle: refusing transaction-writing worker without CERTIMINING_LIVE_ACK=devnet-transactions-authorized" >&2
      exit 2
    fi
    cargo run -p certimining-client --features cluster,ots --bin anchor-b-worker
    ;;
  reconcile)
    require_devnet
    epoch=${2:?reconcile requires an epoch}
    CERTIMINING_EPOCH="$epoch" \
      cargo run -p certimining-client --features cluster,ots --bin reconcile-anchor-cycle
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
