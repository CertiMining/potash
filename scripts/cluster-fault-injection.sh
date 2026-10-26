#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Deterministic, offline fault injection for the split anchoring state machine.

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

scripts/build-sbf.sh
cargo test -p certimining-client --features cluster,ots --lib worker::tests -- --nocapture
cargo test -p certimining-client --features cluster,ots --test devnet_anchoring_cycle \
  anchor_a_dropout_and_restart_leave_no_partial_checkpoint -- --nocapture
cargo test -p certimining-client --features cluster,ots --test devnet_anchoring_cycle \
  delayed_anchor_b_after_dropout_transitions_single_to_dual_without_changing_root -- --nocapture
cargo test -p certimining-client --features cluster,ots --test devnet_anchoring_cycle \
  delayed_and_byzantine_epoch_transitions_preserve_the_contiguous_barrier -- --nocapture
