#!/usr/bin/env bash
# Builds the test-only harness program for the Solana target with the pinned toolchain (D-15):
# Agave 4.2.2's cargo-build-sbf 4.1.0 with platform-tools v1.54. Output: target/deploy/core_harness.so
#
# cargo-build-sbf 4.x uninstalls any other rustup toolchain whose name contains "solana" before it
# links its own (src/toolchain.rs, lines 384-411). It therefore runs against a project-private
# RUSTUP_HOME, and the machine-wide rustup is never touched.
set -euo pipefail
cd "$(dirname "$0")/.."

AGAVE_BIN="${POTASH_AGAVE_BIN:-$HOME/.local/share/potash/agave/v4.2.2/solana-release/bin}"
PRIVATE_RUSTUP_HOME="${POTASH_RUSTUP_HOME:-$HOME/.local/share/potash/rustup}"

# Refuse any other toolchain; the version is read from the installed tool itself.
version="$("$AGAVE_BIN/cargo-build-sbf" --version)"
if ! grep -qx 'cargo-build-sbf 4.1.0' <<<"$version" || ! grep -qx 'platform-tools v1.54' <<<"$version"; then
  echo "build-sbf: expected cargo-build-sbf 4.1.0 with platform-tools v1.54, got: $version" >&2
  exit 1
fi

# The private home borrows the pinned host compiler from rust-toolchain.toml, as "potash-host".
if ! RUSTUP_HOME="$PRIVATE_RUSTUP_HOME" rustup toolchain list | grep -q '^potash-host'; then
  mkdir -p "$PRIVATE_RUSTUP_HOME"
  RUSTUP_HOME="$PRIVATE_RUSTUP_HOME" rustup toolchain link potash-host "$(rustc --print sysroot)"
fi

PATH="$AGAVE_BIN:$PATH" RUSTUP_HOME="$PRIVATE_RUSTUP_HOME" RUSTUP_TOOLCHAIN=potash-host \
  cargo build-sbf --manifest-path programs/core-harness/Cargo.toml
