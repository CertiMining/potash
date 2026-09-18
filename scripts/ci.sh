#!/usr/bin/env bash
# The CI pipeline as one script (S8). Each CI job runs one group. `scripts/ci.sh all` runs every group
# in CI's order and prints each group's test counts and exit code, so a local run is CI verbatim.
#
#   scripts/ci.sh <group>           kat01-offchain | kat01-onchain | checks | miri | deny | all
#   scripts/ci.sh install-<tool>    CI only: rust | agave | miri | cargo-deny
set -uo pipefail
cd "$(dirname "$0")/.."

# Pins, each recorded in docs/DECISIONS.md.
KAT_FILE=crates/certimining-core/tests/data/ShortMsgKAT_256.txt
KAT_SHA256=741862f92342010311504202d7b304955fa28aa03a752633a5e83f971f014851          # D-10
MIRI_TOOLCHAIN=nightly-2026-06-16                                                     # D-11
CARGO_DENY_VERSION=0.20.2                                                             # D-11
AGAVE_VERSION=v4.2.2                                                                  # D-15
AGAVE_LINUX_SHA256=5fc8684f7430038105fde953d4308ed56addf627f658daa61709f345448247ee    # D-15, x86_64 Linux archive

# KAT-01 runs first (D-09): the vendored file must be the published one, then both off-chain paths.
kat01_offchain() {
  rustc --version && cargo --version &&
    echo "$KAT_SHA256  $KAT_FILE" | shasum -a 256 -c - &&
    cargo test -p certimining-core --features native,solana --test kat01_keccak
}

# KAT-01 inside the Solana runtime, through sol_keccak256 (D-08).
kat01_onchain() {
  scripts/build-sbf.sh &&
    cargo test -p core-harness --test kat01_onchain -- --nocapture
}

# Format, the INV-ERR-01 lint gates, every feature set, and the bare-metal no_std proof (D-14).
checks() {
  cargo fmt --all --check &&
    cargo clippy --workspace --all-targets -- -D warnings &&
    cargo clippy --workspace --all-targets --all-features -- -D warnings &&
    cargo test -p certimining-core --no-default-features &&
    cargo test -p certimining-core &&
    cargo test -p certimining-core --no-default-features --features solana &&
    cargo test -p certimining-core --all-features &&
    cargo build -p certimining-core --target thumbv7em-none-eabihf --no-default-features &&
    cargo build -p certimining-core --target thumbv7em-none-eabihf
}

# Miri on the core crate (P-04).
miri() {
  cargo "+$MIRI_TOOLCHAIN" miri --version &&
    cargo "+$MIRI_TOOLCHAIN" miri test -p certimining-core --all-features
}

# Advisories, licences and sources (D-13, D-18). The version is read from the installed tool.
deny() {
  local version
  version="$(cargo deny --version)"
  if [ "$version" != "cargo-deny $CARGO_DENY_VERSION" ]; then
    echo "deny: expected cargo-deny $CARGO_DENY_VERSION, got: $version" >&2
    return 1
  fi
  cargo deny check
}

# CI only. `--no-self-update` keeps rustup from updating itself as a side effect.
install_rust() { rustup toolchain install --no-self-update || rustup show; }
install_miri() { rustup toolchain install "$MIRI_TOOLCHAIN" --profile minimal --component miri,rust-src --no-self-update; }
install_cargo_deny() { cargo install cargo-deny --version "$CARGO_DENY_VERSION" --locked; }
install_agave() {
  local dir="$HOME/.local/share/potash/agave/$AGAVE_VERSION"
  [ -x "$dir/solana-release/bin/cargo-build-sbf" ] && return 0
  mkdir -p "$dir" && (
    cd "$dir" &&
      curl -sSfL -o solana-release.tar.bz2 \
        "https://github.com/anza-xyz/agave/releases/download/$AGAVE_VERSION/solana-release-x86_64-unknown-linux-gnu.tar.bz2" &&
      echo "$AGAVE_LINUX_SHA256  solana-release.tar.bz2" | shasum -a 256 -c - &&
      tar xjf solana-release.tar.bz2 && rm solana-release.tar.bz2
  )
}

run() {
  case "$1" in
    kat01-offchain) kat01_offchain ;;
    kat01-onchain) kat01_onchain ;;
    checks) checks ;;
    miri) miri ;;
    deny) deny ;;
    *) echo "unknown group: $1" >&2; return 2 ;;
  esac
}

# Every group in CI's order. A failing group does not stop the others; the summary names it.
all() {
  local failed=0 summary="" group code log
  for group in kat01-offchain kat01-onchain checks miri deny; do
    log="$(mktemp)"
    echo "===== $group"
    run "$group" 2>&1 | tee "$log"
    code=${PIPESTATUS[0]}
    summary+="$group: exit $code"$'\n'
    summary+="$(grep -E '^test result:' "$log" | sed 's/^/    /')"$'\n'
    [ "$code" -eq 0 ] || failed=1
    rm -f "$log"
  done
  echo "===== summary"
  printf '%s' "$summary"
  return "$failed"
}

case "${1:-}" in
  install-rust) install_rust ;;
  install-agave) install_agave ;;
  install-miri) install_miri ;;
  install-cargo-deny) install_cargo_deny ;;
  all) all ;;
  "") echo "usage: scripts/ci.sh <group> | all | install-<tool>" >&2; exit 2 ;;
  *) run "$1" ;;
esac
