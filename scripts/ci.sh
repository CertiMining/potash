#!/usr/bin/env bash
# The CI pipeline as one script (S8). Each CI job runs one group. `scripts/ci.sh all` runs every group
# in CI's order, stops at a KAT-01 failure as CI does, and prints each group's test counts and exit
# code, so a local run is CI verbatim.
#
#   scripts/ci.sh <group>           kat01-offchain | kat01-onchain | kat02 | vectors | checks | miri |
#                                   deny | all
#   scripts/ci.sh install-<tool>    CI only: rust | agave | miri | cargo-deny
set -uo pipefail
cd "$(dirname "$0")/.."

# Pins, each recorded in docs/DECISIONS.md.
KAT_FILE=crates/certimining-core/tests/data/ShortMsgKAT_256.txt
KAT_SHA256=741862f92342010311504202d7b304955fa28aa03a752633a5e83f971f014851          # D-10
KAT02_FILE=crates/certimining-core/tests/data/rfc8032_7.1.txt
KAT02_SHA256=0717d570f83753773c492e9157bb1407754bf16e3cf9b8be317b2f7c71b42d67        # D-45
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

# The committed vectors (D-56): the manifest must match what is committed, and regenerating into a
# temporary directory must reproduce it byte for byte. The first catches a hand-edited vector; the
# second catches an edit whose manifest was updated to match, and a generator that has drifted from
# its own output.
# Reads a file's permission bits on either platform. GNU stat's -f means file system status, so the
# BSD form must not be tried first: on Linux it succeeds and returns something that is not a mode.
file_mode() {
  local m
  m="$(stat -c '%a' "$1" 2>/dev/null)"
  case "$m" in '' | *[!0-7]*) m="$(stat -f '%OLp' "$1" 2>/dev/null)" ;; esac
  case "$m" in
    '' | *[!0-7]*)
      echo "cannot read the mode of $1" >&2
      return 1
      ;;
  esac
  printf '%04o' "$((8#$m))"
}

vectors() {
  local dir=vectors failed=0 hash mode name actual_hash actual_mode tmp

  # The manifest carries the hash, the mode and the name. Git preserves only the executable bit, so
  # a working tree's modes follow the umask of whoever cloned it: here the committed files are
  # checked for what git actually carries, and the regenerated set is checked against the recorded
  # mode exactly, where the generator sets it itself.
  while read -r hash mode name; do
    [ -n "$name" ] || continue
    actual_hash="$(shasum -a 256 "$dir/$name" | awk '{print $1}')"
    if [ "$hash" != "$actual_hash" ]; then
      echo "vectors: $name does not match its hash" >&2
      failed=1
    fi
    if [ -x "$dir/$name" ]; then
      echo "vectors: $name is executable, and a vector never is" >&2
      failed=1
    fi
    if [ ! -r "$dir/$name" ]; then
      echo "vectors: $name is not readable" >&2
      failed=1
    fi
  done < "$dir/MANIFEST.sha256"
  [ "$failed" -eq 0 ] || return 1

  # Regeneration into a directory the generator creates for itself. This catches an edit whose
  # manifest was updated to match, a generator that has drifted from the output beside it, and a
  # mode the generator no longer writes.
  tmp="$(mktemp -d)" || return 1
  if ! cargo xtask gen-vectors "$tmp/out" >/dev/null; then
    rm -rf "$tmp"
    return 1
  fi
  if ! diff -r "$dir" "$tmp/out"; then
    rm -rf "$tmp"
    return 1
  fi
  while read -r hash mode name; do
    [ -n "$name" ] || continue
    actual_mode="$(file_mode "$tmp/out/$name")" || { failed=1; continue; }
    if [ "$mode" != "$actual_mode" ]; then
      echo "vectors: regenerated $name has mode $actual_mode, and the manifest records $mode" >&2
      failed=1
    fi
  done < "$dir/MANIFEST.sha256"
  rm -rf "$tmp"
  [ "$failed" -eq 0 ] || return 1

  echo "vectors: $(grep -c . "$dir/MANIFEST.sha256") files verified by hash, mode and regeneration"
}

# KAT-02: RFC 8032 §7.1's own vectors, checked by hash before the test reads them (D-45).
kat02() {
  echo "$KAT02_SHA256  $KAT02_FILE" | shasum -a 256 -c - &&
    cargo test -p certimining-core --test kat02_ed25519
}

# KAT-01 inside the Solana runtime, through sol_keccak256 (D-08).
kat01_onchain() {
  scripts/build-sbf.sh &&
    cargo test -p core-harness --test kat01_onchain -- --nocapture
}

# Format, the INV-ERR-01 lint gates, every feature set for both engine crates, and the bare-metal
# no_std proof (D-14, D-61).
checks() {
  cargo fmt --all --check &&
    cargo clippy --workspace --all-targets --no-default-features -- -D warnings &&
    cargo clippy --workspace --all-targets -- -D warnings &&
    cargo clippy --workspace --all-targets --no-default-features --features solana -- -D warnings &&
    cargo clippy --workspace --all-targets --all-features -- -D warnings &&
    cargo test -p certimining-core --no-default-features &&
    cargo test -p certimining-core &&
    cargo test -p certimining-core --no-default-features --features solana &&
    cargo test -p certimining-core --all-features &&
    cargo test -p certimining-log --no-default-features &&
    cargo test -p certimining-log &&
    cargo test -p certimining-log --no-default-features --features solana &&
    cargo test -p certimining-log --all-features &&
    cargo build -p certimining-core --target thumbv7em-none-eabihf --no-default-features &&
    cargo build -p certimining-core --target thumbv7em-none-eabihf &&
    cargo build -p certimining-log --target thumbv7em-none-eabihf --no-default-features &&
    cargo build -p certimining-log --target thumbv7em-none-eabihf
}

# Miri on the engine crates (P-04). The statistical privacy tests are ignored here and run in the
# `checks` group instead: Miri is for undefined behaviour, and it covers the tree's code paths through
# the structural tests at a fraction of the cost (D-66).
miri() {
  cargo "+$MIRI_TOOLCHAIN" miri --version &&
    cargo "+$MIRI_TOOLCHAIN" miri test -p certimining-core --all-features &&
    cargo "+$MIRI_TOOLCHAIN" miri test -p certimining-log --all-features
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
    kat02) kat02 ;;
    vectors) vectors ;;
    checks) checks ;;
    miri) miri ;;
    deny) deny ;;
    *) echo "unknown group: $1" >&2; return 2 ;;
  esac
}

# Every group in CI's order. KAT-01 gates the rest exactly as in CI (D-09, S9-03): if either KAT
# group fails, nothing else runs. The other groups are independent, as CI's jobs are, so each of
# them runs and the summary names any that failed.
all() {
  local failed=0 summary="" group code log
  for group in kat01-offchain kat01-onchain kat02 vectors checks miri deny; do
    log="$(mktemp)"
    echo "===== $group"
    run "$group" 2>&1 | tee "$log"
    code=${PIPESTATUS[0]}
    summary+="$group: exit $code"$'\n'
    summary+="$(grep -E '^test result:' "$log" | sed 's/^/    /')"$'\n'
    rm -f "$log"
    if [ "$code" -ne 0 ]; then
      failed=1
      case "$group" in
        kat01-*)
          summary+="KAT-01 failed, so no later group ran, as in CI."$'\n'
          break
          ;;
      esac
    fi
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
