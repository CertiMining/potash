#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# The CI pipeline as one script (S8). Each CI job runs one group. `scripts/ci.sh all` runs every group
# in CI's order, stops at a KAT-01 failure as CI does, and prints each group's test counts and exit
# code, so a local run is CI verbatim.
#
#   scripts/ci.sh <group>           kat01-offchain | kat01-onchain | kat02 | vectors | checks | miri |
#                                   deny | ts | all
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
CARGO_FUZZ_VERSION=0.13.2                                                             # D-11, D-131
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

  # E-14's demo fixtures, held to the same standard (D-126). A manifest is as editable as the file it
  # covers, so hashes alone would let a scene be tuned by changing both; regeneration is what makes the
  # engine the author. The generator refuses a directory that already holds files, so it writes into a
  # fresh one and the committed set is diffed against that.
  if [ -d demo/fixtures ]; then
    tmp="$(mktemp -d)" || return 1
    if ! cargo xtask gen-demo "$tmp/demo" >/dev/null; then
      rm -rf "$tmp"
      echo "vectors: the demo fixture generator failed" >&2
      return 1
    fi
    if ! diff -r demo/fixtures "$tmp/demo"; then
      rm -rf "$tmp"
      echo "vectors: the committed demo fixtures are not what the engine produces" >&2
      return 1
    fi
    rm -rf "$tmp"
    echo "vectors: $(grep -c . demo/fixtures/MANIFEST.sha256) demo fixtures verified by regeneration"
  fi

  # The same rule over the working tree, not only over what a generator is about to write. A page
  # constant is hand-written and no generator ever sees it, which is how a live receipt digest reached
  # demo/app.js and passed everything.
  cargo xtask check-live-values || return 1
}

# KAT-02: RFC 8032 §7.1's own vectors, checked by hash before the test reads them (D-45).
kat02() {
  echo "$KAT02_SHA256  $KAT02_FILE" | shasum -a 256 -c - &&
    cargo test -p certimining-core --test kat02_ed25519
}

# Inside the Solana runtime (D-08, D-87): KAT-01 through `sol_keccak256`, the engine's own committed
# preimages for §2's runtime-equivalence claim, and the checkpoint program's own cases. Both programs
# are built with the pinned toolchain first.
kat01_onchain() {
  scripts/build-sbf.sh || return 1
  GROUP_FAILED=""
  check "kat01 on chain" cargo test -p core-harness --test kat01_onchain -- --nocapture
  check "runtime equivalence" cargo test -p core-harness --test runtime_equivalence -- --nocapture
  check "checkpoint program" cargo test -p certimining-checkpoint
  check "compute limits" cargo test -p certimining-checkpoint --test compute -- --nocapture
  # INV-ANCH-05's transitions run the real program under LiteSVM, so they need the artefact this
  # group builds (E-10, D-118).
  check "anchor status transitions" cargo test -p certimining-client --test anchor_status
  group_result kat01-onchain
}

# One command of a group, run whatever happened before it. A group used to chain with `&&`, which
# meant a red run stopped at the first failure: E-06's first review found that the run meant to show
# the privacy tests failing against a stub stopped at the core crate's tests and never reached them,
# so the run proved the stub refused and not what it was written to prove. Now every command runs and
# the group names each one that failed.
GROUP_FAILED=""
check() {
  local label="$1"
  shift
  echo "----- $label"
  if ! "$@"; then
    GROUP_FAILED="$GROUP_FAILED
    $label"
  fi
}

# Reports whatever the group collected, and fails if anything did.
group_result() {
  local group="$1"
  if [ -n "$GROUP_FAILED" ]; then
    echo "$group: these commands failed:$GROUP_FAILED" >&2
    return 1
  fi
  echo "$group: every command passed"
}

# Format, the INV-ERR-01 lint gates, every feature set for both engine crates, and the bare-metal
# no_std proof (D-14, D-61).
checks() {
  GROUP_FAILED=""
  # §4.6's claim gate (E-15, D-121). First, because a claim in the repository is a merge blocker of
  # the same severity as a failing test and costs a second to find.
  check "claims" scripts/claim-check.sh
  check "fmt" cargo fmt --all --check
  check "clippy, no default features" cargo clippy --workspace --all-targets --no-default-features -- -D warnings
  check "clippy, default" cargo clippy --workspace --all-targets -- -D warnings
  check "clippy, solana" cargo clippy --workspace --all-targets --no-default-features --features solana -- -D warnings
  check "clippy, all features" cargo clippy --workspace --all-targets --all-features -- -D warnings
  check "test core, no default features" cargo test -p certimining-core --no-default-features
  check "test core, default" cargo test -p certimining-core
  check "test core, solana" cargo test -p certimining-core --no-default-features --features solana
  check "test core, all features" cargo test -p certimining-core --all-features
  # §4.5 asks P-02 for 10,000 generated cases and `config()` runs 512, so the required count reached no
  # committed job and a review found it (E12-04). It is cheap — a few seconds — so it runs here on every
  # push rather than being left to a note telling someone to set the variable by hand.
  check "property counts (§4.5: P-02 at 10,000 cases)" \
    env PROPTEST_CASES=10000 cargo test -p certimining-core --test state_props p02_apply_is_deterministic -- --exact
  check "test log, no default features" cargo test -p certimining-log --no-default-features
  check "test log, default" cargo test -p certimining-log
  check "test log, solana" cargo test -p certimining-log --no-default-features --features solana
  check "test log, all features" cargo test -p certimining-log --all-features
  # The client's tests that need no compiled program. `anchor_status` loads the .so and runs in
  # kat01-onchain instead, because `checks` installs no Agave toolchain and builds no artefact — CI
  # found that by failing where a local run had passed against a stale target directory.
  check "test client" cargo test -p certimining-client --test fetch --test schedule
  check "client, cluster feature" cargo clippy -p certimining-client --all-targets --features cluster -- -D warnings
  # Anchor B (E-10). The unit tests read a committed receipt from disk and reach no calendar, so CI
  # needs no OpenTimestamps client and no network.
  check "client, ots feature" cargo clippy -p certimining-client --all-targets --features ots -- -D warnings
  check "anchor b" cargo test -p certimining-client --features ots --test ots
  check "bare metal core, no default features" cargo build -p certimining-core --target thumbv7em-none-eabihf --no-default-features
  check "bare metal core, default" cargo build -p certimining-core --target thumbv7em-none-eabihf
  check "bare metal log, no default features" cargo build -p certimining-log --target thumbv7em-none-eabihf --no-default-features
  check "bare metal log, default" cargo build -p certimining-log --target thumbv7em-none-eabihf
  group_result checks
}

# Miri on the engine crates (P-04). The statistical privacy tests are ignored here and run in the
# `checks` group instead: Miri is for undefined behaviour, and it covers the tree's code paths through
# the structural tests at a fraction of the cost (D-66).
miri() {
  # The toolchain gates the rest: without it there is nothing to run. Both crates then run whatever
  # the other did, for the same reason the `checks` group does.
  cargo "+$MIRI_TOOLCHAIN" miri --version || return 1
  GROUP_FAILED=""
  check "miri core" cargo "+$MIRI_TOOLCHAIN" miri test -p certimining-core --all-features
  check "miri log" cargo "+$MIRI_TOOLCHAIN" miri test -p certimining-log --all-features
  group_result miri
}

# Advisories, licences and sources (D-13, D-18). The version is read from the installed tool.
#
# **Two graphs, because the workspace is not the whole repository.** `fuzz/` is its own Cargo workspace
# (D-131), so a root `cargo deny check` never sees `libfuzzer-sys` or `arbitrary` — verifiable as
# `cargo deny list | grep -c libfuzzer`, which answers 0. D-131 committed those two crates to these
# gates "like everything else, or they do not ship", and until the fuzz manifest is checked explicitly
# that commitment is untrue rather than met. Both graphs use the same deny.toml, so there is one policy
# and not a looser one for tooling.
deny() {
  local version
  version="$(cargo deny --version)"
  if [ "$version" != "cargo-deny $CARGO_DENY_VERSION" ]; then
    echo "deny: expected cargo-deny $CARGO_DENY_VERSION, got: $version" >&2
    return 1
  fi
  GROUP_FAILED=""
  check "deny workspace" cargo deny check
  check "deny fuzz" cargo deny --manifest-path fuzz/Cargo.toml --config deny.toml check
  group_result deny
}

# §4.5's fuzz targets, at the iteration counts §4.6 gates on (D-131). This group is **not** in `all`:
# it runs in its own nightly workflow, .github/workflows/fuzz.yml, because `all` is the push pipeline
# verbatim and these runs take tens of minutes rather than seconds.
#
# `-rss_limit_mb` and `-timeout` are set rather than left to libFuzzer's defaults, because §4.5 asks F-01
# for zero OOM and zero timeouts and neither can be reported unless a limit exists to cross. The limit is
# per unit: 2 GB of resident memory, 10 seconds of wall clock.
#
# **One run, 3 Oct 2026, every figure from it, total by addition. Apple M2, 8 cores, macOS 26.6.2, from an
# empty corpus.** `slowest_unit_time_sec` was 0 for all five and the highest peak was F-03's 565 MB.
#
#   F-01 fuzz_params_decode  1,000,000 in   13 s   76,923/s   505 MB
#   F-02 fuzz_canonicalize   1,000,000 in   11 s   90,909/s   434 MB
#   F-03 fuzz_apply          1,000,000 in  355 s    2,816/s   565 MB
#   F-04 fuzz_proof_verify   1,000,000 in  527 s    1,897/s   404 MB
#   F-05 fuzz_tree_build        25,000 in  620 s       40/s   380 MB
#                                       ----------
#                                 whole group 1,526 s, 25 min 26 s
#
# A review found the previous block arithmetically impossible: it mixed one run's F-01 with an earlier
# run's F-03 and F-04 and quoted a total from a third, so no addition of its rows reached it.
#
# §4.5 fixes a million for F-01 and F-02 and states no count for the other three; F-03 and F-04 run a
# million anyway. **F-05 has no stable rate** — 25,000 from empty has measured 16, 64, 75, 195, 217, 318
# and 620 seconds — because the leaf count is itself fuzzed and a 4,096-leaf unit at H = 16 costs orders
# of magnitude more than a small one. Its count stays at 25,000 (D-134). What bounds it regardless of
# count is the derived-count clamp: heights 4 to 12 reach capacity, 13 to 16 do not, and those boundaries
# are pinned by a deterministic test instead.
fuzz() {
  local version
  version="$(cargo fuzz --version)"
  if [ "$version" != "cargo-fuzz $CARGO_FUZZ_VERSION" ]; then
    echo "fuzz: expected cargo-fuzz $CARGO_FUZZ_VERSION, got: $version" >&2
    return 1
  fi
  GROUP_FAILED=""
  fuzz_target fuzz_params_decode 1000000
  fuzz_target fuzz_canonicalize 1000000
  fuzz_target fuzz_apply 1000000
  fuzz_target fuzz_proof_verify 1000000
  fuzz_target fuzz_tree_build 25000
  group_result fuzz
}

fuzz_target() {
  check "fuzz $1 ($2 runs)" cargo "+$MIRI_TOOLCHAIN" fuzz run "$1" -- \
    "-runs=$2" -rss_limit_mb=2048 -timeout=10 -print_final_stats=1
}

# The TypeScript verifier of E-11 (D-93, D-97). `npm ci` installs the committed lock file exactly, so
# the tree tested here is the tree the gate audited. The KAT file runs first, as it does on the Rust
# side, then the whole suite; the network test skips itself unless CERTIMINING_DEVNET is set, which
# CI never sets.
ts() {
  GROUP_FAILED=""
  local node_version npm_version
  node_version="$(node --version)"
  npm_version="$(npm --version)"
  echo "node $node_version, npm $npm_version"
  check "ts supply chain" scripts/ts-gate.sh
  check "ts typecheck" npm --prefix ts run typecheck
  check "ts build" npm --prefix ts run build
  check "ts vectors and packages" npm --prefix ts test
  # E-14's demo shares this group because it shares the runtime and the verifier it is built on: the
  # footprint Scene 1 diffs is round-tripped through the verifier's own account decoder, so a layout
  # that drifted from §2.4 fails here rather than on screen.
  check "demo fixtures and footprint" node --test "demo/test/*.test.mjs"
  group_result ts
}

# CI only. `--no-self-update` keeps rustup from updating itself as a side effect.
install_rust() { rustup toolchain install --no-self-update || rustup show; }
install_miri() { rustup toolchain install "$MIRI_TOOLCHAIN" --profile minimal --component miri,rust-src --no-self-update; }
install_cargo_deny() { cargo install cargo-deny --version "$CARGO_DENY_VERSION" --locked; }
install_cargo_fuzz() { cargo install cargo-fuzz --version "$CARGO_FUZZ_VERSION" --locked; }
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
    fuzz) fuzz ;;
    ts) ts ;;
    *) echo "unknown group: $1" >&2; return 2 ;;
  esac
}

# Every group in CI's order. KAT-01 gates the rest exactly as in CI (D-09, S9-03): if either KAT
# group fails, nothing else runs. The other groups are independent, as CI's jobs are, so each of
# them runs and the summary names any that failed.
#
# `fuzz` is deliberately not in this list. ci.yml runs on every push and the fuzz group takes tens of
# minutes, so it has its own nightly workflow; `all` stays the push pipeline verbatim, which is the
# only reason the list is worth comparing against ci.yml at all.
all() {
  local failed=0 summary="" group code log
  for group in kat01-offchain kat01-onchain kat02 vectors checks miri deny ts; do
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
  install-cargo-fuzz) install_cargo_fuzz ;;
  all) all ;;
  "") echo "usage: scripts/ci.sh <group> | all | install-<tool>" >&2; exit 2 ;;
  *) run "$1" ;;
esac
