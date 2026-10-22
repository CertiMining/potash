#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Upgrades an already-deployed programs/certimining-checkpoint on devnet, in place.
#
# scripts/deploy-devnet.sh is the *first* deploy and refuses once a program exists, because the
# address key signs once and never again (D-88). Its comment names the upgrade command; this script is
# that command with the guards around it, so an upgrade is not the one step in the procedure performed
# by hand from a comment.
#
# Two keys, and only one of them appears here:
#   deploy-keypair.json  pays, and holds the upgrade authority. The only key this script uses.
#   program-id.json      the address. **Never touched.** An upgrade names the program by pubkey.
#
# Public halves only: no secret reaches the terminal, a log or a commit.
set -euo pipefail
cd "$(dirname "$0")/.."

URL="https://api.devnet.solana.com"
AGAVE_BIN="${POTASH_AGAVE_BIN:-$HOME/.local/share/potash/agave/v4.2.2/solana-release/bin}"
KEYS="$HOME/.config/certimining"
PAYER_KEY="$KEYS/deploy-keypair.json"
SO="target/deploy/certimining_checkpoint.so"
# The ProgramData account carries a 45-byte header before the program bytes (bpf_loader_upgradeable).
PROGRAMDATA_HEADER=45

# The same version gate build-sbf.sh and deploy-devnet.sh apply. An upgrade from an unpinned toolchain
# would replace bytes on a public cluster with bytes no CI run ever saw.
version="$("$AGAVE_BIN/solana" --version)"
grep -q 'solana-cli 4.2.2' <<<"$version" || { echo "upgrade: expected the Agave 4.2.2 CLI, got: $version" >&2; exit 1; }

[ -f "$PAYER_KEY" ] || { echo "upgrade: $PAYER_KEY is missing. The keys live outside the repository (S6)." >&2; exit 1; }
[ "$(stat -f '%OLp' "$PAYER_KEY")" = "600" ] || { echo "upgrade: $PAYER_KEY is not mode 0600." >&2; exit 1; }

declared="$(grep -o 'declare_id!("[^"]*"' programs/certimining-checkpoint/src/lib.rs | cut -d'"' -f2)"
payer_id="$("$AGAVE_BIN/solana-keygen" pubkey "$PAYER_KEY")"
source_commit_short="$(git rev-parse --short HEAD)"

# The program must already exist. deploy-devnet.sh owns the other case, and saying so is cheaper than
# letting the loader report it.
if ! "$AGAVE_BIN/solana" account "$declared" --url "$URL" 2>/dev/null | grep -q 'Executable: true'; then
  echo "upgrade: $declared is not a deployed program on devnet." >&2
  echo "         A first deploy is scripts/deploy-devnet.sh, which uses the address key." >&2
  exit 1
fi

show="$("$AGAVE_BIN/solana" program show "$declared" --url "$URL")"
programdata="$(awk '/ProgramData Address:/ {print $3}' <<<"$show")"
authority="$(awk '/Authority:/ {print $2}' <<<"$show")"
deployed_len="$(awk '/Data Length:/ {print $3}' <<<"$show")"
deployed_slot="$(awk '/Last Deployed In Slot:/ {print $5}' <<<"$show")"

# **The authority is checked here rather than discovered by a failed transaction.** If the upgrade
# authority is not the key this script holds, the upgrade cannot succeed and the reason should be a
# sentence rather than a loader error.
[ "$authority" = "$payer_id" ] || {
  echo "upgrade: the upgrade authority on chain is $authority and this script holds $payer_id." >&2
  echo "         Either the authority was transferred, or this is not the deployment you meant." >&2
  exit 1; }

# The artefact must be the pinned toolchain's and must correspond to a commit, for the reason
# deploy-devnet.sh records: bytes on a public cluster that match no tree cannot be rebuilt by a reader.
if [ -n "$(git status --porcelain -- programs crates Cargo.toml Cargo.lock rust-toolchain.toml)" ]; then
  echo "upgrade: the program sources are not clean, so the deployed bytes would match no commit." >&2
  echo "         Commit first, then upgrade." >&2
  exit 1
fi

# **Built here rather than taken from target/.** A clean tree and a stale artefact pass every check
# above while corresponding to different commits, which is not a hypothetical: on 22 October a local
# `cargo test` run loaded a previous `.so`, reported the opposite of the truth about a wire-format
# change, and was believed until the result was too strange to be right. deploy-devnet.sh checks the
# tree and trusts the file. This builds the file from the tree it just checked, so the digest printed
# below is the digest of these sources and not of whatever was there before.
echo "Building from $source_commit_short with the pinned toolchain, so the artefact matches the tree."
scripts/build-sbf.sh >/dev/null || { echo "upgrade: scripts/build-sbf.sh failed; nothing was sent." >&2; exit 1; }
[ -f "$SO" ] || { echo "upgrade: $SO is missing after a successful build, which should not happen." >&2; exit 1; }

artefact_len="$(wc -c <"$SO" | tr -d ' ')"
artefact_sha="$(shasum -a 256 "$SO" | cut -d' ' -f1)"
source_commit="$(git rev-parse HEAD)"

# **A no-op upgrade is refused rather than performed.** Only checkable when the lengths agree: the
# dumped account is padded to its own size, so it is truncated to the length the chain reports before
# being hashed.
if [ "$artefact_len" = "$deployed_len" ]; then
  dump="$(mktemp -t potash-deployed)"
  trap 'rm -f "$dump"' EXIT
  "$AGAVE_BIN/solana" program dump "$declared" "$dump" --url "$URL" >/dev/null
  deployed_sha="$(dd if="$dump" bs=1 count="$deployed_len" 2>/dev/null | shasum -a 256 | cut -d' ' -f1)"
  if [ "$deployed_sha" = "$artefact_sha" ]; then
    echo "upgrade: the cluster already holds these exact bytes (sha256 $artefact_sha)." >&2
    echo "         Nothing to upgrade. Rebuild from the commit you meant, or there is no change." >&2
    exit 1
  fi
fi

echo "program:   $declared"
echo "authority: $payer_id  (also the payer, disclosed per D-88)"
echo "before:    $deployed_len bytes, last deployed in slot $deployed_slot"
echo "after:     $artefact_len bytes  sha256 $artefact_sha"
echo "source:    $source_commit  (clean)"
echo

# **The account has to be large enough before the loader is asked to write into it.** A ProgramData
# account is allocated to fit the program it was deployed with and does not grow by itself, so an
# upgrade to a larger program fails on a full account. Establishing the capacity here means the
# failure is a sentence and a priced decision rather than a half-finished deploy.
pd_len="$("$AGAVE_BIN/solana" account "$programdata" --url "$URL" | awk '/^Length:/ {print $2}')"
capacity=$((pd_len - PROGRAMDATA_HEADER))
echo "ProgramData $programdata holds $pd_len bytes, so $capacity are usable for program bytes."
if [ "$artefact_len" -gt "$capacity" ]; then
  additional=$((artefact_len - capacity))
  echo "That is $additional bytes short of this artefact."
  echo
  echo "An extend is irreversible — a ProgramData account cannot be shrunk — and it costs rent."
  echo "Run it, then run this script again:"
  echo
  echo "  $AGAVE_BIN/solana program extend $declared $additional \\"
  echo "    --url $URL --keypair $PAYER_KEY"
  echo
  echo "Extending by exactly the shortfall rather than a margin, so nothing is spent on a guess"
  echo "about the next build. A larger build later needs another extend, and this will say so."
  exit 1
fi
echo "Room for the artefact; no extend needed."
echo

"$AGAVE_BIN/solana" program deploy \
  --url "$URL" \
  --keypair "$PAYER_KEY" \
  --program-id "$declared" \
  --upgrade-authority "$PAYER_KEY" \
  "$SO"

# Read the deployment back, so the record states what the cluster holds rather than what was sent.
echo
"$AGAVE_BIN/solana" program show "$declared" --url "$URL"
echo
echo "Record these with the upgrade: commit $source_commit, sha256 $artefact_sha."
echo "A reader rebuilds that commit with scripts/build-sbf.sh and compares the digest."
