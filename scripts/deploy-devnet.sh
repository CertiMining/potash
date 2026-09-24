#!/usr/bin/env bash
# Deploys programs/certimining-checkpoint to devnet with the pinned toolchain of D-15 and the keys S6
# keeps outside this repository. Public halves only: no secret reaches the terminal, a log or a commit.
#
# Three keys, three jobs (D-88):
#   program-id.json          the address in declare_id!. Nobody funds it; it signs once here, never
#                            again. Afterwards it holds only the program account's own rent.
#   deploy-keypair.json      pays the deploy and holds the upgrade authority, which is disclosed, not burned.
#   checkpoint-authority.json  signs publish and attach, unattended. It does not appear in this script.
set -euo pipefail
cd "$(dirname "$0")/.."

# The cluster is named here and nowhere else: this script refuses to point anywhere but devnet.
URL="https://api.devnet.solana.com"
AGAVE_BIN="${POTASH_AGAVE_BIN:-$HOME/.local/share/potash/agave/v4.2.2/solana-release/bin}"
KEYS="$HOME/.config/certimining"
PROGRAM_KEY="$KEYS/program-id.json"
PAYER_KEY="$KEYS/deploy-keypair.json"
SO="target/deploy/certimining_checkpoint.so"

# The same version gate build-sbf.sh applies: a deploy from an unpinned toolchain would put bytes on a
# public cluster that no CI run ever saw.
version="$("$AGAVE_BIN/solana" --version)"
grep -q 'solana-cli 4.2.2' <<<"$version" || { echo "deploy: expected the Agave 4.2.2 CLI, got: $version" >&2; exit 1; }

# Both keys must exist and be owner-readable only before anything is spent.
for k in "$PROGRAM_KEY" "$PAYER_KEY"; do
  [ -f "$k" ] || { echo "deploy: $k is missing. The keys live outside the repository (S6)." >&2; exit 1; }
  [ "$(stat -f '%OLp' "$k")" = "600" ] || { echo "deploy: $k is not mode 0600." >&2; exit 1; }
done

program_id="$("$AGAVE_BIN/solana-keygen" pubkey "$PROGRAM_KEY")"
payer_id="$("$AGAVE_BIN/solana-keygen" pubkey "$PAYER_KEY")"

# The two keys are distinct by construction, and the script says so rather than assuming it: one file
# copied over the other would silently collapse the separation D-88 exists to keep.
[ "$program_id" != "$payer_id" ] || { echo "deploy: the address key and the payer key are the same key (D-88)." >&2; exit 1; }

# The id on the cluster must be the id the code was compiled against, or every PDA in the test suite
# addresses a different program than the one just deployed.
declared="$(grep -o 'declare_id!("[^"]*"' programs/certimining-checkpoint/src/lib.rs | cut -d'"' -f2)"
[ "$program_id" = "$declared" ] || { echo "deploy: declare_id! says $declared, the keypair says $program_id" >&2; exit 1; }

# GUARD (owner's ruling, 24 Sep 2026): the address key is never funded and never signs after this
# deploy. Two refusals enforce it.
#
# First: it must hold nothing. The loader creates the program account with the system program's
# create_account, which refuses any address already holding lamports (solana-system-program 4.2.2,
# system_processor.rs:161-167), so a funded address is both a policy breach and a failed deploy.
program_balance="$("$AGAVE_BIN/solana" balance "$program_id" --url "$URL" | awk '{print $1}')"
[ "$program_balance" = "0" ] || {
  echo "deploy: the address key holds $program_balance SOL and must hold none (D-88)." >&2
  echo "        It is an address, not a wallet. Fund $payer_id instead." >&2
  exit 1; }

# Second: once the program exists, this script is finished with that key forever. An upgrade is a
# different command that never touches it — it names the program by PUBKEY and signs with the
# authority alone:
#   solana program deploy --url "$URL" --keypair <payer> --program-id <PUBKEY> \
#     --upgrade-authority <payer> "$SO"
if "$AGAVE_BIN/solana" account "$program_id" --url "$URL" 2>/dev/null | grep -q 'Executable: true'; then
  echo "deploy: $program_id is already a deployed program." >&2
  echo "        Upgrading does not use the address key. Use --program-id with the PUBKEY, not the file." >&2
  exit 1
fi

# The artefact must be the one the pinned SBF toolchain produced, not a stale file from another build.
[ -f "$SO" ] || { echo "deploy: $SO is missing. Run scripts/build-sbf.sh." >&2; exit 1; }
echo "program:  $program_id  (address only: unfunded, signs once, never again)"
echo "payer:    $payer_id  (also the upgrade authority, disclosed per D-88)"
echo "artefact: $SO  $(wc -c <"$SO" | tr -d ' ') bytes  sha256 $(shasum -a 256 "$SO" | cut -d' ' -f1)"

# The deploy itself. --upgrade-authority is stated rather than inherited from any CLI config, so the
# governance claim in the README is the one this command made.
"$AGAVE_BIN/solana" program deploy \
  --url "$URL" \
  --keypair "$PAYER_KEY" \
  --program-id "$PROGRAM_KEY" \
  --upgrade-authority "$PAYER_KEY" \
  "$SO"

# Read the deployment back, so the record states what the cluster holds rather than what was sent.
"$AGAVE_BIN/solana" program show "$program_id" --url "$URL"
