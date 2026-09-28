#!/usr/bin/env bash
# Asks the cluster what it holds, and names anything LIVE-VALUES.txt does not.
#
# The rule is that no synthetic artifact carries a value from a live deployment. A list of those
# values built from memory has the same defect as a fixture built from memory: the first version of
# LIVE-VALUES.txt omitted two of the five signatures the deployment holds, one of which a review
# found and one of which nothing had. This asks the chain instead.
#
# Run it after every publish cycle. Each one adds a signature, and a new epoch adds a checkpoint
# address whose transactions this would otherwise never see.
set -euo pipefail
cd "$(dirname "$0")/.."

RPC="${CERTIMINING_RPC:-https://api.devnet.solana.com}"
LIST=LIVE-VALUES.txt

[ -f "$LIST" ] || { echo "live-values: $LIST is missing" >&2; exit 1; }

# **Which accounts, and why not all of them.** The announced deployment's own state: the program, its
# configuration, and each checkpoint. Not the authorities — the checkpoint key signed across three
# deployments and a 200-epoch compressed run, so asking about it returns 147 signatures from logs that
# no longer exist. Those are not provenance anybody would fabricate, and a list holding them would be
# unmaintainable, which is its own way of not being maintained. The scope is what the rule is about:
# values a reader could mistake for this deployment's.
addresses="$(grep -vE '^\s*#|^\s*$' "$LIST" |
  grep -E 'announced deployment$|checkpoint address, epoch' |
  awk '{print $1}' | grep -vE '^0x')"

[ -n "$addresses" ] || { echo "live-values: no announced-deployment addresses in $LIST" >&2; exit 1; }

missing=0
for address in $addresses; do
  body="$(printf '{"jsonrpc":"2.0","id":1,"method":"getSignaturesForAddress","params":["%s",{"limit":50}]}' "$address")"
  signatures="$(curl -sS -X POST "$RPC" -H 'Content-Type: application/json' -d "$body" |
    python3 -c 'import json,sys; [print(s["signature"]) for s in (json.load(sys.stdin).get("result") or [])]')"
  for signature in $signatures; do
    if ! grep -qF "$signature" "$LIST"; then
      echo "live-values: $signature touched $address and is not in $LIST" >&2
      missing=$((missing + 1))
    fi
  done
done

if [ "$missing" -ne 0 ]; then
  echo "live-values: $missing value(s) on chain are not listed. Add them, with what each one is." >&2
  exit 1
fi
echo "live-values: the chain holds nothing $LIST does not"
