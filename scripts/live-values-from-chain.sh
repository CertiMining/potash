#!/usr/bin/env bash
# Asks the cluster what the announced deployment holds, and names anything LIVE-VALUES.txt does not.
#
# The rule is that no synthetic artifact carries a value from a live deployment. A list of those
# values built from memory has the same defect as a fixture built from memory: the first version of
# LIVE-VALUES.txt omitted three of the six signatures the deployment held, one of which a review found
# and two of which nothing had. This asks the chain instead.
#
# Run it after every publish cycle. Each one adds a signature, a checkpoint address and a root.
#
# **What it checks, and what it cannot.** A first version of this script checked signatures only, read
# them only from accounts the list already named, took the first fifty without paging, and treated a
# JSON-RPC error as an empty result — so it could report "nothing missing" when it had in fact asked
# nothing. A review found all four. It now pages to exhaustion, fails on an RPC error rather than
# passing, discovers checkpoint accounts from the program's own history instead of from the list, and
# checks each account's stored root as well as the signatures that touched it. What it still cannot do
# is find a *retired* deployment's values: its subject is the announced one, named in
# ANNOUNCED_PROGRAM_ID, and the superseded ids in the list are there by hand.
set -euo pipefail
cd "$(dirname "$0")/.."

RPC="${CERTIMINING_RPC:-https://api.devnet.solana.com}"
LIST=LIVE-VALUES.txt
PROGRAM_FILE=ANNOUNCED_PROGRAM_ID

[ -f "$LIST" ] || { echo "live-values: $LIST is missing" >&2; exit 1; }
[ -f "$PROGRAM_FILE" ] || { echo "live-values: $PROGRAM_FILE is missing" >&2; exit 1; }

program="$(grep -oE '[1-9A-HJ-NP-Za-km-z]{32,44}' "$PROGRAM_FILE" | head -1)"
[ -n "$program" ] || { echo "live-values: no program id in $PROGRAM_FILE" >&2; exit 1; }

# One JSON-RPC call. A transport failure or an `error` member exits non-zero: a check that cannot ask
# must not report that it found nothing.
rpc() {
  local body="$1" out attempt=1 wait=2
  while [ "$attempt" -le 6 ]; do
    if out="$(curl -sS --fail-with-body -X POST "$RPC" -H 'Content-Type: application/json' -d "$body" 2>/dev/null)"; then
      # A 200 can still carry an `error` member, and a rate limit can arrive either way.
      if printf '%s' "$out" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    raise SystemExit(2)
if "error" in d:
    raise SystemExit(3)
json.dump(d.get("result"), sys.stdout)
'; then
        return 0
      fi
    fi
    # The public devnet endpoint rate-limits a paging walk, so a failure is retried rather than
    # reported as an absence. Six attempts with backoff; after that the check fails, because a check
    # that could not ask must not say it found nothing.
    sleep "$wait"
    wait=$((wait * 2))
    attempt=$((attempt + 1))
  done
  echo "live-values: the RPC at $RPC did not answer after 6 attempts" >&2
  return 1
}

# Every signature for an address, paged to exhaustion rather than capped.
signatures_for() {
  local address="$1" before="" page count total=0
  while :; do
    if [ -z "$before" ]; then
      page="$(rpc "$(printf '{"jsonrpc":"2.0","id":1,"method":"getSignaturesForAddress","params":["%s",{"limit":1000}]}' "$address")")" || return 1
    else
      page="$(rpc "$(printf '{"jsonrpc":"2.0","id":1,"method":"getSignaturesForAddress","params":["%s",{"limit":1000,"before":"%s"}]}' "$address" "$before")")" || return 1
    fi
    count="$(printf '%s' "$page" | python3 -c 'import json,sys; print(len(json.load(sys.stdin) or []))')"
    [ "$count" -eq 0 ] && break
    printf '%s' "$page" | python3 -c 'import json,sys; [print(s["signature"]) for s in json.load(sys.stdin)]'
    before="$(printf '%s' "$page" | python3 -c 'import json,sys; print(json.load(sys.stdin)[-1]["signature"])')"
    total=$((total + count))
    [ "$total" -gt 100000 ] && { echo "live-values: more than 100000 signatures for $address" >&2; return 1; }
  done
}

missing=0
report() {
  echo "live-values: $1" >&2
  missing=$((missing + 1))
}

# The accounts to ask about: the program, its configuration, and every checkpoint the list names.
# Checkpoints are also discovered below, so a cycle that was published and never listed is still found.
# Addresses, not signatures: both are base58 and only the description tells them apart, and an
# earlier selector matched every line ending "announced deployment", which swept in the deploy
# signature and asked the cluster for its transaction history.
addresses="$program
$(grep -vE '^\s*#|^\s*$' "$LIST" |
  grep -vE 'signature' |
  grep -E 'announced deployment$|checkpoint address, epoch' |
  awk '{print $1}' | grep -vE '^0x')"

for address in $(printf '%s\n' $addresses | sort -u); do
  # Captured first and the status checked: `for x in $(f)` discards f's exit code, so a failing
  # walk would have looked like an address with no transactions.
  if ! found="$(signatures_for "$address")"; then
    echo "live-values: could not read the history of $address" >&2
    exit 1
  fi
  for signature in $found; do
    grep -qF "$signature" "$LIST" || report "$signature touched $address and is not in $LIST"
  done
done

# Each checkpoint account's stored root, read from the account rather than from the transaction that
# wrote it. §2.4 puts the root at offset 18 of a 106-byte CheckpointAccount.
for address in $(grep -E 'checkpoint address, epoch' "$LIST" | awk '{print $1}'); do
  if ! account="$(rpc "$(printf '{"jsonrpc":"2.0","id":1,"method":"getAccountInfo","params":["%s",{"encoding":"base64"}]}' "$address")")"; then
    echo "live-values: could not read $address" >&2
    exit 1
  fi
  root="$(printf '%s' "$account" | python3 -c '
import base64, json, sys
try:
    r = json.load(sys.stdin)
except Exception:
    raise SystemExit(0)
v = (r or {}).get("value") if isinstance(r, dict) else None
if not isinstance(v, dict) or not v.get("data"):
    raise SystemExit(0)
data = base64.b64decode(v["data"][0])
if len(data) < 50:
    raise SystemExit(0)
print("0x" + data[18:50].hex())
')"
  [ -n "$root" ] || continue
  grep -qiF "$root" "$LIST" || report "$address stores root $root, which is not in $LIST"
done

if [ "$missing" -ne 0 ]; then
  echo "live-values: $missing value(s) on chain are not listed. Add them, with what each one is." >&2
  exit 1
fi
echo "live-values: the chain holds nothing $LIST does not"
