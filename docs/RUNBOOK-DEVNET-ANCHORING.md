# Devnet split-anchoring runbook

This runbook operates the two-process cycle defined by D-139 and bounded by D-142. It is for local
staging and Solana **devnet only**. It neither deploys to mainnet nor proves that an OpenTimestamps
Bitcoin claim is true without the separate header-confirmation step.

## Roles and custody boundary

Keep these roles distinct. The preflight compares the five public identities on every host and opens
only the private keys belonging to that host.

| Host | Private material allowed | Private material forbidden |
| --- | --- | --- |
| Deployment | program-address key, deploy/upgrade authority | worker payer, checkpoint authority, batcher signing key, `k_master` |
| Batcher | batcher signing key, `k_master` | all Solana private keys |
| Anchor-B worker | worker fee payer, checkpoint authority | program/deploy keys, batcher signing key, `k_master` |

The worker fee payer is deliberately not the deploy/upgrade authority. The payer only funds
transactions; giving an unattended worker the upgrade authority for that purpose defeats key
separation. All private files must be outside the repository and mode `0600`.

## 1. Local staging rehearsal

This is the safe first command. It builds the real SBF program and runs it under LiteSVM:

```bash
scripts/devnet-anchoring-cycle.sh simulate
```

The rehearsal creates a real epoch tree, signs and verifies its handoff, publishes the root, computes
the receipt digest from the exact `TAG_RCPT || u16_le(len) || receipt` preimage, attaches it, and reads
the checkpoint back as `Dual`. It also mutates the signed root, collapses two identities, changes the
receipt prefix, and skips an epoch; each mutation must fail.

The local receipt bytes are intentionally synthetic. This command does **not** exercise an
OpenTimestamps calendar or Bitcoin proof-of-work. The repository's committed receipt/header tests and
the final `confirm-anchor-b` command cover those boundaries.

## 2. Configure the public manifest

Install the same non-secret values on all three hosts:

```bash
export CERTIMINING_PROFILE=devnet
export CERTIMINING_RPC=https://api.devnet.solana.com
export CERTIMINING_PROGRAM_ID='<program address>'
export CERTIMINING_DEPLOY_AUTHORITY_ID='<deploy/upgrade authority pubkey>'
export CERTIMINING_WORKER_PAYER_ID='<worker fee-payer pubkey>'
export CERTIMINING_CHECKPOINT_AUTHORITY_ID='<checkpoint authority pubkey>'
export CERTIMINING_BATCHER_KEY='<batcher Ed25519 public key, 64 lowercase hex characters>'
```

`CERTIMINING_PROGRAM_ID` must equal the program address compiled into this checkout. Every public
identity must differ from every other public identity.

Configure only the private paths for the current host, then run its offline preflight:

```bash
# Deployment host only
export CERTIMINING_PROGRAM_KEY=/secure/program-address.json
export CERTIMINING_DEPLOY_AUTHORITY=/secure/deploy-authority.json
scripts/devnet-anchoring-cycle.sh preflight deployment

# Batcher host only
export CERTIMINING_MASTER_KEY=/secure/k-master
export CERTIMINING_BATCHER_SIGNING_KEY=/secure/batcher-signing-key
scripts/devnet-anchoring-cycle.sh preflight batcher

# Worker host only
export CERTIMINING_WORKER_PAYER=/secure/worker-payer.json
export CERTIMINING_CHECKPOINT_AUTHORITY=/secure/checkpoint-authority.json
scripts/devnet-anchoring-cycle.sh preflight worker
```

Do not leave another role's private-path variable exported. Preflight treats that as a failure even
when the file is absent. Fund the worker payer on devnet separately and confirm its balance before
starting the worker; never copy the deploy authority to solve a fee-payer shortage.

## 3. Produce and transfer a handoff

On the batcher host, point `CERTIMINING_HANDOFFS` at an outbound directory, optionally provide the
submission file, and produce exactly the next UTC epoch:

```bash
export CERTIMINING_HANDOFFS=/var/lib/certimining/handoffs
export CERTIMINING_SUBMISSIONS=/var/lib/certimining/input/41001.txt
scripts/devnet-anchoring-cycle.sh batch 41001
```

Transfer `41001.handoff` to the worker's inbound handoff directory using the operator's authenticated
transport. The artifact contains no leaf set and no master key. The worker verifies the epoch,
height, expected batcher public key, and signature before it can publish the root.

## 4. Run and monitor the Anchor-B worker

On the worker host, configure its handoff and receipt directories and pinned OpenTimestamps client:

```bash
export CERTIMINING_HANDOFFS=/var/lib/certimining/handoffs
export CERTIMINING_RECEIPTS=/var/lib/certimining/receipts
export OTS=$HOME/.local/share/potash/ots-venv/bin/ots
export CERTIMINING_LIVE_ACK=devnet-transactions-authorized
scripts/devnet-anchoring-cycle.sh worker
```

This is the only helper command that writes to devnet. It publishes the Anchor-A checkpoint, submits
the root to OpenTimestamps, waits while the receipt is pending, upgrades it, and attaches the receipt
digest. Stop it with the service manager or `Ctrl-C`; restarting is safe because checkpoint and
receipt transitions are write-once and the worker re-observes state before choosing its next step.

Monitor the worker log for the explicit stages `published`, `stamped`, `single`, and `attached`. A
missing or malformed handoff, unconfirmed receipt, unreachable RPC, unexpected calendar state, or
non-contiguous log stops or waits explicitly; none is translated into success.

## 5. Reconcile the receipt and epoch

After `attached`, run the read-only reconciliation command on a host with the public manifest and a
copy of the handoff and upgraded receipt:

```bash
export CERTIMINING_HANDOFFS=/var/lib/certimining/handoffs
export CERTIMINING_RECEIPTS=/var/lib/certimining/receipts
scripts/devnet-anchoring-cycle.sh reconcile 41001
```

Success means all of the following agree: batcher signature and epoch; handoff root and on-chain
root; upgraded receipt and root; locally recomputed receipt-prefix digest and the on-chain digest;
anchor kind `1`; `Dual` status; and the configured contiguous epoch range. The printed Bitcoin height
is still a receipt **claim**. Confirm it against independently obtained headers with:

```bash
CERTIMINING_STAMPED=/var/lib/certimining/receipts/41001.root \
CERTIMINING_RECEIPT=/var/lib/certimining/receipts/41001.root.ots \
CERTIMINING_HEADERS=/path/to/independent/headers.bin \
  cargo run -p certimining-client --features ots --bin confirm-anchor-b
```

Set the checkpoint height, hash, bits, and time variables described by `confirm-anchor-b` when the
header file does not descend from its compiled checkpoint. Do not infer confirmation from a receipt
claim alone.

## Recovery and missed epochs

1. Stop the worker and preserve its logs, handoffs, roots, and receipts.
2. Run `preflight worker` again. Correct custody/configuration failures before any retry.
3. Reconcile the last epoch believed complete. An explicit failure is unresolved evidence, not a
   reason to advance the epoch.
4. Starting at the first missing epoch, have the batcher reproduce or deliver its signed handoff.
   Process one epoch at a time in ascending order. Never jump to a later day: the program rejects a
   gap and the staging mutation test proves that guard is observed.
5. Restart the worker. It derives its next action from on-chain state plus receipt files, so it will
   publish, submit, or attach whichever step is incomplete.
6. Reconcile every recovered epoch before declaring the backlog clear.

Do not delete a pending receipt, overwrite a differing handoff, reuse an identity to speed recovery,
or substitute the deploy authority for the worker payer. Escalate an unresolved state to the human
operator; this runbook provides no merge, issue-closure, or production-deployment authority.
