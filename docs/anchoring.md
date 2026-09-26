# The chain: one root per epoch, and how a counterparty reads it

The program stores a root per epoch and an optional receipt digest, and nothing else, ever. The client
publishes on the epoch cadence and lets anyone fetch a root by deriving its address. This file
describes what `certimining-checkpoint` and `certimining-client` do; TCU-02 §1.5, §2.3 and §2.4 are the
contract they follow.

## Three instructions, and no fourth

`initialize` writes the authority and the tree height once, refusing a height outside `[4, 16]` with
`0x05`. `publish_checkpoint` writes one root for one epoch. `attach_anchor_receipt` moves the receipt
digest from zero to a value, once.

**There is no update, close, revoke, shred or set-state, and none may be added.** A pull request
introducing one is rejected regardless of its guard conditions. That is not a style rule: an
instruction that can change a published root would make every claim in this repository conditional on
whoever can call it.

## The order `publish_checkpoint` decides in

1. The config's schema version, because an account this program did not write is not one it extends.
2. **Whether the checkpoint account already exists**, which is `0x0E`.
3. Whether the epoch is `last_epoch + 1`, which is `0x0D`.

The order matters and the specification names it (D-80). Republishing epoch `e` satisfies both
conditions at once, so without a stated order one of the two codes could never be returned, and a code
no path can return reads as coverage that does not exist. This is also why the account is created here
rather than by Anchor's `init`: an account the framework has already created cannot be asked whether it
existed. The create is the same system-program call, with the same rent and the same owner.

## What a counterparty does, and does not, take on trust

`root_for_epoch` derives `["cm_ckpt", epoch_le]` against the program id. No index and no
`getProgramAccounts`: the address a counterparty reads is one they computed, not one a server chose
for them.

**What that does not remove is the RPC itself.** The account comes back from one endpoint, over its
word alone: this client asks for no bank proof, runs no light client, and does not compare answers
across endpoints. A malicious or compromised RPC can hand two counterparties two different,
structurally valid checkpoints for one epoch, and every check below would pass on both. Deriving the
address closes the question of *which* account is being read; it does not close the question of
whether the answer is the chain's. A counterparty who needs that assurance today has to ask more than
one endpoint, and this client does not do it for them (D-107).

What comes back is then **placed before it is believed**: the account must be owned by the program,
carry the program's discriminator, carry schema version 1, and carry the epoch that was asked for
(D-82). An RPC node can return anything, including a real checkpoint for a different epoch, and
INV-ANCH-06 eliminates log equivocation only because every verifier resolves the same root — which
holds only if each verifier checks what it resolved.

Absence is not refusal, and neither of them is a gap. **There is no interior gap to find**
(S9-R2-02): `publish_checkpoint` accepts `last_epoch + 1` and nothing else, so the published range runs
unbroken from `start_epoch` to `last_epoch`.

`sequence_lag` places every epoch a caller asks about, and returns `Lag`:

| Field | What it means |
|---|---|
| `before_log_start` | a day the log did not exist for. Not a failure of anyone's |
| `not_yet_published` | the sequence has not reached it. **This is the batcher failure INV-ANCH-02 is about** |
| `refused` | an account came back inside the published range and failed a check. Evidence about the response, not the log |
| `epochs_behind()` | how far the sequence trails the highest epoch asked about |

The `refused` arm needs its meaning stated, because the obvious reading is wrong. A third party
**cannot** place an account at one of these addresses: `allocate` requires the target to sign
(`solana-system-program-4.2.2`, `system_processor.rs:82-89`), a program-derived address is off-curve
and has no key, and only the owning program can sign for it with its seeds. Sending it lamports is all
an outsider can do, which is the attack D-104 closes. So inside the published range every account was
written by this program, and a refusal there means the answers did not come from one view of the chain
— a stale replica, a different fork, or an endpoint that is not serving the chain at all.

**This client does not read a clock**, so it does not rule on lag. §2.3 and INV-IFACE-01 keep clocks
out of verification; the client reports the distance, and whoever holds a clock decides what it means.

**A known limit, filed rather than hidden.** `sequence_lag` reads the configuration and each
checkpoint through separate requests with no shared response context, so an inconsistent view can
produce a `refused` or an absent account that says nothing about the log. The error text says exactly
that rather than drawing a conclusion. Binding the reads to one snapshot is tracked for after the
deadline.

## Publication time belongs to the schedule

`publication_time(epoch)` is the epoch boundary plus a fixed offset, and the build starts a constant
lead before it. The crate holds no clock: the service supplies the time, exactly as the batcher is
supplied its epoch.

Publishing when the tree happens to be ready would leak build time, and build time tracks record
count. §4.4a bounds a 256-leaf build at 10 ms and E-06 measured 201 µs in release, against a ten-minute
lead — but the size of the lead is not the property. **The property is that the lead is constant.**

## What the privacy tests here prove, and what they cannot

V-Z-01 and V-Z-06 are release blockers and run under LiteSVM, because a closed list of permitted bytes
can only be checked where the same inputs give the same bytes every time (D-85).

- **V-Z-01's byte-exact half:** epochs of 0, 1, 128 and 255 records, published in more than one order
  on two separate logs, compared for instruction length, transaction length, account length and every
  byte of the account against §4.4's closed list. A byte that differs and is not on the list fails the
  blocker by offset. Two probes confirm it bites: one reserved byte made to vary with the root, and an
  account whose size varies with the root.
- **V-Z-06:** a daily filer and a twice-yearly filer over thirty epochs, compared the same way. One
  checkpoint per epoch either way, because cadence belongs to the schedule and not to the filers.

**What LiteSVM cannot show is whether a real network's landing slot tracks epoch content.** That half
of V-Z-01 runs on devnet over 200 consecutive epochs against an absolute correlation below 0.2, fixed
before any epoch was published and recorded on issue #9.

## What the chain does not carry

No `c`, no tenure identifier, no jurisdiction or registry code, no category, no date belonging to a
record, no submission identifier, no promise. An epoch's account holds its number, its root, when it was
published, a receipt digest and two bytes of bookkeeping. §4.4's V-Z-05 greps the on-chain history for
the rest.

## The upgrade authority is live, and said so

INV-GOV-01 allows two answers and the owner chose disclosure (D-88): the upgrade authority stays with
the deploy payer for this deployment, and this file states that it is live, who holds it and why.
This file is where the disclosure lives until E-15 writes the repository's README, which is the entry
point most readers arrive through; three texts claimed a README that did not exist (Codex round one,
finding 12).

Three keys carry three jobs, and none of them is the same key. The **program address** is the id in
`declare_id!`: nobody funds it, it signs once at the deploy and never again, and
`scripts/deploy-devnet.sh` refuses to run if either of those stops being true. After the deploy the
address holds the program account's rent-exemption and nothing else. The **deploy payer**
pays for the deploy and is the authority disclosed here. The **checkpoint authority** signs
`publish_checkpoint` and `attach_anchor_receipt`, and is the only key that runs unattended; it cannot
upgrade the program.

## Where it is deployed

| | |
|---|---|
| Cluster | Solana devnet |
| Program | `jzJzgKWMo7QhCADuVSGT2cT5VkHjhHEz5tkgDugL3no` |
| ProgramData | filled at deploy |
| Upgrade authority | `5uxZGvtkipqzLWjyNfFGEMxGFfd3FPveti4uQE7FdCXz` (live, see above) |
| Checkpoint authority | `7sXh9zUcJP16RKw6ndBHAzYqT9fNNgZR79rwiG1imtNB` |
| `tree_height` | 8, written once at `initialize` |
| Deployed in slot | filled at deploy |

**A superseded deployment.** `HS82CAXgVykfVniBzPp9eArDfVLmFYcik3evyAx7iVZB` was announced on 24 September and is superseded. Its epoch 1 carries a receipt digest standing for no OpenTimestamps receipt, written into a field that is write-once, so it claims an anchor it does not have and always will; and its log begins at epoch 1 rather than at a UTC day index, which the rule in §1.4 now forbids. Neither is repairable in place, and the address above replaces it.

Devnet runs Agave 4.3.0 while this repository pins 4.2.2, so the suite that proves the program's
behaviour and the cluster that runs it are not the same version. D-86 makes that a thing to measure
rather than assume: `crates/certimining-client/tests/devnet.rs` re-runs the LiteSVM assertions against
the live program, and the two columns are recorded together on issues #8 and #9.

Every invariant this program enforces is enforced by *this* program, and whoever holds that key can
replace it. That is a trust assumption of the same kind as RES-03's batcher-key custody, and it is
written where a reader meets the claims rather than left to be inferred. Burning the authority is a
decision for a deployment claiming permanence, and it is recorded for after the deadline.
