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

`root_for_epoch` derives `["cm_ckpt", epoch_le]` against the program id. No index, no
`getProgramAccounts`, no server that could answer differently for different askers.

What comes back is then **placed before it is believed**: the account must be owned by the program,
carry the program's discriminator, carry schema version 1, and carry the epoch that was asked for
(D-82). An RPC node can return anything, including a real checkpoint for a different epoch, and
INV-ANCH-06 eliminates log equivocation only because every verifier resolves the same root — which
holds only if each verifier checks what it resolved.

Absence is not refusal. Nothing at the derived address means the epoch was never published, and for an
epoch that should have been that is a gap and evidence of batcher failure (INV-ANCH-02). `missing_epochs`
returns the epochs rather than a boolean, so a caller cannot reduce a gap to a warning.

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
the deploy key for this deployment, and the README states that it is live, who holds it and why.

Every invariant this program enforces is enforced by *this* program, and whoever holds that key can
replace it. That is a trust assumption of the same kind as RES-03's batcher-key custody, and it is
written where a reader meets the claims rather than left to be inferred. Burning the authority is a
decision for a deployment claiming permanence, and it is recorded for after the deadline.
