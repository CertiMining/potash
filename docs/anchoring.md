# The chain: one root per epoch, and how a counterparty reads it

The program stores a root per epoch and an optional receipt digest, and **never anything about what
was filed**. The checkpoint account carries housekeeping beside those two — the epoch, the publication
slot and time, the anchor status, the bump — and §2.4 below lays out all nine fields; an earlier
version of this sentence said "nothing else, ever", which the table a page down contradicts. What no
field carries is a record, an identifier, a count or a category. The client
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
count. §4.4a no longer bounds the build (D-137), so the headroom is stated against measurement: E-06
measured 201 µs in release and the TypeScript verifier 2.7 ms, against a ten-minute lead — but the size of
the lead is not the property. **The property is that the lead is constant.**

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
| Program | `By5XeTsCS4Qf17U9EuGUTzEFz29wQdFFeqJtfhnFQkZB` |
| ProgramData | `9yQQgxecM7d4spoKxH1UVxhBqzoYKbCfk9n8NSjJXX9K` |
| Upgrade authority | `5uxZGvtkipqzLWjyNfFGEMxGFfd3FPveti4uQE7FdCXz` (live, see above) |
| Checkpoint authority | `7sXh9zUcJP16RKw6ndBHAzYqT9fNNgZR79rwiG1imtNB` |
| `tree_height` | 8, written once at `initialize` |
| `start_epoch` | 20723, the UTC day index at `initialize` (D-109) |
| Deployed in slot | 504783809 · 164,752 bytes · sha256 `fa8b5f305abf4e7fd73df1207772eae73a49413dfbc94c95d1fc7a17c3785bb5` from `ade6a18` |

**Two superseded deployments.** `HS82CAXgVykfVniBzPp9eArDfVLmFYcik3evyAx7iVZB`, announced 24 September, is superseded. Its epoch 1 carries a receipt digest standing for no OpenTimestamps receipt, written into a field that is write-once, so it claims an anchor it does not have and always will; and its log begins at epoch 1 rather than at a UTC day index, which the rule in §1.4 now forbids. Neither is repairable in place.

`jzJzgKWMo7QhCADuVSGT2cT5VkHjhHEz5tkgDugL3no`, announced 25 September, is superseded too, and for a reason of ours rather than the chain's: V-Z-01's landing-delay gate published 200 consecutive epochs against it at one a minute, and §1.4 makes an epoch a UTC day index, so its sequence now runs 209 days ahead of the calendar. `publish_checkpoint` is monotone, so that cannot be walked back. The gate's measurement is unaffected — it measured whether epoch *content* moves a landing slot, which numbering does not enter — and the rule that prevents a third supersession is in the code: every compressed harness refuses the announced program id, and a separate `initialize` harness exists because those refusals left nothing able to start the announced log.

The address above replaces both. D-88 carries all three with what each one was.

Devnet runs Agave 4.3.0 while this repository pins 4.2.2, so the suite that proves the program's
behaviour and the cluster that runs it are not the same version. D-86 makes that a thing to measure
rather than assume: `crates/certimining-client/tests/devnet.rs` re-runs the LiteSVM assertions against
the live program, and the two columns are recorded together on issues #8 and #9.

**What this log demonstrates, and what it does not (D-138).** It demonstrates an append-only log
anchored to two independent chains: real roots, real checkpoints, real OpenTimestamps receipts, on a
schedule. It does **not** demonstrate count-hiding. The publication harness builds every epoch from
three records whose submission ids and leaves are deterministic constants in
`crates/certimining-client/tests/publish_epoch.rs`, because the deployment has no issuer feeding it, so
the record count is published in the same file that produces the root. Every root this log has
published — 20723 through 20731 — can be rebuilt from this repository alone. Until D-138 the harness
also held `k_master` as a source constant, which INV-TREE-05 requires never to be published; it now
reads the key from outside the repository, so a deployment copying this harness does not inherit the
defect. That repair does not give *this* log count-hiding, because its records remain public. §4.4's
privacy tests and the demo are what exercise the property.

Every invariant this program enforces is enforced by *this* program, and whoever holds that key can
replace it. That is a trust assumption of the same kind as RES-03's batcher-key custody, and it is
written where a reader meets the claims rather than left to be inferred. Burning the authority is a
decision for a deployment claiming permanence, and it is recorded for after the deadline.

## The cycles run so far, on the announced log

Anchor B's design is two stages hours apart (D-112), and these are instances of it arriving as
described rather than an argument that it will.

| Epoch | Root | Anchor A, slot | Anchor B | Receipt | Status |
|---|---|---|---|---|---|
| 20723 | `0xdc349df9…0d0791` | 504985662 | Bitcoin block 968,917 | `anchors/epochs/20723.ots` | `dual` |
| 20724 | `0x8ab166ba…f02891` | 504997440 | Bitcoin block 968,923 | `anchors/epochs/20724.ots` | `dual` |
| 20725 | `0x0d872549…a86443` | 505533854 | Bitcoin block 969,173 | `anchors/epochs/20725.ots` | `dual` |
| 20726 | `0x93bb7266…12a63e` | 506347475 | Bitcoin block 969,474 | `anchors/epochs/20726.ots` | `dual` |
| 20727 | `0xaf59b7a0…3f9a73` | 506347535 | Bitcoin block 969,474 | `anchors/epochs/20727.ots` | `dual` |
| 20728 | `0x7c6b6c2d…9d8d07` | 506679656 | Bitcoin block 969,632 | `anchors/epochs/20728.ots` | `dual` |
| 20729 | `0x93d90db1…8984c1` | 507274820 | Bitcoin block 969,809 | `anchors/epochs/20729.ots` | `dual` |
| 20730 | `0xc37e64d3…6c92d5` | 507274885 | Bitcoin block 969,869 | `anchors/epochs/20730.ots` | `dual` |
| 20731 | `0x4a37066f…890d15` | 507636283 | Bitcoin block 969,968 | `anchors/epochs/20731.ots` | `dual` |
| 20732 | `0xcfa92cc7…1ae465` | 508282376 | Bitcoin block 970,294 | `anchors/epochs/20732.ots` | `dual` |
| 20733 | `0xdc1aa505…f4b513` | 508282423 | Bitcoin block 970,294 | `anchors/epochs/20733.ots` | `dual` |
| 20734 | `0x602451d1…699933` | 509018081 | *pending* | *not yet committed* | `single` |
| 20735 | `0x6aa9a23c…cb6afa` | 509018123 | *pending* | *not yet committed* | `single` |

**Epochs 20734 and 20735 are mid-cycle.** Both were published and stamped on day 20735, and their
receipts carry calendar attestations only until a Bitcoin block confirms them. Two days were owed:
nothing was published on day 20734, and day 20735 paid both — the fourth time the cadence has been
missed and the fourth time the next day paid it.

**Before them, every published epoch read `dual`.** 20732 and 20733 were published and
stamped early on day 20733 and attached later the same day, both at block 970,294 — they were stamped
minutes apart and share a block, which the wait is not a constant and cycles four and five also showed.
Epoch 20731 sat between the two stages for two days and left it on day 20733, at block 969,968.

That is the state on the day this was written and it is not a property of the design. D-112 spends the
one write-once opportunity on the upgraded receipt, so every newly published epoch reads `single` for
the hours between publication and a Bitcoin block, and the table will show `single` again the next time
an epoch is published. INV-ANCH-04 budgets that latency; INV-ANCH-05 forbids reporting `dual` on a
calendar's promise.
Each receipt is committed and its row completed once a block confirms it, because `receipt_digest` is
write-once (INV-ANCH-03) and the one opportunity is spent on the upgraded form.

**Epoch 20728 is what the other end of that wait looks like.** Its receipt was stamped on day 20728 and
carried calendar attestations only for about a day and a half; `ots upgrade` found Bitcoin attestations on
day 20730, and `attach_anchor_receipt` committed the digest of the upgraded receipt. The row names block
969,632 because that is the height the attached claim carries — the first Bitcoin attestation in the
receipt's operation tree, which is what `verify_receipt` returns. The receipt also carries a second
calendar's attestation at block 969,627, and naming one of two is the convention every row here follows.
Neither height is checked against Bitcoin by anything in this repository, which is H-12
([#48](https://github.com/CertiMining/potash/issues/48)).

**A day has been missed three times, and all three were paid the day after.** Nothing published on day
20726; on day 20727 both 20726 and 20727 were published, stamped and attached. Nothing published on day
20729 either; on day 20730 both 20729 and 20730 were published and stamped. Nothing published on day
20732; on day 20733 both 20732 and 20733 were published and stamped, so `last_epoch` is the current UTC
day index again.

**This paragraph has now gone stale twice, which is the argument for not writing the distance down.** It
read "missed twice, and both times the log caught up" for two days after the third miss made it false,
and the correction that replaced it — "the third is open" — was itself false within the hour, because the
day was paid. Nothing edited either sentence; the sequence moved underneath them. So the distance from
`last_epoch` to the current day is not recorded here at all: `sequence_lag` reports it, against a clock,
which is where §2.3 and INV-IFACE-01 put the clock.

**Epoch 20731 was published with the key D-138 moved out of the repository, and that is recorded rather
than quietly corrected.** The cycle for that day was run from a working clone still on a feature branch
from 3 October, which predates the custody fix, so the harness it ran held the old constant. 20731's
published root reproduces exactly from `[0x5a; 32]` and this repository alone — checked, not assumed.
`publish_checkpoint` writes once per epoch, so it stands. The affected range is 20723 through 20731,
and the rotation held from epoch 20732 on. **That is now shown rather than asserted.** 20732 and 20733 were published from a clean checkout of `main` with the master key read from outside the repository, and the harness that built them refuses `[0x5a; 32]` outright, so neither root could have come from the exposed constant. Epochs 20723 through 20731 remain affected and stand as published. `publish_checkpoint` takes `last_epoch + 1` and nothing else, so a skipped day
does not vanish — it stays owed, and every later epoch is published one day late until it is paid
back. Epochs 20726 and 20727 share a Bitcoin block because they were stamped minutes apart and the
calendars aggregated them into the same one.

**There is no worker.** The cycle is run by hand (D-117, [#49](https://github.com/CertiMining/potash/issues/49)), which is why a day can be missed at all.

Full roots, and the transactions that carry them, are in `LIVE-VALUES.txt`, which is checked against the
chain by `scripts/live-values-from-chain.py` after every cycle. That check is manual, because it needs
the network and CI has none: `cargo xtask check-live-values` in the `vectors` group does the static half,
which is that no value in the list reaches a synthetic artifact. The two halves are not
interchangeable, and cycles four and five showed it — both were published, stamped, attached and written
up here, while their receipt digests and attach signatures went unlisted until the script was run again
on 2 Oct 2026. The static gate passed throughout; what was missing was the list's own completeness.

**An earlier version of this paragraph said the static gate passed "because nothing was fabricated", and
that was an overclaim a review refuted (PR #57, round one, High).** Something fabricated was there. At
that head `demo/test/footprint.test.mjs` built a synthetic checkpoint carrying epoch 20723's **real**
publication slot beside a root and a receipt digest invented for the fixture — a live provenance value
lending credibility to data published nowhere, which is precisely the pairing LIVE-VALUES.txt was written
after. Both halves of the gate exited 0, and neither was wrong to: the list accepted only 32-byte hex and
base58, so a decimal slot could not be listed even deliberately, and the chain script never read those two
offsets. The rule was unqualified and its enforcement had a shape-sized hole in it.

What a static pass establishes is therefore narrower than that sentence claimed: no **listed** value
appears in the synthetic surface. And two classes are deliberately unlisted — bumps and epoch day
indices, which substring matching cannot hold without firing on unrelated text. The owner ruled on
4 Oct 2026 that those are review-enforced against a subject test: a short live value may not appear in a
synthetic artifact unless the artifact's subject is the announced deployment, and the use is recorded in
`LIVE-VALUES.txt` by file, value and occurrence, where a reviewer checks it. The earlier wording was
"a synthetic artifact uses a value no live account holds", which was already false when written — the
demo is about epoch 20723 and V-P-12 carries the live bumps 250 and 255 because the deployment is its
subject — so a reviewer had no predicate that admitted those and rejected what the rule is for. `LIVE-VALUES.txt` carries the reasoning and H-20 removes the need for it. It says nothing about live values the list does not hold. Three things
changed rather than the claim being softened — `published_slot` and `published_unix` are listed for every
epoch, `cargo xtask check-live-values` accepts decimals of six digits or more, and the chain script reads
and compares both fields. Epoch numbers are still absent on purpose: a UTC day index is a date rather than
something the deployment produced, and the demo is legitimately about epoch 20723.

Every **attached** receipt — epochs 20723 to 20733, which is all of them — is committed and every one is
the upgraded form, so `ots verify` reaches a Bitcoin block header rather than a calendar's promise.

**This sentence has been wrong in both directions, and that is a fact about hand-kept records rather
than about this one.** It once said "every receipt" without qualification, which overstated (PR #57,
round one, Low). The correction named epochs 20723 to 20727 and said 20728's was neither committed nor
attached — true that day, and false four cycles later, by which time 20728 through 20731 were both.
Nothing edited it; the cycles advanced. The table below is the part a reader can check without trusting
either sentence, because each digest recomputes from the committed bytes. Each attached digest is `Keccak256(TAG_RCPT ‖ len ‖ receipt)`
over exactly the committed bytes, so a reader recomputes it from the file rather than taking this
document's word:

| Epoch | Receipt | Bytes | sha256 of the file | Digest attached on chain |
|---|---|---|---|---|
| 20723 | `anchors/epochs/20723.ots` | 1,459 | `5ed1e32037c11847f81566927c33a36824ec22e569cc3a1092bc64524b302c08` | `0xb0191834ee402a4f4e961a7f3974865b2c6f8c184835e18706e0974515a1cdf7` |
| 20724 | `anchors/epochs/20724.ots` | 1,669 | `74475915f67faf91881fe078d94b3dcf915625497f92ceec54a010c6e1b8a515` | `0x5b6f5fd971c3bc05e2164c35bf357dbbe73595b5f326a579739d4c0f16e89cf8` |
| 20725 | `anchors/epochs/20725.ots` | 3,778 | `4a78864f0e51da9d34c9085ecf01b7290da758ba2ba8ed77b7a68f83f80ad213` | `0x5046e0f027962a041ccb254a1d8c1b76dc4019d1b5b242c06fe68a5b0fc6c28b` |
| 20726 | `anchors/epochs/20726.ots` | 1,458 | `5cbca5f7d16c89c70b4e36e5b7c39e809549873a83705eac3f30459410141466` | `0x8dbc93f4e4d1f6c257bc1d43813cc33234e5f2c4fda12f427509230d4e148f6a` |
| 20727 | `anchors/epochs/20727.ots` | 1,423 | `569245ff5acaaf5042c42c83b9437452aaaf5ef470c3260f45cfa37d9a0b1988` | `0x600a93158741542f04aee04a01d5174f225f3d87cecfd8e8bea33cdc488a9917` |
| 20728 | `anchors/epochs/20728.ots` | 3,841 | `1acd43ec499e75f4a50da8f97d34d423281e87e1138dd799988773b8e448ae3f` | `0xb62ebab2a0cd166513499ff9cc0c69888f6df8ef3758d4e1fd1cf84f920773c0` |
| 20729 | `anchors/epochs/20729.ots` | 2,599 | `9df34f124391509df8949f2efe359aa253ca721f950ff1fdbde7b27e0dd9436f` | `0x770178b7ca09fa52b0d99aeb6aa82cc36fd3c24f5fa0a5e6051ab432a7ee299c` |
| 20730 | `anchors/epochs/20730.ots` | 2,634 | `ffebe180c51d1b0ababb6d16c069d736a9891bc0c6640af16789689976b1376d` | `0xa4020a0c14087b0316d0bf9ae623c320dd9aa2fa63fe3a307e7d5ede46b23be7` |
| 20731 | `anchors/epochs/20731.ots` | 3,707 | `53347acb6079a911dc9623cde6b6ea4157208015b99eecde93119cb14c38da5e` | `0x59e12c7770ec794367cbc0f069518f900074f523d97b785700069f12f9b7ce16` |
| 20732 | `anchors/epochs/20732.ots` | 3,849 | `149641b35a58472e9205c53b5d2ed5bc1809ff9b8841772751ea2dc7bf45cba8` | `0x6fc016569fd8e8433ed6e53b8d0a8a5463f877833e7990e36d25e66f1c531630` |
| 20733 | `anchors/epochs/20733.ots` | 3,884 | `820f3f8b8f3a89c707e487ef9ccf74d2200a87a1994b4accfe7c57e227464d42` | `0xf9cc11346e1ee774353071c712aa470f314dc6ded91059856be5fd7932f4a2af` |

**The wait is not a constant and the table shows it.** Across five cycles the confirmations landed
anywhere from six blocks to a few hundred after publication, and two epochs stamped minutes apart
shared a block. INV-ANCH-04 budgets that latency rather than bounding it, and five instances are five
instances — not a measured distribution.

Epoch 20724 is the first publication whose epoch number and publication day are the same UTC day,
which is what §1.4's rule and INV-ANCH-01's cadence produce together once a log is running. Epoch
20723 was published inside day 20724, an hour and a half after midnight UTC, because a log's first
publishable epoch is its `start_epoch` and that day had already turned.

The receipt is committed by a person, never by the worker (D-116), so a run that produces one does not
thereby gain write access to the public record.
