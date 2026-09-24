# The batcher and its promises

The batcher accepts submissions, hands back a signed promise that the leaf will appear in a root
inside two epochs, and seals epochs into trees. The promise is what makes censorship provable rather
than deniable. This file describes what `certimining-log`'s batcher does; TCU-02 §1.6 and §2.3 are
the contract it follows.

## What a promise is

```
SPI = Ed25519_sign( batcher_key,
        Keccak256( TAG_SPI ‖ leaf ‖ submission_id ‖ accepted_epoch
                            ‖ promised_epoch ‖ max_merge_delay ) )
```

The signature covers the **digest**, not the preimage. That is the one place this differs from a
record's attestation, where the qualified person signs the 161-byte leaf preimage, and getting it the
wrong way round would be invisible until an independent implementation disagreed. A test pins it
against §1.6's field order, and the V-P-10 vector records both the preimage and the digest so a
disagreement localises.

A `SignedPromise` carries seven fields: the leaf, the submission identifier, the acceptance epoch, the
promised epoch, the merge delay, the batcher's public key and the signature (D-68, D-74). Nothing else.
`encode` writes them in that order as **161 octets**, which is the transferable artifact; the Rust value
is not it, because a struct carries padding and says nothing about what travels between two parties. A
privacy test asserts that neither the master key, nor the epoch key, nor a tenure identifier, nor a
jurisdiction code, nor a payload URI appears anywhere in those octets.

**A signature proves authorship, not compliance.** `verify_promise` refuses, with `0x17`, a promise
whose `max_merge_delay` is not the 2 INV-SPI-01 fixes, and one whose `promised_epoch` falls outside
`accepted_epoch` through `accepted_epoch + max_merge_delay`. Both are genuine signatures over values the
specification does not allow, and the key holder does not choose the policy its own promise is judged
against.

**The acceptance epoch is what makes that checkable, and it is itself checkable.** The checkpoint
sequence is public, one root per epoch, monotone and gapless, so a reader can place any epoch number
against a published root and a time. A promise claiming acceptance in epoch `e` but satisfied only by a
root published after `e + 2` is visibly backdated: either the acceptance epoch is a lie or the promise
was broken, and the artifact beside the public sequence is enough to say which.

**The key a promise carries is not the authority.** Anyone can sign a promise, so `verify_promise`
takes the batcher key the counterparty expects and compares it first: a key that is not the expected
one is `0x08`, decided before any verification runs, and a signature that does not verify is `0x07`.
The key inside the promise is there so a reader can see which key signed it.

## What the submission identifier discloses

It is an ordinal counter, sixteen bytes little-endian, because §2.3's `submit` takes only a leaf and
the batcher must mint one (D-69). **It reveals the submission's position in the batcher's sequence to
anyone shown the promise**, and it travels only inside the promise: no disclosure package, no
checkpoint, nothing on chain. Position in the epoch tree does not follow from it, because §1.4
assigns slots by a PRF over it under a key the counterparty does not hold, and V-Z-04 measures
exactly that with sequential identifiers.

The counter lives in the batcher's snapshot, and `resume` checks it rather than trusting it, because a
snapshot comes from storage and is therefore input. Identifiers must be unique and all below the
counter, the current epoch no fuller than `C`, and the queue no longer than the merge delay can absorb;
anything else is `0x05`. Two submissions under one identifier would otherwise fail the seal with `0x05`
long after the promise went out.

**What no check here can see is a rollback** to an older snapshot that was consistent when it was
taken, because nothing in the value says which of two snapshots is later. Atomic, rollback-resistant
persistence is a property of how the service stores this, and it belongs to E-09.

## What happens when an epoch is full

The current epoch takes the first `C` submissions. Everything after waits in the overflow queue and
is sealed a whole epoch at a time, so the submission at queue position `k` lands in
`epoch + 1 + k / C`, and that is the epoch its promise names.

**A full epoch never refuses.** A submitter holding no promise has no evidence of having submitted,
which is precisely the censorship the promise exists to make provable, so the promise names the next
epoch the batcher can meet and `overflow_queue_len` reports what is waiting (D-71). §4.3's V-N-14 is
answered by two layers: the tree returns `0x12` when asked to build more than `C` leaves, and the
batcher never asks it to.

`submit` does refuse in one case: when no epoch inside the merge delay can hold the submission at
all, which at `H = 8` means 769 submissions in one epoch. A promise the batcher knows it cannot keep
would manufacture its own accusation three epochs later, so it returns `0x12` instead. The epoch is
decided before the identifier is minted, so a refusal consumes nothing.

## Sealing

```rust
let built = batcher.seal::<NativeKeccak>(epoch)?;
```

`seal` takes the epoch it is asked for and refuses any other with `0x0D`, which is INV-ANCH-02's
discipline one layer early: one epoch at a time, in order. It builds before it moves, so a refused
build leaves the batcher exactly where it was and a failed seal cannot lose a queue. Then it advances
by one and pulls what it can from the overflow queue. An empty epoch seals like any other, because
INV-ANCH-01 skips none.

The batcher holds no clock. The caller owns the calendar: it constructs the batcher at an epoch and
advances it by sealing (D-70). That keeps time out of a crate that builds for bare metal, and keeps
every test's epoch a stated input rather than a reading that changes overnight.

## What an unsatisfied promise actually proves

§1.6 calls it a self-contained, transferable proof of misbehaviour. The precise claim is narrower, and
the specification now says so (D-72).

**Absence cannot be proven from a Merkle root.** A counterparty holding a promise and the three roots
of its window cannot show the leaf is missing; only the batcher can show it is present. So an
unsatisfied promise is transferable in the sense that anyone can check its signature and its binding
and see which epochs it covers, and the conclusion it supports is rebuttable: the batcher answers
with an inclusion proof or it does not, and silence is the evidence.

**A rebuttal counts only inside the window.** `promise_kept` takes a `PublishedRoot`, which carries an
epoch and the root together, requires the proof to be for that same epoch, requires the epoch to fall
from `promised_epoch` through `promised_epoch + max_merge_delay`, and requires the path to verify for
the promise's own leaf. Outside the window in either direction is `0x14`; an inconsistent or failing
proof is `0x13`.

**What it does not do is establish that the root was published.** A Merkle path commits to leaves and
not to the epoch label beside it, so an epoch and a root that never appeared together would pass every
check this function makes. Provenance comes from the checkpoint account E-08 writes and E-09 fetches.
The pair travels in one type so the two halves cannot drift apart inside a call, and that is the whole
of what this crate contributes; the seam is named here rather than implied.

## What lives elsewhere

- **No signer lives in the engine, under any feature.** A signer holds a key, and S6 keeps the
  batcher key outside this repository, so `Signer` is a trait and nothing more. The tests supply
  RFC 8032 §7.1's published key through it; the service at E-09 supplies a real one from outside.
- **Publishing is E-08's and E-09's.** The batcher returns a `BuiltEpoch` and writes nothing to
  Solana. The constant-rate schedule of §1.5, which decides when a checkpoint is submitted, belongs
  to the client rather than to this crate.
- **Gap detection is the client's.** A stalled batcher stalls everyone in the batch, and nothing here
  prevents it (RES-07). What the architecture gives is visibility: a gap in the on-chain epoch
  sequence is evidence of batcher failure, which INV-ANCH-02 requires the client to surface.
