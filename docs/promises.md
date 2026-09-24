# The batcher and its promises

The batcher accepts submissions, hands back a signed promise that the leaf will appear in a root
inside two epochs, and seals epochs into trees. The promise is what makes censorship provable rather
than deniable. This file describes what `certimining-log`'s batcher does; TCU-02 §1.6 and §2.3 are
the contract it follows.

## What a promise is

```
SPI = Ed25519_sign( batcher_key,
        Keccak256( TAG_SPI ‖ leaf ‖ submission_id ‖ promised_epoch ‖ max_merge_delay ) )
```

The signature covers the **digest**, not the preimage. That is the one place this differs from a
record's attestation, where the qualified person signs the 161-byte leaf preimage, and getting it the
wrong way round would be invisible until an independent implementation disagreed. A test pins it
against §1.6's field order, and the V-P-10 vector records both the preimage and the digest so a
disagreement localises.

A `SignedPromise` carries six fields and 153 bytes: the leaf, the submission identifier, the promised
epoch, the merge delay, the batcher's public key and the signature (D-68). Nothing else. A privacy
test asserts that neither the master key, nor the epoch key, nor a tenure identifier, nor a
jurisdiction code, nor a payload URI appears anywhere in those bytes.

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

The counter lives in the batcher's snapshot, so a restart continues it rather than reissuing one.
Two submissions under one identifier in an epoch would be refused by the tree with `0x05`.

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

**A rebuttal counts only inside the window.** `promise_kept` requires the proof to verify for the
promise's own leaf and the root to belong to an epoch from `promised_epoch` through
`promised_epoch + max_merge_delay`. A root published later confirms the breach rather than rebutting
it, and returns `0x14`. A proof that does not verify, including a proof of some other leaf, is `0x13`.

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
