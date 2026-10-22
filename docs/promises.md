# The batcher and its promises

The batcher accepts submissions, hands back a signed promise that the leaf will appear in a root
inside two epochs, and seals epochs into trees. The promise makes censorship **answerable** rather
than deniable: a signed, checkable claim naming the epochs by which a leaf must appear, which the
batcher either meets or leaves unmet in public. It does not make censorship *provable* — see
[what an unsatisfied promise proves](#what-an-unsatisfied-promise-actually-proves).

This file describes `certimining-log`'s batcher; TCU-02 §1.6 and §2.3 are the contract.

## What a promise is

```
SPI = Ed25519_sign( batcher_key,
        Keccak256( TAG_SPI ‖ leaf ‖ submission_id ‖ accepted_epoch
                            ‖ promised_epoch ‖ max_merge_delay ) )
```

The signature covers the **digest**, not the preimage — the one place this differs from a record's
attestation, where the qualified person signs the 161-byte preimage. Reversed, it would stay
invisible until an independent implementation disagreed, so a test pins §1.6's field order and
V-P-10 records both preimage and digest.

A `SignedPromise` carries seven fields and nothing else: leaf, submission identifier, acceptance
epoch, promised epoch, merge delay, batcher public key, signature (D-68, D-74). `encode` writes them
in that order as **161 octets**, which is the transferable artifact — the Rust value is not, since a
struct carries padding and says nothing about what travels between parties. A privacy test asserts
that no master key, epoch key, tenure identifier, jurisdiction code or payload URI appears in those
octets.

**A signature proves authorship, not compliance.** `verify_promise` refuses, with `0x17`, a promise
whose `max_merge_delay` is not the 2 INV-SPI-01 fixes, and one whose `promised_epoch` falls outside
`accepted_epoch` through `accepted_epoch + max_merge_delay`. Both are genuine signatures over values the
specification does not allow, and the key holder does not choose the policy its own promise is judged
against.

**What the acceptance epoch establishes.** The signature binds the batcher's *assertion* of
acceptance; the checkpoint sequence establishes when a root was published, not when a promise was
issued. Acceptance time comes only from the counterparty's own observation, so `verify_promise` takes
it: the signed acceptance epoch must equal the checkpoint epoch seen when the promise arrived, or be
exactly one behind, never ahead. Ahead is the backdating attack — a batcher defers its own
accountability by naming a future epoch and then meeting it. One behind is allowed because a promise
can cross an epoch boundary.

**A promise passed to someone who observed nothing is judged against a timestamp over the promise
itself** (§1.6, v0.2.8). The counterparty that receives it stamps its own 161-octet encoding through
the anchor B path, and the receipt travels with the promise. A later holder runs the same checks
against the UTC day index of the block the receipt names, in place of an observation it never made.
The receipt must timestamp exactly those 161 octets, so a stamp cannot be moved from one promise to
another, and the block must be reachable from a committed checkpoint through headers that each meet
the target their own difficulty bits encode.

What it fixes is an upper bound: a promise cannot have been accepted after the moment it demonstrably
already existed, which is the direction the backdating attack runs in. It fixes no lower bound, and a
claimed acceptance *earlier* than the real one moves the batcher's own deadline earlier, against its
interest.

Two things it does not fix, and both are in §1.6 rather than left here. The epoch a receipt
establishes is a calendar epoch where the counterparty's observation is a sequence epoch, so under
batcher lag this bound is the looser of the two by exactly the lag. And a Bitcoin timestamp is chosen
by a miner within consensus limits and is not monotone, so the day index derived from it can be one
too high at a midnight boundary and, more rarely, one too low.

**The promise and its receipt travel as one artifact.** A disclosure package carries neither. The
receipt covers octets that include the submission identifier, and that identifier reaches no
disclosure package — which is what the next section is about.

**The key a promise carries is not the authority.** Anyone can sign one, so `verify_promise` takes
the batcher key the counterparty expects and compares it first: an unexpected key is `0x08`, decided
before any verification runs; a signature that does not verify is `0x07`. The key inside the promise
only shows which key signed it.

## What the submission identifier discloses

An ordinal counter, sixteen bytes little-endian, because §2.3's `submit` takes only a leaf and the
batcher must mint one (D-69). **It reveals the submission's position in the batcher's sequence to
anyone shown the promise**, and travels only inside the promise: no disclosure package, no
checkpoint, nothing on chain. Position in the epoch tree does not follow from it — §1.4 assigns slots
by a PRF under a key the counterparty does not hold, and V-Z-04 measures that with sequential
identifiers.

A snapshot comes from storage and is therefore input, so `resume` checks the counter rather than
trusting it: identifiers unique and below the counter, the current epoch no fuller than `C`, the
queue no longer than the merge delay can absorb. Anything else is `0x05`, which two submissions under
one identifier would otherwise raise at the seal, long after the promise went out.

**No check here sees a rollback** to an older snapshot that was consistent when taken, because
nothing in the value says which of two is later. Atomic, rollback-resistant persistence belongs to
E-09.

## What happens when an epoch is full

The current epoch takes the first `C` submissions. Everything after waits in the overflow queue and
is sealed a whole epoch at a time, so the submission at queue position `k` lands in
`epoch + 1 + k / C`, and that is the epoch its promise names.

**A full epoch never refuses.** A submitter holding no promise has no evidence of having submitted,
which is the censorship the promise exists to make answerable — so the promise names the next epoch
the batcher can meet, and `overflow_queue_len` reports what waits (D-71). §4.3's V-N-14 is answered
twice over: the tree returns `0x12` when asked for more than `C` leaves, and the batcher never asks.

`submit` refuses in one case: when no epoch inside the merge delay can hold the submission, which at
`H = 8` means 769 in one epoch. A promise the batcher knows it cannot keep would manufacture its own
accusation three epochs later, so it returns `0x12`. The epoch is decided before the identifier is
minted, so a refusal consumes nothing.

## Sealing

```rust
let built = batcher.seal::<NativeKeccak>(epoch)?;
```

`seal` takes the epoch it is asked for and refuses any other with `0x0D` — INV-ANCH-02's discipline
one layer early. It builds before it moves, so a refused build leaves the batcher where it was and a
failed seal cannot lose a queue; then it advances by one and pulls what it can from the overflow
queue. An empty epoch seals like any other, because INV-ANCH-01 skips none.

The batcher holds no clock: the caller constructs it at an epoch and advances it by sealing (D-70).
That keeps time out of a crate that builds for bare metal, and every test's epoch a stated input
rather than a reading that changes overnight.

## What an unsatisfied promise actually proves

§1.6 calls it a self-contained, transferable proof of misbehaviour. The precise claim is narrower,
and the specification says so (D-72).

**Absence cannot be proven from a Merkle root.** A counterparty holding a promise and the three roots
of its window cannot show the leaf is missing; only the batcher can show it is present. An
unsatisfied promise is transferable in that anyone can check its signature, its binding and which
epochs it covers — and the conclusion is rebuttable: the batcher answers with an inclusion proof or
it does not, and silence is the evidence.

**A rebuttal counts only inside the window.** `promise_kept` takes a `PublishedRoot`, which carries an
epoch and the root together, requires the proof to be for that same epoch, requires the epoch to fall
from `promised_epoch` through `promised_epoch + max_merge_delay`, and requires the path to verify for
the promise's own leaf. Outside the window in either direction is `0x14`; an inconsistent or failing
proof is `0x13`.

**It does not establish that the root was published.** A Merkle path commits to leaves, not to the
epoch label beside them, so an epoch and a root that never appeared together would pass every check
this function makes. Provenance comes from the checkpoint account E-08 writes and E-09 fetches; the
pair travels in one type so the halves cannot drift apart inside a call. That is the whole of this
crate's contribution, and the seam is named rather than implied.

## What lives elsewhere

- **No signer lives in the engine, under any feature.** A signer holds a key and S6 keeps the
  batcher key outside this repository, so `Signer` is a trait and nothing more. Tests supply
  RFC 8032 §7.1's published key through it; E-09 supplies a real one from outside.
- **Publishing is E-08's and E-09's.** The batcher returns a `BuiltEpoch` and writes nothing to
  Solana. §1.5's constant-rate schedule belongs to the client.
- **A stall is visible as distance, not as a gap.** A stalled batcher stalls everyone in the batch,
  and nothing here prevents it (RES-07). There is no interior gap to detect: `publish_checkpoint`
  takes only `last_epoch + 1`, so the published range is contiguous by construction, and INV-ANCH-02
  was corrected in v0.2.0 to say so (D-106). A stall shows as the distance from `last_epoch` to the
  current day, which `sequence_lag` reports against a clock.
