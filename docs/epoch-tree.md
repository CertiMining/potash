# The fixed-capacity epoch tree

Every epoch is a complete binary tree of the same height. Real leaves sit in slots chosen by a
keyed pseudorandom function, every remaining slot carries padding, and one root is published
whatever the record count was. An epoch holding one filing and an epoch holding two hundred are
identical in leaf count, proof length and root distribution (INV-TREE-01, INV-TREE-02). This file
describes what `certimining-log` does; TCU-02 §1.4 and §2.3 are the contract it follows.

Hiding quality comes from the capacity being fixed and always full, not from it being large. The
deployment ships `H = 8`, so `C = 256` slots, which absorbs roughly 250 filings a day against an
industry rate of one or two (D-02).

## The PRF, and the three things it does

`PRF(k, x) = Keccak256( TAG_PRF ‖ k ‖ len(x) ‖ x )`, in `certimining-core::prf`. The tag is inside
the construction and never repeated in `x`, and each `x` carries its use code first, so the three
uses cannot collide however their fields line up. `len(x)` is a `u16` little-endian, which is
INV-ENC-04 rather than Borsh's own `u32` framing (D-59).

| Use | `x` | Preimage |
|---|---|---|
| `0x01` epoch key | the epoch, `u64` little-endian | 51 bytes |
| `0x02` slot seed | the submission identifier, 16 bytes | 59 bytes |
| `0x03` padding | the slot index, `u16` little-endian | 45 bytes |

An input longer than seventeen bytes is refused with `0x0C` rather than hashed, so a fourth use
cannot arrive without a decision. An input with no use code at all is `0x05`.

`k_e = PRF(k_master, 0x01 ‖ e_le)` is derived inside `build`, from the epoch the tree already knows,
so no caller can reuse one epoch's key for another (D-63). The epoch key is never published, never
carried in a disclosure package and never sent to a counterparty. Count-hiding rests on that, which
is a trust assumption on whoever holds `k_master` and is named as one in the specification's RES-03.

## Where a real leaf lands

```
slot(i) = first free index from PRF(k_e, 0x02 ‖ submission_id) mod C, probing upward
```

Four rules make that reproducible (D-60):

- **The reduction.** The seed is read as a little-endian integer, as INV-ENC-02 requires of every
  integer here, and reduced modulo `C`. Because `C` is a power of two this is the low `H` bits, which
  lie in the digest's first two bytes. An implementation reading the digest as big-endian builds a
  different tree from the same inputs, which is why the rule is written down.
- **The order.** Submissions are assigned in ascending order of identifier, so one set of
  submissions gives one tree whatever order the caller supplies them in. Without this, the same
  epoch built by the batcher and by the TypeScript verifier of E-11 can differ by iteration order
  alone, and V-P-08 compares the two byte for byte.
- **The probe.** One slot upward at a time, wrapping at `C`, taking the first free slot it meets.
- **The refusals.** More real submissions than `C` is `0x12`, and queueing the excess is the
  batcher's business (INV-TREE-04, E-07). Two submissions under one identifier is `0x05`: the set is
  malformed, and a proof could be answered for neither. A height outside `[4, 16]` is `0x05`, as it
  is at `initialize`.

## The two kinds of leaf, and the nodes

```
real leaf     = Keccak256( TAG_MTL0 ‖ leafₙ )
padding leaf  = Keccak256( TAG_PAD  ‖ PRF(k_e, 0x03 ‖ slot_index_le) )
internal node = Keccak256( TAG_MTN1 ‖ left ‖ right )
```

A padding leaf commits to the PRF output rather than carrying it, so nothing on the tree is a
preimage of anything. Both leaf forms are 32 bytes of Keccak output under their own tag, and without
`k_e` neither is distinguishable from the other. That claim is measured rather than asserted: see
the privacy tests below.

`BuiltEpoch` carries the epoch, the height, the root, every slot's leaf digest and the assignment
that proof generation needs. Nothing in it marks a slot real or padding, because that is exactly what
V-Z-02 tries to recover (D-62). The internal nodes are held privately so a proof costs `H` lookups
rather than a rebuild: 65,535 digests at `H = 16`, which with the leaves beside them is about four
megabytes for one epoch. That is a host-side cost the batcher pays and the verifier never does.

## Proofs

A proof carries the height it was built at, one sibling per level from the leaf upward, the slot
whose bits are the path, and the epoch its root belongs to. Nothing else, and in particular no
preimage. Proof length is exactly `H`, whatever the record count.

```rust
ProofVerifier::verify::<NativeKeccak>(&chain_leaf, &proof, &root)?;
ProofVerifier::verify_for_height::<NativeKeccak>(&chain_leaf, &proof, &root, 8)?;
```

`verify` takes the **chain leaf** `leafₙ` and applies `TAG_MTL0` itself, so no caller can omit the
tag. It checks what a proof can be checked for on its own: a height §1.8 allows, one sibling per
level, a slot that addresses a leaf at that height, and the root recomputed from the leaf. Bit 0 of
the slot decides the first level, and a clear bit means the leaf is the left child.

The configured height is a second input rather than a proof field, so `verify_for_height` is what a
caller holding its log's `H` uses: a proof claiming another height is `0x13` before any hashing
(V-N-16b). Both functions are pure. They take no log handle, read no clock and touch no storage, so
a counterparty verifies offline against a root they fetched from Solana themselves (INV-IFACE-01).

Every failure on the verification path is `0x13`. Asking an epoch for a proof of a submission it does
not hold is a different condition and takes its own code, `0x16`: nothing failed to verify, the
epoch simply does not hold that submission (D-67).

The proof's `epoch` field is what tells a caller which root to fetch. `verify` cannot check it,
because the root it is given is the only thing it has to check against, which is the price of being
pure. A proof presented against the wrong epoch's root fails on the root instead (V-N-17).

## What the privacy tests measure

`crates/certimining-log/tests/privacy.rs` holds §4.4's three blockers. They were written before the
tree they measure, and their pass conditions were fixed before any of its numbers were visible
(D-65, D-66). Every input is deterministic, so a failure is a finding rather than an unlucky draw.

- **V-Z-02, padding indistinguishability.** A classifier is given an epoch's root and all `C` leaf
  digests in slot order and no key. It is computationally bounded, specifically the named battery
  below: an adversary who could search the key space would derive `k_e` and count exactly, so this
  test shows that these statistics do not distinguish, never that none can (RES-09). It scores nine
  features — per-position byte
  deviation, population count, zero bytes, leading zero bits, longest equal run, distinct byte
  values, a chi-squared statistic over nibbles, Hamming distance to the adjacent slots, and Hamming
  distance to the root — each alone and combined. The statistic is a distinguishing game rather than
  raw accuracy: each trial presents one real leaf and one padding leaf and the classifier names the
  real one. Raw accuracy would be worthless here, because an epoch holding one real leaf and 255
  padding leaves scores 255 out of 256 for a classifier that answers "padding" every time and learns
  nothing. Every statistic must stay inside a two-sided binomial band at α = 0.001.
- **V-Z-03, proof non-leakage.** Nothing a proof carries may be a preimage: every sibling is checked
  against every chain leaf and every PRF output of its epoch. Then the classifier runs over the
  siblings a counterparty collects, which is the only thing about a sibling there is to recover. No
  field of a proof may vary with the record count either, and `slot_index` is the field that could, so
  every slot is compared against D-60's assignment transcribed independently in the test. **The
  comparison runs over a stated, finite matrix, not over every possible epoch:** V-Z-03 runs it at 1,
  128 and 255 real leaves under the real hasher, and the tree's own conformance test runs it at every
  count from an empty epoch to a full one at `H = 4` and `H = 8` under the stand-in hasher, which is
  the same assignment code. A mutation that fired only at a count neither visits would pass, which is
  how the third review falsified an earlier and looser claim here.
- **V-Z-04, position non-leakage.** The slot index is correlated against submission order, issuer and
  time within epoch, using sequential submission identifiers, which is the hard case: the identifier
  itself carries the order. The absolute correlation must stay below 0.05 at CI's sample size.

The full 10,000-epoch run of V-Z-04 is a release gate rather than a CI step (D-66). It takes about
two seconds in a release build and two and a half minutes in the debug build CI runs, which is why it
is ignored by default and run like this:

```
cargo test --release -p certimining-log -- --ignored
```

Its numbers are recorded on issue #16 before submission, and the bound there is 0.02.

## What lives elsewhere

- **The batcher and its promises are E-07's.** `build` takes the submissions it is given and refuses
  a set larger than `C`; queueing the excess within the merge delay of §1.6 belongs to the batcher.
- **The checkpoint is E-08's.** Nothing here writes to Solana, and the tree publishes no root by
  itself.
- **The independent verifier is E-11's**, written from TCU-02 alone and never from this source. The
  committed vectors under `vectors/` are what the two implementations check themselves against.
- **Count-hiding is not anonymity, and it is computational.** The tree hides how many records an
  epoch held from an adversary who cannot recover `k_e`. It does not hide that an epoch was
  published, it hides nothing from whoever holds `k_master` (RES-03), and it is not an
  information-theoretic property: an adversary who could search the key space would recompute every
  padding leaf and count exactly (RES-09). V-Z-02 bounds a named battery of statistics, which is
  evidence of no obvious tell rather than proof that no distinguisher exists.
