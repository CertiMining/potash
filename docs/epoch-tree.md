# The fixed-capacity epoch tree

Every epoch is a complete binary tree of the same height. Real leaves sit in slots chosen by a keyed
pseudorandom function, every remaining slot carries padding, and one root is published whatever the
record count was. An epoch holding one filing and one holding two hundred are identical in leaf
count, proof length and root distribution (INV-TREE-01, INV-TREE-02). This file describes
`certimining-log`; TCU-02 §1.4 and §2.3 are the contract.

Hiding quality comes from the capacity being fixed and always full, not from its being large. The
deployment ships `H = 8`, so `C = 256` slots — roughly 250 filings a day against an industry rate of
one or two (D-02).

## The PRF, and the three things it does

`PRF(k, x) = Keccak256( TAG_PRF ‖ k ‖ len(x) ‖ x )`, in `certimining-core::prf`. The tag sits inside
the construction and never in `x`, and each `x` carries its use code first, so the three uses cannot
collide however their fields line up. `len(x)` is a `u16` little-endian — INV-ENC-04, not Borsh's
`u32` framing (D-59).

| Use | `x` | Preimage |
|---|---|---|
| `0x01` epoch key | the epoch, `u64` little-endian | 51 bytes |
| `0x02` slot seed | the submission identifier, 16 bytes | 59 bytes |
| `0x03` padding | the slot index, `u16` little-endian | 45 bytes |

An input longer than seventeen bytes is refused with `0x0C` rather than hashed, so a fourth use
cannot arrive without a decision. An input with no use code at all is `0x05`.

`k_e = PRF(k_master, 0x01 ‖ e_le)` is derived inside `build` from the epoch the tree already knows,
so no caller can reuse one epoch's key for another (D-63). The epoch key is never published, never
in a disclosure package, never sent to a counterparty. Count-hiding rests on that — a trust
assumption on whoever holds `k_master`, named as one in RES-03.

## Where a real leaf lands

```
slot(i) = first free index from PRF(k_e, 0x02 ‖ submission_id) mod C, probing upward
```

Four rules make that reproducible (D-60):

- **The reduction.** The seed is read little-endian, as INV-ENC-02 requires of every integer here,
  and reduced modulo `C` — the low `H` bits, since `C` is a power of two. Read big-endian, an
  implementation builds a different tree from the same inputs, which is why the rule is written down.
- **The order.** Submissions are assigned in ascending order of identifier, so one set gives one
  tree whatever order the caller supplies. Without it, the batcher and E-11's TypeScript verifier can
  differ by iteration order alone; V-P-08 compares the two byte for byte.
- **The probe.** One slot upward at a time, wrapping at `C`, taking the first free slot.
- **The refusals.** More real submissions than `C` is `0x12`; queueing the excess is the batcher's
  (INV-TREE-04, E-07). Two submissions under one identifier is `0x05` — the set is malformed and a
  proof could be answered for neither. A height outside `[4, 16]` is `0x05`, as at `initialize`.

## The two kinds of leaf, and the nodes

```
real leaf     = Keccak256( TAG_MTL0 ‖ leafₙ )
padding leaf  = Keccak256( TAG_PAD  ‖ PRF(k_e, 0x03 ‖ slot_index_le) )
internal node = Keccak256( TAG_MTN1 ‖ left ‖ right )
```

A padding leaf commits to the PRF output rather than carrying it, so nothing on the tree is a
preimage of anything. Both forms are 32 bytes of Keccak output under their own tag, and without
`k_e` neither is distinguishable from the other — measured rather than asserted, in the privacy
tests below.

`BuiltEpoch` carries the epoch, height, root, every slot's leaf digest and the assignment proof
generation needs. Nothing marks a slot real or padding, because that is what V-Z-02 tries to recover
(D-62). Internal nodes are held privately so a proof costs `H` lookups rather than a rebuild: 65,535
digests at `H = 16`, about four megabytes with the leaves — a host-side cost the batcher pays and the
verifier never does.

## Proofs

A proof carries the height it was built at, one sibling per level from the leaf upward, the slot
whose bits are the path, and the epoch its root belongs to. Nothing else, and in particular no
preimage. Proof length is exactly `H`, whatever the record count.

```rust
ProofVerifier::verify::<NativeKeccak>(&chain_leaf, &proof, &root)?;
ProofVerifier::verify_for_height::<NativeKeccak>(&chain_leaf, &proof, &root, 8)?;
```

`verify` takes the **chain leaf** `leafₙ` and applies `TAG_MTL0` itself, so no caller can omit the
tag. It checks what a proof can be checked for alone: a height §1.8 allows, one sibling per level, a
slot addressing a leaf at that height, and the root recomputed from the leaf. Bit 0 of the slot
decides the first level; a clear bit means the leaf is the left child.

The configured height is a second input rather than a proof field, so a caller holding its log's `H`
uses `verify_for_height`: a proof claiming another height is `0x13` before any hashing (V-N-16b).
Both functions are pure — no log handle, no clock, no storage — so a counterparty verifies offline
against a root they fetched themselves (INV-IFACE-01).

Every failure on the verification path is `0x13`. Asking an epoch for a proof of a submission it does
not hold takes its own code, `0x16`: nothing failed to verify (D-67).

The proof's `epoch` field tells a caller which root to fetch. `verify` cannot check it — the root it
is given is all it has to check against, the price of purity — so a proof presented against the wrong
epoch's root fails on the root instead (V-N-17).

## What the privacy tests measure

`crates/certimining-log/tests/privacy.rs` holds §4.4's three blockers. They were written before the
tree they measure, with pass conditions fixed before any of its numbers were visible (D-65, D-66).
Every input is deterministic, so a failure is a finding rather than an unlucky draw.

- **V-Z-02, padding indistinguishability.** A classifier is given an epoch's root and all `C` leaf
  digests in slot order, and no key. It scores nine features — per-position byte deviation,
  population count, zero bytes, leading zero bits, longest equal run, distinct byte values, a
  chi-squared statistic over nibbles, Hamming distance to the adjacent slots, and Hamming distance
  to the root — each alone and combined, and every one must stay inside a two-sided binomial band at
  α = 0.001. The statistic is a distinguishing game, not raw accuracy: each trial presents one real
  leaf and one padding leaf and the classifier names the real one. Raw accuracy would be worthless,
  since answering "padding" every time scores 255 of 256 on an epoch holding one record. What this
  bounds is [a named battery, not every distinguisher](#what-lives-elsewhere).
- **V-Z-03, proof non-leakage.** Nothing a proof carries may be a preimage: every sibling is checked
  against every chain leaf and every PRF output of its epoch. Then the classifier runs over the
  siblings a counterparty collects, which is the only thing about a sibling there is to recover. No
  field of a proof may vary with the record count either, and `slot_index` is the field that could, so
  every slot is compared against D-60's assignment transcribed independently in the test. **The
  comparison runs over a stated, finite matrix, not over every possible epoch:** V-Z-03 at 1, 128 and
  255 real leaves under the real hasher, and the tree's conformance test at every count from empty to
  full at `H = 4` and `H = 8` under the stand-in hasher, which is the same assignment code. A
  mutation firing only at a count neither visits would pass.
- **V-Z-04, position non-leakage.** The slot index is correlated against submission order, issuer and
  time within epoch, using sequential submission identifiers, which is the hard case: the identifier
  itself carries the order. The absolute correlation must stay below 0.05 at CI's sample size.

The full 10,000-epoch V-Z-04 run is a release gate, not a CI step (D-66): about two seconds in
release, two and a half minutes in the debug build CI runs. Ignored by default, run with:

```
cargo test --release -p certimining-log -- --ignored
```

Its numbers are recorded on issue #16 before submission, and the bound there is 0.02.

## What two epochs show that one does not (H-01)

V-Z-02 judges every epoch alone, because D-66 fixed its classifier before the tree existed. Looking
across epochs finds one thing it cannot, and the finding is a property of the construction rather
than a weakness in it.

**Padding is bound to its epoch.** `k_e = PRF(k_master, 0x01 ‖ e_le)`, so slot `s` holds a different
padding leaf in every epoch and no adversary can precompute a table of padding values. That is
checked rather than assumed: every padding leaf of 64 epochs is collected and a repeat fails.

**A real leaf is not bound to its epoch.** `Keccak256(TAG_MTL0 ‖ leafₙ)` carries no epoch at all. So
the same submission built into two epochs produces the identical digest, and only its slot moves —
the slot is keyed by `k_e` and the leaf is not.

**That asymmetry is a distinguisher, with no key and no statistics.** An observer holding two epochs
that share a submission finds it by intersecting the leaf sets: exactly one digest is in both, and it
is the real one. The test runs that intersection rather than describing it.

It needs a submission to appear in two epochs, which the batcher does not do — §1.6 assigns each
submission one promised epoch and `seal` moves the queue forward. So this is what the construction
permits, not what the deployment exposes. It is recorded here because the difference between those
two is exactly what a reader of a privacy claim needs, and because a change that made padding
epoch-independent would silently remove the first property while leaving every existing test green.

A classifier given one slot across many epochs, scoring each leaf's distance from that slot's own
mean, stays inside the same two-sided band at α = 0.001 as V-Z-02's. Looking across epochs finds no
statistical tell; it finds the exact one above.

**And an occupancy estimator stays inside it too, which is the question added in v0.2.10 (H-01).**
Everything above asks whether a leaf is real. The count is a separate question with a separate answer:
an observer who can estimate how many records an epoch holds has broken count-hiding whether or not
any leaf is ever named, and an estimator aggregating over all `C` slots has power a two-leaf game does
not. Two epochs of different occupancy are presented and the adversary names the one holding more real
leaves, scoring each slot by how well its leaf fits the family its own slot forms across 32 epochs it
was told nothing about. Chance is one half and the same band applies. D-66 records what the probes
showed, including that none of them was caught by this adversary and missed by the rest of the suite.

## What lives elsewhere

- **The batcher and its promises are E-07's.** `build` refuses a set larger than `C`; queueing the
  excess within §1.6's merge delay belongs to the batcher.
- **The checkpoint is E-08's.** Nothing here writes to Solana.
- **The independent verifier is E-11's**, written from TCU-02 alone and never from this source. The
  committed vectors under `vectors/` are what the two implementations check themselves against.
- **Count-hiding is not anonymity, and it is computational.** The tree hides how many records an
  epoch held from an adversary who cannot recover `k_e`. It does not hide that an epoch was
  published; it hides nothing from whoever holds `k_master` (RES-03); and an adversary who could
  search the key space would recompute every padding leaf and count exactly (RES-09). V-Z-02 bounds
  a named battery of statistics — evidence of no obvious tell, not proof that no distinguisher
  exists.
