# TCU-02 — CertiMining Anchored Log (Plan C)

**Version 0.1.2 · Supersedes TCU-01 in full · Target: Colosseum Crypto World's Fair, submissions due 12 Oct 2026**
**Program:** `certimining_checkpoint` (Solana / Anchor) · **Engine:** `certimining-core` + `certimining-log` (runtime-agnostic)

---

## §0 Scope, non-goals, and what this can and cannot carry

**Shape.** An off-chain append-only log of mineral estimate records, one chain per asset, batched into fixed-capacity Merkle epochs and anchored at a constant rate to Solana (anchor A) and OpenTimestamps (anchor B). Counterparties receive records and inclusion proofs out of band, under whatever NDA already governs the data room. The chain carries 32-byte roots and nothing else.

**TCU-01 is withdrawn.** It put typed records on-chain — categories, effective dates, QP keys, pledge relationships — which publishes the timing of material change identification at an identified asset. That is incompatible with the selective disclosure regime it claims to serve and unsellable into a sector that treats confidentiality as existential. Nothing from TCU-01's on-chain surface survives; its off-chain state machine (§1.4 there) survives unchanged and is reused here.

**What this asserts.** That a record existed, unaltered, in a stated position of a stated asset's chain, at a time bounded by a Solana slot and a Bitcoin block.

**What this does not assert.** NI 43-101 compliance, the accuracy of the estimate, the honesty of the assayer, the existence of the mineralization, or that the log is complete.

**What this architecturally cannot carry — asset equivocation.** An issuer can maintain two divergent chains for the same physical asset, submit both, and present chain 1 to lender A and chain 2 to lender B. Both inclusion proofs verify against the same root. Neither lender detects it.

This is worth stating precisely, because it is narrower than log equivocation and the two are routinely conflated. Log equivocation — showing different verifiers different logs — is *eliminated* here: the root is on a public chain, so every verifier reads the same root. What remains is that the binding from *physical asset* to *chain* is unverifiable without a shared, jointly observable asset identifier, and providing one is exactly what the confidentiality requirement forbids. Detection of a collision between two parties has an irreducible observability cost; you can hide what the asset is, you cannot hide that a collision occurred.

**Consequence for claims.** This TCU carries tamper-evidence, ordering, and timestamp assurance. It does **not** carry a fraud-prevention or double-pledge claim, and no README, pitch, or submission copy may imply one. That restriction is a merge gate (§4.6), not editorial preference.

**Non-goals.** No on-chain record data. No token, transfer gate, or collateral hook. No key destruction path. No threshold custody (demonstrated separately at ETHGlobal NY). No selective-disclosure proof system — disclosure is a decision the issuer makes out of band, not a cryptographic operation.

**Forward compatibility.** §2.6 reserves hook points for a later extension module (TCU-03), unspecified here. Nothing in TCU-02 depends on it and nothing in TCU-02 is redesigned by it.

---

## §1 Mathematical / specification invariants

### 1.1 Primitives

| Use | Primitive |
|---|---|
| Record leaf, head chain, Merkle nodes | Keccak-256 (`sol_keccak256` on-chain; native keccak off-chain) |
| Padding leaves, slot permutation | KMAC-style PRF: `PRF(k, x) = Keccak256(TAG_PRF ‖ k ‖ len(x) ‖ x)`. The tag lives **inside** the PRF construction and is never repeated in `x`; the three PRF uses are separated by a leading use code in `x`: `0x01` epoch-key derivation, `0x02` slot assignment, `0x03` padding. |
| QP attestation, batcher inclusion promises | Ed25519 (RFC 8032), verified off-chain by the verifier |
| Anchor B | OpenTimestamps over the epoch root |

**INV-PRIM-01.** One hash family across the system. No Poseidon, no BLS12-381, no SHA-256. Poseidon's circuit-friendliness buys nothing without a proof system, and there is none here. Any copy claiming otherwise is wrong and blocks submission.

**INV-PRIM-02.** Ed25519 verification happens in the verifier, not in the Solana program. The program performs no signature checks beyond the checkpoint authority's transaction signature.

### 1.2 Domain separation and encoding

```
TAG_ASSET = b"CMv1ASST"   TAG_LEAF = b"CMv1LEAF"   TAG_HEAD = b"CMv1HEAD"
TAG_MTL0  = b"CMv1MTL0"   TAG_MTN1 = b"CMv1MTN1"   TAG_PAD  = b"CMv1PADD"
TAG_CKPT  = b"CMv1CKPT"   TAG_PRF  = b"CMv1PRF0"   TAG_SPI  = b"CMv1SPI0"
```

**INV-ENC-01.** Every preimage carries exactly one domain tag, first.
**INV-ENC-02.** Integers little-endian, fixed width, Borsh. Digests carried as raw `[u8;32]`.
**INV-ENC-03.** QP and batcher signatures are over Borsh canonical bytes. JSON is display only; a verifier that trusts JSON fields without recomputing from the Borsh preimage is non-conforming.
**INV-ENC-04.** Variable-length fields are `u16` length-prefixed inside preimages.

### 1.3 Asset chain (off-chain, unchanged from TCU-01 §1.4)

```
c      = Keccak256( TAG_ASSET ‖ J ‖ R ‖ len(T) ‖ T )          // local identifier only
h₀     = Keccak256( TAG_HEAD ‖ c ‖ schema_version )
leafₙ₊₁= Keccak256( TAG_LEAF ‖ c ‖ (n+1) ‖ payload_digest ‖ assessment_digest
                  ‖ qp_key ‖ category ‖ effective_at ‖ change_identified_at )
hₙ₊₁   = Keccak256( TAG_HEAD ‖ hₙ ‖ leafₙ₊₁ )
```

Transition `S_{n+1} = f(S_n, R_{n+1})` is defined iff:

```
(a) prev_head = hₙ                          else 0x03
(b) seq = n+1                               else 0x04
(c) ed25519_verify(qp_key, leafₙ₊₁, σ)      else 0x07
(d) effective_at ≥ last_effective_at        else 0x0A
(e) category_sequence_ok(kₙ, category)      → sets flag bit 0; never rejects
(f) payload_uri well-formed, ≤128           else 0x05
```

**INV-STATE-01.** Append-only. No operation decrements `seq`, rewrites `head`, or removes a record. The engine exposes no delete, no compaction, no rewrite-on-correction.
**INV-STATE-02.** For `m < n`, `hₙ` is recomputable from `h_m` and leaves `m+1..n`. Insertion, deletion or reordering is detectable by any holder of a later head.
**INV-STATE-03.** `c` never appears on-chain, in a Merkle path, or in any artifact leaving the issuer's control except inside a disclosure package the issuer has chosen to release.
**INV-STATE-04.** Effective dates non-decreasing.
**INV-STATE-05.** `change_identified_at` and `assessment_digest` are mandatory-present, optional-valued. A submitter with no materiality memo writes zeros, so absence is recorded rather than omitted and is as auditable as presence.
**INV-STATE-06 (record and flag, never reject).** CIM categories: `0=Inferred, 1=Indicated, 2=Measured` (Resources); `3=Probable, 4=Proven` (Reserves). When a record carries a reserve category and no earlier record in the same chain carries category ∈ {1,2}, the engine **accepts the record and sets flag bit 0** (`RESERVE_WITHOUT_PRIOR_RESOURCE`). It never rejects on category sequence.

Rationale: the professional standard governing resource-to-reserve conversion runs through an economic study this chain does not model, and real files legitimately contain acquired assets, carried-forward historical estimates, and out-of-order filings. Enforcement would reject valid work; flagging preserves the signal and leaves the judgment with the reader. See decision **D-01** (Appendix B).

**INV-STATE-06a (flags are observations, not verdicts).** Flag bits are computed deterministically from chain state, are part of the record account but **excluded from the leaf preimage**, and carry no normative weight. A flag says what the engine noticed, never that a filing is improper. Client copy must render flags as observations; wording that implies non-compliance is a merge blocker (§4.6).

Schema 1 flag bits: `bit 0 = RESERVE_WITHOUT_PRIOR_RESOURCE`, `bit 1 = CATEGORY_DOWNGRADE`, `bits 2–15 reserved (zero)`.
**INV-STATE-07.** All arithmetic checked; overflow returns `0x10`.

### 1.4 Epoch tree — fixed capacity, count-hiding

Epoch `e` = UTC day index. The tree has a **fixed height `H`, chosen once at `initialize` and immutable thereafter**. Default for this deployment: **`H = 8`, capacity `C = 256` slots**. Whatever `H` is, every epoch uses it, every epoch, forever.

Hiding quality comes from the capacity being fixed and always full, not from it being large. `C = 256` absorbs roughly 250 filings a day against a realistic industry rate of one or two, so overflow is not a practical concern, and it is four times cheaper to build than `C = 1024`. See decision **D-02** (Appendix B) for the revision triggers.

```
slot(i)        = first free index from PRF(k_e, 0x02 ‖ submission_id) mod C, linear probe
real leaf      = Keccak256( TAG_MTL0 ‖ leafₙ )
padding leaf   = Keccak256( TAG_PAD  ‖ PRF(k_e, 0x03 ‖ slot_index_le) )
internal node  = Keccak256( TAG_MTN1 ‖ left ‖ right )
epoch root     = root of the complete binary tree over all C slots
```

**INV-TREE-01 (fixed shape).** Every epoch tree has exactly `C` leaves and height `H`. Proof length is constant at `H` siblings. Nothing about the tree's shape, proof length, or root varies with the number of real records.

**INV-TREE-02 (padding indistinguishability).** Padding leaves are PRF outputs under the epoch key `k_e`. Without `k_e` they are computationally indistinguishable from real leaf digests. A verifier holding a valid inclusion proof learns the position of one leaf and nothing about any sibling's nature.

**INV-TREE-03 (position carries no meaning).** Slot assignment is pseudorandom under `k_e`. Position does not encode issuer, asset, time within epoch, or submission order.

**INV-TREE-04 (overflow discipline).** If real submissions exceed `C` in an epoch, the excess spills to the next epoch within the merge delay of §1.6. The program never publishes a variable number of roots per epoch, because root count is a volume signal. If overflow becomes routine, `H` is raised by a versioned schema change — never by publishing a second root.

**INV-TREE-06 (height is immutable per log).** `H` is written at `initialize` and no instruction changes it. Changing capacity mid-life would make one epoch's shape differ from another's, which is itself a volume signal. A capacity change requires a new log under a new schema version; records under the old log remain verifiable forever.

**INV-TREE-05 (epoch key handling).** `k_e = PRF(k_master, 0x01 ‖ e_le)`. `k_e` is never published, never included in a disclosure package, and never transmitted to a counterparty. Count-hiding rests on this; it is a trust assumption on the batcher and is named as such (RES-03).

### 1.5 Constant-rate anchoring

**Terminology.** The *publication time* of an epoch is the scheduled moment at which its `publish_checkpoint` transaction is submitted. It is never called a slot, because *slot* already has two meanings in this document: a Solana slot, as in `published_slot`, and a position in the epoch tree, as in `slot_index`.

**INV-ANCH-01 (constant rate).** A checkpoint is published every epoch unconditionally, including epochs with zero real submissions. An empty epoch and a full epoch produce identical on-chain footprints: same instruction, same account size, same transaction byte length, same cadence. Every byte that differs from one checkpoint to the next is fixed by the epoch number, the publication schedule or a pseudorandom digest, never by how many records the epoch held. Publication time does not depend on how long an epoch took to build, and no epoch is skipped or delayed because it is empty. Each epoch has a fixed publication time, set by the schedule alone. The batcher starts building the epoch tree early enough that a full tree finishes before that time, and submits `publish_checkpoint` at that time whether the build took 2 ms or 200 ms. The slot the transaction lands in, and so `published_slot` and `published_unix`, may vary with network conditions. That variation must be independent of epoch content: it never tracks the build or the record count.

This is cover traffic applied at Layer 1 rather than Layer 5. It is what removes the "something material just happened at an identified asset" signal that makes public typed registries unusable in this domain, and it is the property most likely to generalize beyond mining.

**INV-ANCH-02 (single authority, monotone epochs).** `publish_checkpoint` accepts `e = last_epoch + 1` only. Gaps and replays are rejected. A gap in the on-chain sequence is itself evidence of batcher failure and must surface in the client.

**INV-ANCH-03 (write-once).** Checkpoint accounts are written once. `attach_anchor_receipt` may transition `receipt_digest` from zero to a value exactly once. No instruction mutates a non-zero field.

**INV-ANCH-04 (anchor B is opaque).** The program stores the OTS receipt digest and never parses the receipt. Bitcoin confirmation latency (hours) sits inside the operational envelope for this event frequency.

**INV-ANCH-05 (honest degradation).** Until anchor B is attached, the client reports `anchorStatus: "single"`; after, `"dual"`. Silent degradation is a merge blocker.

**INV-ANCH-06 (log equivocation eliminated).** Because the root is on a public chain, all verifiers resolve the same root for epoch `e`. The batcher cannot show different logs to different verifiers. Asset equivocation (§0) is a separate and unsolved property.

### 1.6 Inclusion promises and merge delay

On accepting a submission the batcher returns a signed promise:

```
SPI = Ed25519_sign( batcher_key,
        Keccak256( TAG_SPI ‖ leaf ‖ submission_id ‖ promised_epoch ‖ max_merge_delay ) )
```

**INV-SPI-01.** `max_merge_delay = 2` epochs. If `leaf` is absent from the roots of `promised_epoch .. promised_epoch + max_merge_delay`, the SPI is a self-contained, transferable proof of batcher misbehaviour.
**INV-SPI-02.** The batcher cannot issue an SPI it can satisfy two ways: the promise binds the exact leaf digest, so satisfying it requires including that leaf.
**INV-SPI-03.** The log proves what was submitted, not what existed. An issuer who never submits a record leaves no trace of it. No invariant can close this from inside the architecture (RES-05).

### 1.7 Governance

**INV-GOV-01.** A live program upgrade authority makes every invariant conditional on the current deployment. Before submission the authority is set to `None`, or the README states plainly that it is live and why.
**INV-GOV-02.** The checkpoint authority key is a liveness dependency, not an integrity one: it can stall the log or publish garbage roots, and can do neither retroactively nor selectively (INV-ANCH-06).

### 1.8 Hard limits

| Limit | Value |
|---|---|
| Epoch capacity `C` | configurable at `initialize`, `H ∈ [4, 16]`; **deployed default `H = 8`, `C = 256`** |
| Inclusion proof | exactly `H` siblings (256 bytes at default) |
| Record flags | `u16`, schema-1 bits 0–1 used, excluded from leaf preimage |
| `CheckpointAccount` | 106 bytes |
| Instruction data, `publish_checkpoint` | 48 bytes |
| `payload_uri` | ≤128 bytes, scheme ∈ {`ipfs://`,`https://`,`ar://`} |
| Tenure ID post-canonicalization | ≤64 bytes |
| Max merge delay | 2 epochs |
| Compute, `publish_checkpoint` | ≤ 15,000 CU |
| Compute, `attach_anchor_receipt` | ≤ 12,000 CU |

---

## §2 Interface / contract trait definitions

Three crates. `certimining-core` holds digests and the state machine, `no_std`-compatible, zero Solana dependency. `certimining-log` holds the batcher, tree, and verifier. `certimining-checkpoint` is the Anchor program. The core crate must pass identical vectors under a native harness and under the Solana runtime — that is the vendor-neutrality claim made testable rather than asserted.

### 2.1 Error space

```rust
#[repr(u16)]
pub enum RegistryError {
    HeadMismatch             = 0x03,
    SequenceOutOfOrder       = 0x04,
    MalformedPayload         = 0x05,
    AttestationMissing       = 0x06,
    AttestationInvalid       = 0x07,
    AttestationKeyMismatch   = 0x08,
    CategorySequenceUnsupported = 0x09, // RESERVED. Never returned under schema 1 (INV-STATE-06).
    NonMonotonicEffectiveAt  = 0x0A,
    DomainTagMismatch        = 0x0B,
    RecordTooLarge           = 0x0C,
    EpochOutOfOrder          = 0x0D,
    CheckpointAlreadyWritten = 0x0E,
    UnsupportedSchemaVersion = 0x0F,
    ArithmeticOverflow       = 0x10,
    CanonicalizationFailed   = 0x11,
    EpochCapacityExceeded    = 0x12,
    InclusionProofInvalid    = 0x13,
    MergeDelayExceeded       = 0x14,
    ReceiptAlreadyAttached   = 0x15,
}
```

On-chain codes are returned as `6000 + code` (Anchor offset); the client reverses the offset and surfaces raw hex. Codes are stable across versions; new conditions take new codes.

**INV-ERR-01.** No panic, unwrap, expect, unchecked index, or wrapping arithmetic on any path. `#![forbid(unsafe_code)]`, `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::arithmetic_side_effects)]` at every crate root.

### 2.2 Core traits

```rust
pub type Digest = [u8; 32];
pub type Result<T> = core::result::Result<T, RegistryError>;

pub trait Preimage {
    const TAG: [u8; 8];
    fn write_preimage(&self, out: &mut dyn PreimageSink) -> Result<()>;
    fn digest(&self) -> Result<Digest>;
}

pub trait ChainState {
    fn genesis(asset_commitment: &Digest, schema_version: u16) -> Result<Digest>;
    fn leaf(&self, r: &RecordLeafInput) -> Result<Digest>;
    fn apply(&mut self, r: &RecordLeafInput) -> Result<Digest>;
    fn head(&self) -> Digest;
    fn seq(&self) -> u64;
}

pub trait AssetIdentity {
    fn canonicalize(tenure_raw: &str) -> Result<heapless::Vec<u8, 64>>;
    fn commitment(j: &[u8;4], r: &[u8;8], tenure: &[u8]) -> Result<Digest>;
}
```

### 2.3 Log traits

```rust
pub trait EpochTree {
    /// Height is a deployment parameter, not a constant. Default H = 8 (C = 256).
    /// Valid range 4..=16; fixed at `initialize` and immutable thereafter (INV-TREE-06).
    fn height(&self) -> u8;
    fn capacity(&self) -> usize;      // 1usize << height()
    fn build(epoch: u64, height: u8, key: &Digest,
             real: &[(SubmissionId, Digest)]) -> Result<BuiltEpoch>;
    fn root(&self) -> Digest;
    fn proof(&self, id: &SubmissionId) -> Result<InclusionProof>;
}

pub trait InclusionVerifier {
    /// Pure. No network, no clock, no storage.
    fn verify(leaf: &Digest, proof: &InclusionProof, root: &Digest) -> Result<()>;
}

pub trait Batcher {
    fn submit(&mut self, leaf: Digest) -> Result<SignedPromise>;
    fn seal(&mut self, epoch: u64) -> Result<BuiltEpoch>;
    fn overflow_queue_len(&self) -> usize;
}

pub trait AnchorClient {
    fn publish(&self, epoch: u64, root: Digest) -> Result<AnchorRef>;       // Solana
    fn timestamp(&self, root: Digest) -> Result<ReceiptDigest>;             // OTS
    fn status(&self, epoch: u64) -> AnchorStatus;                           // Pending|Single|Dual
}

pub struct InclusionProof {
    pub height: u8,                          // must equal the log's configured H
    pub siblings: heapless::Vec<Digest, 16>, // exactly `height` entries, else 0x13
    pub slot_index: u16,
    pub epoch: u64,
}
```

**INV-IFACE-01.** `InclusionVerifier::verify` is pure and takes no batcher handle. A counterparty must be able to verify offline, given only the record, the proof, and a root they fetched from Solana themselves.

### 2.4 On-chain surface

```rust
#[program]
pub mod certimining_checkpoint {
    pub fn initialize(ctx: Context<Initialize>, authority: Pubkey) -> Result<()>;
    pub fn publish_checkpoint(ctx: Context<Publish>, epoch: u64, root: [u8;32]) -> Result<()>;
    pub fn attach_anchor_receipt(ctx: Context<Attach>, epoch: u64,
                                 receipt_digest: [u8;32], kind: u8) -> Result<()>;
}
```

`initialize` takes `tree_height` (4..=16, default 8) and writes it once. No instruction changes it afterwards (INV-TREE-06).

**There is no other instruction, and none may be added.** No update, close, revoke, shred, or set-state. A pull request introducing one is rejected regardless of its guard conditions.

```
LogConfig (PDA ["cm_cfg"])            offset  len        CheckpointAccount (PDA ["cm_ckpt", epoch_le])
  discriminator                            0    8          discriminator            0    8
  schema_version                           8    2          schema_version           8    2
  authority (Pubkey)                      10   32          epoch                   10    8
  last_epoch                              42    8          root                    18   32
  tree_height                             50    1          published_slot          50    8
  bump                                    51    1          published_unix          58    8
  reserved                                52   16          receipt_digest          66   32
                                        total   68         anchor_kind             98    1
                                                           bump                    99    1
                                                           reserved               100    6
                                                                                 total  106
```

### 2.5 Disclosure package (out of band)

```jsonc
{
  "schema": "certimining/v1/disclosure",
  "record": { "seq": 7, "category": 2, "effective_at": 1760000000,
              "change_identified_at": 1759900000, "payload_digest": "0x…",
              "assessment_digest": "0x…", "qp_key": "0x…", "payload_uri": "ipfs://…",
              "flags": 0 },
  "preimage_borsh": "base64…",
  "chain": { "prev_head": "0x…", "head": "0x…", "genesis": "0x…" },
  "qp_signature": "0x…64B",
  "inclusion": { "epoch": 20361, "height": 8, "slot_index": 113,
                 "siblings": ["0x…", "…exactly `height` entries"] },
  "anchor": { "solana_tx": "…", "solana_slot": 0, "ots_receipt_digest": "0x…" }
}
```

**INV-DISC-01.** The package never contains `c`, the epoch key, sibling preimages, or any other asset's data. `slot_index` is pseudorandom and carries no information (INV-TREE-03).
**INV-DISC-03.** `flags` is advisory and excluded from every digest. A verifier recomputes flags from the chain rather than trusting the supplied value, and a mismatch is reported as a discrepancy, not an invalid record.

**INV-DISC-02.** A conforming verifier recomputes the leaf from `preimage_borsh`, checks the QP signature, walks the chain segment, verifies inclusion against a root it fetched from Solana independently, and fails closed on any disagreement between JSON fields and the Borsh preimage.

### 2.6 Hook points for TCU-03 (extension module — unspecified here)

Reserved, unimplemented, and load-bearing on nothing in this TCU:

- `LogConfig.reserved[0..1]` — module schema flag.
- An extension trait object slot in the batcher, defaulting to a no-op.
- `RecordLeafInput.ext_commitment: Option<Digest>`, always `None` in v0.1 and excluded from the leaf preimage under schema 1.

**INV-FWD-01.** Adding TCU-03 must not change any schema-1 digest. If it would, it becomes schema 2 with its own vectors, and schema-1 records remain verifiable forever.

---

## §3 Execution tasks

Twenty-six days to the deadline. The engine is the submission; the ordering below finishes a shippable entry by E-13 and spends the remainder on demo quality rather than on scope.

**E-01 · Core skeleton (day 1).** `certimining-core`, lint gates, `Digest`/`RegistryError`, keccak behind `feature="native"` and `feature="solana"`.

**E-02 · Canonicalization + commitment (days 1–2).** NFKC → uppercase → filter → bounds. Property test: idempotent, total, never panics on invalid UTF-8.

**E-03 · Preimage writers (days 2–3).** Domain-tagged, length-prefixed writers for asset, leaf, head, checkpoint, padding, SPI. No string formatting anywhere in the path.

**E-04 · State machine (days 3–5).** `ChainState::apply` with all six conditions, checked arithmetic, pure unit tests, no Solana types in scope. Includes flag computation per INV-STATE-06/06a — flags computed, recorded, excluded from the leaf preimage, never a rejection path.

**E-05 · Vector generator (day 5).** `cargo xtask gen-vectors` emitting `vectors/*.json` plus `vectors/MANIFEST.sha256`. Vectors are generated artifacts, never hand-edited.

**E-06 · Fixed-capacity epoch tree (days 6–8).** PRF, slot assignment with linear probing, padding leaves, complete-tree build, proof generation, pure verifier. Height is a runtime parameter (4..=16) with tests at H = 4, 8 and 12; the deployment ships H = 8. The count-hiding property lives here; write its tests before the implementation.

**E-07 · Batcher + SPI (days 8–10).** Submission intake, signed promises, epoch sealing, overflow queue with merge-delay accounting.

**E-08 · Anchor program (days 10–11).** `initialize`, `publish_checkpoint`, `attach_anchor_receipt`. Monotone epochs, write-once fields, error offset mapping. Small surface; budget most of the time for the negative tests.

**E-09 · Solana anchor client (days 11–12).** Publish path, root fetch by epoch, confirmation handling, gap detection surfaced to the client.

**E-10 · OTS worker (days 12–14).** Root → OpenTimestamps → receipt storage → `attach_anchor_receipt`. `anchorStatus` reporting per INV-ANCH-05.

**E-11 · Independent TS verifier (days 14–17).** Deliberately re-implemented from the spec rather than ported — it is the cross-implementation determinism check. Fetches roots from Solana itself, verifies a disclosure package offline, fails closed.

**E-12 · Fuzz + property harness (days 17–19).** Targets per §4.5.

**E-13 · Benchmarks + CU profiling (days 19–20).** Per-commit CU recording, criterion benches. **Submission is shippable from here.**

**E-14 · Demo fixture (days 20–23).** Three scenes: (1) the public view — a column of roots, with a control showing that an epoch containing one record and an epoch containing 255 are identical on-chain in field shape, account size, instruction length and cadence, with every differing byte fixed by the epoch number, the publication schedule or a pseudorandom digest (V-Z-01), and the roots indistinguishable from random without the epoch key; (2) a counterparty verifying a disclosure package offline; (3) a tampered record — one byte flipped — failing verification while the root stands unchanged.

**E-15 · README + scope statement (days 23–24).** §0 verbatim, including what the architecture cannot carry. The asset-equivocation limit is stated in the README, not buried in docs.

**E-16 · Hardening (days 24–26).** Upgrade authority decision, licence headers, `MANIFEST.sha256` verified in CI, repo head OTS-anchored, no fraud-prevention language anywhere in the submission copy.

---

## §4 Acceptance criteria and verification vectors

### 4.1 Known-answer tests

- **KAT-01.** Keccak-256 against published vectors: empty, 1-byte, and the 135/136/137-byte rate-boundary cases. Runs first; a failure aborts the build before anything else executes.
- **KAT-02.** Ed25519 against RFC 8032 §7.1.
- **KAT-03.** Borsh encodings of every params struct against committed byte fixtures.

### 4.2 Positive vectors

| ID | Input | Expected |
|---|---|---|
| V-P-01 | `"bc-tenure 1043-a"` and `"BC_TENURE1043A"` | Identical canonical `T`, identical `c` |
| V-P-02 | Genesis for known `c`, schema 1 | Fixed `h₀` |
| V-P-03 | Chain of 5 records, categories 0→1→2→3→4 | Fixed `h₅` and all intermediate heads |
| V-P-04 | Same leaves recomputed from `h₂` forward | Identical `h₅` (INV-STATE-02) |
| V-P-05 | Epoch tree at H = 8, 1 real leaf, key `k` | Fixed root, 8-sibling proof verifies |
| V-P-06 | Epoch tree at H = 8, 255 real leaves, same key | Fixed root, every proof verifies, proof length still 8 |
| V-P-06b | Same leaf set at H = 4 and H = 12 | Each builds cleanly; proof length tracks `H` exactly |
| V-P-11 | Reserve category with no prior resource record | **Accepted**, flag bit 0 set, leaf digest identical to the unflagged case |
| V-P-07 | Zero-record epoch | Valid root, published, indistinguishable footprint |
| V-P-08 | Rust core vs TS verifier, all of the above | Byte-identical digests and identical accept/reject |
| V-P-09 | Record with zero `assessment_digest` and zero `change_identified_at` | Accepted; absence recorded (INV-STATE-05) |
| V-P-10 | SPI satisfied at `promised_epoch + 2` | Valid; at +3, `0x14` |

Digest values are produced by E-05 and committed with a manifest hash. None are authored by hand and none appear in this document.

### 4.3 Negative vectors — each returns its code, no panic

| ID | Input | Expected |
|---|---|---|
| V-N-01 | `prev_head` arbitrary | `0x03` |
| V-N-02 | `seq` gap and `seq` replay | `0x04` both |
| V-N-03 | `payload_uri` 129 bytes / non-ASCII / unknown scheme | `0x05` each |
| V-N-04 | Missing QP signature | `0x06` |
| V-N-05 | Signature over JSON instead of Borsh preimage | `0x07` |
| V-N-06 | Signature by a key other than `qp_key` | `0x08` |
| V-N-07 | Category 4 with no prior 1 or 2 in chain | **Not an error.** Must accept; `0x09` must never be returned under schema 1 |
| V-N-07b | Category value 5 or 255 | `0x05` |
| V-N-08 | `effective_at` earlier than predecessor | `0x0A` |
| V-N-09 | Wrong domain tag in preimage | `0x0B` |
| V-N-10 | `publish_checkpoint` with `epoch ≠ last+1` | `0x0D` |
| V-N-11 | Second `publish_checkpoint` for same epoch | `0x0E` |
| V-N-12 | Second `attach_anchor_receipt` for same epoch | `0x15` |
| V-N-13 | `schema_version = 2` | `0x0F` |
| V-N-14 | `C + 1` real submissions in one epoch (257 at default) | `0x12`, overflow queued, not dropped |
| V-N-15 | Inclusion proof with one sibling altered | `0x13` |
| V-N-16 | Proof with `H − 1` or `H + 1` siblings | `0x13` |
| V-N-16b | Proof whose `height` field disagrees with the log's configured `H` | `0x13` |
| V-N-22 | `initialize` with `tree_height` = 3 or 17 | `0x05` |
| V-N-17 | Proof verified against the wrong epoch's root | `0x13` |
| V-N-18 | Truncated params buffer, every prefix length | `0x05` or Borsh error, never a panic |
| V-N-19 | Checkpoint written by a non-authority signer | Anchor constraint violation |
| V-N-20 | `seq = u64::MAX` | `0x10` |
| V-N-21 | Tenure ID canonicalizing to empty | `0x11` |

### 4.4 Privacy acceptance tests — these are the ones that matter

| ID | Test | Pass condition |
|---|---|---|
| V-Z-01 | **Count-hiding.** Publish consecutive epochs holding 0, 1, 128 and 255 real leaves at H = 8, in more than one order, with tree-build time varied deliberately. | Instruction length, transaction length, account size and field layout are identical. A byte may differ between two epochs only if the epoch number, the publication schedule or a pseudorandom digest fixes it: in the checkpoint account, `epoch`, `bump`, `published_slot`, `published_unix`, `root` and `receipt_digest`; in the `publish_checkpoint` transaction, the checkpoint address, the recent blockhash, the signature and the `epoch` and `root` arguments. Every other byte is identical across record counts. This list is exhaustive and closed: any other byte that differs is a failure, and adding a byte to the list requires an amendment to this specification, never an edit to the test. `epoch` advances by exactly one per epoch, empty epochs included, and every epoch is submitted at its scheduled time however long its build took. Network delay may move the landing slot, but it must be independent of epoch content: the test measures the correlation of landing delay with record count, and with build time, across many epochs, and fails on any correlation above noise. It bounds no single epoch's delay, because one slow publication proves nothing either way. |
| V-Z-02 | **Padding indistinguishability.** Given a root, all `C` leaf digests, and no epoch key, classify each leaf as real or padding. | No test in the suite may distinguish them; the classifier's accuracy must be statistically indistinguishable from 50%. |
| V-Z-03 | **Proof non-leakage.** Given a valid inclusion proof, recover anything about any sibling. | Siblings are digests only; no preimage is derivable. Asserted structurally by the proof format. |
| V-Z-04 | **Position non-leakage.** Correlate `slot_index` with submission order, issuer, or time within epoch across 10,000 simulated epochs. | No correlation above noise. |
| V-Z-05 | **No asset identifier escapes.** Grep the full on-chain byte history and every disclosure package for `c`, tenure IDs, jurisdiction codes and registry codes. | Zero occurrences on-chain. In the disclosure package, only fields listed in §2.5. |
| V-Z-06 | **Timing non-leakage.** Compare the on-chain timeline of an issuer who submits daily against one who submits twice a year. | Identical checkpoint cadence and footprint. |

**A failure in §4.4 is a release blocker of the same severity as a correctness failure.** These tests encode the reason this architecture exists.

### 4.4a Performance thresholds

Restored in v0.1.1 — these were carried in TCU-01 and lost when TCU-02 was written, while E-13 still cited §4.4 for them.

| Measure | Threshold |
|---|---|
| `publish_checkpoint` compute | ≤ 15,000 CU |
| `attach_anchor_receipt` compute | ≤ 12,000 CU |
| Chain-walk verification, 10,000 records — **hash recomputation only** | < 5 ms, single thread, reference laptop |
| Epoch root build, 256 leaves | < 10 ms |
| Inclusion proof verification | < 1 ms |
| TS verifier, 1,000-record chain, hash recomputation only | < 50 ms |
| Full verification including per-record Ed25519 checks | **measured and reported, no threshold in v0.1** |

The split matters. Signature verification dominates at scale — the 5 ms figure is achievable only for the hash chain, and a 10,000-record chain with a signature check per record is a different order of cost. E-13 measures both and publishes both numbers; a threshold on the signature path is set in v0.2 once there is real data, not guessed now.

CU figures are recorded per commit in CI; a regression past threshold fails the build.

### 4.5 Fuzz and property targets

- **F-01** `fuzz_params_decode` — arbitrary bytes into every decoder. 1,000,000 iterations, zero panics, zero OOM, zero timeouts.
- **F-02** `fuzz_canonicalize` — arbitrary bytes and invalid UTF-8. 1,000,000 iterations; output ≤64 bytes or clean `0x11`.
- **F-03** `fuzz_apply` — arbitrary record sequences. Every iteration asserts: `seq` never decreases, no head value repeats, every accepted transition is recomputable from its inputs.
- **F-04** `fuzz_proof_verify` — arbitrary proof bytes against a fixed root. No accept without a genuine path; no out-of-bounds read reachable.
- **F-05** `fuzz_tree_build` — arbitrary real-leaf sets `0..=C` and arbitrary `height` bytes. Valid heights always produce a complete tree of that height; invalid heights return `0x05`; never panics.
- **P-01** Removing or reordering any leaf in a chain of n changes `hₙ`.
- **P-02** `apply` is deterministic across 10,000 generated cases from arbitrary starting states.
- **P-03** For any two real-leaf counts `a ≠ b`, serialized on-chain artifacts are identical in length and structure (the property form of V-Z-01).
- **P-04** Miri clean on core and log crates; `cargo-deny` clean on all three.

### 4.6 Merge gates

A PR merges only if: KATs pass; committed vectors match; every negative vector returns its documented code without panicking; **every §4.4 privacy test passes**; fuzz targets meet iteration counts in the nightly job; CU thresholds hold; no new on-chain instruction exists; and no artifact in the repo — code, comment, README, or demo copy — claims fraud prevention, double-pledge prevention, or regulatory compliance.

---

## Appendix A — Residuals

- **RES-01 · Asset equivocation is unsolved.** Two chains for one physical asset both verify. Cross-party detection requires a jointly observable identifier, which is what the confidentiality requirement forbids. TCU-03 addresses this at a cost; TCU-02 does not address it at all and must not imply otherwise.
- **RES-02 · Category flags are heuristics, not standards.** Resource-to-reserve conversion runs through a study this chain does not model. Flag bit 0 marks a pattern worth a reader's attention; it does not mark a filing as improper, and the engine never rejects on it. Whether the pattern is even diagnostic is open until a working QP reviews it (D-01).
- **RES-03 · Count-hiding rests on batcher key custody.** Whoever holds `k_master` can distinguish padding from real leaves retrospectively. In a single-issuer deployment the issuer holds it and is hiding only from outsiders, which is the intended threat model but should be stated rather than assumed.
- **RES-04 · The QP key is not credentialed.** Binding a key to a live professional registration is a Layer 6 problem this TCU does not solve.
- **RES-05 · The log proves submission, not existence.** A record never submitted leaves no trace. No construction inside this architecture closes that; only an obligation to submit, external to the system, does.
- **RES-06 · Canonicalization is the real identity attack surface.** Two spellings of one tenure produce two commitments. Published rules and a registry-code namespace narrow it; they do not close it.
- **RES-07 · Batcher liveness.** A stalled batcher stalls the integrity claim for everyone in the batch. Gap detection makes the stall visible; it does not prevent it.
- **RES-08 · The physical-digital boundary.** Sampling fraud, grade misrepresentation at the point of measurement, and sample substitution sit entirely outside what any of this can reach.

---

## Appendix B — Decision log

Decisions taken deliberately, with the conditions that would reopen them. A decision reversed later is normal; a decision reversed without anyone noticing it was ever made is not.

### D-01 · Category sequence is flagged, not enforced

**Date:** 17 Sep 2026 · **Status:** settled for schema 1 · **Affects:** INV-STATE-06, error `0x09`, V-P-11, V-N-07

**Options considered.** (A) Enforce — reject a reserve-category record with no prior resource record. (B) Flag — accept, record an observation, leave judgment to the reader. (C) Drop — store categories as inert data.

**Chosen:** B.

**Why.** Enforcement encodes a professional standard the chain does not actually model. Real files contain acquired assets, carried-forward historical estimates and out-of-order filings, so an enforcement rule that is even slightly wrong rejects legitimate work — and the first QP to hit it concludes the system does not understand their profession. Flagging keeps the useful signal at none of that cost. (C) discards a genuinely informative pattern.

**Reopen if:** a working QP confirms the sequence rule holds without exceptions in Canadian practice; or flag bit 0 fires on a large share of real filings, which would mean the pattern is normal and the flag is noise; or a customer asks for hard rejection as a control, in which case it becomes a deployment policy above the engine, never inside it.

**Cost of the choice.** The demo shows an observation rather than a block, which is less dramatic. Accepted.

### D-02 · Epoch capacity configurable, deployed at 256

**Date:** 17 Sep 2026 · **Status:** settled for this deployment · **Affects:** §1.4, INV-TREE-01/06, §1.8, `EpochTree`, `InclusionProof`, V-P-05/06/06b, V-N-14/16b/22, V-Z-01

**Options considered.** (A) Fixed 1024 (H = 10). (B) Fixed 256 (H = 8). (C) Configurable 4..=16, ship at 256.

**Chosen:** C at H = 8.

**Why.** Hiding quality comes from capacity being fixed and always full, not from being large — 100 filings hidden among 256 identical slots is exactly as invisible as among 1024. Size buys only overflow headroom, and 256 already exceeds any plausible filing rate by two orders of magnitude while costing a quarter of the work per epoch. Configurability makes a future volume change a settings decision instead of a rewrite.

**Reopen if:** any of these hold, raise `H` for a **new** log rather than the existing one (INV-TREE-06 forbids changing it in place):
- Multiple issuers are batched into one log and combined daily volume approaches 25% of `C` (64 filings/day at default).
- Overflow spill occurs in more than one epoch per quarter, since routine spill leaks volume through delay.
- A deployment batches machine-generated records (per-sample or per-assay) rather than per-filing records, which changes the volume model entirely.

**Cost of the choice.** Height becomes a runtime parameter rather than a constant, so proofs carry a height field and the verifier must check it against the log's configuration — one extra failure mode (`V-N-16b`), accepted in exchange for not needing a rewrite later.
