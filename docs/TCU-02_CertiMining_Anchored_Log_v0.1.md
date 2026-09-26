# TCU-02 — CertiMining Anchored Log (Plan C)

**Version 0.1.14 plus unmerged amendments on this branch · Supersedes TCU-01 in full · Target: Colosseum Crypto World's Fair, submissions due 12 Oct 2026**
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
| Padding leaves, slot permutation | KMAC-style PRF: `PRF(k, x) = Keccak256(TAG_PRF ‖ k ‖ len(x) ‖ x)`. The tag lives **inside** the PRF construction and is never repeated in `x`; the three PRF uses are separated by a leading use code in `x`: `0x01` epoch-key derivation, `0x02` slot assignment, `0x03` padding. `len(x)` is a `u16` little-endian, as INV-ENC-04 requires of every length prefix here, and `k` is 32 bytes. Each `x` carries its use code first and then one field: the epoch as a `u64` little-endian under `0x01`, the submission identifier's sixteen bytes under `0x02`, and the slot index as a `u16` little-endian under `0x03`. So `x` is 9, 17 and 3 bytes, and the three preimages are 51, 59 and 45 bytes (D-59). |
| QP attestation, batcher inclusion promises | Ed25519 (RFC 8032), verified off-chain by the verifier |
| Anchor B | OpenTimestamps over the epoch root |

**INV-PRIM-01 (scoped on this branch, unmerged).** One hash family for **every digest this system computes and commits to**: Keccak-256, for records, heads, nodes, PRF outputs, promises, roots and the anchor-B receipt digest. No Poseidon, no BLS12-381, no SHA-256 in any of them. Poseidon's circuit-friendliness buys nothing without a proof system, and there is none here. **Any copy claiming otherwise, about one of this system's own constructions, is wrong and blocks submission.**

**Digests produced by external systems this design anchors to or runs on are consumed in their native format and are never mixed into a preimage of ours.** There are exactly two, and they are named rather than left as a general licence:

- **OpenTimestamps receipts** commit to `SHA-256` of the bytes that were stamped, because that is the OTS format. The worker stamps the 32 root bytes; the receipt's own start digest is therefore SHA-256, and what this system computes over the receipt is `receipt_digest`, which is Keccak-256 (§2.4, D-113).
- **Solana address and account-discriminator derivation** is `SHA-256` by construction, so no verifier can derive a checkpoint address or recognise an account without it (§2.4, D-91).

**Why this was amended.** Before this branch the invariant forbade SHA-256 outright and said a copy claiming otherwise blocks submission, while two constructions the architecture cannot avoid require it. E-11's independent implementation found the first from the address side and E-10 met the second from the receipt side (D-102, D-119). The invariant was written to stop mixed hash families inside the chain, the tree and the preimages, and it still does exactly that; it was never meant to reach an external anchor's format or a runtime's addressing, and as written it forbade both.

**INV-PRIM-02.** Ed25519 verification happens in the verifier, not in the Solana program. The program performs no signature checks beyond the checkpoint authority's transaction signature.

### 1.2 Domain separation and encoding

```
TAG_ASSET = b"CMv1ASST"   TAG_LEAF = b"CMv1LEAF"   TAG_HEAD = b"CMv1HEAD"
TAG_MTL0  = b"CMv1MTL0"   TAG_MTN1 = b"CMv1MTN1"   TAG_PAD  = b"CMv1PADD"
TAG_CKPT  = b"CMv1CKPT"   TAG_PRF  = b"CMv1PRF0"   TAG_SPI  = b"CMv1SPI0"
TAG_RCPT  = b"CMv1RCPT"
```

`TAG_RCPT` is anchor B's receipt digest (§2.4, D-113), added on this branch, unmerged. **`TAG_CKPT` is declared and consumed by nothing**, which E-11's independent implementation recorded as a defect by the same reasoning D-80 applies to unreachable error codes. It stays declared, and whether it gains a checkpoint preimage or is retired is filed for after the deadline; it was deliberately not spent on the receipt digest, because reusing a reserved tag for the first thing that needs one is how a tag stops meaning anything.

**INV-ENC-01.** Every preimage carries exactly one domain tag, first.
**INV-ENC-02.** Integers little-endian, fixed width, Borsh. Digests carried as raw `[u8;32]`.
**INV-ENC-03.** QP and batcher signatures are over Borsh canonical bytes. JSON is display only; a verifier that trusts JSON fields without recomputing from the Borsh preimage is non-conforming.
**INV-ENC-04.** Variable-length fields are `u16` length-prefixed inside preimages. Where this differs from Borsh's own framing, which prefixes a byte string with a `u32`, this rule governs; fixed-width integers and fixed-size arrays are encoded exactly as Borsh encodes them.

### 1.3 Asset chain (off-chain, unchanged from TCU-01 §1.4)

```
c      = Keccak256( TAG_ASSET ‖ J ‖ R ‖ len(T) ‖ T )          // local identifier only
h₀     = Keccak256( TAG_HEAD ‖ c ‖ schema_version )
leafₙ₊₁= Keccak256( TAG_LEAF ‖ c ‖ (n+1) ‖ payload_digest ‖ assessment_digest
                  ‖ qp_key ‖ category ‖ effective_at ‖ change_identified_at )
hₙ₊₁   = Keccak256( TAG_HEAD ‖ hₙ ‖ leafₙ₊₁ )
```

**Preimage field widths.** Every integer is little-endian and fixed width (INV-ENC-02); digests and keys are raw bytes.

| Preimage | Fields, in order after the tag | Total bytes |
|---|---|---|
| `c` | `J` 4, `R` 8, `len(T)` u16, `T` 1–64 | 23–86 |
| `h₀` | `c` 32, `schema_version` u16 | 42 |
| `leafₙ₊₁` | `c` 32, `seq` u64, `payload_digest` 32, `assessment_digest` 32, `qp_key` 32, `category` u8, `effective_at` i64, `change_identified_at` i64 | 161 |
| `hₙ₊₁` | `hₙ` 32, `leafₙ₊₁` 32 | 72 |

`category` is a `u8`, so a value outside 0–4 is representable and returns `0x05` (V-N-07b). `effective_at` and `change_identified_at` are signed 64-bit Unix seconds, matching the on-chain clock. The two preimages under `TAG_HEAD` are unambiguous because their lengths differ.

**Canonical tenure `T`.** `T` is the tenure identifier after canonicalization: Unicode NFKD, then uppercasing of a to z only, then removal of every character other than A–Z and 0–9. `T` is 1 to 64 bytes. Raw input over 256 bytes, invalid UTF-8, or a result that is empty or longer than 64 bytes returns `0x11`. `commitment` refuses any `T` that is not already canonical, with `0x11`, so a raw spelling can never be committed.

Transition `S_{n+1} = f(S_n, R_{n+1})` is defined iff:

```
(a) prev_head = hₙ                          else 0x03
(b) seq = n+1                               else 0x04
(c) ed25519_verify(qp_key, preimage(leafₙ₊₁), σ)  else 0x07
(d) effective_at ≥ last_effective_at        else 0x0A
(e) category_sequence_ok(kₙ, category)      → sets flag bit 0; never rejects
(f) category ∈ 0..=4 and payload_uri well-formed   else 0x05
```

**Order of judgement.** A record passes four stages, and the first stage it fails decides its code.

1. **Decode.** A buffer that does not decode is refused there, with `0x05` or the decoder's error, because it has no fields to judge (V-N-18).
2. **Schema gate.** `schema_version` must be 1, and the record must carry no `ext_commitment`. Under INV-FWD-01 an extension arrives as a new schema version, so a record carrying one is asking for schema 2 and is refused with `0x0F` (V-N-13, V-N-24).
3. **Conditions (a) to (f)**, in the order above. Condition (e) sets a flag and never rejects.
4. **Commit.** The head advances, the sequence number increases and the flags are recorded.

A record that fails more than one stage returns the code of the earliest stage it failed, and one that fails more than one condition within stage 3 returns the code of the earliest condition (V-N-23).

**What the QP signs.** `σ` covers the 161-byte leaf preimage, the bytes a disclosure package carries as `preimage_borsh`, not the leaf digest (INV-ENC-03). A signature over any other encoding, JSON included, fails condition (c) and returns `0x07` (V-N-05). An absent signature returns `0x06`. When a record carries an expected QP key and it differs from the record's `qp_key`, the transition returns `0x08` before verification runs (V-N-06).

**Why those are two codes and not one.** Ed25519 verification returns one bit. A failure says that the signature does not verify under the key the record claims, and nothing about which key did sign, so "signed by another key" is not distinguishable from "bad signature" without a second input naming the authorized key. `0x08` is therefore reserved for the case where such an input exists and disagrees with the record; a signature made by some other key, with no expected key supplied, is an ordinary verification failure and returns `0x07` (V-N-25).

**Well-formed `payload_uri`.** One to 128 bytes, printable ASCII only, beginning with `ipfs://`, `https://` or `ar://`, with at least one byte after the scheme and no whitespace or control byte. Nothing further is parsed: the engine resolves no URI and checks no host.

**INV-STATE-01.** Append-only. No operation decrements `seq`, rewrites `head`, or removes a record. The engine exposes no delete, no compaction, no rewrite-on-correction.
**INV-STATE-02.** For `m < n`, `hₙ` is recomputable from `h_m` and leaves `m+1..n`. Insertion, deletion or reordering is detectable by any holder of a later head.
**INV-STATE-03.** `c` never appears on-chain, in a Merkle path, or in any artifact leaving the issuer's control except inside a disclosure package the issuer has chosen to release.
**INV-STATE-04.** Effective dates non-decreasing.
**INV-STATE-05.** `change_identified_at` and `assessment_digest` are mandatory-present, optional-valued. A submitter with no materiality memo writes zeros, so absence is recorded rather than omitted and is as auditable as presence.
**INV-STATE-06 (record and flag, never reject).** CIM categories: `0=Inferred, 1=Indicated, 2=Measured` (Resources); `3=Probable, 4=Proven` (Reserves). When a record carries a reserve category and no earlier record in the same chain carries category ∈ {1,2}, the engine **accepts the record and sets flag bit 0** (`RESERVE_WITHOUT_PRIOR_RESOURCE`). It never rejects on category sequence.

Rationale: the professional standard governing resource-to-reserve conversion runs through an economic study this chain does not model, and real files legitimately contain acquired assets, carried-forward historical estimates, and out-of-order filings. Enforcement would reject valid work; flagging preserves the signal and leaves the judgment with the reader. See decision **D-01** (Appendix B).

**INV-STATE-06a (flags are observations, not verdicts).** Flag bits are computed deterministically from chain state, are part of the record account but **excluded from the leaf preimage**, and carry no normative weight. A flag says what the engine noticed, never that a filing is improper. Client copy must render flags as observations; wording that implies non-compliance is a merge blocker (§4.6).

Schema 1 flag bits: `bit 0 = RESERVE_WITHOUT_PRIOR_RESOURCE`, `bit 1 = CATEGORY_DOWNGRADE`, `bits 2–15 reserved (zero)`.

**Bit 1 is set when the record's category is lower than the previous record's category in the same chain**, and is never set on the first record. Categories 0 to 2 are resource confidence levels and 3 to 4 are reserve levels, so a return from Probable to Measured sets the bit, which is the case worth noticing, while a conversion from Measured to Probable does not. Like bit 0, it records an observation and never rejects.
**INV-STATE-07.** All arithmetic checked; overflow returns `0x10`.

### 1.4 Epoch tree — fixed capacity, count-hiding

Epoch `e` = UTC day index, `floor(unix_seconds / 86400)`. **A log begins at the day it is initialized**, not at zero: `initialize` writes `start_epoch`, the UTC day index the chain itself reports at that moment, and `publish_checkpoint` then takes exactly `last_epoch + 1` forever after. Before this branch this document gave the epoch its meaning and left a new log's `last_epoch` at zero, which made the first publishable epoch `1` — 2 January 1970 — and put the current day roughly twenty thousand transactions away, so the daily cadence INV-ANCH-01 requires was unreachable from the first deploy (D-109).

`start_epoch` is an argument to `initialize` so that the intended value is visible in the transaction, and the program requires it to equal the day index the on-chain clock reports. The operator states it; the chain decides it. The match is exact, so a transaction prepared before midnight and landing after it is refused and resubmitted with the new day; a tolerance would be a choice between two values, and this value is not the operator's to choose.

The tree has a **fixed height `H`, chosen once at `initialize` and immutable thereafter**. Default for this deployment: **`H = 8`, capacity `C = 256` slots**. Whatever `H` is, every epoch uses it, every epoch, forever.

Hiding quality comes from the capacity being fixed and always full, not from it being large. `C = 256` absorbs roughly 250 filings a day against a realistic industry rate of one or two, so overflow is not a practical concern, and it is four times cheaper to build than `C = 1024`. See decision **D-02** (Appendix B) for the revision triggers.

```
slot(i)        = first free index from PRF(k_e, 0x02 ‖ submission_id) mod C, linear probe
real leaf      = Keccak256( TAG_MTL0 ‖ leafₙ )
padding leaf   = Keccak256( TAG_PAD  ‖ PRF(k_e, 0x03 ‖ slot_index_le) )
internal node  = Keccak256( TAG_MTN1 ‖ left ‖ right )
epoch root     = root of the complete binary tree over all C slots
```

**How a slot is chosen (D-60).** The PRF output is read as a little-endian integer, as INV-ENC-02 requires of every integer here, and reduced modulo `C`. Because `C` is a power of two this is the low `H` bits, which lie in the digest's first two bytes. Real submissions are assigned in ascending order of submission identifier, so one set of submissions produces one tree whatever order the caller supplies them in. The probe steps upward by one slot and wraps at `C`, taking the first free slot it meets. More real submissions than `C` in one epoch is `0x12` (V-N-14). Two submissions carrying the same identifier in one epoch is `0x05`: the set is malformed, and a proof could be answered for neither of them. A height outside `[4, 16]` is `0x05`, as it is at `initialize` (V-N-22).

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

**INV-ANCH-02 (single authority, monotone epochs).** `publish_checkpoint` accepts `e = last_epoch + 1` only. Gaps and replays are rejected. A gap in the on-chain sequence is itself evidence of batcher failure and must surface in the client. **The sequence begins at `LogConfig.start_epoch`** (§1.4, D-109): an epoch before it is not a gap but a day the log did not exist for, and a client that could not tell the two apart would accuse a batcher of failing to publish before it was deployed.

**INV-ANCH-03 (write-once).** Checkpoint accounts are written once. `attach_anchor_receipt` may transition `receipt_digest` from zero to a value exactly once. No instruction mutates a non-zero field.

**INV-ANCH-04 (anchor B is opaque).** The program stores the OTS receipt digest and never parses the receipt. Bitcoin confirmation latency (hours) sits inside the operational envelope for this event frequency.

**INV-ANCH-05 (honest degradation).** Until anchor B is attached, the client reports `anchorStatus: "single"`; after, `"dual"`. Silent degradation is a merge blocker.

**`single` before Bitcoin confirms is the budgeted latency, not degradation (D-112).** An OpenTimestamps receipt is issued with calendar attestations only and is replaced by `ots upgrade` once a Bitcoin block confirms it. `receipt_digest` is write-once (INV-ANCH-03), so there is one opportunity to commit to a receipt, and it is spent on the upgraded one that carries the Bitcoin attestation. An epoch therefore reads `single` for the hours between publication and confirmation. That is the latency INV-ANCH-04 declares to be inside the operational envelope for this event frequency, arriving as designed rather than as a fault, and a client reporting `single` in that window is reporting the truth: no Bitcoin-anchored receipt exists yet for that epoch. What INV-ANCH-05 forbids is the opposite — reporting `dual` on the strength of a calendar's promise, which commits to nothing a counterparty can check.

**INV-ANCH-06 (log equivocation eliminated).** Because the root is on a public chain, all verifiers resolve the same root for epoch `e`. The batcher cannot show different logs to different verifiers. Asset equivocation (§0) is a separate and unsolved property.

### 1.6 Inclusion promises and merge delay

On accepting a submission the batcher returns a signed promise:

```
SPI = Ed25519_sign( batcher_key,
        Keccak256( TAG_SPI ‖ leaf ‖ submission_id ‖ accepted_epoch
                            ‖ promised_epoch ‖ max_merge_delay ) )
```

`submission_id` is 16 bytes, `accepted_epoch` and `promised_epoch` are `u64` and `max_merge_delay` is a `u8`, so the preimage is 73 bytes: `TAG_SPI`, `leaf` 32, `submission_id` 16, `accepted_epoch` 8, `promised_epoch` 8, `max_merge_delay` 1.

**Why the acceptance epoch is signed (D-74).** Without it, `max_merge_delay` bounds the end of the window relative to `promised_epoch` and nothing bounds `promised_epoch` relative to acceptance: a batcher holding the expected key could accept a submission, name an epoch arbitrarily far ahead, and never become answerable. With it, `promised_epoch` is judged against something the batcher signed, and `promised_epoch` outside `accepted_epoch .. accepted_epoch + max_merge_delay` is `0x17`.

**What the acceptance epoch does and does not establish (D-74).** Three statements:

1. The signature binds the batcher's **assertion** of acceptance.
2. The checkpoint sequence establishes **root publication**, not promise issuance.
3. Acceptance time is supplied only by **the counterparty's own observation at receipt**.

So verification takes that observation as an input. `accepted_epoch` must equal the checkpoint epoch the counterparty observed when the promise arrived, or be exactly one behind it, and **never ahead**: an acceptance epoch later than observed is the backdating attack, in which a batcher defers its own accountability by naming a future epoch and then meeting it, leaving no visible breach. One epoch behind is allowed because a promise can arrive across an epoch boundary. Anything else is `0x17`.

A promise's later transfer to a party that made no observation of its own is not covered by this. Closing that needs an independently timestamped receipt, which is recorded as a decision and deferred (D-74, Appendix A's RES-10).

`submission_id` is minted by the batcher, which takes only a leaf, and it is an ordinal counter (D-69). **It therefore reveals the submission's position in the batcher's sequence to anyone shown the promise**, and it travels only inside the promise: it appears in no disclosure package, no checkpoint and nothing on chain. Position in the epoch tree does not follow from it, because §1.4 assigns slots by PRF over it under a key the counterparty does not hold.

**INV-SPI-01.** `max_merge_delay = 2` epochs. If `leaf` is absent from the roots of `promised_epoch .. promised_epoch + max_merge_delay`, the SPI is a self-contained, transferable accusation of batcher misbehaviour.

**A signature proves authorship, not compliance.** `max_merge_delay` is fixed at 2 by INV-SPI-01 and
`promised_epoch` is bounded by the signed `accepted_epoch`, so a correctly signed promise carrying
either value outside what this section allows is refused with `0x17` rather than authenticated. The key
holder does not choose the policy its own promise is judged against.

**What that can and cannot be (D-72).** **Absence cannot be proven from a Merkle root.** A counterparty holding a promise and the three roots of the window cannot show the leaf is missing; only the batcher can show it is present. An unsatisfied promise is transferable in the sense that anyone can check its signature and its binding and see which epochs it covers, and the conclusion it supports is rebuttable: the batcher answers with an inclusion proof or it does not answer, and silence is the evidence. **A rebuttal counts only if its inclusion proof resolves to a root published inside the window, `promised_epoch` through `promised_epoch + max_merge_delay`. A proof against any later root confirms the breach rather than rebutting it**, which is what `0x14` reports.
**INV-SPI-02.** The batcher cannot issue an SPI it can satisfy two ways: the promise binds the exact leaf digest, so satisfying it requires including that leaf.
**INV-SPI-03.** The log proves what was submitted, not what existed. An issuer who never submits a record leaves no trace of it. No invariant can close this from inside the architecture (RES-05).

### 1.7 Governance

**INV-GOV-01.** A live program upgrade authority makes every invariant conditional on the current deployment. Before submission the authority is set to `None`, or the repository states plainly, at the entry point a reader arrives through, that it is live and why. Until the README of E-15 exists, that place is `docs/anchoring.md`, and the disclosure moves to the README when there is one. A disclosure a reader does not meet is not a disclosure (Codex round one, finding 12).
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
| Tenure ID raw input | ≤256 bytes |
| Max merge delay | 2 epochs |
| Compute, `publish_checkpoint` | ≤ 15,000 CU |
| Compute, `attach_anchor_receipt` | ≤ 12,000 CU |

---

## §2 Interface / contract trait definitions

Four crates. `certimining-core` holds digests and the state machine, `no_std`-compatible, zero Solana dependency. `certimining-log` holds the batcher, tree, and verifier, `no_std` with an allocator. `certimining-checkpoint` is the Anchor program. `certimining-client` publishes checkpoints and fetches roots, is `std`, and is the only crate that speaks to a cluster (D-84). The core crate must pass identical vectors under a native harness and under the Solana runtime — that is the vendor-neutrality claim made testable rather than asserted.

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
    SubmissionNotInEpoch     = 0x16,
    PromisePolicyInvalid     = 0x17,
}
```

On-chain codes are returned as `6000 + code` (Anchor offset); the client reverses the offset and surfaces raw hex. Codes are stable across versions; new conditions take new codes.

**Where two refusal conditions can hold at once, this document names which check runs first, and a code no path can return is a defect in this document rather than a spare** (D-80). `0x09` is the one deliberate exception: it is reserved and never returned under schema 1, which INV-STATE-06 states and D-01 explains.

**INV-ERR-01.** No panic, unwrap, expect, unchecked index, or wrapping arithmetic on any path. `#![forbid(unsafe_code)]`, `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::arithmetic_side_effects)]` at every crate root.

### 2.2 Core traits

```rust
pub type Digest = [u8; 32];
pub type Result<T> = core::result::Result<T, RegistryError>;

/// Collects a preimage's bytes in order. `write` returns `0x0C` if the preimage would exceed
/// `MAX_PREIMAGE_LEN`, which is 256; the largest preimage in schema 1 is the 161-byte leaf.
pub trait PreimageSink {
    fn write(&mut self, bytes: &[u8]) -> Result<()>;
}

pub trait Preimage {
    const TAG: [u8; 8];
    fn write_preimage(&self, out: &mut dyn PreimageSink) -> Result<()>;
    /// The hasher is named at the call site; nothing picks one implicitly.
    fn digest<H: Hasher>(&self) -> Result<Digest>;
}

/// Ed25519 verification (RFC 8032). The caller names the implementation, as it names the hasher.
/// The on-chain build carries none, so the program cannot verify a signature (INV-PRIM-02).
pub trait Verifier {
    fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<()>;
}

/// Ed25519 signing, for the batcher's promises (§1.6, D-73). The engine holds no key and has nowhere
/// to put one: an implementation of this trait holds it, outside this repository. The caller names the
/// implementation, as it names the hasher and the verifier.
pub trait Signer {
    fn sign(&self, message: &[u8]) -> Result<[u8; 64]>;
    fn public_key(&self) -> [u8; 32];
}

/// One record as it arrives. `c` is not here: the chain holds it.
pub struct RecordLeafInput {
    pub prev_head: Digest,
    pub seq: u64,
    pub payload_digest: Digest,
    pub assessment_digest: Digest,        // zeros when there is no memo (INV-STATE-05)
    pub qp_key: [u8; 32],
    pub expected_qp_key: Option<[u8; 32]>, // present: a mismatch is 0x08 (V-N-06)
    pub signature: Option<[u8; 64]>,       // absent is 0x06 (V-N-04)
    pub category: u8,
    pub effective_at: i64,
    pub change_identified_at: i64,         // zero when there is no memo (INV-STATE-05)
    pub payload_uri: heapless::Vec<u8, 128>,
    pub ext_commitment: Option<Digest>,    // §2.6 hook: always None in v0.1, never hashed
}

/// What one accepted transition produces. A refused transition produces nothing, so no stale
/// value can be read back afterwards.
#[must_use]
pub struct Applied {
    pub leaf: Digest,     // what the batcher submits and a promise binds
    pub head: Digest,     // the chain's new head
    pub flags: u16,       // observations only, excluded from the leaf preimage (INV-STATE-06a)
}

pub trait ChainState {
    fn genesis(asset_commitment: &Digest, schema_version: u16) -> Result<Digest>;
    fn leaf(&self, r: &RecordLeafInput) -> Result<Digest>;
    fn apply(&mut self, r: &RecordLeafInput) -> Result<Applied>;
    fn head(&self) -> Digest;
    fn seq(&self) -> u64;
}

pub trait AssetIdentity {
    fn canonicalize(tenure_raw: &str) -> Result<heapless::Vec<u8, 64>>;
    /// Raw bytes, which may not be valid UTF-8; invalid input returns 0x11.
    fn canonicalize_bytes(tenure_raw: &[u8]) -> Result<heapless::Vec<u8, 64>>;
    fn commitment(j: &[u8;4], r: &[u8;8], tenure: &[u8]) -> Result<Digest>;
}
```

### 2.3 Log traits

```rust
pub type SubmissionId = [u8; 16];

pub trait EpochTree {
    /// Height is a deployment parameter, not a constant. Default H = 8 (C = 256).
    /// Valid range 4..=16; fixed at `initialize` and immutable thereafter (INV-TREE-06).
    fn height(&self) -> u8;
    fn capacity(&self) -> usize;      // 1usize << height()
    /// `key` is `k_master`: the epoch key is derived inside `build`, from the epoch it already
    /// knows, so no caller can reuse one `k_e` across epochs (INV-TREE-05, D-63). The hasher is
    /// named at the call site, as it is for every digest in §2.2.
    fn build<H: Hasher>(epoch: u64, height: u8, key: &Digest,
                        real: &[(SubmissionId, Digest)]) -> Result<BuiltEpoch>;
    fn root(&self) -> Digest;
    /// A submission this epoch does not hold is `0x16`. It is its own condition, not a proof that
    /// failed to verify, so it takes its own code rather than sharing `0x13` (D-67).
    fn proof(&self, id: &SubmissionId) -> Result<InclusionProof>;
}

/// What one sealed epoch carries (D-62). Nothing in it marks a slot real or padding. `Vec` here
/// is `alloc`'s: the log crate is `no_std` with an allocator, because a tree at H = 16 holds 65,536
/// leaves and no fixed-capacity type carries that (D-61).
pub struct BuiltEpoch {
    pub epoch: u64,
    pub height: u8,
    pub root: Digest,
    pub leaves: Vec<Digest>,                     // exactly C entries, in slot order
    pub assignment: Vec<(SubmissionId, u16)>,    // ascending by identifier
}

pub trait InclusionVerifier {
    /// Pure. No network, no clock, no storage. `leaf` is the chain leaf `leafₙ`; the verifier
    /// applies `TAG_MTL0` itself, so no caller can omit the tag (INV-ENC-01, D-64).
    fn verify<H: Hasher>(leaf: &Digest, proof: &InclusionProof, root: &Digest) -> Result<()>;
    /// The same check for a caller that knows its log's configured height: a proof whose `height`
    /// disagrees is `0x13` before any hashing (V-N-16b). Pure in the same way.
    fn verify_for_height<H: Hasher>(leaf: &Digest, proof: &InclusionProof, root: &Digest,
                                    configured_height: u8) -> Result<()>;
}

/// A promise that a leaf will appear in a root inside the merge delay (§1.6, D-68). Self-contained, so
/// a counterparty checks it without the batcher. `batcher_key` is carried for display and is never the
/// authority: `verify_promise` takes the key the counterparty expects and compares the two.
pub struct SignedPromise {
    pub leaf: Digest,
    pub submission_id: SubmissionId,
    pub accepted_epoch: u64,
    pub promised_epoch: u64,
    pub max_merge_delay: u8,
    pub batcher_key: [u8; 32],
    pub signature: [u8; 64],
}

pub trait Batcher {
    /// Mints a submission identifier, queues the leaf and returns its promise. A full epoch does not
    /// refuse: the promise names the next epoch the batcher can meet, the leaf waits in the overflow
    /// queue, and nothing is dropped (D-71, INV-TREE-04). The hasher and the signer are named at the
    /// call site; the batcher holds the master key it was constructed with and no key of its own.
    fn submit<H: Hasher, S: Signer>(&mut self, leaf: Digest, signer: &S) -> Result<SignedPromise>;
    fn seal<H: Hasher>(&mut self, epoch: u64) -> Result<BuiltEpoch>;
    fn overflow_queue_len(&self) -> usize;
}

/// Checks a promise's signature over **the SPI digest**, which is what §1.6 signs, against the batcher
/// key the counterparty expects (D-68), and against the policy §1.6 fixes (D-74). A key mismatch is
/// `0x08`, decided first. A signature proves authorship and not compliance, so a `max_merge_delay`
/// other than the one INV-SPI-01 fixes, a `promised_epoch` outside the window the signed
/// `accepted_epoch` allows, or an `accepted_epoch` that is not the observed epoch or exactly one behind
/// it, is `0x17`. A signature that does not verify is `0x07`.
///
/// `observed_epoch` is the caller's own reading of the checkpoint sequence when the promise arrived.
/// It is an input because nothing in the artifact can supply it: see §1.6's three statements.
pub fn verify_promise<H: Hasher, V: Verifier>(
    promise: &SignedPromise,
    expected_batcher_key: &[u8; 32],
    observed_epoch: u64,
) -> Result<()>;

/// An epoch's root as the caller obtained it from a published checkpoint. The two travel together
/// because a root without its epoch says nothing about when it was published, and an epoch beside a
/// root it did not come from says nothing at all.
pub struct PublishedRoot {
    pub epoch: u64,
    pub root: Digest,
}

/// Whether a promise was kept, as far as this function can tell. The proof must be for the same epoch
/// as the root it is checked against, that epoch must fall inside the promised window, and the path
/// must verify for the promise's own leaf. Outside the window in either direction is `0x14` (D-72); an
/// inconsistent or failing proof is `0x13`.
///
/// **It does not establish that the root was published.** D-72's rule is that only a root published
/// inside the window rebuts the accusation, and publication provenance comes from the checkpoint
/// account of §2.4, which the client fetches and hands here. This function enforces consistency
/// between what it is given, and the seam where provenance enters is the caller's.
pub fn promise_kept<H: Hasher>(
    promise: &SignedPromise,
    proof: &InclusionProof,
    published: &PublishedRoot,
) -> Result<()>;

pub trait AnchorClient {
    fn publish(&self, epoch: u64, root: Digest) -> Result<AnchorRef>;       // Solana
    fn submit(&self, root: Digest) -> Result<PendingReceipt>;               // OTS, returns at once
    fn upgrade(&self, p: &PendingReceipt) -> Result<Option<ReceiptDigest>>; // None until Bitcoin
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
    pub fn initialize(ctx: Context<Initialize>, authority: Pubkey,
                      tree_height: u8, start_epoch: u64) -> Result<()>;
    pub fn publish_checkpoint(ctx: Context<Publish>, epoch: u64, root: [u8;32]) -> Result<()>;
    pub fn attach_anchor_receipt(ctx: Context<Attach>, epoch: u64,
                                 receipt_digest: [u8;32], kind: u8) -> Result<()>;
}
```

`initialize` takes `tree_height` (4..=16, default 8) and writes it once; anything outside the range is `0x05` (V-N-22). It also takes `start_epoch` and writes it once, refusing with `0x05` anything but the UTC day index the on-chain clock reports (§1.4, D-109); `last_epoch` is written as `start_epoch - 1`, so the first publication is `start_epoch` itself. `start_epoch` occupies eight of the sixteen bytes that were reserved, so `LogConfig` is still 68 bytes. No instruction changes it afterwards (INV-TREE-06). The `LogConfig` PDA is its own guard against a second call, since the account already exists. **Whoever calls `initialize` first owns the log**, so it belongs to the deploy procedure rather than to whoever gets there first; a front-run is visible because `LogConfig.authority` is not the operator's key, and the remedy is a redeploy to a new program id. The program's upgrade authority is settled in the same step, which is where INV-GOV-01's choice is made (D-79).

**`publish_checkpoint` checks in this order** (D-80): the checkpoint account already exists is `0x0E`, and only then `epoch ≠ last_epoch + 1` is `0x0D`. Both conditions can hold at once — republishing epoch `e` is also an epoch that is not `last + 1` — so the order is stated here rather than left to an implementation, and the account is created explicitly so existence can be seen before it is refused.

**`attach_anchor_receipt` is the authority's alone**, `kind` accepts exactly one value, `1` for OpenTimestamps, with anything else `0x05`, and a second attach is `0x15` (D-81). The field is write-once, so an open writer could block the real receipt for ever with one garbage digest. An all-zero digest is `0x05`: zero is the sentinel that means *not yet attached*, so writing it would leave the field looking unwritten and let a second attachment through (D-105).

**What `receipt_digest` is (D-113).** `receipt_digest = Keccak256(TAG_RCPT ‖ len(receipt) ‖ receipt)`, where `receipt` is the bytes of the **upgraded** OTS receipt — the one carrying a Bitcoin attestation — `len` is a `u16` as INV-ENC-04 requires of every variable-length field, and the tag is first as INV-ENC-01 requires of every preimage. Before this branch the document named the field, fixed its width and said the program never parses it, and never said what function produced the 32 bytes, so two conforming implementations could disagree about every receipt. The program still parses nothing: it stores what it is given, and the digest is the counterparty's means of checking that the receipt they were handed is the one the epoch committed to (INV-ANCH-04).

**There is no other instruction, and none may be added.** No update, close, revoke, shred, or set-state. A pull request introducing one is rejected regardless of its guard conditions.

```
LogConfig (PDA ["cm_cfg"])            offset  len        CheckpointAccount (PDA ["cm_ckpt", epoch_le])
  discriminator                            0    8          discriminator            0    8
  schema_version                           8    2          schema_version           8    2
  authority (Pubkey)                      10   32          epoch                   10    8
  last_epoch                              42    8          root                    18   32
  tree_height                             50    1          published_slot          50    8
  bump                                    51    1          published_unix          58    8
  start_epoch                             52    8          receipt_digest          66   32
  reserved                                60    8
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

**E-02 · Canonicalization + commitment (days 1–2).** NFKD → ASCII uppercase → filter to A–Z and 0–9 → bounds (§1.3). Property test: idempotent, total, never panics on invalid UTF-8.

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
| V-N-06 | A record whose expected QP key differs from the `qp_key` it claims | `0x08`, decided before verification runs |
| V-N-07 | Category 4 with no prior 1 or 2 in chain | **Not an error.** Must accept; `0x09` must never be returned under schema 1 |
| V-N-07b | Category value 5 or 255 | `0x05` |
| V-N-08 | `effective_at` earlier than predecessor | `0x0A` |
| V-N-09 | Wrong domain tag in preimage | `0x0B` |
| V-N-10 | `publish_checkpoint` with `epoch ≠ last+1` | `0x0D` |
| V-N-11 | Second `publish_checkpoint` for same epoch | `0x0E` |
| V-N-12 | Second `attach_anchor_receipt` for same epoch | `0x15` |
| V-N-13 | `schema_version = 2` | `0x0F` |
| V-N-14 | `C + 1` real submissions in one epoch (257 at default) | **The tree returns `0x12`** when asked to build more than `C` leaves into one epoch. **The batcher never asks:** it queues the excess, promises it the next epoch it can meet, and reports it through `overflow_queue_len`, so a submission past capacity is queued and never dropped (D-71). |
| V-N-15 | Inclusion proof with one sibling altered | `0x13` |
| V-N-16 | Proof with `H − 1` or `H + 1` siblings | `0x13` |
| V-N-16b | Proof whose `height` field disagrees with the log's configured `H` | `0x13` |
| V-N-22 | `initialize` with `tree_height` = 3 or 17 | `0x05` |
| V-N-17 | Proof verified against the wrong epoch's root | `0x13` |
| V-N-18 | Truncated params buffer, every prefix length | `0x05` or Borsh error, never a panic |
| V-N-19 | Checkpoint written by a non-authority signer | Anchor constraint violation |
| V-N-20 | `seq = u64::MAX` | `0x10` |
| V-N-21 | Tenure ID canonicalizing to empty | `0x11` |
| V-N-23 | A record failing both (a) and (f) | `0x03`; the earlier condition decides |
| V-N-24 | A record carrying `ext_commitment`, with a wrong `prev_head` | `0x0F`; the schema gate precedes (a) |
| V-N-25 | A signature made by a key other than the `qp_key` the record claims, with no expected key supplied | `0x07` |
| V-N-26 | `initialize` given a `start_epoch` that is not the UTC day index the on-chain clock reports — too low, too high, zero, or `u64::MAX` | `0x05` |

### 4.4 Privacy acceptance tests — these are the ones that matter

| ID | Test | Pass condition |
|---|---|---|
| V-Z-01 | **Count-hiding.** Publish consecutive epochs holding 0, 1, 128 and 255 real leaves at H = 8, in more than one order, with tree-build time varied deliberately. | Instruction length, transaction length, account size and field layout are identical. A byte may differ between two epochs only if the epoch number, the publication schedule or a pseudorandom digest fixes it: in the checkpoint account, `epoch`, `bump`, `published_slot`, `published_unix`, `root` and `receipt_digest`; in the `publish_checkpoint` transaction, the checkpoint address, the recent blockhash, the signature and the `epoch` and `root` arguments. Every other byte is identical across record counts. This list is exhaustive and closed: any other byte that differs is a failure, and adding a byte to the list requires an amendment to this specification, never an edit to the test. `epoch` advances by exactly one per epoch, empty epochs included, and every epoch is submitted at its scheduled time however long its build took. Network delay may move the landing slot, but it must be independent of epoch content: the test measures the correlation of landing delay with record count, and with build time, across many epochs, and fails on any correlation above noise. It bounds no single epoch's delay, because one slow publication proves nothing either way. **Where each half runs (D-85):** the byte-exact comparison runs under LiteSVM in CI, which is deterministic and is what a closed list needs; the landing-delay correlation runs on devnet before submission, over **200 consecutive epochs**, with an absolute Pearson correlation **below 0.2** against record count and against build time. That bound is looser than V-Z-04's because a public network's scheduling noise is not what is under test: what is under test is whether epoch content moves the landing slot at all, and a leak of that kind produces a correlation near 1. Both figures are fixed here before any epoch is published, and recorded on issue #9. |
| V-Z-02 | **Padding indistinguishability.** Given an epoch's root and all `C` leaf digests in slot order and no epoch key, classify each leaf as real or padding. **The adversary is computationally bounded, which is exactly what INV-TREE-02 claims.** An adversary who could search the 256-bit key space would derive `k_e`, recompute every padding leaf and answer with certainty, so count-hiding here is computational and no test can make it information-theoretic. An earlier draft of this row granted the classifier unlimited compute, which contradicted INV-TREE-02 and claimed more than any test can establish. The classifier is specified here rather than left to whoever writes the test, so a reader can judge how hard it tries: per-position byte statistics across the leaf set, and a structural-regularity check over each digest being deviation from the set's per-position byte mean, population count, zero-byte count, leading-zero bits, longest run of equal bytes, distinct byte values, a chi-squared statistic over nibbles, and Hamming distance to the root and to the adjacent slots. | The statistic is a distinguishing game, not raw accuracy: each trial presents one real leaf and one padding leaf from a freshly built epoch, the classifier names the real one, and successes must not leave a two-sided binomial test at α = 0.001 against p = 1/2. Accuracy alone cannot carry this test, because an epoch holding one real leaf and 255 padding leaves scores 255/256 for a classifier that answers "padding" every time and learns nothing; the pair game removes the base rate. A balanced epoch, `C/2` real, is also classified leaf by leaf, where accuracy is meaningful and the same band applies. Every feature is scored alone and the combined score as well, and each must pass. CI runs 200 epochs (D-66). **What this establishes is bounded and stated as such:** the named battery does not distinguish real leaves from padding. It is not a proof that no distinguisher exists, and it says nothing about an adversary who can recover `k_e`. Strengthening the battery is tracked for after the submission deadline. See RES-09. |
| V-Z-03 | **Proof non-leakage.** Given a valid inclusion proof, recover anything about any sibling, or anything about how many real leaves its epoch held. | Siblings are digests only and no preimage is derivable, which the proof format asserts structurally and the test checks against every chain leaf and every PRF output of the epoch. **No field of a proof varies with the record count:** `height` is the log's, `epoch` is the tree's, the sibling count is `height`, and `slot_index` is pseudorandom under `k_e`. A proof that encoded the count in any of these would be a leak V-Z-01 cannot see, because a proof never goes on chain. The test builds epochs of 1, 128 and 255 real leaves at one height and compares those fields across all three. `slot_index` is the field a count could hide in, so the test does not compare it across counts but pins it: every slot must equal the assignment D-60 prescribes, computed independently in the test from the PRF construction and the probing rule rather than taken from the engine. A regenerated vector set cannot stand in for that, because the generator runs the engine under test. **The matrix is finite and stated:** this row's own samples are 1, 128 and 255 real leaves under the engine's hasher, and the epoch tree's conformance test repeats the same comparison at every count from 0 to `C` at `H = 4` and `H = 8` under a stand-in hasher, which exercises the identical assignment code. Neither is a proof that no count-dependent assignment exists; both are equality to D-60 over the counts they visit. |
| V-Z-04 | **Position non-leakage.** Correlate `slot_index` with submission order, issuer, and time within epoch across 10,000 simulated epochs. | The absolute Pearson correlation must stay below 0.05 at the sample size CI runs and below 0.02 over the full 10,000 epochs, for each of the three. Both bounds are conservative: CI's standard error is about 0.006, so the bound sits eight standard errors out, while a real positional leak produces a correlation near 1. CI runs 400 epochs; the full run is ignored by default, is a release gate, and is recorded on issue #16 (D-66). |
| V-Z-05 | **No asset identifier escapes.** Grep the full on-chain byte history and every disclosure package for `c`, tenure IDs, jurisdiction codes and registry codes. | Zero occurrences on-chain. In the disclosure package, only fields listed in §2.5. |
| V-Z-06 | **Timing non-leakage.** Compare the on-chain timeline of an issuer who submits daily against one who submits twice a year. | Identical checkpoint cadence and footprint. Run under LiteSVM beside V-Z-01's byte-exact half, because the property is about what the chain shows rather than about network timing (D-85). |

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

**The banned phrasings, versioned here rather than only in the script that greps for them (D-121).** `scripts/claim-check.sh` reads this block, so an independent reader of this document knows exactly what is forbidden and a change to the list is a change to the specification. Matching is case-insensitive.

```claim-phrasings-banned
prevents fraud
prevent fraud
fraud prevention claim of
fraud-proof
fraudproof
prevents double-pledg
prevent double-pledg
prevents double pledg
detects double-pledg
detects double pledg
double-pledge prevention claim of
ensures compliance
ensure compliance
guarantees compliance
guarantee compliance
regulatory compliance claim of
compliant with ni 43-101
ni 43-101 compliant
ni 43-101-compliant
tamper-proof
tamperproof
proves the estimate
proves compliance
certifies compliance
```

**Why phrasings and not the bare nouns.** §0 and this section contain the words *fraud prevention*, *double-pledge prevention* and *regulatory compliance*, because naming a claim is how a document forbids it. A check that banned the nouns would fail on the text that bans the claim. So the phrasings above are constructions a denial never uses, and the nouns are handled separately: every occurrence of one is listed in `docs/claim-denials.txt` **by a hash of its line**, so editing a denial withdraws its exemption and the check fires again. An exemption that survives edits is how a claim eventually lands beside a denial.

---

## Appendix A — Residuals

- **RES-01 · Asset equivocation is unsolved.** Two chains for one physical asset both verify. Cross-party detection requires a jointly observable identifier, which is what the confidentiality requirement forbids. TCU-03 addresses this at a cost; TCU-02 does not address it at all and must not imply otherwise.
- **RES-02 · Category flags are heuristics, not standards.** Resource-to-reserve conversion runs through a study this chain does not model. Flag bit 0 marks a pattern worth a reader's attention; it does not mark a filing as improper, and the engine never rejects on it. Whether the pattern is even diagnostic is open until a working QP reviews it (D-01).
- **RES-03 · Count-hiding rests on batcher key custody.** Whoever holds `k_master` can distinguish padding from real leaves retrospectively. In a single-issuer deployment the issuer holds it and is hiding only from outsiders, which is the intended threat model but should be stated rather than assumed.
- **RES-04 · The QP key is not credentialed.** Binding a key to a live professional registration is a Layer 6 problem this TCU does not solve.
- **RES-05 · The log proves submission, not existence.** A record never submitted leaves no trace. No construction inside this architecture closes that; only an obligation to submit, external to the system, does.
- **RES-06 · Canonicalization is the real identity attack surface.** Two spellings of one tenure produce two commitments. Published rules and a registry-code namespace narrow it; they do not close it. Letters with no compatibility decomposition, such as œ, æ and ß, are removed rather than transliterated, so spellings that differ only in them still produce different commitments.
- **RES-07 · Batcher liveness.** A stalled batcher stalls the integrity claim for everyone in the batch. Gap detection makes the stall visible; it does not prevent it.
- **RES-08 · The physical-digital boundary.** Sampling fraud, grade misrepresentation at the point of measurement, and sample substitution sit entirely outside what any of this can reach.
- **RES-10 · A promise establishes acceptance only to the party that observed it, and its construction carries no version.** Verification compares the signed acceptance epoch against the counterparty's own observation at receipt (§1.6), so a promise transferred onward to a party that observed nothing carries an assertion that party cannot check. Closing that needs an independently timestamped receipt, deferred by D-74. Separately, the SPI construction has no version field: it is fixed for this deployment, and changing it once promises exist outside this repository would need a mechanism §1.6 does not have, where the record chain has `schema_version`.
- **RES-09 · Count-hiding is computational, not information-theoretic.** Padding leaves are PRF outputs under `k_e`, so indistinguishability holds against an adversary who cannot recover that key and fails against one who can. §4.4's V-Z-02 bounds a named battery of statistics, which is evidence that the construction carries no obvious tell; it is not a proof that no distinguisher exists. The claim to make outside this document is that an outside observer cannot tell how many records an epoch holds, never that nobody can.

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
