# Specification defects found while building the TypeScript verifier

Each entry records a place where TCU-02 v0.1.16 does not determine the answer, what was needed,
what the document says, the readings available, and which vector or invariant forced the question.
Nothing here was resolved by looking at another implementation. Where a committed vector settles a
question the document leaves open, that is said plainly: a vector is evidence of what one
implementation did, not of what the specification requires.

The entries are ordered by how much of the verifier they touch.

---

## D-1 · §2.5, §1.3, INV-DISC-02 — `payload_uri` cannot be compared against the bytes

**What was needed.** The set of JSON fields that INV-DISC-02's "fails closed on any disagreement
between JSON fields and the Borsh preimage" covers.

**What the document says.** §2.5's `record` block lists `payload_uri`. §1.3's leaf preimage, the
161 bytes `preimage_borsh` carries, contains `c`, `seq`, `payload_digest`, `assessment_digest`,
`qp_key`, `category`, `effective_at` and `change_identified_at`, and nothing else. INV-DISC-03
excludes `flags` from the comparison and says nothing about `payload_uri`.

**Candidate readings.**
1. `payload_uri` is display only and unverifiable from a package. A counterparty cannot tell
   whether the URI shown is the one the qualified person attested to, because the signature does
   not cover it.
2. The comparison is over "every field the preimage carries", and `payload_uri` falls outside it
   silently, which is reading 1 with the consequence left unstated.
3. `payload_uri` belongs in the leaf preimage and its absence is an oversight, in which case every
   committed digest changes.

**What forced the question.** Building the comparison. V-N-03 and V-N-23 show that `payload_uri`
is judged by condition (f) when a record is admitted, so the engine does care what it says; but
the same vectors' signatures verify over a preimage that omits it, which is why one signature
serves V-N-01, V-N-03, V-N-06, V-N-23 and V-N-24 unchanged while their URIs differ.

**Consequence if reading 1 holds.** An issuer can release two packages for one record, differing
only in `payload_uri`, and both verify completely. The URI is the pointer to the actual estimate,
so this is not a cosmetic field.

**What this verifier does.** Compares the seven fields the preimage carries, in preimage order,
and leaves `payload_uri` uncompared. README.md lists it under what the verifier does not check.

---

## D-2 · §1.4, D-60 — "ascending order of submission identifier" does not say which order

**What was needed.** The order in which real submissions are assigned to slots, because the probe
is first-free-upward and the winner of a contested slot depends on who was placed first. The order
therefore decides the root.

**What the document says.** §1.4: "Real submissions are assigned in ascending order of submission
identifier, so one set of submissions produces one tree whatever order the caller supplies them
in." §2.3: `assignment` is "ascending by identifier". `SubmissionId` is `[u8; 16]`.

**Candidate readings.**
1. Lexicographic order over the sixteen bytes.
2. Numeric order with the identifier read as a little-endian `u128`, which is what INV-ENC-02
   requires of every integer in the document, and what D-69's "ordinal counter" implies the
   identifier is.

These differ as soon as identifiers cross a byte boundary, which the vectors do.

**What forced the question.** V-P-06. Its 255 identifiers run from `0x03e8` to `0x04e6` written
little-endian; its `assignment` block begins at `0x00040000…` and ends at `0xff030000…`, which is
lexicographic and is not numeric. The vector settles it. The document does not, and it points the
other way: D-69 says the identifier is an ordinal counter, so reading it as a number is the more
natural reading of "ascending", and it produces a different root.

**What this verifier does.** Lexicographic, to match the committed vectors, with this defect
recorded. If the document is amended to say "as a little-endian integer", V-P-06's root changes.

---

## D-3 · INV-DISC-03 — a verifier cannot recompute flags from a disclosure package

**What was needed.** How a package verifier satisfies "A verifier recomputes flags from the chain
rather than trusting the supplied value, and a mismatch is reported as a discrepancy".

**What the document says.** INV-STATE-06 sets bit 0 when a record carries a reserve category and
no *earlier record in the same chain* carries category 1 or 2. Bit 1 is set when the record's
category is lower than *the previous record's*. §2.5's package carries one record, one `prev_head`,
one `head` and one `genesis`, and no earlier category at all.

**Candidate readings.**
1. "From the chain" means from the whole chain, which only the issuer or a holder of every record
   has. A package verifier cannot do it and must report the flags as unchecked.
2. The verifier is expected to obtain the chain separately, which INV-DISC-02's offline
   requirement and INV-IFACE-01's "given only the record, the proof, and a root" contradict.

**What forced the question.** Writing the flag step of the package verifier. There is no input in
§2.5 from which bit 0 or bit 1 follows.

**What this verifier does.** Reports `declared`, `recomputed: null` and `discrepancy: null` when no
chain context is supplied, and recomputes and reports a discrepancy when a caller supplies the two
values the computation needs. A discrepancy never refuses the package, which INV-DISC-03 is clear
about.

---

## D-4 · §2.5, §2.1 — no code is defined for a package whose own fields disagree

**What was needed.** What a verifier returns when `chain.head` is not
`Keccak256(TAG_HEAD ‖ prev_head ‖ leaf)`, and what `chain.genesis` is for.

**What the document says.** §2.1's codes belong to §1.3's transition conditions, and D-80 says a
code no path can return is a defect rather than a spare. §2.5 carries `genesis`, `prev_head` and
`head`. INV-DISC-02 says the verifier "walks the chain segment". A package holds one leaf, so the
only relation inside it is the single head step; `genesis` is reachable only when `seq` is 1.

**Candidate readings.**
1. The head step is §1.3's own relation, so a disagreement is 0x03, the code §1.3 gives when a
   record and a head do not agree.
2. It is a package-level failure with no §2.1 code, like the JSON-versus-Borsh mismatch.
3. `genesis` is decoration and is not checked at all.

**What forced the question.** Assembling a package whose `head` was wrong and having to name the
failure.

**What this verifier does.** 0x03 for the head step, reading 1. A named package-level failure,
`ChainSegmentBroken`, for `prev_head ≠ genesis` at `seq = 1`, since no §2.1 condition covers it.
For `seq > 1` the `genesis` field is reported as not checkable from one package, and the README
says so.

---

## D-5 · §1.3 — the order between 0x08 and 0x06 inside condition (c)

**What was needed.** The code for a record that carries an expected QP key different from its
`qp_key` *and* no signature at all.

**What the document says.** "An absent signature returns 0x06. When a record carries an expected
QP key and it differs from the record's `qp_key`, the transition returns 0x08 before verification
runs." Both sentences are about condition (c) and neither orders the two.

**Candidate readings.** 0x08 first, because the key is judged before anything is verified; or 0x06
first, because with no signature there is nothing for a key to belong to.

**What forced the question.** Writing condition (c). No committed vector holds both: V-N-04 has no
expected key, V-N-06 has a signature.

**What this verifier does.** 0x08 first, following §2.3's `verify_promise`, where the document does
order them: "A key mismatch is 0x08, decided first."

---

## D-6 · §2.3, §1.6 — the order between 0x17 and 0x07 in `verify_promise`

**What was needed.** The code for a promise that is outside §1.6's policy *and* carries a signature
that does not verify.

**What the document says.** §2.3 lists a key mismatch first, then the three conditions that are
0x17, then "A signature that does not verify is 0x07". §1.6 says a *correctly signed* promise
carrying a value outside the section is "refused with 0x17 rather than authenticated", which
settles the case where the signature is good and says nothing about the case where it is not.

**Candidate readings.** Policy before signature, following the order §2.3 lists; or signature
before policy, on the ground that an unauthenticated artifact has no policy to judge.

**What forced the question.** Writing `verifyPromise`. V-P-10's promise is well formed on both
counts, and V-N-14's is too.

**What this verifier does.** Key, then policy, then signature, following §2.3's order.

---

## D-7 · §1.1 — "Ed25519 (RFC 8032)" does not pin the verification equation

**What was needed.** Whether verification is cofactored or cofactorless, whether non-canonical
point and scalar encodings are rejected, and whether small-order public keys are refused.

**What the document says.** §1.1 names "Ed25519 (RFC 8032)" and INV-PRIM-02 places verification in
the verifier. Nothing further.

**Why it matters here more than usual.** RFC 8032 permits either verification equation, and
implementations differ on exactly these edge cases; ZIP-215 exists because they do. Two
implementations that both claim RFC 8032 can disagree about specific signatures, which is the one
thing V-P-08's cross-implementation determinism claim is meant to exclude. No committed vector
exercises the difference: every signature in the corpus is either a well-formed signature by the
right key or a well-formed signature over the wrong message.

**What this verifier does.** Strict RFC 8032 semantics, `zip215: false` in the library that
implements it, chosen because §1.1 names the RFC and not ZIP-215. A conformance suite should carry
the disagreement cases rather than leaving the choice to each implementer.

---

## D-8 · INV-PRIM-01 against §2.4 — "No SHA-256" forbids what fetching a root requires

**What was needed.** Which primitive derives the checkpoint address and the account discriminator.

**What the document says.** INV-PRIM-01: "One hash family across the system. No Poseidon, no
BLS12-381, no SHA-256. ... Any copy claiming otherwise is wrong and blocks submission." §2.4 then
specifies the discriminator as "the first eight bytes of `SHA-256("account:" ‖ N)`", and a Solana
program-derived address is SHA-256 by construction, so no implementation can read a checkpoint
account without it.

**Candidate readings.** INV-PRIM-01 is scoped to the log's own digests, with §2.4's uses outside
it; or INV-PRIM-01 is literal, in which case §2.4 contradicts it and a verifier cannot fetch a
root by itself.

**What forced the question.** The instruction that this verifier derive the address and decode the
account rather than take a Solana SDK, which is exactly where SHA-256 becomes unavoidable.

**What this verifier does.** Reads INV-PRIM-01 as scoped to log digests, keeps SHA-256 in one file
behind a comment that says where it may be used, and never lets it near a record, head, node, PRF
output or promise. The invariant should say "no SHA-256 in any log digest".

---

## D-9 · §2.3 — a proof's height is unbounded when no configured height is supplied

**What was needed.** What `InclusionVerifier::verify` does with a proof claiming height 20 and
twenty siblings.

**What the document says.** `verify_for_height` refuses a proof whose height is not the log's
(V-N-16b). Plain `verify` takes no such input. §1.8 bounds a log's `H` to [4, 16], and INV-TREE-06
fixes it per log.

**Candidate readings.** `verify` walks whatever height it is given, leaving the bound to the caller;
or §1.8's range binds every proof, so a height outside it is 0x13 before any hashing.

**What forced the question.** Deciding whether to bound `verify`. V-N-16 alters the sibling count
against a fixed `height` field and so does not reach this.

**What this verifier does.** Refuses a height outside [4, 16] in both functions, from §1.8.

---

## D-10 · §4.1 — KAT-01 and KAT-02 name vectors that are not in the document or the corpus

**What was needed.** The published Keccak-256 answers for the empty input, a one-byte input, and
the 135, 136 and 137-byte rate-boundary inputs, and the RFC 8032 §7.1 cases.

**What the document says.** §4.1 names all of them and says KAT-01 "runs first; a failure aborts
the build before anything else executes". Only KAT-03 is committed under `vectors/`.

**What forced the question.** Writing KAT-01. An implementer working from this document alone, as
this unit requires, cannot obtain the rate-boundary constants.

**What this verifier does.** Pins Keccak-256 of the empty string and of "abc", and RFC 8032 §7.1
TEST 1 and TEST 2, whose key pair the corpus itself depends on. For 1, 135, 136, 137 and 272 bytes
it checks the library's SHA3-256 against the platform's own SHA-3, which is the same sponge over
the same permutation at the same rate with a different pad byte, and checks that Keccak-256 and
SHA3-256 disagree and that streaming and one-shot absorption agree. That exercises the absorption
boundary the row is about; it is labelled in the test as a cross-implementation check and not as
the published KAT.

---

## D-11 · §1.2, E-03 — `TAG_CKPT` is defined, required of a writer, and never used

**What was needed.** The checkpoint preimage, since §1.2 declares `TAG_CKPT = b"CMv1CKPT"` and E-03
requires "domain-tagged, length-prefixed writers for asset, leaf, head, checkpoint, padding, SPI".

**What the document says.** No preimage anywhere in §1 uses `TAG_CKPT`; §2.4's instruction data
and account layout are Borsh fields with no tag; KAT-03 carries nine writers and no checkpoint.

**What forced the question.** Writing the tag table. D-80's rule about unreachable error codes
applies by the same reasoning to an unreachable domain tag.

**What this verifier does.** Declares the tag for completeness and builds no checkpoint preimage,
because there is nothing to build from. Nothing in the verifier depends on it.

---

## D-12 · §2.5 — `anchor` carries provenance that nothing says how to check

**What was needed.** Whether a conforming verifier must check `anchor.solana_tx` and
`anchor.solana_slot`, and against what.

**What the document says.** INV-DISC-02 requires inclusion "against a root it fetched from Solana
independently", and §2.3 says publication provenance comes from the checkpoint account of §2.4,
which "the client fetches and hands here", leaving that seam to the caller. §2.5 puts a transaction
signature and a slot in the package anyway, and INV-ANCH-05 makes `anchorStatus` a client concern.

**Candidate readings.** The `anchor` block is informational; or a verifier should confirm that the
named transaction is the one that wrote the epoch's checkpoint, which needs a second RPC method and
a transaction parser the document does not specify.

**What this verifier does.** Fetches the checkpoint account for `inclusion.epoch` at the address it
derives itself, checks that the account answers for that epoch, and ignores the `anchor` block.
README.md lists it under what the verifier does not check.

---

## D-13 · §2.3 — `SignedPromise` has no stated wire encoding, and the vectors carry one

**What was needed.** The byte layout behind V-P-10's and V-N-14's `encoded` field.

**What the document says.** §1.6 fixes the 73-byte SPI preimage. §2.3 declares the `SignedPromise`
struct. Nothing says how a promise travels.

**What this verifier does.** Borsh over §2.3's declared field order, which is 161 bytes and
reproduces both vectors exactly, including the batcher key and signature that follow the policy
fields. The reconstruction is checked by re-encoding, so a wrong guess would not have survived; the
document should still say it.

---

## Minor observations

- **§4.3's record vectors omit `c`.** Their `chain` blocks carry `head`, `seq` and
  `last_effective_at`, and condition (c) cannot run without the asset commitment, because the
  signature is over a preimage whose bytes 8 to 39 are `c`. V-N-03's unknown-scheme case is refused
  at (f), which proves (c) passed, which proves some particular `c` was used. The corpus names
  exactly one, `0xb98ec707…`, in V-P-01, V-P-02, V-P-03 and KAT-03, and the signatures verify under
  it. An implementer has to infer that. This is a defect in the vector set rather than the
  document, and it is the kind that a second implementation is likely to trip over.
- **V-P-11's unflagged case is a state no chain reaches.** It asks for the same record on a chain
  that "has seen a resource" while `seq` is 0 and `prev_head` is the genesis head, so the state has
  seen a record and holds none. The assertion it supports, that a flag does not change the leaf
  digest, is sound; the construction is not reachable by `apply`.
- **§2.5's example package is not labelled schema 1.** The `record` block carries no
  `schema_version`, and the schema gate of §1.3 is about the chain's version rather than the
  package's. A package produced under a later schema would be distinguishable only by the `schema`
  string, `"certimining/v1/disclosure"`, which names the package format and not the record's.
