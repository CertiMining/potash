# The supersession state machine

One chain per asset, append-only. Each record commits against its predecessor's head, and the engine
offers no way to delete, compact or rewrite anything (INV-STATE-01). This file describes what
`certimining-core::state` does; TCU-02 §1.3 is the contract it follows.

## Starting and resuming a chain

`AssetChain::start` takes the asset commitment and a schema version, and computes the genesis head
`h₀ = Keccak256( TAG_HEAD ‖ c ‖ schema_version )`. Any schema version but 1 returns `0x0F`.

A chain outlives the process that built it, so `snapshot` returns everything needed to continue it
and `resume` takes that back. A snapshot carries the head, the sequence number, the newest effective
date, whether a resource record has been seen, and the previous record's category. The last two are
there because both flags need history rather than just the head.

## Applying a record

```rust
let applied = chain.apply(&record)?;   // Applied { leaf, head, flags }
```

A record passes four stages, and **the first stage it fails decides its code**. Decoding stands
before all of them and belongs to whoever reads a record off the wire: a buffer that does not decode
has no fields to judge. This module takes a decoded record.

| Stage | Rule | Code when it fails |
|---|---|---|
| Schema gate | the record carries no `ext_commitment`: under INV-FWD-01 an extension arrives as a new schema version, so a record carrying one is asking for schema 2 | `0x0F` |
| (a) | `prev_head` equals the current head | `0x03` |
| (b) | `seq` is the chain's next, computed with checked arithmetic | `0x04`, or `0x10` at the limit |
| (c) | the QP's signature verifies over the leaf preimage | `0x06`, `0x07` or `0x08` |
| (d) | `effective_at` is not earlier than the previous record's | `0x0A` |
| (e) | the category sequence | never rejects; sets a flag |
| (f) | category in 0 to 4, and `payload_uri` well formed | `0x05` |

So a record with both a wrong head and a broken URI returns `0x03`, and one carrying an extension
alongside a wrong head returns `0x0F`. The flags of (e) are computed once (f) has passed, because
they only matter on a record that is accepted.

A refused record leaves the chain exactly as it was, whatever refused it.

`apply` returns the three things one transition produces: the leaf the batcher submits, the chain's
new head, and the flags. It is `#[must_use]`, so dropping the result is a compiler warning — the
leaf is the value the batching path depends on. There is deliberately no `flags` accessor: its
answer would depend on when it was called, and a flag read against the wrong record is the kind of
fault that shows up later in a disclosure package.

## What the QP signs

The signature covers the **161-byte leaf preimage**, the bytes a disclosure package carries as
`preimage_borsh`, not the leaf digest. A signature over any other encoding, JSON included, fails
with `0x07`. That is what V-N-05 tests, and KAT-02's tests include the case of signing the digest by
mistake.

The three attestation codes divide like this: no signature at all is `0x06`; a record whose expected
QP key differs from the key it claims is `0x08`, decided before any verification runs; and a
signature that does not verify under the claimed key is `0x07`.

Verification itself is named by the caller, exactly as the hasher is, and only the `native` feature
carries an implementation. A program built for Solana has no verifier at all, which is what
INV-PRIM-02 requires.

## Flags

Two bits under schema 1, both observations and never a rejection (INV-STATE-06a):

- **Bit 0, reserve without a prior resource.** Set when the record carries a reserve category, 3 or
  4, and no earlier record in the chain carried category 1 or 2.
- **Bit 1, category downgrade.** Set when the record's category is lower than the previous record's.
  Never set on the first record.

Categories 0 to 2 are resource confidence levels and 3 to 4 are reserve levels, so a return from
Probable to Measured sets bit 1, which is the case worth noticing, while a conversion from Measured
to Probable sets nothing.

Flags are computed from chain state and stay out of the leaf preimage, so a flagged record and an
unflagged one with identical fields have the same leaf digest. A test holds that. Error `0x09` is
reserved and never returned: the engine records the category sequence and leaves the judgement to
the reader (D-01).

## `payload_uri`

One to 128 bytes, printable ASCII only, beginning with `ipfs://`, `https://` or `ar://`, with at
least one byte after the scheme and no whitespace or control byte. Nothing else is parsed: no URI is
resolved, no host is checked. The field is validated and never hashed.

## Limits, and what lives elsewhere

- **Nothing here touches the epoch tree.** Slot assignment, padding and the tree are E-06's; the
  batcher and its promises are E-07's.
- **The extension hook is refused, not ignored.** `ext_commitment` is reserved for a later module
  and carries nothing under schema 1, so a record that sets it returns `0x0F` rather than being
  accepted with the field silently dropped.
- **Committed vectors arrive at E-05.** The tests here prove the relationships §4.2 names — genesis
  is deterministic, a chain recomputes from a later head to the same result, a flag does not move a
  digest — and the fixed values land with the generator.
- **Dates are not validated beyond ordering.** A record may carry any `effective_at` that is not
  earlier than its predecessor's, including one in the future; the engine records what was filed.
