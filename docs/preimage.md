# Preimages

Every digest in the engine is Keccak-256 over a preimage built by one of the writers in
`certimining-core::preimage`. No call site assembles one by hand, which is what closes ambiguous
concatenation as a collision path. This file describes what those writers produce; TCU-02 §1.2 to
§1.6 is the contract they follow.

## The four encoding rules

- **One tag, first** (INV-ENC-01). Each preimage opens with exactly one of the eight-byte domain
  tags of §1.2, so a digest computed for one purpose cannot be read as another.
- **Integers little-endian and fixed width** (INV-ENC-02). Digests and keys are raw bytes, never
  length-prefixed.
- **Signatures are over these bytes** (INV-ENC-03), not over any JSON rendering of them.
- **Byte strings carry a `u16` length** (INV-ENC-04). Borsh's own framing for a byte string is a
  `u32`; where the two differ, INV-ENC-04 governs, which is what §1.3 already required of the
  tenure.

## What each writer produces

| Writer | Tag | Fields, in order after the tag | Bytes |
|---|---|---|---|
| `AssetPreimage` | `CMv1ASST` | `J` 4, `R` 8, `len(T)` u16, `T` 1–64 | 23–86 |
| `GenesisHeadPreimage` | `CMv1HEAD` | `c` 32, `schema_version` u16 | 42 |
| `LeafPreimage` | `CMv1LEAF` | `c` 32, `seq` u64, `payload_digest` 32, `assessment_digest` 32, `qp_key` 32, `category` u8, `effective_at` i64, `change_identified_at` i64 | 161 |
| `StepHeadPreimage` | `CMv1HEAD` | `hₙ` 32, `leafₙ₊₁` 32 | 72 |
| `RealLeafPreimage` | `CMv1MTL0` | `leafₙ` 32 | 40 |
| `PaddingPreimage` | `CMv1PADD` | the slot's PRF output 32 | 40 |
| `NodePreimage` | `CMv1MTN1` | `left` 32, `right` 32 | 72 |
| `SpiPreimage` | `CMv1SPI0` | `leaf` 32, `submission_id` 16, `promised_epoch` u64, `max_merge_delay` u8 | 65 |

Two preimages share `CMv1HEAD`, the genesis head and each step. They cannot be confused, because one
is 42 bytes and the other 72.

`category`, `effective_at` and `change_identified_at` had no width in the spec until v0.1.4 settled
them (D-28), and the promise's two types had no definition until the same amendment (D-29).

## Using a writer

```rust
let leaf = LeafPreimage { /* fields */ };
let digest = leaf.digest::<NativeKeccak>()?;   // or SolanaKeccak, on-chain
```

The hasher is named at the call site, never chosen implicitly (D-20). To reach the bytes themselves,
for instance to place them in a disclosure package (§2.5), write into a `PreimageBuf` and read
`as_bytes`.

A `PreimageBuf` holds 256 bytes. A write that would pass that returns `0x0C`; the largest preimage
in schema 1 is the 161-byte leaf, so the limit is reached only by a caller writing something that is
not one of these preimages.

## Reading a tag

`read_tag` returns the eight bytes at the front of a buffer, and `check_tag` compares them with the
tag a reader expects. A buffer shorter than eight bytes is `0x05`, the code V-N-18 fixes for a
truncated buffer. Eight bytes that are not the expected tag is `0x0B` (V-N-09). Neither panics on
any input.

## Limits, and what lives elsewhere

- **The asset writer refuses a tenure that is not already canonical**, with `0x11`, exactly as
  `AssetIdentity::commitment` does; the commitment is that writer, so the two cannot drift.
- **Field values are not validated here.** A category outside 0 to 4 encodes without complaint; the
  state machine rejects it with `0x05` (V-N-07b, E-04). Flags never enter the leaf preimage
  (INV-STATE-06a), and neither does `payload_uri`.
- **The checkpoint preimage does not exist.** `CMv1CKPT` is reserved, the spec gives it no fields,
  and nothing reads one; it arrives with its consumer (D-30).
- **The PRF is not here.** Padding takes the PRF output as an input, so the epoch key never reaches
  this module (E-06).
- **Nothing on this path formats a string**, which a test enforces by reading the module's source.
- **Committed vectors arrive at E-05.** Until then KAT-03 builds its expected bytes from the spec
  inside the test (D-35).
