/**
 * §1.2 / §1.3 / §1.4 / §1.6 preimage writers.
 *
 * Every preimage is assembled through one sink so that the tag-first rule (INV-ENC-01) and the
 * 256-byte ceiling (§2.2's `MAX_PREIMAGE_LEN`, which returns 0x0C) are enforced in a single place
 * rather than at nine call sites.
 */
import { type Digest, concat, i64le, u16le, u64le, bytesEqual } from "./bytes.ts";
import { RegistryFailure } from "./errors.ts";
import { TAG_ASSET, TAG_HEAD, TAG_LEAF, TAG_LEN, TAG_MTL0, TAG_MTN1, TAG_PAD, TAG_PRF, TAG_SPI } from "./tags.ts";

/** §2.2: `write` returns 0x0C if the preimage would exceed MAX_PREIMAGE_LEN, which is 256. */
export const MAX_PREIMAGE_LEN = 256;

export class PreimageSink {
  private parts: Uint8Array[] = [];
  private len = 0;

  write(bytes: Uint8Array): void {
    if (this.len + bytes.length > MAX_PREIMAGE_LEN) {
      throw new RegistryFailure("RecordTooLarge", `preimage would reach ${this.len + bytes.length} bytes`);
    }
    this.parts.push(bytes);
    this.len += bytes.length;
  }

  bytes(): Uint8Array {
    return concat(this.parts);
  }
}

function build(tag: Uint8Array, fields: Uint8Array[]): Uint8Array {
  const sink = new PreimageSink();
  sink.write(tag); // INV-ENC-01: exactly one domain tag, first
  for (const f of fields) sink.write(f);
  return sink.bytes();
}

function fixed(name: string, b: Uint8Array, len: number): Uint8Array {
  if (b.length !== len) throw new RegistryFailure("MalformedPayload", `${name} must be ${len} bytes, got ${b.length}`);
  return b;
}

/**
 * Reads a preimage that is expected to carry `tag`. A preimage read under a tag other than its
 * own is 0x0B (V-N-09) — the check that makes the two TAG_HEAD shapes and everything else
 * un-confusable at the boundary.
 */
export function readTagged(preimage: Uint8Array, expectedTag: Uint8Array): Uint8Array {
  if (preimage.length < TAG_LEN) throw new RegistryFailure("MalformedPayload", "preimage shorter than its tag");
  if (!bytesEqual(preimage.subarray(0, TAG_LEN), expectedTag)) {
    throw new RegistryFailure("DomainTagMismatch", "preimage carries a different domain tag");
  }
  return preimage.subarray(TAG_LEN);
}

/** §1.3 `c = TAG_ASSET ‖ J ‖ R ‖ len(T) ‖ T`. `T` must already be canonical; the caller checks that. */
export function assetPreimage(j: Uint8Array, r: Uint8Array, tenure: Uint8Array): Uint8Array {
  fixed("jurisdiction", j, 4);
  fixed("registry", r, 8);
  if (tenure.length < 1 || tenure.length > 64) {
    throw new RegistryFailure("CanonicalizationFailed", `tenure must be 1..64 bytes, got ${tenure.length}`);
  }
  return build(TAG_ASSET, [j, r, u16le(tenure.length), tenure]);
}

/** §1.3 `h₀ = TAG_HEAD ‖ c ‖ schema_version`. */
export function genesisHeadPreimage(c: Digest, schemaVersion: number): Uint8Array {
  return build(TAG_HEAD, [fixed("asset commitment", c, 32), u16le(schemaVersion)]);
}

export type LeafFields = {
  seq: bigint;
  payloadDigest: Digest;
  assessmentDigest: Digest;
  qpKey: Uint8Array;
  category: number;
  effectiveAt: bigint;
  changeIdentifiedAt: bigint;
};

/** §1.3's 161-byte leaf preimage: the bytes the QP signs and a package carries as `preimage_borsh`. */
export function leafPreimage(c: Digest, f: LeafFields): Uint8Array {
  if (!Number.isInteger(f.category) || f.category < 0 || f.category > 255) {
    throw new RegistryFailure("MalformedPayload", `category is a u8, got ${f.category}`);
  }
  return build(TAG_LEAF, [
    fixed("asset commitment", c, 32),
    u64le(f.seq),
    fixed("payload digest", f.payloadDigest, 32),
    fixed("assessment digest", f.assessmentDigest, 32),
    fixed("qp key", f.qpKey, 32),
    Uint8Array.of(f.category),
    i64le(f.effectiveAt),
    i64le(f.changeIdentifiedAt),
  ]);
}

/** §1.3 `hₙ₊₁ = TAG_HEAD ‖ hₙ ‖ leafₙ₊₁`. Its length differs from h₀'s, which is what keeps them apart. */
export function stepHeadPreimage(prevHead: Digest, leaf: Digest): Uint8Array {
  return build(TAG_HEAD, [fixed("previous head", prevHead, 32), fixed("leaf", leaf, 32)]);
}

/** §1.4 real leaf: `TAG_MTL0 ‖ leafₙ`. */
export function realLeafPreimage(leaf: Digest): Uint8Array {
  return build(TAG_MTL0, [fixed("leaf", leaf, 32)]);
}

/** §1.4 padding leaf: `TAG_PAD ‖ PRF(k_e, 0x03 ‖ slot_index_le)`. */
export function paddingLeafPreimage(prfOutput: Digest): Uint8Array {
  return build(TAG_PAD, [fixed("prf output", prfOutput, 32)]);
}

/** §1.4 internal node: `TAG_MTN1 ‖ left ‖ right`. */
export function nodePreimage(left: Digest, right: Digest): Uint8Array {
  return build(TAG_MTN1, [fixed("left", left, 32), fixed("right", right, 32)]);
}

/** §1.1 `PRF(k, x) = Keccak256(TAG_PRF ‖ k ‖ len(x) ‖ x)`, `len(x)` a u16 LE (INV-ENC-04). */
export function prfPreimage(k: Digest, x: Uint8Array): Uint8Array {
  return build(TAG_PRF, [fixed("prf key", k, 32), u16le(x.length), x]);
}

export type PromiseFields = {
  leaf: Digest;
  submissionId: Uint8Array;
  acceptedEpoch: bigint;
  promisedEpoch: bigint;
  maxMergeDelay: number;
};

/** §1.6's 73-byte SPI preimage. */
export function spiPreimage(p: PromiseFields): Uint8Array {
  if (!Number.isInteger(p.maxMergeDelay) || p.maxMergeDelay < 0 || p.maxMergeDelay > 255) {
    throw new RegistryFailure("MalformedPayload", "max_merge_delay is a u8");
  }
  return build(TAG_SPI, [
    fixed("leaf", p.leaf, 32),
    fixed("submission id", p.submissionId, 16),
    u64le(p.acceptedEpoch),
    u64le(p.promisedEpoch),
    Uint8Array.of(p.maxMergeDelay),
  ]);
}
