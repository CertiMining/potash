/**
 * §1.2 / §1.3 / §1.4 / §1.6 preimage writers.
 *
 * Every preimage is assembled through one sink so that the tag-first rule (INV-ENC-01) and the
 * 256-byte ceiling (§2.2's `MAX_PREIMAGE_LEN`, which returns 0x0C) are enforced in a single place
 * rather than at nine call sites.
 */
import { type Digest } from "./bytes.ts";
/** §2.2: `write` returns 0x0C if the preimage would exceed MAX_PREIMAGE_LEN, which is 256. */
export declare const MAX_PREIMAGE_LEN = 256;
export declare class PreimageSink {
    private parts;
    private len;
    write(bytes: Uint8Array): void;
    bytes(): Uint8Array;
}
/**
 * Reads a preimage that is expected to carry `tag`. A preimage read under a tag other than its
 * own is 0x0B (V-N-09) — the check that makes the two TAG_HEAD shapes and everything else
 * un-confusable at the boundary.
 */
export declare function readTagged(preimage: Uint8Array, expectedTag: Uint8Array): Uint8Array;
/** §1.3 `c = TAG_ASSET ‖ J ‖ R ‖ len(T) ‖ T`. `T` must already be canonical; the caller checks that. */
export declare function assetPreimage(j: Uint8Array, r: Uint8Array, tenure: Uint8Array): Uint8Array;
/** §1.3 `h₀ = TAG_HEAD ‖ c ‖ schema_version`. */
export declare function genesisHeadPreimage(c: Digest, schemaVersion: number): Uint8Array;
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
export declare function leafPreimage(c: Digest, f: LeafFields): Uint8Array;
/** §1.3 `hₙ₊₁ = TAG_HEAD ‖ hₙ ‖ leafₙ₊₁`. Its length differs from h₀'s, which is what keeps them apart. */
export declare function stepHeadPreimage(prevHead: Digest, leaf: Digest): Uint8Array;
/** §1.4 real leaf: `TAG_MTL0 ‖ leafₙ`. */
export declare function realLeafPreimage(leaf: Digest): Uint8Array;
/** §1.4 padding leaf: `TAG_PAD ‖ PRF(k_e, 0x03 ‖ slot_index_le)`. */
export declare function paddingLeafPreimage(prfOutput: Digest): Uint8Array;
/** §1.4 internal node: `TAG_MTN1 ‖ left ‖ right`. */
export declare function nodePreimage(left: Digest, right: Digest): Uint8Array;
/** §1.1 `PRF(k, x) = Keccak256(TAG_PRF ‖ k ‖ len(x) ‖ x)`, `len(x)` a u16 LE (INV-ENC-04). */
export declare function prfPreimage(k: Digest, x: Uint8Array): Uint8Array;
export type PromiseFields = {
    leaf: Digest;
    submissionId: Uint8Array;
    acceptedEpoch: bigint;
    promisedEpoch: bigint;
    maxMergeDelay: number;
};
/** §1.6's 73-byte SPI preimage. */
export declare function spiPreimage(p: PromiseFields): Uint8Array;
