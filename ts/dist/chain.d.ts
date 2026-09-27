/**
 * §1.3's asset chain: the commitment, the genesis head, the leaf, and the transition
 * `S_{n+1} = f(S_n, R_{n+1})` with its four stages and six conditions.
 */
import { type Digest } from "./bytes.ts";
import { type LeafFields } from "./preimage.ts";
export declare const SCHEMA_VERSION = 1;
export declare const U64_MAX = 18446744073709551615n;
/** INV-STATE-06a: schema-1 flag bits. Bits 2–15 are reserved and zero. */
export declare const FLAG_RESERVE_WITHOUT_PRIOR_RESOURCE: number;
export declare const FLAG_CATEGORY_DOWNGRADE: number;
export declare const CATEGORY_MIN = 0;
export declare const CATEGORY_MAX = 4;
/** §1.3: 0 Inferred, 1 Indicated, 2 Measured are resources; 3 Probable, 4 Proven are reserves. */
export declare const RESOURCE_CATEGORIES: number[];
export declare const FIRST_RESERVE_CATEGORY = 3;
export type RecordLeafInput = {
    prevHead: Digest;
    seq: bigint;
    payloadDigest: Digest;
    assessmentDigest: Digest;
    qpKey: Uint8Array;
    expectedQpKey: Uint8Array | null;
    signature: Uint8Array | null;
    category: number;
    effectiveAt: bigint;
    changeIdentifiedAt: bigint;
    payloadUri: Uint8Array;
    extCommitment: Digest | null;
};
export type ChainState = {
    /** `c`, which the chain holds; §2.2 keeps it out of `RecordLeafInput`. */
    assetCommitment: Digest;
    schemaVersion: number;
    head: Digest;
    seq: bigint;
    lastEffectiveAt: bigint | null;
    sawResource: boolean;
    previousCategory: number | null;
};
export type Applied = {
    leaf: Digest;
    head: Digest;
    flags: number;
};
/** §1.3 `c`. `commitment` refuses any `T` that is not already canonical, with 0x11. */
export declare function assetCommitment(j: Uint8Array, r: Uint8Array, tenure: Uint8Array): Digest;
/** Canonicalizes a raw spelling and then commits to it. */
export declare function assetCommitmentFromRaw(j: Uint8Array, r: Uint8Array, rawTenure: Uint8Array): Digest;
/** §1.3 `h₀`. A schema this engine does not implement is 0x0F (V-N-13). */
export declare function genesisHead(assetCommitmentDigest: Digest, schemaVersion: number): Digest;
export declare function leafFieldsOf(r: RecordLeafInput): LeafFields;
/** The 161 bytes the QP signs (INV-ENC-03) and a package carries as `preimage_borsh`. */
export declare function leafPreimageOf(assetCommitmentDigest: Digest, r: RecordLeafInput): Uint8Array;
export declare function leafDigest(assetCommitmentDigest: Digest, r: RecordLeafInput): Digest;
/** §1.3 `hₙ₊₁ = Keccak256(TAG_HEAD ‖ hₙ ‖ leafₙ₊₁)`. */
export declare function advanceHead(prevHead: Digest, leaf: Digest): Digest;
/**
 * §1.3's well-formed `payload_uri`: one to 128 bytes, printable ASCII only, one of three schemes,
 * at least one byte after the scheme, no whitespace and no control byte. Nothing further is parsed.
 */
export declare function isWellFormedPayloadUri(uri: Uint8Array): boolean;
/** INV-STATE-06 / 06a: what the engine noticed, never a verdict, and never a rejection path. */
export declare function computeFlags(state: ChainState, category: number): number;
/**
 * §1.3's transition. The stages run in the order the document fixes, and the first stage a record
 * fails decides its code; within stage 3 the first condition it fails decides (V-N-23, V-N-24).
 *
 * Stage 1, decode, has no work here: the caller hands in a decoded record.
 */
export declare function applyRecord(state: ChainState, r: RecordLeafInput): Applied;
/** The state after an accepted transition. Append-only: nothing here decrements or rewrites. */
export declare function commit(state: ChainState, r: RecordLeafInput, applied: Applied): ChainState;
