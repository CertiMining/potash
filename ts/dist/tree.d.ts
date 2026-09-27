/**
 * §1.4's fixed-capacity, count-hiding epoch tree: the PRF uses, slot assignment with linear
 * probing, padding leaves, the complete-tree build, and the pure inclusion verifier of §2.3.
 */
import { type Digest } from "./bytes.ts";
/** §1.1's three PRF use codes, which separate the three uses inside one construction. */
export declare const USE_EPOCH_KEY = 1;
export declare const USE_SLOT = 2;
export declare const USE_PADDING = 3;
export declare const MIN_HEIGHT = 4;
export declare const MAX_HEIGHT = 16;
/** §1.8's deployed default. Nothing in the verifier assumes it; it is checked against the log. */
export declare const DEFAULT_HEIGHT = 8;
export type SubmissionId = Uint8Array;
export type InclusionProof = {
    height: number;
    siblings: Digest[];
    slotIndex: number;
    epoch: bigint;
};
export type BuiltEpoch = {
    epoch: bigint;
    height: number;
    root: Digest;
    leaves: Digest[];
    assignment: Array<{
        submissionId: SubmissionId;
        slot: number;
    }>;
};
export declare function capacityOf(height: number): number;
/** `PRF(k, x) = Keccak256(TAG_PRF ‖ k ‖ len(x) ‖ x)`. */
export declare function prf(k: Digest, x: Uint8Array): Digest;
/** INV-TREE-05: `k_e = PRF(k_master, 0x01 ‖ e_le)`. Derived per epoch, never published. */
export declare function epochKey(masterKey: Digest, epoch: bigint): Digest;
/** §1.4: the slot seed, `PRF(k_e, 0x02 ‖ submission_id)`. */
export declare function slotSeed(epochKeyDigest: Digest, submissionId: SubmissionId): Digest;
/**
 * D-60: the PRF output is read as a little-endian integer and reduced modulo `C`. `C` is a power
 * of two, so that is the low `H` bits, which lie in the digest's first two bytes.
 */
export declare function slotFromSeed(seed: Digest, height: number): number;
/** §1.4: `padding leaf = Keccak256(TAG_PAD ‖ PRF(k_e, 0x03 ‖ slot_index_le))`. */
export declare function paddingLeaf(epochKeyDigest: Digest, slotIndex: number): Digest;
/** §1.4: `real leaf = Keccak256(TAG_MTL0 ‖ leafₙ)`. */
export declare function realLeaf(chainLeaf: Digest): Digest;
/** §1.4: `internal node = Keccak256(TAG_MTN1 ‖ left ‖ right)`. */
export declare function internalNode(left: Digest, right: Digest): Digest;
/**
 * §1.4's slot assignment. Real submissions are assigned in ascending order of submission
 * identifier, so one set of submissions produces one tree whatever order the caller supplies them
 * in; the probe steps upward by one slot and wraps at `C`, taking the first free slot it meets.
 */
export declare function assignSlots(epochKeyDigest: Digest, height: number, real: Array<{
    submissionId: SubmissionId;
    leaf: Digest;
}>): Array<{
    submissionId: SubmissionId;
    slot: number;
    leaf: Digest;
}>;
/** The complete binary tree over all `C` slots. Its shape never varies with the record count. */
export declare function rootOf(leaves: Digest[]): Digest;
/**
 * §2.3 `EpochTree::build`. `key` is `k_master`: the epoch key is derived inside, from the epoch
 * the tree already knows, so no caller can reuse one `k_e` across epochs (INV-TREE-05, D-63).
 */
export declare function buildEpoch(epoch: bigint, height: number, masterKey: Digest, real: Array<{
    submissionId: SubmissionId;
    leaf: Digest;
}>): BuiltEpoch;
/** §2.3 `EpochTree::proof`. A submission this epoch does not hold is 0x16, not 0x13 (D-67). */
export declare function proofFor(built: BuiltEpoch, submissionId: SubmissionId): InclusionProof;
/**
 * §2.3 `InclusionVerifier::verify`. Pure: no network, no clock, no storage, no batcher handle
 * (INV-IFACE-01). `leaf` is the chain leaf `leafₙ`; the verifier applies `TAG_MTL0` itself, so no
 * caller can omit the tag (INV-ENC-01, D-64).
 */
export declare function verifyInclusion(leaf: Digest, proof: InclusionProof, root: Digest): void;
/**
 * §2.3 `InclusionVerifier::verify_for_height`: the same check for a caller that knows its log's
 * configured height. A proof whose `height` disagrees is 0x13 before any hashing (V-N-16b).
 */
export declare function verifyInclusionForHeight(leaf: Digest, proof: InclusionProof, root: Digest, configuredHeight: number): void;
