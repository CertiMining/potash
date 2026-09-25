/**
 * §1.4's fixed-capacity, count-hiding epoch tree: the PRF uses, slot assignment with linear
 * probing, padding leaves, the complete-tree build, and the pure inclusion verifier of §2.3.
 */
import { type Digest, bytesEqual, compareBytes, concat, readU16le, u16le, u64le } from "./bytes.ts";
import { RegistryFailure } from "./errors.ts";
import { keccak256 } from "./hash.ts";
import { nodePreimage, paddingLeafPreimage, prfPreimage, realLeafPreimage } from "./preimage.ts";

/** §1.1's three PRF use codes, which separate the three uses inside one construction. */
export const USE_EPOCH_KEY = 0x01;
export const USE_SLOT = 0x02;
export const USE_PADDING = 0x03;

export const MIN_HEIGHT = 4;
export const MAX_HEIGHT = 16;
/** §1.8's deployed default. Nothing in the verifier assumes it; it is checked against the log. */
export const DEFAULT_HEIGHT = 8;

export type SubmissionId = Uint8Array; // 16 bytes

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
  assignment: Array<{ submissionId: SubmissionId; slot: number }>;
};

export function capacityOf(height: number): number {
  return 1 << height;
}

function assertHeight(height: number): void {
  if (!Number.isInteger(height) || height < MIN_HEIGHT || height > MAX_HEIGHT) {
    throw new RegistryFailure("MalformedPayload", `tree height ${height} is outside [4, 16]`);
  }
}

/** `PRF(k, x) = Keccak256(TAG_PRF ‖ k ‖ len(x) ‖ x)`. */
export function prf(k: Digest, x: Uint8Array): Digest {
  return keccak256(prfPreimage(k, x));
}

/** INV-TREE-05: `k_e = PRF(k_master, 0x01 ‖ e_le)`. Derived per epoch, never published. */
export function epochKey(masterKey: Digest, epoch: bigint): Digest {
  return prf(masterKey, concat([Uint8Array.of(USE_EPOCH_KEY), u64le(epoch)]));
}

/** §1.4: the slot seed, `PRF(k_e, 0x02 ‖ submission_id)`. */
export function slotSeed(epochKeyDigest: Digest, submissionId: SubmissionId): Digest {
  if (submissionId.length !== 16) {
    throw new RegistryFailure("MalformedPayload", `submission_id must be 16 bytes, got ${submissionId.length}`);
  }
  return prf(epochKeyDigest, concat([Uint8Array.of(USE_SLOT), submissionId]));
}

/**
 * D-60: the PRF output is read as a little-endian integer and reduced modulo `C`. `C` is a power
 * of two, so that is the low `H` bits, which lie in the digest's first two bytes.
 */
export function slotFromSeed(seed: Digest, height: number): number {
  assertHeight(height);
  return readU16le(seed, 0) & (capacityOf(height) - 1);
}

/** §1.4: `padding leaf = Keccak256(TAG_PAD ‖ PRF(k_e, 0x03 ‖ slot_index_le))`. */
export function paddingLeaf(epochKeyDigest: Digest, slotIndex: number): Digest {
  const output = prf(epochKeyDigest, concat([Uint8Array.of(USE_PADDING), u16le(slotIndex)]));
  return keccak256(paddingLeafPreimage(output));
}

/** §1.4: `real leaf = Keccak256(TAG_MTL0 ‖ leafₙ)`. */
export function realLeaf(chainLeaf: Digest): Digest {
  return keccak256(realLeafPreimage(chainLeaf));
}

/** §1.4: `internal node = Keccak256(TAG_MTN1 ‖ left ‖ right)`. */
export function internalNode(left: Digest, right: Digest): Digest {
  return keccak256(nodePreimage(left, right));
}

/**
 * §1.4's slot assignment. Real submissions are assigned in ascending order of submission
 * identifier, so one set of submissions produces one tree whatever order the caller supplies them
 * in; the probe steps upward by one slot and wraps at `C`, taking the first free slot it meets.
 */
export function assignSlots(
  epochKeyDigest: Digest,
  height: number,
  real: Array<{ submissionId: SubmissionId; leaf: Digest }>,
): Array<{ submissionId: SubmissionId; slot: number; leaf: Digest }> {
  assertHeight(height);
  const capacity = capacityOf(height);
  if (real.length > capacity) {
    throw new RegistryFailure("EpochCapacityExceeded", `${real.length} real submissions into ${capacity} slots`);
  }
  const ordered = [...real].sort((a, b) => compareBytes(a.submissionId, b.submissionId));
  for (let i = 1; i < ordered.length; i++) {
    if (compareBytes(ordered[i - 1]!.submissionId, ordered[i]!.submissionId) === 0) {
      // Two submissions carrying the same identifier in one epoch is 0x05: the set is malformed,
      // and a proof could be answered for neither of them.
      throw new RegistryFailure("MalformedPayload", "two submissions carry the same identifier in one epoch");
    }
  }
  const taken = new Array<boolean>(capacity).fill(false);
  const out: Array<{ submissionId: SubmissionId; slot: number; leaf: Digest }> = [];
  for (const entry of ordered) {
    const start = slotFromSeed(slotSeed(epochKeyDigest, entry.submissionId), height);
    let slot = start;
    let steps = 0;
    while (taken[slot]) {
      slot = (slot + 1) % capacity;
      steps += 1;
      if (steps > capacity) throw new RegistryFailure("EpochCapacityExceeded", "no free slot");
    }
    taken[slot] = true;
    out.push({ submissionId: entry.submissionId, slot, leaf: entry.leaf });
  }
  return out;
}

/** The complete binary tree over all `C` slots. Its shape never varies with the record count. */
export function rootOf(leaves: Digest[]): Digest {
  let level = leaves;
  while (level.length > 1) {
    const next: Digest[] = [];
    for (let i = 0; i < level.length; i += 2) next.push(internalNode(level[i]!, level[i + 1]!));
    level = next;
  }
  return level[0]!;
}

/**
 * §2.3 `EpochTree::build`. `key` is `k_master`: the epoch key is derived inside, from the epoch
 * the tree already knows, so no caller can reuse one `k_e` across epochs (INV-TREE-05, D-63).
 */
export function buildEpoch(
  epoch: bigint,
  height: number,
  masterKey: Digest,
  real: Array<{ submissionId: SubmissionId; leaf: Digest }>,
): BuiltEpoch {
  assertHeight(height);
  const ke = epochKey(masterKey, epoch);
  const assigned = assignSlots(ke, height, real);
  const capacity = capacityOf(height);
  const leaves: Digest[] = new Array(capacity);
  for (const a of assigned) leaves[a.slot] = realLeaf(a.leaf);
  for (let i = 0; i < capacity; i++) if (leaves[i] === undefined) leaves[i] = paddingLeaf(ke, i);
  return {
    epoch,
    height,
    root: rootOf(leaves),
    leaves,
    assignment: assigned
      .map((a) => ({ submissionId: a.submissionId, slot: a.slot }))
      .sort((a, b) => compareBytes(a.submissionId, b.submissionId)),
  };
}

/** §2.3 `EpochTree::proof`. A submission this epoch does not hold is 0x16, not 0x13 (D-67). */
export function proofFor(built: BuiltEpoch, submissionId: SubmissionId): InclusionProof {
  const entry = built.assignment.find((a) => bytesEqual(a.submissionId, submissionId));
  if (entry === undefined) {
    throw new RegistryFailure("SubmissionNotInEpoch", "this epoch holds no such submission");
  }
  const siblings: Digest[] = [];
  let index = entry.slot;
  let level = built.leaves;
  while (level.length > 1) {
    const siblingIndex = index % 2 === 0 ? index + 1 : index - 1;
    siblings.push(level[siblingIndex]!);
    const next: Digest[] = [];
    for (let i = 0; i < level.length; i += 2) next.push(internalNode(level[i]!, level[i + 1]!));
    level = next;
    index = Math.floor(index / 2);
  }
  return { height: built.height, siblings, slotIndex: entry.slot, epoch: built.epoch };
}

/**
 * §2.3 `InclusionVerifier::verify`. Pure: no network, no clock, no storage, no batcher handle
 * (INV-IFACE-01). `leaf` is the chain leaf `leafₙ`; the verifier applies `TAG_MTL0` itself, so no
 * caller can omit the tag (INV-ENC-01, D-64).
 */
export function verifyInclusion(leaf: Digest, proof: InclusionProof, root: Digest): void {
  if (!Number.isInteger(proof.height) || proof.height < MIN_HEIGHT || proof.height > MAX_HEIGHT) {
    throw new RegistryFailure("InclusionProofInvalid", `proof height ${proof.height} is outside §1.8's [4, 16]`);
  }
  if (proof.siblings.length !== proof.height) {
    throw new RegistryFailure("InclusionProofInvalid", `${proof.siblings.length} siblings for height ${proof.height}`);
  }
  if (!Number.isInteger(proof.slotIndex) || proof.slotIndex < 0 || proof.slotIndex >= capacityOf(proof.height)) {
    throw new RegistryFailure("InclusionProofInvalid", `slot_index ${proof.slotIndex} is outside the tree`);
  }
  let node = realLeaf(leaf);
  for (let level = 0; level < proof.height; level++) {
    const sibling = proof.siblings[level]!;
    if (sibling.length !== 32) {
      throw new RegistryFailure("InclusionProofInvalid", `sibling at level ${level} is not 32 bytes`);
    }
    node = ((proof.slotIndex >> level) & 1) === 0 ? internalNode(node, sibling) : internalNode(sibling, node);
  }
  if (!bytesEqual(node, root)) {
    throw new RegistryFailure("InclusionProofInvalid", "the path does not reach the root");
  }
}

/**
 * §2.3 `InclusionVerifier::verify_for_height`: the same check for a caller that knows its log's
 * configured height. A proof whose `height` disagrees is 0x13 before any hashing (V-N-16b).
 */
export function verifyInclusionForHeight(
  leaf: Digest,
  proof: InclusionProof,
  root: Digest,
  configuredHeight: number,
): void {
  if (proof.height !== configuredHeight) {
    throw new RegistryFailure("InclusionProofInvalid", `proof height ${proof.height} is not the log's ${configuredHeight}`);
  }
  verifyInclusion(leaf, proof, root);
}
