/**
 * §1.6's signed inclusion promise (SPI): its digest, its wire form, the policy §1.6 fixes, and
 * D-72's rule about which roots can rebut an accusation.
 */
import { type Digest } from "./bytes.ts";
import { type InclusionProof } from "./tree.ts";
/** INV-SPI-01 fixes it at 2 epochs. The key holder does not choose the policy it is judged against. */
export declare const MAX_MERGE_DELAY = 2;
export type SignedPromise = {
    leaf: Digest;
    submissionId: Uint8Array;
    acceptedEpoch: bigint;
    promisedEpoch: bigint;
    maxMergeDelay: number;
    /** Carried for display, never the authority: `verifyPromise` takes the key the counterparty expects. */
    batcherKey: Uint8Array;
    signature: Uint8Array;
};
export type PublishedRoot = {
    epoch: bigint;
    root: Digest;
};
/** The 73-byte preimage of §1.6, and the digest the batcher actually signs. */
export declare function spiDigest(p: SignedPromise): Digest;
export declare const PROMISE_ENCODED_LEN = 161;
/** Borsh over §2.3's `SignedPromise` in its declared field order. */
export declare function encodePromise(p: SignedPromise): Uint8Array;
export declare function decodePromise(b: Uint8Array): SignedPromise;
/**
 * §2.3 `verify_promise`. A key mismatch is 0x08, decided first. A signature proves authorship and
 * not compliance, so a `max_merge_delay` other than INV-SPI-01's, a `promised_epoch` outside the
 * window the signed `accepted_epoch` allows, or an `accepted_epoch` that is not the observed epoch
 * or exactly one behind it, is 0x17. A signature that does not verify is 0x07.
 *
 * `observedEpoch` is the caller's own reading of the checkpoint sequence when the promise arrived.
 * Nothing in the artifact can supply it (§1.6's three statements), so it is an input.
 */
export declare function verifyPromise(promise: SignedPromise, expectedBatcherKey: Uint8Array, observedEpoch: bigint): void;
/**
 * §2.3 `promise_kept`. The proof must be for the same epoch as the root it is checked against,
 * that epoch must fall inside the promised window, and the path must verify for the promise's own
 * leaf. Outside the window in either direction is 0x14 (D-72); an inconsistent or failing proof is
 * 0x13. It does not establish that the root was published: provenance is the caller's seam.
 */
export declare function promiseKept(promise: SignedPromise, proof: InclusionProof, published: PublishedRoot): void;
