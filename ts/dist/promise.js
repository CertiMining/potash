/**
 * §1.6's signed inclusion promise (SPI): its digest, its wire form, the policy §1.6 fixes, and
 * D-72's rule about which roots can rebut an accusation.
 */
import { bytesEqual, concat, readU64le, u64le } from "./bytes.js";
import { RegistryFailure } from "./errors.js";
import { ed25519Verify, keccak256 } from "./hash.js";
import { spiPreimage } from "./preimage.js";
import { verifyInclusion } from "./tree.js";
/** INV-SPI-01 fixes it at 2 epochs. The key holder does not choose the policy it is judged against. */
export const MAX_MERGE_DELAY = 2;
/** The 73-byte preimage of §1.6, and the digest the batcher actually signs. */
export function spiDigest(p) {
    return keccak256(spiPreimage({
        leaf: p.leaf,
        submissionId: p.submissionId,
        acceptedEpoch: p.acceptedEpoch,
        promisedEpoch: p.promisedEpoch,
        maxMergeDelay: p.maxMergeDelay,
    }));
}
export const PROMISE_ENCODED_LEN = 161;
/** Borsh over §2.3's `SignedPromise` in its declared field order. */
export function encodePromise(p) {
    return concat([
        p.leaf,
        p.submissionId,
        u64le(p.acceptedEpoch),
        u64le(p.promisedEpoch),
        Uint8Array.of(p.maxMergeDelay),
        p.batcherKey,
        p.signature,
    ]);
}
export function decodePromise(b) {
    if (b.length !== PROMISE_ENCODED_LEN) {
        throw new RegistryFailure("MalformedPayload", `a promise is ${PROMISE_ENCODED_LEN} bytes, got ${b.length}`);
    }
    return {
        leaf: b.slice(0, 32),
        submissionId: b.slice(32, 48),
        acceptedEpoch: readU64le(b, 48),
        promisedEpoch: readU64le(b, 56),
        maxMergeDelay: b[64],
        batcherKey: b.slice(65, 97),
        signature: b.slice(97, 161),
    };
}
/**
 * §2.3 `verify_promise`. A key mismatch is 0x08, decided first. A signature proves authorship and
 * not compliance, so a `max_merge_delay` other than INV-SPI-01's, a `promised_epoch` outside the
 * window the signed `accepted_epoch` allows, or an `accepted_epoch` that is not the observed epoch
 * or exactly one behind it, is 0x17. A signature that does not verify is 0x07.
 *
 * `observedEpoch` is the caller's own reading of the checkpoint sequence when the promise arrived.
 * Nothing in the artifact can supply it (§1.6's three statements), so it is an input.
 */
export function verifyPromise(promise, expectedBatcherKey, observedEpoch) {
    if (!bytesEqual(promise.batcherKey, expectedBatcherKey)) {
        throw new RegistryFailure("AttestationKeyMismatch", "the promise names a batcher key the counterparty does not expect");
    }
    if (promise.maxMergeDelay !== MAX_MERGE_DELAY) {
        throw new RegistryFailure("PromisePolicyInvalid", `max_merge_delay ${promise.maxMergeDelay}, and INV-SPI-01 fixes it at ${MAX_MERGE_DELAY}`);
    }
    // Backdating: an acceptance epoch later than observed lets a batcher defer its own
    // accountability. One epoch behind is allowed because a promise can cross an epoch boundary.
    if (promise.acceptedEpoch > observedEpoch || promise.acceptedEpoch + 1n < observedEpoch) {
        throw new RegistryFailure("PromisePolicyInvalid", `accepted_epoch ${promise.acceptedEpoch} against an observed ${observedEpoch}`);
    }
    if (promise.promisedEpoch < promise.acceptedEpoch ||
        promise.promisedEpoch > promise.acceptedEpoch + BigInt(promise.maxMergeDelay)) {
        throw new RegistryFailure("PromisePolicyInvalid", `promised_epoch ${promise.promisedEpoch} is outside the accepted window`);
    }
    if (!ed25519Verify(promise.batcherKey, spiDigest(promise), promise.signature)) {
        throw new RegistryFailure("AttestationInvalid", "the promise's signature does not verify over the SPI digest");
    }
}
/**
 * §2.3 `promise_kept`. The proof must be for the same epoch as the root it is checked against,
 * that epoch must fall inside the promised window, and the path must verify for the promise's own
 * leaf. Outside the window in either direction is 0x14 (D-72); an inconsistent or failing proof is
 * 0x13. It does not establish that the root was published: provenance is the caller's seam.
 */
export function promiseKept(promise, proof, published) {
    if (proof.epoch !== published.epoch) {
        throw new RegistryFailure("InclusionProofInvalid", "the proof is for a different epoch than the root");
    }
    const windowEnd = promise.promisedEpoch + BigInt(promise.maxMergeDelay);
    if (published.epoch < promise.promisedEpoch || published.epoch > windowEnd) {
        throw new RegistryFailure("MergeDelayExceeded", `epoch ${published.epoch} is outside ${promise.promisedEpoch}..${windowEnd}`);
    }
    verifyInclusion(promise.leaf, proof, published.root);
}
