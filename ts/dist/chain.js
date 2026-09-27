/**
 * §1.3's asset chain: the commitment, the genesis head, the leaf, and the transition
 * `S_{n+1} = f(S_n, R_{n+1})` with its four stages and six conditions.
 */
import { bytesEqual } from "./bytes.js";
import { RegistryFailure } from "./errors.js";
import { canonicalizeBytes, isCanonicalTenure } from "./canonical.js";
import { ed25519Verify, keccak256 } from "./hash.js";
import { assetPreimage, genesisHeadPreimage, leafPreimage, stepHeadPreimage } from "./preimage.js";
export const SCHEMA_VERSION = 1;
export const U64_MAX = 0xffffffffffffffffn;
/** INV-STATE-06a: schema-1 flag bits. Bits 2–15 are reserved and zero. */
export const FLAG_RESERVE_WITHOUT_PRIOR_RESOURCE = 1 << 0;
export const FLAG_CATEGORY_DOWNGRADE = 1 << 1;
export const CATEGORY_MIN = 0;
export const CATEGORY_MAX = 4;
/** §1.3: 0 Inferred, 1 Indicated, 2 Measured are resources; 3 Probable, 4 Proven are reserves. */
export const RESOURCE_CATEGORIES = [1, 2];
export const FIRST_RESERVE_CATEGORY = 3;
/** §1.3 `c`. `commitment` refuses any `T` that is not already canonical, with 0x11. */
export function assetCommitment(j, r, tenure) {
    if (!isCanonicalTenure(tenure)) {
        throw new RegistryFailure("CanonicalizationFailed", "tenure is not in canonical form");
    }
    return keccak256(assetPreimage(j, r, tenure));
}
/** Canonicalizes a raw spelling and then commits to it. */
export function assetCommitmentFromRaw(j, r, rawTenure) {
    return assetCommitment(j, r, canonicalizeBytes(rawTenure));
}
/** §1.3 `h₀`. A schema this engine does not implement is 0x0F (V-N-13). */
export function genesisHead(assetCommitmentDigest, schemaVersion) {
    if (schemaVersion !== SCHEMA_VERSION) {
        throw new RegistryFailure("UnsupportedSchemaVersion", `schema_version ${schemaVersion}`);
    }
    return keccak256(genesisHeadPreimage(assetCommitmentDigest, schemaVersion));
}
export function leafFieldsOf(r) {
    return {
        seq: r.seq,
        payloadDigest: r.payloadDigest,
        assessmentDigest: r.assessmentDigest,
        qpKey: r.qpKey,
        category: r.category,
        effectiveAt: r.effectiveAt,
        changeIdentifiedAt: r.changeIdentifiedAt,
    };
}
/** The 161 bytes the QP signs (INV-ENC-03) and a package carries as `preimage_borsh`. */
export function leafPreimageOf(assetCommitmentDigest, r) {
    return leafPreimage(assetCommitmentDigest, leafFieldsOf(r));
}
export function leafDigest(assetCommitmentDigest, r) {
    return keccak256(leafPreimageOf(assetCommitmentDigest, r));
}
/** §1.3 `hₙ₊₁ = Keccak256(TAG_HEAD ‖ hₙ ‖ leafₙ₊₁)`. */
export function advanceHead(prevHead, leaf) {
    return keccak256(stepHeadPreimage(prevHead, leaf));
}
const URI_SCHEMES = ["ipfs://", "https://", "ar://"];
/**
 * §1.3's well-formed `payload_uri`: one to 128 bytes, printable ASCII only, one of three schemes,
 * at least one byte after the scheme, no whitespace and no control byte. Nothing further is parsed.
 */
export function isWellFormedPayloadUri(uri) {
    if (uri.length < 1 || uri.length > 128)
        return false;
    for (const b of uri) {
        // Printable ASCII, with space and every control byte excluded.
        if (b <= 0x20 || b >= 0x7f)
            return false;
    }
    let text = "";
    for (const b of uri)
        text += String.fromCharCode(b);
    for (const scheme of URI_SCHEMES) {
        if (text.startsWith(scheme) && text.length > scheme.length)
            return true;
    }
    return false;
}
/** INV-STATE-06 / 06a: what the engine noticed, never a verdict, and never a rejection path. */
export function computeFlags(state, category) {
    let flags = 0;
    if (category >= FIRST_RESERVE_CATEGORY && !state.sawResource) {
        flags |= FLAG_RESERVE_WITHOUT_PRIOR_RESOURCE;
    }
    if (state.previousCategory !== null && category < state.previousCategory) {
        flags |= FLAG_CATEGORY_DOWNGRADE;
    }
    return flags;
}
/**
 * §1.3's transition. The stages run in the order the document fixes, and the first stage a record
 * fails decides its code; within stage 3 the first condition it fails decides (V-N-23, V-N-24).
 *
 * Stage 1, decode, has no work here: the caller hands in a decoded record.
 */
export function applyRecord(state, r) {
    // Stage 2 — schema gate. An extension arrives as a new schema version (INV-FWD-01), so a
    // record carrying `ext_commitment` is asking for schema 2 and is refused here, before (a).
    if (state.schemaVersion !== SCHEMA_VERSION) {
        throw new RegistryFailure("UnsupportedSchemaVersion", `chain schema_version ${state.schemaVersion}`);
    }
    if (r.extCommitment !== null) {
        throw new RegistryFailure("UnsupportedSchemaVersion", "record carries ext_commitment, which schema 1 does not hash");
    }
    // Stage 3, condition (a).
    if (!bytesEqual(r.prevHead, state.head)) {
        throw new RegistryFailure("HeadMismatch", "prev_head is not the chain's current head");
    }
    // Condition (b). INV-STATE-07: the counter is checked, never wrapped (V-N-20).
    if (state.seq >= U64_MAX) {
        throw new RegistryFailure("ArithmeticOverflow", "seq has no successor");
    }
    const nextSeq = state.seq + 1n;
    if (r.seq !== nextSeq) {
        throw new RegistryFailure("SequenceOutOfOrder", `expected seq ${nextSeq}, got ${r.seq}`);
    }
    // Condition (c). A named expected key that disagrees is 0x08, decided before verification runs.
    if (r.expectedQpKey !== null && !bytesEqual(r.expectedQpKey, r.qpKey)) {
        throw new RegistryFailure("AttestationKeyMismatch", "expected qp_key differs from the record's qp_key");
    }
    if (r.signature === null) {
        throw new RegistryFailure("AttestationMissing", "no qualified person's signature");
    }
    const preimage = leafPreimageOf(state.assetCommitment, r);
    if (!ed25519Verify(r.qpKey, preimage, r.signature)) {
        throw new RegistryFailure("AttestationInvalid", "signature does not verify over the leaf preimage");
    }
    // Condition (d).
    if (state.lastEffectiveAt !== null && r.effectiveAt < state.lastEffectiveAt) {
        throw new RegistryFailure("NonMonotonicEffectiveAt", `effective_at ${r.effectiveAt} precedes ${state.lastEffectiveAt}`);
    }
    // Condition (e) — sets a flag and never rejects.
    const flags = computeFlags(state, r.category);
    // Condition (f).
    if (r.category < CATEGORY_MIN || r.category > CATEGORY_MAX) {
        throw new RegistryFailure("MalformedPayload", `category ${r.category} is outside 0..=4`);
    }
    if (!isWellFormedPayloadUri(r.payloadUri)) {
        throw new RegistryFailure("MalformedPayload", "payload_uri is not well formed");
    }
    // Stage 4 — commit.
    const leaf = keccak256(preimage);
    const head = advanceHead(state.head, leaf);
    return { leaf, head, flags };
}
/** The state after an accepted transition. Append-only: nothing here decrements or rewrites. */
export function commit(state, r, applied) {
    return {
        assetCommitment: state.assetCommitment,
        schemaVersion: state.schemaVersion,
        head: applied.head,
        seq: r.seq,
        lastEffectiveAt: r.effectiveAt,
        sawResource: state.sawResource || RESOURCE_CATEGORIES.includes(r.category),
        previousCategory: r.category,
    };
}
