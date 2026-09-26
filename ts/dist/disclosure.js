/**
 * §2.5's disclosure package, and INV-DISC-02's conforming verifier.
 *
 * INV-DISC-02: "A conforming verifier recomputes the leaf from `preimage_borsh`, checks the QP
 * signature, walks the chain segment, verifies inclusion against a root it fetched from Solana
 * independently, and fails closed on any disagreement between JSON fields and the Borsh preimage."
 *
 * The order below is fixed by that sentence plus INV-ENC-03: the display copy is checked against
 * the bytes *first*, before any signature check and before any inclusion check, because until the
 * two agree there is no single record to judge. Flags are excluded from that comparison, per
 * INV-DISC-03.
 */
import { base64Decode, bytesEqual, fromHex, readI64le, readU64le, toHex } from "./bytes.js";
import { PackageFailure, RegistryFailure, describeFailure, isFailure } from "./errors.js";
import { advanceHead, computeFlags } from "./chain.js";
import { ed25519Verify, keccak256 } from "./hash.js";
import { readTagged } from "./preimage.js";
import { TAG_LEAF } from "./tags.js";
import { verifyInclusion, verifyInclusionForHeight } from "./tree.js";
import {} from "./promise.js";
export const DISCLOSURE_SCHEMA = "certimining/v1/disclosure";
export const LEAF_PREIMAGE_LEN = 161;
function must(value, what) {
    if (value === undefined || value === null)
        throw new PackageFailure("MalformedPackage", `missing ${what}`);
    return value;
}
function hexField(value, what, len) {
    if (typeof value !== "string")
        throw new PackageFailure("MalformedPackage", `${what} is not a string`);
    try {
        return fromHex(value, len);
    }
    catch (e) {
        throw new PackageFailure("MalformedPackage", `${what}: ${e.message}`);
    }
}
/** JSON carries integers as numbers or as decimal strings; either is read exactly or refused. */
function intField(value, what) {
    if (typeof value === "bigint")
        return value;
    if (typeof value === "number") {
        if (!Number.isSafeInteger(value)) {
            throw new PackageFailure("MalformedPackage", `${what} is not an exactly representable integer`);
        }
        return BigInt(value);
    }
    if (typeof value === "string" && /^-?\d+$/.test(value))
        return BigInt(value);
    throw new PackageFailure("MalformedPackage", `${what} is not an integer`);
}
function smallInt(value, what, max) {
    const v = intField(value, what);
    if (v < 0n || v > BigInt(max))
        throw new PackageFailure("MalformedPackage", `${what} is outside 0..${max}`);
    return Number(v);
}
/**
 * Reads the 161 bytes as §1.3 lays them out. A buffer carrying another domain tag is 0x0B
 * (V-N-09); one of the wrong length has no fields to judge and is 0x05.
 */
export function readLeafPreimage(preimage) {
    if (preimage.length !== LEAF_PREIMAGE_LEN) {
        throw new RegistryFailure("MalformedPayload", `leaf preimage is ${preimage.length} bytes, and §1.3 fixes it at ${LEAF_PREIMAGE_LEN}`);
    }
    const body = readTagged(preimage, TAG_LEAF);
    return {
        assetCommitment: body.slice(0, 32),
        seq: readU64le(body, 32),
        payloadDigest: body.slice(40, 72),
        assessmentDigest: body.slice(72, 104),
        qpKey: body.slice(104, 136),
        category: body[136],
        effectiveAt: readI64le(body, 137),
        changeIdentifiedAt: readI64le(body, 145),
    };
}
/**
 * The display copy against the bytes, in the order §1.3 writes the fields, stopping at the first
 * that differs. `flags` is excluded (INV-DISC-03); `payload_uri` has no counterpart in a schema-1
 * leaf preimage and so cannot be compared at all (see SPEC-DEFECTS.md, §2.5/§1.3).
 */
export function compareJsonToBytes(record, bytes) {
    const mismatch = (field, json, borsh) => {
        throw new PackageFailure("JsonBorshMismatch", `${field}: JSON says ${json}, the preimage says ${borsh}`);
    };
    const seq = intField(record.seq, "record.seq");
    if (seq !== bytes.seq)
        mismatch("seq", `${seq}`, `${bytes.seq}`);
    const payloadDigest = hexField(record.payload_digest, "record.payload_digest", 32);
    if (!bytesEqual(payloadDigest, bytes.payloadDigest)) {
        mismatch("payload_digest", toHex(payloadDigest), toHex(bytes.payloadDigest));
    }
    const assessmentDigest = hexField(record.assessment_digest, "record.assessment_digest", 32);
    if (!bytesEqual(assessmentDigest, bytes.assessmentDigest)) {
        mismatch("assessment_digest", toHex(assessmentDigest), toHex(bytes.assessmentDigest));
    }
    const qpKey = hexField(record.qp_key, "record.qp_key", 32);
    if (!bytesEqual(qpKey, bytes.qpKey))
        mismatch("qp_key", toHex(qpKey), toHex(bytes.qpKey));
    const category = smallInt(record.category, "record.category", 255);
    if (category !== bytes.category)
        mismatch("category", `${category}`, `${bytes.category}`);
    const effectiveAt = intField(record.effective_at, "record.effective_at");
    if (effectiveAt !== bytes.effectiveAt)
        mismatch("effective_at", `${effectiveAt}`, `${bytes.effectiveAt}`);
    const changeIdentifiedAt = intField(record.change_identified_at, "record.change_identified_at");
    if (changeIdentifiedAt !== bytes.changeIdentifiedAt) {
        mismatch("change_identified_at", `${changeIdentifiedAt}`, `${bytes.changeIdentifiedAt}`);
    }
}
function parseProof(inclusion) {
    const epoch = intField(must(inclusion.epoch, "inclusion.epoch"), "inclusion.epoch");
    const height = smallInt(must(inclusion.height, "inclusion.height"), "inclusion.height", 255);
    const slotIndex = smallInt(must(inclusion.slot_index, "inclusion.slot_index"), "inclusion.slot_index", 0xffff);
    const rawSiblings = must(inclusion.siblings, "inclusion.siblings");
    if (!Array.isArray(rawSiblings))
        throw new PackageFailure("MalformedPackage", "inclusion.siblings is not an array");
    const siblings = rawSiblings.map((s, i) => hexField(s, `inclusion.siblings[${i}]`, 32));
    return { height, siblings, slotIndex, epoch };
}
/**
 * The offline path: a record, a proof and a root, and nothing else. Pure — no network, no clock,
 * no storage — which is what INV-IFACE-01 requires of a counterparty's verification.
 */
export function verifyDisclosurePackage(pkg, options) {
    const checks = [];
    const notes = [];
    let leaf;
    let fields;
    let flags;
    const record = (name, status, detail) => {
        checks.push(detail === undefined ? { name, status } : { name, status, detail });
    };
    try {
        // 0 — is this a §2.5 package at all?
        if (pkg === null || typeof pkg !== "object")
            throw new PackageFailure("MalformedPackage", "not an object");
        if (pkg.schema !== DISCLOSURE_SCHEMA) {
            throw new PackageFailure("MalformedPackage", `schema is ${JSON.stringify(pkg.schema)}, not ${DISCLOSURE_SCHEMA}`);
        }
        const rec = must(pkg.record, "record");
        const chain = must(pkg.chain, "chain");
        const inclusion = must(pkg.inclusion, "inclusion");
        for (const key of Object.keys(pkg)) {
            if (!["schema", "record", "preimage_borsh", "chain", "qp_signature", "inclusion", "anchor"].includes(key)) {
                notes.push(`package carries a field §2.5 does not list: ${key}`);
            }
        }
        record("package shape", "pass");
        // 1 — the bytes. Everything downstream is derived from these, never from the display copy.
        let preimage;
        try {
            preimage = base64Decode(must(pkg.preimage_borsh, "preimage_borsh"));
        }
        catch (e) {
            if (isFailure(e))
                throw e;
            throw new PackageFailure("MalformedPackage", `preimage_borsh: ${e.message}`);
        }
        fields = readLeafPreimage(preimage);
        record("preimage_borsh decodes as a §1.3 leaf preimage", "pass");
        // 2 — the display copy against the bytes, before any other work (INV-DISC-02, INV-ENC-03).
        compareJsonToBytes(rec, fields);
        record("JSON record agrees with the Borsh preimage", "pass", "flags excluded per INV-DISC-03");
        // 3 — the leaf.
        leaf = keccak256(preimage);
        record("leaf recomputed from preimage_borsh", "pass", toHex(leaf));
        // 4 — the QP signature, over those bytes and not over any other encoding (INV-ENC-03).
        const signatureField = pkg.qp_signature;
        if (signatureField === undefined || signatureField === null) {
            throw new RegistryFailure("AttestationMissing", "the package carries no qp_signature");
        }
        const signature = hexField(signatureField, "qp_signature", 64);
        if (!ed25519Verify(fields.qpKey, preimage, signature)) {
            throw new RegistryFailure("AttestationInvalid", "qp_signature does not verify over preimage_borsh");
        }
        record("QP signature verifies over the 161 preimage bytes", "pass");
        // 5 — the chain segment.
        const prevHead = hexField(must(chain.prev_head, "chain.prev_head"), "chain.prev_head", 32);
        const head = hexField(must(chain.head, "chain.head"), "chain.head", 32);
        const genesis = hexField(must(chain.genesis, "chain.genesis"), "chain.genesis", 32);
        if (!bytesEqual(advanceHead(prevHead, leaf), head)) {
            throw new RegistryFailure("HeadMismatch", "chain.head is not Keccak256(TAG_HEAD ‖ prev_head ‖ leaf)");
        }
        record("chain.head follows from prev_head and the leaf", "pass");
        if (fields.seq === 1n) {
            if (!bytesEqual(prevHead, genesis)) {
                throw new PackageFailure("ChainSegmentBroken", "the record is at seq 1 and prev_head is not chain.genesis");
            }
            record("chain.genesis is the predecessor of a seq-1 record", "pass");
        }
        else {
            record("chain.genesis reaches chain.prev_head", "skipped", "one package carries no intermediate leaves");
        }
        // 6 — inclusion, against a root the caller obtained independently.
        const proof = parseProof(inclusion);
        if (proof.epoch !== options.root.epoch) {
            throw new PackageFailure("RootEpochMismatch", `the proof is for epoch ${proof.epoch} and the root for ${options.root.epoch}`);
        }
        if (options.configuredHeight === undefined) {
            verifyInclusion(leaf, proof, options.root.root);
            record("inclusion proof reaches the root", "pass", "no configured height supplied, so §2.3's plain verify ran");
        }
        else {
            verifyInclusionForHeight(leaf, proof, options.root.root, options.configuredHeight);
            record("inclusion proof reaches the root at the log's configured height", "pass", `H = ${options.configuredHeight}`);
        }
        // 7 — flags. Advisory, excluded from every digest, and never a reason to refuse (INV-DISC-03).
        const declared = smallInt(rec.flags, "record.flags", 0xffff);
        if (options.chainContext === undefined) {
            flags = {
                declared,
                recomputed: null,
                discrepancy: null,
                note: "not recomputable: bit 0 and bit 1 are properties of earlier records in the chain, which one package does not carry",
            };
            record("flags", "skipped", flags.note);
        }
        else {
            const state = {
                sawResource: options.chainContext.sawResource,
                previousCategory: options.chainContext.previousCategory,
            };
            const recomputed = computeFlags(state, fields.category);
            const discrepancy = recomputed !== declared;
            flags = {
                declared,
                recomputed,
                discrepancy,
                note: discrepancy ? "declared flags differ from the flags this chain state produces" : "declared flags match",
            };
            record("flags recomputed from the chain", "pass", flags.note);
            if (discrepancy)
                notes.push(`flag discrepancy: package declares ${declared}, the chain gives ${recomputed}`);
        }
        return { ok: true, leaf, fields, flags, checks, notes };
    }
    catch (e) {
        if (!isFailure(e))
            throw e; // a bug here must not be mistaken for a refusal
        const failure = e;
        checks.push({ name: "verification", status: "fail", detail: describeFailure(failure) });
        return {
            ok: false,
            failure: failure instanceof RegistryFailure
                ? { kind: "registry", code: failure.code, codeName: failure.codeName, message: failure.message }
                : { kind: "package", failure: failure.failure, message: failure.message },
            leaf,
            fields,
            flags,
            checks,
            notes,
        };
    }
}
/**
 * INV-DISC-01's own check, for a holder who wants it: `c` may appear inside `preimage_borsh` and
 * nowhere else in the package. Returns the fields where it was found in clear.
 */
export function findAssetCommitmentOutsidePreimage(pkg, assetCommitment) {
    const needle = toHex(assetCommitment).slice(2).toLowerCase();
    const found = [];
    const walk = (value, path) => {
        if (typeof value === "string") {
            if (value.toLowerCase().includes(needle))
                found.push(path);
        }
        else if (Array.isArray(value)) {
            value.forEach((v, i) => walk(v, `${path}[${i}]`));
        }
        else if (value !== null && typeof value === "object") {
            for (const [k, v] of Object.entries(value)) {
                if (path === "" && k === "preimage_borsh")
                    continue; // where INV-DISC-01 places it
                walk(v, path === "" ? k : `${path}.${k}`);
            }
        }
    };
    walk(pkg, "");
    return found;
}
