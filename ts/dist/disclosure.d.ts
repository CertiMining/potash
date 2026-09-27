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
import { type Digest } from "./bytes.ts";
import { type PublishedRoot } from "./promise.ts";
export declare const DISCLOSURE_SCHEMA = "certimining/v1/disclosure";
export declare const LEAF_PREIMAGE_LEN = 161;
export type DisclosurePackage = {
    schema: string;
    record: {
        seq: number | string;
        category: number;
        effective_at: number | string;
        change_identified_at: number | string;
        payload_digest: string;
        assessment_digest: string;
        qp_key: string;
        payload_uri: string;
        flags: number;
    };
    preimage_borsh: string;
    chain: {
        prev_head: string;
        head: string;
        genesis: string;
    };
    qp_signature: string;
    inclusion: {
        epoch: number | string;
        height: number;
        slot_index: number;
        siblings: string[];
    };
    anchor?: {
        solana_tx?: string;
        solana_slot?: number | string;
        ots_receipt_digest?: string;
    };
};
/** What the 161 bytes say, once they have been read as §1.3 lays them out. */
export type LeafFromBytes = {
    assetCommitment: Digest;
    seq: bigint;
    payloadDigest: Digest;
    assessmentDigest: Digest;
    qpKey: Uint8Array;
    category: number;
    effectiveAt: bigint;
    changeIdentifiedAt: bigint;
};
export type FlagReport = {
    declared: number;
    recomputed: number | null;
    /** null when no chain context was supplied, so nothing could be recomputed (INV-DISC-03). */
    discrepancy: boolean | null;
    note: string;
};
export type DisclosureReport = {
    ok: boolean;
    failure?: {
        kind: "registry";
        code: number;
        codeName: string;
        message: string;
    } | {
        kind: "package";
        failure: string;
        message: string;
    } | undefined;
    leaf?: Digest | undefined;
    fields?: LeafFromBytes | undefined;
    flags?: FlagReport | undefined;
    /** Each check the verifier ran, in the order it ran them. */
    checks: Array<{
        name: string;
        status: "pass" | "fail" | "skipped";
        detail?: string;
    }>;
    notes: string[];
};
export type VerifyOptions = {
    /** The root the counterparty obtained for the proof's epoch, from the chain or from a caller. */
    root: PublishedRoot;
    /** The log's configured `H` (§2.4 `LogConfig.tree_height`). Given, a disagreeing proof is 0x13. */
    configuredHeight?: number;
    /**
     * What the holder knows of the chain before this record, if anything. Supplied, flags are
     * recomputed and a mismatch is reported as a discrepancy (INV-DISC-03); absent, flags are
     * reported as not recomputable, because one package does not carry its own history.
     */
    chainContext?: {
        sawResource: boolean;
        previousCategory: number | null;
    };
};
/**
 * Reads the 161 bytes as §1.3 lays them out. A buffer carrying another domain tag is 0x0B
 * (V-N-09); one of the wrong length has no fields to judge and is 0x05.
 */
export declare function readLeafPreimage(preimage: Uint8Array): LeafFromBytes;
/**
 * The display copy against the bytes, in the order §1.3 writes the fields, stopping at the first
 * that differs. `flags` is excluded (INV-DISC-03); `payload_uri` has no counterpart in a schema-1
 * leaf preimage and so cannot be compared at all (see SPEC-DEFECTS.md, §2.5/§1.3).
 */
export declare function compareJsonToBytes(record: DisclosurePackage["record"], bytes: LeafFromBytes): void;
/**
 * The offline path: a record, a proof and a root, and nothing else. Pure — no network, no clock,
 * no storage — which is what INV-IFACE-01 requires of a counterparty's verification.
 */
export declare function verifyDisclosurePackage(pkg: DisclosurePackage, options: VerifyOptions): DisclosureReport;
/**
 * INV-DISC-01's own check, for a holder who wants it: `c` may appear inside `preimage_borsh` and
 * nowhere else in the package. Returns the fields where it was found in clear.
 */
export declare function findAssetCommitmentOutsidePreimage(pkg: DisclosurePackage, assetCommitment: Digest): string[];
