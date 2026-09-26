/**
 * §2.1's error space, and the one failure class that sits outside it.
 *
 * §2.1's codes belong to §1.3's transition conditions: they are what a registry returns when it
 * judges a record. A disclosure package is never seen by a registry, so a package-level failure
 * that §2.1 has no condition for does not borrow one of its codes and does not invent a new one.
 * Those failures are `PackageFailure` below, named and unnumbered.
 */
export declare const REGISTRY_CODES: {
    readonly HeadMismatch: 3;
    readonly SequenceOutOfOrder: 4;
    readonly MalformedPayload: 5;
    readonly AttestationMissing: 6;
    readonly AttestationInvalid: 7;
    readonly AttestationKeyMismatch: 8;
    readonly CategorySequenceUnsupported: 9;
    readonly NonMonotonicEffectiveAt: 10;
    readonly DomainTagMismatch: 11;
    readonly RecordTooLarge: 12;
    readonly EpochOutOfOrder: 13;
    readonly CheckpointAlreadyWritten: 14;
    readonly UnsupportedSchemaVersion: 15;
    readonly ArithmeticOverflow: 16;
    readonly CanonicalizationFailed: 17;
    readonly EpochCapacityExceeded: 18;
    readonly InclusionProofInvalid: 19;
    readonly MergeDelayExceeded: 20;
    readonly ReceiptAlreadyAttached: 21;
    readonly SubmissionNotInEpoch: 22;
    readonly PromisePolicyInvalid: 23;
};
export type RegistryCodeName = keyof typeof REGISTRY_CODES;
/** Anchor's on-chain offset: the program returns `6000 + code` and the client reverses it (§2.1). */
export declare const ANCHOR_ERROR_OFFSET = 6000;
export declare function codeName(code: number): RegistryCodeName | undefined;
export declare function formatCode(code: number): string;
/** A refusal that §2.1 has a code for. */
export declare class RegistryFailure extends Error {
    code: number;
    codeName: RegistryCodeName;
    detail: string | undefined;
    constructor(name: RegistryCodeName, detail?: string);
}
/**
 * The package-level failures, which carry no §2.1 code.
 *
 * `JsonBorshMismatch` is the one INV-DISC-02 names: "fails closed on any disagreement between
 * JSON fields and the Borsh preimage". It is a property of the display copy a package ships
 * beside its bytes, and no §1.3 transition can produce it, so it takes a name and no number.
 */
export declare const PACKAGE_FAILURES: readonly ["MalformedPackage", "JsonBorshMismatch", "RootUnavailable", "RootEpochMismatch", "ChainSegmentBroken", "EpochBeforeLogStart", "CheckpointSequenceGap", "CheckpointNotYetPublished"];
export type PackageFailureName = (typeof PACKAGE_FAILURES)[number];
export declare class PackageFailure extends Error {
    failure: PackageFailureName;
    detail: string | undefined;
    constructor(failure: PackageFailureName, detail?: string);
}
export type Failure = RegistryFailure | PackageFailure;
export declare function isFailure(e: unknown): e is Failure;
/** A one-line description of a failure, whichever kind it is. */
export declare function describeFailure(f: Failure): string;
