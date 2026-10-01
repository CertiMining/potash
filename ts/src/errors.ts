/**
 * §2.1's error space, and the one failure class that sits outside it.
 *
 * §2.1's codes belong to §1.3's transition conditions: they are what a registry returns when it
 * judges a record. A disclosure package is never seen by a registry, so a package-level failure
 * that §2.1 has no condition for does not borrow one of its codes and does not invent a new one.
 * Those failures are `PackageFailure` below, named and unnumbered.
 */

export const REGISTRY_CODES = {
  HeadMismatch: 0x03,
  SequenceOutOfOrder: 0x04,
  MalformedPayload: 0x05,
  AttestationMissing: 0x06,
  AttestationInvalid: 0x07,
  AttestationKeyMismatch: 0x08,
  CategorySequenceUnsupported: 0x09, // reserved; never returned under schema 1 (INV-STATE-06)
  NonMonotonicEffectiveAt: 0x0a,
  DomainTagMismatch: 0x0b,
  RecordTooLarge: 0x0c,
  EpochOutOfOrder: 0x0d,
  CheckpointAlreadyWritten: 0x0e,
  UnsupportedSchemaVersion: 0x0f,
  ArithmeticOverflow: 0x10,
  CanonicalizationFailed: 0x11,
  EpochCapacityExceeded: 0x12,
  InclusionProofInvalid: 0x13,
  MergeDelayExceeded: 0x14,
  ReceiptAlreadyAttached: 0x15,
  SubmissionNotInEpoch: 0x16,
  PromisePolicyInvalid: 0x17,
} as const;

export type RegistryCodeName = keyof typeof REGISTRY_CODES;

/** Anchor's on-chain offset: the program returns `6000 + code` and the client reverses it (§2.1). */
export const ANCHOR_ERROR_OFFSET = 6000;

export function codeName(code: number): RegistryCodeName | undefined {
  for (const [name, value] of Object.entries(REGISTRY_CODES)) {
    if (value === code) return name as RegistryCodeName;
  }
  return undefined;
}

export function formatCode(code: number): string {
  return `0x${code.toString(16).padStart(2, "0").toUpperCase()}`;
}

/** A refusal that §2.1 has a code for. */
export class RegistryFailure extends Error {
  code: number;
  codeName: RegistryCodeName;
  detail: string | undefined;

  constructor(name: RegistryCodeName, detail?: string) {
    // The only object in this file indexed by a variable, and the variable is always a literal from
    // this repository: no code name ever comes out of a package or an account. Were that to change,
    // this lookup would need `Object.hasOwn` for the reason `checkOnlyListedFields` does.
    const code = REGISTRY_CODES[name];
    super(`${formatCode(code)} ${name}${detail ? `: ${detail}` : ""}`);
    this.name = "RegistryFailure";
    this.code = code;
    this.codeName = name;
    this.detail = detail;
  }
}

/**
 * The package-level failures, which carry no §2.1 code.
 *
 * `JsonBorshMismatch` is the one INV-DISC-02 names: "fails closed on any disagreement between
 * JSON fields and the Borsh preimage". It is a property of the display copy a package ships
 * beside its bytes, and no §1.3 transition can produce it, so it takes a name and no number.
 */
export const PACKAGE_FAILURES = [
  "MalformedPackage",       // the JSON is not a §2.5 package at all: missing field, wrong type, bad hex
  "JsonBorshMismatch",      // a §2.5 `record` field disagrees with `preimage_borsh` (INV-DISC-02)
  "RootUnavailable",        // the fetch failed, or the account is not the program's
  "RootEpochMismatch",      // the fetched checkpoint is for a different epoch than the proof claims
  // §2.5 lists what a package contains and §4.4's V-Z-05 passes only on "only the fields §2.5
  // lists", so a field outside that list is refused rather than noted: INV-DISC-01's leak is the
  // point, and an epoch key hidden in an unread corner is exactly what it forbids.
  "UnlistedField",
  // §1.4's three different reasons a checkpoint account can be absent, named apart because the
  // section distinguishes them: the failure an on-chain read can show is lag, an epoch before
  // `start_epoch` is a day the log did not exist for, and a refusal inside the published range is
  // evidence about the response rather than about the log, since INV-ANCH-02 runs that range
  // unbroken and only the owning program can allocate an address in it.
  "EpochBeforeLogStart",
  "InconsistentChainView",
  "CheckpointNotYetPublished",
] as const;

export type PackageFailureName = (typeof PACKAGE_FAILURES)[number];

export class PackageFailure extends Error {
  failure: PackageFailureName;
  detail: string | undefined;

  constructor(failure: PackageFailureName, detail?: string) {
    super(`${failure}${detail ? `: ${detail}` : ""}`);
    this.name = "PackageFailure";
    this.failure = failure;
    this.detail = detail;
  }
}

export type Failure = RegistryFailure | PackageFailure;

export function isFailure(e: unknown): e is Failure {
  return e instanceof RegistryFailure || e instanceof PackageFailure;
}

/** A one-line description of a failure, whichever kind it is. */
export function describeFailure(f: Failure): string {
  return f instanceof RegistryFailure
    ? `${formatCode(f.code)} ${f.codeName}${f.detail ? `: ${f.detail}` : ""}`
    : `${f.failure} (no §2.1 code)${f.detail ? `: ${f.detail}` : ""}`;
}
