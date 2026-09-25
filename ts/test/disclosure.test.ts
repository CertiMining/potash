/**
 * INV-DISC-02's verifier, against packages assembled in `packages.ts`: one that is right, and one
 * that is wrong in each way the invariant names.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { base64Encode, fromHex, toHex } from "../src/bytes.ts";
import { keccak256 } from "../src/hash.ts";
import { verifyDisclosurePackage, findAssetCommitmentOutsidePreimage, readLeafPreimage } from "../src/disclosure.ts";
import { leafPreimage } from "../src/preimage.ts";
import { TAG_HEAD } from "../src/tags.ts";
import { ASSET_COMMITMENT, GENESIS_HEAD, loadVector } from "./support.ts";
import { clone, epochHoldingRecord, fullEpochHoldingRecord, packageFrom, recordLeaf, RECORD_SUBMISSION_ID } from "./packages.ts";

const built = epochHoldingRecord();
const root = { epoch: built.epoch, root: built.root };
const good = packageFrom(built);

function expectPackageFailure(pkg: any, r: any, failure: string, what: string, options: any = {}): void {
  const report = verifyDisclosurePackage(pkg, { root: r, ...options });
  assert.equal(report.ok, false, `${what}: the package was accepted`);
  assert.equal(report.failure?.kind, "package", `${what}: ${report.failure?.message}`);
  assert.equal((report.failure as any).failure, failure, `${what}: ${report.failure?.message}`);
}

function expectCode(pkg: any, r: any, code: number, codeName: string, what: string, options: any = {}): void {
  const report = verifyDisclosurePackage(pkg, { root: r, ...options });
  assert.equal(report.ok, false, `${what}: the package was accepted`);
  assert.equal(report.failure?.kind, "registry", `${what}: ${report.failure?.message}`);
  assert.equal((report.failure as any).code, code, `${what}: ${report.failure?.message}`);
  assert.equal((report.failure as any).codeName, codeName, `${what}: ${report.failure?.message}`);
}

test("a well-formed package verifies against the root of the epoch that holds it", () => {
  const report = verifyDisclosurePackage(good, { root, configuredHeight: 8 });
  assert.equal(report.ok, true, JSON.stringify(report.failure));
  assert.equal(toHex(report.leaf!), toHex(recordLeaf().leaf));
  assert.equal(report.fields!.seq, 1n);
  assert.equal(toHex(report.fields!.assetCommitment), toHex(ASSET_COMMITMENT));
  assert.equal(report.checks.every((c) => c.status !== "fail"), true);
});

test("the same record verifies in a full epoch: 255 vector leaves and this one", () => {
  const fullEpoch = fullEpochHoldingRecord();
  const pkg = packageFrom(fullEpoch);
  const report = verifyDisclosurePackage(pkg, { root: { epoch: fullEpoch.epoch, root: fullEpoch.root }, configuredHeight: 8 });
  assert.equal(report.ok, true, JSON.stringify(report.failure));
  assert.equal(pkg.inclusion.siblings.length, 8, "proof length does not vary with the record count");
});

test("INV-IFACE-01: verification is offline, with no network reachable", () => {
  const realFetch = globalThis.fetch;
  (globalThis as any).fetch = () => {
    throw new Error("the offline path reached the network");
  };
  try {
    assert.equal(verifyDisclosurePackage(good, { root, configuredHeight: 8 }).ok, true);
  } finally {
    (globalThis as any).fetch = realFetch;
  }
});

test("INV-DISC-01: `c` appears inside preimage_borsh and nowhere else in the package", () => {
  assert.deepEqual(findAssetCommitmentOutsidePreimage(good, ASSET_COMMITMENT), []);
  const text = JSON.stringify(good);
  for (const forbidden of ["BCTENURE1043A", "bc-tenure", "CABC", "MTO00001"]) {
    assert.equal(text.includes(forbidden), false, `the package carries ${forbidden} in clear`);
  }
});

test("INV-DISC-02: a JSON field that disagrees with the Borsh preimage fails closed, field by field", () => {
  const cases: Array<[string, unknown]> = [
    ["seq", 2],
    ["payload_digest", `0x${"11".repeat(32)}`],
    ["assessment_digest", `0x${"44".repeat(32)}`],
    ["qp_key", `0x${"55".repeat(32)}`],
    ["category", 3],
    ["effective_at", 1700000001],
    ["change_identified_at", 1],
  ];
  for (const [field, value] of cases) {
    const pkg = clone(good);
    (pkg.record as any)[field] = value;
    const report = verifyDisclosurePackage(pkg, { root, configuredHeight: 8 });
    assert.equal(report.ok, false, `${field}: accepted`);
    assert.equal((report.failure as any).failure, "JsonBorshMismatch", `${field}: ${report.failure?.message}`);
    assert.match(report.failure!.message, new RegExp(`^JsonBorshMismatch: ${field}:`), "the failure names the field that differs");
  }
});

test("the JSON-versus-Borsh check runs before the signature check and before the inclusion check", () => {
  const pkg = clone(good);
  pkg.record.seq = 9; // disagrees with the preimage
  pkg.qp_signature = `0x${"00".repeat(64)}`; // would be 0x07
  pkg.inclusion.siblings[0] = `0x${"00".repeat(32)}`; // would be 0x13
  const report = verifyDisclosurePackage(pkg, { root, configuredHeight: 8 });
  assert.equal(report.ok, false);
  assert.equal((report.failure as any).failure, "JsonBorshMismatch");
  // Nothing downstream ran: no check after the comparison is recorded.
  assert.equal(report.checks.some((c) => c.name.startsWith("QP signature")), false);
  assert.equal(report.checks.some((c) => c.name.startsWith("inclusion")), false);
});

test("INV-DISC-03: flags are excluded from the comparison and never make a record invalid", () => {
  const pkg = clone(good);
  pkg.record.flags = 1; // the record's own flags say otherwise; this must not refuse the package
  const report = verifyDisclosurePackage(pkg, { root, configuredHeight: 8 });
  assert.equal(report.ok, true, JSON.stringify(report.failure));
  assert.equal(report.flags!.declared, 1);
  assert.equal(report.flags!.recomputed, null, "one package carries no chain history to recompute from");
  assert.equal(report.flags!.discrepancy, null);

  // Given the chain context the holder has, the discrepancy is reported, and still not fatal.
  const withContext = verifyDisclosurePackage(pkg, {
    root,
    configuredHeight: 8,
    chainContext: { sawResource: false, previousCategory: null },
  });
  assert.equal(withContext.ok, true);
  assert.equal(withContext.flags!.recomputed, 0);
  assert.equal(withContext.flags!.discrepancy, true);
  assert.equal(withContext.notes.some((n) => n.startsWith("flag discrepancy")), true);
});

test("a tampered signature is 0x07, and an absent one is 0x06", () => {
  const tampered = clone(good);
  const sig = fromHex(tampered.qp_signature, 64);
  sig[0] = sig[0]! ^ 0x01;
  tampered.qp_signature = toHex(sig);
  expectCode(tampered, root, 0x07, "AttestationInvalid", "a flipped signature bit");

  const absent = clone(good);
  delete (absent as any).qp_signature;
  expectCode(absent, root, 0x06, "AttestationMissing", "no signature at all");
});

test("one flipped byte in the record fails verification while the root stands", () => {
  // Flipped in the bytes alone, the display copy catches it.
  const inBytes = clone(good);
  const preimage = recordLeaf().preimage.slice();
  preimage[48] = preimage[48]! ^ 0x01; // first byte of payload_digest: tag 8, c 32, seq 8, then the digest
  inBytes.preimage_borsh = base64Encode(preimage);
  const report = verifyDisclosurePackage(inBytes, { root, configuredHeight: 8 });
  assert.equal((report.failure as any).failure, "JsonBorshMismatch");

  // Flipped in both, so the two agree, the QP signature catches it.
  const inBoth = clone(inBytes);
  inBoth.record.payload_digest = toHex(readLeafPreimage(preimage).payloadDigest);
  expectCode(inBoth, root, 0x07, "AttestationInvalid", "a flipped byte carried consistently");

  // And the root is untouched throughout.
  assert.equal(toHex(root.root), toHex(epochHoldingRecord().root));
});

test("a preimage under another domain tag is 0x0B, and one of the wrong length is 0x05", () => {
  const wrongTag = clone(good);
  const bytes = recordLeaf().preimage.slice();
  bytes.set(TAG_HEAD, 0);
  wrongTag.preimage_borsh = base64Encode(bytes);
  expectCode(wrongTag, root, 0x0b, "DomainTagMismatch", "a leaf preimage read under TAG_HEAD");

  const short = clone(good);
  short.preimage_borsh = base64Encode(recordLeaf().preimage.slice(0, 160));
  expectCode(short, root, 0x05, "MalformedPayload", "a truncated preimage");
});

test("a chain segment that does not hold is refused", () => {
  const badHead = clone(good);
  badHead.chain.head = `0x${"ab".repeat(32)}`;
  expectCode(badHead, root, 0x03, "HeadMismatch", "a head that does not follow from prev_head and the leaf");

  const badGenesis = clone(good);
  badGenesis.chain.genesis = `0x${"cd".repeat(32)}`;
  expectPackageFailure(badGenesis, root, "ChainSegmentBroken", "a seq-1 record whose predecessor is not the genesis");
});

test("inclusion failures: a sibling altered, a short path, the wrong height, another epoch's root", () => {
  const altered = clone(good);
  const sibling = fromHex(altered.inclusion.siblings[0]!, 32);
  sibling[0] = sibling[0]! ^ 0x01;
  altered.inclusion.siblings[0] = toHex(sibling);
  expectCode(altered, root, 0x13, "InclusionProofInvalid", "one sibling altered", { configuredHeight: 8 });

  const short = clone(good);
  short.inclusion.siblings = short.inclusion.siblings.slice(0, 7);
  expectCode(short, root, 0x13, "InclusionProofInvalid", "H − 1 siblings", { configuredHeight: 8 });

  const long = clone(good);
  long.inclusion.siblings = [...long.inclusion.siblings, `0x${"00".repeat(32)}`];
  expectCode(long, root, 0x13, "InclusionProofInvalid", "H + 1 siblings", { configuredHeight: 8 });

  const wrongHeight = clone(good);
  expectCode(wrongHeight, root, 0x13, "InclusionProofInvalid", "a proof of height 8 against a log configured at 12", {
    configuredHeight: 12,
  });

  // V-N-17's shape: a valid proof against another epoch's root. The root is relabelled with the
  // proof's epoch, so what fails is the path and not the epoch comparison.
  const otherEpoch = loadVector("V-N-17");
  const otherRoot = { epoch: built.epoch, root: fromHex(otherEpoch.inputs.other_root, 32) };
  expectCode(good, otherRoot, 0x13, "InclusionProofInvalid", "another epoch's root", { configuredHeight: 8 });
});

test("a root for a different epoch than the proof is refused before any hashing", () => {
  expectPackageFailure(good, { epoch: built.epoch + 1n, root: built.root }, "RootEpochMismatch", "epoch disagreement", {
    configuredHeight: 8,
  });
});

test("a package that is not a §2.5 package at all is refused", () => {
  const wrongSchema = clone(good);
  (wrongSchema as any).schema = "certimining/v2/disclosure";
  expectPackageFailure(wrongSchema, root, "MalformedPackage", "an unknown schema");

  const noRecord = clone(good);
  delete (noRecord as any).record;
  expectPackageFailure(noRecord, root, "MalformedPackage", "no record block");

  const badBase64 = clone(good);
  badBase64.preimage_borsh = "not base64!!";
  expectPackageFailure(badBase64, root, "MalformedPackage", "preimage_borsh is not base64");

  const badHex = clone(good);
  badHex.record.qp_key = "0xnothex";
  expectPackageFailure(badHex, root, "MalformedPackage", "a field that is not hex");

  const unsafeInt = clone(good);
  (unsafeInt.record as any).seq = 2 ** 53;
  expectPackageFailure(unsafeInt, root, "MalformedPackage", "an integer JSON cannot carry exactly");
});

test("the verifier reports a field §2.5 does not list rather than ignoring it", () => {
  const extra = clone(good);
  (extra as any).epoch_key = `0x${"99".repeat(32)}`;
  const report = verifyDisclosurePackage(extra, { root, configuredHeight: 8 });
  assert.equal(report.ok, true);
  assert.equal(report.notes.some((n) => n.includes("epoch_key")), true);
});

test("the leaf a package carries is the leaf the vector's own writer produces", () => {
  const v = loadVector("V-P-09");
  const { preimage, leaf } = recordLeaf();
  assert.equal(toHex(preimage), v.expected.leaf_preimage);
  assert.equal(toHex(leaf), v.expected.leaf);
  assert.equal(toHex(keccak256(leafPreimage(ASSET_COMMITMENT, readLeafPreimage(preimage)))), v.expected.leaf);
  assert.equal(toHex(GENESIS_HEAD), v.inputs.record.prev_head);
  assert.equal(toHex(built.assignment.find((a) => toHex(a.submissionId) === toHex(RECORD_SUBMISSION_ID))!.submissionId), toHex(RECORD_SUBMISSION_ID));
});
