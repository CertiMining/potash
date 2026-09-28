/**
 * INV-DISC-02's verifier, against packages assembled in `packages.ts`: one that is right, and one
 * that is wrong in each way the invariant names.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { base64Encode, fromHex, toHex } from "../src/bytes.ts";
import { keccak256 } from "../src/hash.ts";
import { RegistryFailure } from "../src/errors.ts";
import { advanceHead } from "../src/chain.ts";
import {
  verifyDisclosureJson,
  verifyDisclosurePackage,
  findAssetCommitmentOutsidePreimage,
  readLeafPreimage,
} from "../src/disclosure.ts";
import { genesisHeadPreimage, leafPreimage } from "../src/preimage.ts";
import { TAG_HEAD } from "../src/tags.ts";
import { decodeCheckpointAccount, decodeLogConfig } from "../src/solana/accounts.ts";
import { DEVNET_PROGRAM_ID, fetchRoot } from "../src/solana/rpc.ts";
import { ASSET_COMMITMENT, GENESIS_HEAD, loadVector } from "./support.ts";
import {
  checkpointBytes,
  clone,
  signedPackageAt,
  epochHoldingRecord,
  fullEpochHoldingRecord,
  logConfigBytes,
  packageFrom,
  recordLeaf,
  RECORD_SUBMISSION_ID,
} from "./packages.ts";

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

test("a chain segment that does not hold is refused, for each of §1.3's head constructions", () => {
  // hₙ₊₁ = Keccak256(TAG_HEAD ‖ hₙ ‖ leafₙ₊₁).
  const badHead = clone(good);
  badHead.chain.head = `0x${"ab".repeat(32)}`;
  expectCode(badHead, root, 0x03, "HeadMismatch", "a head that does not follow from prev_head and the leaf");

  // h₀ = Keccak256(TAG_HEAD ‖ c ‖ schema_version).
  const badGenesis = clone(good);
  badGenesis.chain.genesis = `0x${"cd".repeat(32)}`;
  expectCode(badGenesis, root, 0x03, "HeadMismatch", "a genesis that is not this asset's");

  // Condition (a) at n = 0: prev_head must be h₀ for a seq-1 record. Here the genesis is the real
  // one and prev_head is not it, so what fails is (a) and not the genesis value.
  const badPrevHead = clone(good);
  const orphanHead = keccak256(new TextEncoder().encode("some other chain's head"));
  badPrevHead.chain.prev_head = toHex(orphanHead);
  badPrevHead.chain.head = toHex(advanceHead(orphanHead, recordLeaf().leaf));
  expectCode(badPrevHead, root, 0x03, "HeadMismatch", "a seq-1 record whose predecessor is not the genesis");
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

test("a field §2.5 does not list refuses the package, and is not merely reported", () => {
  // This test asserted the opposite until an independent review pointed out that it was wrong:
  // V-Z-05 passes only on "only the fields §2.5 lists", and §4.4 makes that a release gate of the
  // same severity as a correctness failure, so accepting the package with a note is non-conforming.
  const extra = clone(good);
  (extra as any).epoch_key = `0x${"99".repeat(32)}`;
  const report = verifyDisclosurePackage(extra, { root, configuredHeight: 8 });
  assert.equal(report.ok, false, "a package carrying an epoch key was accepted");
  assert.equal((report.failure as any).failure, "UnlistedField");
  assert.match(report.failure!.message, /epoch_key/);
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

// ---------------------------------------------------------------------------------------------
// Three findings from an independent review. Each test below was run against the code as it stood
// before the fix and failed there; the mutations in tools/mutation-check.mjs keep them honest.
// ---------------------------------------------------------------------------------------------

test("FINDING 1: a package cannot invent its genesis", () => {
  // §1.3: h₀ = Keccak256(TAG_HEAD ‖ c ‖ schema_version), and `c` is bytes 8..40 of the preimage,
  // so the genesis head of this asset's chain is recomputable from what the package already carries.
  const { preimage, leaf } = recordLeaf();
  const c = readLeafPreimage(preimage).assetCommitment;
  assert.equal(good.chain.genesis, toHex(keccak256(genesisHeadPreimage(c, 1))), "the assembled package is honest");

  // An attacker rewrites genesis, prev_head and head together, leaving the signed preimage, the
  // proof and the root untouched. Every relation inside the old check still holds.
  const invented = clone(good);
  const forgedGenesis = keccak256(new TextEncoder().encode("a chain that is not this asset's"));
  invented.chain.genesis = toHex(forgedGenesis);
  invented.chain.prev_head = toHex(forgedGenesis);
  invented.chain.head = toHex(advanceHead(forgedGenesis, leaf));
  assert.equal(invented.preimage_borsh, good.preimage_borsh, "the signed bytes are untouched");
  assert.equal(invented.qp_signature, good.qp_signature, "the signature is untouched");
  assert.deepEqual(invented.inclusion, good.inclusion, "the proof is untouched");
  expectCode(invented, root, 0x03, "HeadMismatch", "an invented genesis", { configuredHeight: 8 });

  // The genesis is checked for every package, not only at seq 1: it is a function of `c` alone.
  const wrongGenesisOnly = clone(good);
  wrongGenesisOnly.chain.genesis = toHex(forgedGenesis);
  expectCode(wrongGenesisOnly, root, 0x03, "HeadMismatch", "a genesis that is not this asset's", { configuredHeight: 8 });

  // A genesis computed under another schema version is not this verifier's genesis either.
  const otherSchema = clone(good);
  otherSchema.chain.genesis = toHex(keccak256(genesisHeadPreimage(c, 2)));
  expectCode(otherSchema, root, 0x03, "HeadMismatch", "a genesis under schema 2", { configuredHeight: 8 });
});

test("FINDING 2: a field §2.5 does not list is refused, at every level", () => {
  // §2.5 lists what a package contains; INV-DISC-01 says what it must never contain; §4.4's V-Z-05
  // passes only when the package holds "only the fields §2.5 lists" and makes that a release gate.
  const epochKey = `0x${"99".repeat(32)}`;

  const topLevel = clone(good);
  (topLevel as any).epoch_key = epochKey;
  expectPackageFailure(topLevel, root, "UnlistedField", "an epoch key at the top level", { configuredHeight: 8 });

  const nested = clone(good);
  (nested.record as any).epoch_key = epochKey;
  expectPackageFailure(nested, root, "UnlistedField", "an epoch key inside record", { configuredHeight: 8 });

  for (const [container, field] of [["chain", "k_e"], ["inclusion", "sibling_preimages"], ["anchor", "epoch_key"]] as const) {
    const pkg = clone(good);
    (pkg as any)[container][field] = epochKey;
    expectPackageFailure(pkg, root, "UnlistedField", `${container}.${field}`, { configuredHeight: 8 });
  }

  // Nor can anything hide inside a field §2.5 shows as a scalar.
  const hidden = clone(good);
  (hidden.anchor as any).solana_tx = { epoch_key: epochKey };
  expectPackageFailure(hidden, root, "UnlistedField", "an object where §2.5 shows a string", { configuredHeight: 8 });

  // The refusal names the path, and comes before any hashing: the leak is the point, not the shape.
  const report = verifyDisclosurePackage(nested, { root, configuredHeight: 8 });
  assert.match(report.failure!.message, /record\.epoch_key/);
  assert.equal(report.checks.some((c) => c.name.startsWith("leaf")), false, "work was done before the package was refused");
  assert.equal(report.notes.length, 0, "an unlisted field is a refusal, not a note");
});

test("FINDING 3: a checkpoint account under another schema version is refused", () => {
  // §1.3's schema gate refuses a record whose schema_version is not 1 with 0x0F, before any
  // condition is judged. An account is read the same way: decode, then the gate.
  const root32 = fromHex(`0x${"ab".repeat(32)}`, 32);
  for (const version of [0, 2, 65535]) {
    const data = checkpointBytes({ epoch: 20361n, root: root32, schemaVersion: version });
    assert.throws(
      () => decodeCheckpointAccount(data),
      (e: unknown) => e instanceof RegistryFailure && e.code === 0x0f && e.codeName === "UnsupportedSchemaVersion",
      `checkpoint schema_version ${version}`,
    );
    assert.throws(
      () => decodeLogConfig(logConfigBytes({ schemaVersion: version })),
      (e: unknown) => e instanceof RegistryFailure && e.code === 0x0f,
      `LogConfig schema_version ${version}`,
    );
  }
  // Schema 1 still decodes, so the gate is the version and not the field's presence.
  assert.equal(decodeCheckpointAccount(checkpointBytes({ epoch: 20361n, root: root32 })).schemaVersion, 1);

  // And the gate holds through the fetch path, where the account arrives from a cluster.
  const stub = (async () => ({
    ok: true,
    json: async () => ({
      result: {
        value: {
          data: [base64Encode(checkpointBytes({ epoch: 20361n, root: root32, schemaVersion: 2 })), "base64"],
          owner: DEVNET_PROGRAM_ID,
        },
      },
    }),
  }) as any) as unknown as typeof fetch;
  return assert.rejects(
    fetchRoot(20361n, { fetchImpl: stub }),
    (e: unknown) => e instanceof RegistryFailure && e.code === 0x0f,
    "a schema-2 checkpoint reached the caller",
  );
});


test("FINDING 1: a record past seq 1 cannot establish its chain position from one package", () => {
  // §1.3's leaf preimage covers c, seq, the two digests, qp_key, category and the two dates. It does
  // not cover prev_head or head, so nothing signs them; and INV-STATE-02 recomputes hₙ from h_m and
  // the leaves between, which one package does not carry. So for seq > 1 an arbitrary prev_head is
  // exactly as well signed and as well anchored as the real one.
  const invented = signedPackageAt(7n, keccak256(new TextEncoder().encode("not this chain's head at six")));
  const report = verifyDisclosurePackage(invented.pkg, { root: invented.root, configuredHeight: 8 });

  // What is established, is: the signature holds, the leaf is in the anchored tree, the genesis is
  // this asset's. What is not, must not be reported as passing.
  assert.equal(report.chainPosition.established, false, "a seq-7 package claimed an established chain position");
  assert.match(report.chainPosition.detail, /prev_head/);
  const step = report.checks.find((c) => c.name.includes("prev_head"));
  assert.ok(step !== undefined, "no check line speaks about prev_head");
  assert.equal(step.status, "unestablished", `the prev_head line reports "${step.status}"`);
  assert.equal(report.checks.some((c) => c.status === "pass" && /prev_head is the chain/.test(c.name)), false);
  assert.ok(
    report.notes.some((n) => /chain position/i.test(n)),
    "the notes do not tell a reader the chain position was not established",
  );

  // At seq 1 the genesis head follows from `c`, so the position is established and says so.
  const first = verifyDisclosurePackage(good, { root, configuredHeight: 8 });
  assert.equal(first.ok, true);
  assert.equal(first.chainPosition.established, true);

  // A caller who holds the previous package can close the gap, the way §2.2 closes the QP key's with
  // `expected_qp_key` and §2.3 closes the observed epoch's: by supplying what the artifact cannot.
  const real = signedPackageAt(7n, fromHex(`0x${"5c".repeat(32)}`, 32));
  const withExpected = verifyDisclosurePackage(real.pkg, {
    root: real.root,
    configuredHeight: 8,
    chainContext: { sawResource: true, previousCategory: 2, expectedPrevHead: fromHex(`0x${"5c".repeat(32)}`, 32) },
  });
  assert.equal(withExpected.ok, true, JSON.stringify(withExpected.failure));
  assert.equal(withExpected.chainPosition.established, true, "a supplied prev_head did not establish the position");

  // And a supplied prev_head that disagrees is condition (a) failing: 0x03.
  expectCode(real.pkg, real.root, 0x03, "HeadMismatch", "a prev_head the caller did not expect", {
    configuredHeight: 8,
    chainContext: { sawResource: true, previousCategory: 2, expectedPrevHead: fromHex(`0x${"ee".repeat(32)}`, 32) },
  });

  // Internal inconsistency still refuses: a head that does not follow from prev_head and the leaf.
  const broken = clone(invented.pkg);
  broken.chain.head = `0x${"ab".repeat(32)}`;
  expectCode(broken, invented.root, 0x03, "HeadMismatch", "a head that does not follow", { configuredHeight: 8 });
});

test("FINDING 2: the field allow-list cannot be bypassed by an inherited property name", () => {
  // §2.5's closure and V-Z-05 must not depend on what the language happens to put on an object. Each
  // of these names survives a JSON round trip as an own property, and indexing the shape with it
  // finds something inherited from Object.prototype rather than nothing.
  const names = ["constructor", "__proto__", "toString", "valueOf", "hasOwnProperty", "isPrototypeOf"];
  // Three value shapes, because each took a different path through the walk: an empty object reached
  // the end of the loop and was accepted outright, a single value was refused as malformed rather
  // than as unlisted, and a populated object was caught one level too deep, at its child's name.
  const values: unknown[] = [{}, `0x${"99".repeat(32)}`, { epoch_key: `0x${"99".repeat(32)}` }];

  for (const name of names) {
    for (const container of [null, "record", "chain", "inclusion", "anchor"] as const) {
      for (const value of values) {
        const text =
          container === null
            ? JSON.stringify({ ...good, [name]: value })
            : JSON.stringify({ ...good, [container]: { ...(good as any)[container], [name]: value } });
        const pkg = JSON.parse(text);
        const target = container === null ? pkg : pkg[container];
        assert.ok(Object.hasOwn(target, name), `${name} did not survive the JSON round trip`);

        const where = container === null ? name : `${container}.${name}`;
        const report = verifyDisclosurePackage(pkg, { root, configuredHeight: 8 });
        assert.equal(report.ok, false, `${where} carrying ${JSON.stringify(value)} was accepted`);
        assert.equal(
          (report.failure as any).failure,
          "UnlistedField",
          `${where}: refused as ${(report.failure as any).failure}, which is not what it is`,
        );
        // The refusal names the unlisted field itself, not one of its children: the field is the
        // problem, and a message pointing a level deeper would send a reader to the wrong place.
        assert.match(report.failure!.message, new RegExp(`^UnlistedField: ${where.replace(".", "\\.")} `), where);
      }
    }
  }
});

test("FINDING 2: a container's fields must be its own, not its prototype's", () => {
  // If the fields live on a prototype, the walk sees an empty object while the readers below find
  // them by ordinary property access: what was checked and what was used would not be the same
  // object. §2.5's list can only close a package whose fields the walk can see.
  const onPrototype = Object.create(good) as typeof good;
  assert.equal(Object.keys(onPrototype).length, 0, "the fields are inherited, not own");
  assert.equal(onPrototype.schema, "certimining/v1/disclosure", "and they are still readable by property access");
  expectPackageFailure(onPrototype, root, "MalformedPackage", "a package whose fields are inherited", {
    configuredHeight: 8,
  });

  const recordOnPrototype = { ...good, record: Object.create(good.record) as typeof good.record };
  expectPackageFailure(recordOnPrototype, root, "MalformedPackage", "a record whose fields are inherited", {
    configuredHeight: 8,
  });
});


test("a package arriving as JSON text verifies through the same path", () => {
  // The form a package actually travels in. Parsing here is what guarantees the object the field walk
  // inspects is the object the checks use: no accessors, no prototype of its own.
  const ok = verifyDisclosureJson(JSON.stringify(good), { root, configuredHeight: 8 });
  assert.equal(ok.ok, true, JSON.stringify(ok.failure));
  assert.equal(ok.chainPosition.established, true);

  const leaked = verifyDisclosureJson(JSON.stringify({ ...good, constructor: {} }), { root, configuredHeight: 8 });
  assert.equal(leaked.ok, false);
  assert.equal((leaked.failure as any).failure, "UnlistedField");

  const notJson = verifyDisclosureJson("{ not json", { root, configuredHeight: 8 });
  assert.equal(notJson.ok, false);
  assert.equal((notJson.failure as any).failure, "MalformedPackage");
  assert.equal(notJson.chainPosition.established, false);
});
