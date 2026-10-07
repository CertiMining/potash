/**
 * §4.4a. The row that names this artifact is "TS verifier, 1,000-record chain, hash recomputation
 * only — < 50 ms"; the two rows below it that a verifier can reach are measured as well, and the
 * signature path is measured and reported without a threshold, as §4.4a says for v0.1.
 *
 * The numbers this run produced, and the machine they were produced on, are printed by the test
 * and recorded in README.md.
 */
import test from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import { ed25519 } from "@noble/curves/ed25519.js";
import { toHex } from "../src/bytes.ts";
import { keccak256 } from "../src/hash.ts";
import { advanceHead, applyRecord, commit, genesisHead, leafPreimageOf, type ChainState, type RecordLeafInput } from "../src/chain.ts";
import { buildEpoch, proofFor, verifyInclusion } from "../src/tree.ts";
import { ASSET_COMMITMENT, QP_KEY, RFC8032_TEST_SECRET } from "./support.ts";

const RECORDS = 1000;

function buildChain(n: number): { records: RecordLeafInput[]; start: ChainState } {
  assert.equal(toHex(ed25519.getPublicKey(RFC8032_TEST_SECRET)), toHex(QP_KEY), "the RFC key pair does not match");
  const start: ChainState = {
    assetCommitment: ASSET_COMMITMENT,
    schemaVersion: 1,
    head: genesisHead(ASSET_COMMITMENT, 1),
    seq: 0n,
    lastEffectiveAt: null,
    sawResource: false,
    previousCategory: null,
  };
  const records: RecordLeafInput[] = [];
  let state = start;
  for (let i = 1; i <= n; i++) {
    const record: RecordLeafInput = {
      prevHead: state.head,
      seq: BigInt(i),
      payloadDigest: keccak256(Uint8Array.of(i & 0xff, (i >> 8) & 0xff)),
      assessmentDigest: new Uint8Array(32),
      qpKey: QP_KEY,
      expectedQpKey: null,
      signature: null,
      category: 2,
      effectiveAt: 1700000000n + BigInt(i),
      changeIdentifiedAt: 0n,
      payloadUri: new TextEncoder().encode(`ipfs://record-${i}`),
      extCommitment: null,
    };
    record.signature = ed25519.sign(leafPreimageOf(ASSET_COMMITMENT, record), RFC8032_TEST_SECRET);
    const applied = applyRecord(state, record);
    state = commit(state, record, applied);
    records.push(record);
  }
  return { records, start };
}

function median(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)]!;
}

function measure(runs: number, fn: () => void): { median: number; min: number; max: number } {
  const times: number[] = [];
  for (let i = 0; i < runs; i++) {
    const t0 = performance.now();
    fn();
    times.push(performance.now() - t0);
  }
  return { median: median(times), min: Math.min(...times), max: Math.max(...times) };
}

test("§4.4a: the one wall-clock threshold holds, and the other rows are reported", () => {
  const { records, start } = buildChain(RECORDS);

  // Hash recomputation only: leaf preimage, leaf digest, head step. No signature check.
  const chainWalk = measure(7, () => {
    let head = start.head;
    for (const r of records) {
      const leaf = keccak256(leafPreimageOf(ASSET_COMMITMENT, r));
      head = advanceHead(head, leaf);
    }
    assert.notEqual(toHex(head), toHex(start.head));
  });

  // The same walk with §1.3's condition (c) on every record.
  const fullWalk = measure(3, () => {
    let state = start;
    for (const r of records) state = commit(state, r, applyRecord(state, r));
  });

  const real = Array.from({ length: 256 }, (_, i) => ({
    submissionId: (() => {
      const id = new Uint8Array(16);
      new DataView(id.buffer).setUint32(0, i, true);
      return id;
    })(),
    leaf: keccak256(Uint8Array.of(i)),
  }));
  const masterKey = new TextEncoder().encode("CMv1 TEST MASTER KEY, NOT SECRET");
  const treeBuild = measure(7, () => {
    buildEpoch(20400n, 8, masterKey, real);
  });

  const built = buildEpoch(20400n, 8, masterKey, real);
  const proof = proofFor(built, real[0]!.submissionId);
  const proofVerify = measure(9, () => {
    for (let i = 0; i < 100; i++) verifyInclusion(real[0]!.leaf, proof, built.root);
  });

  const cpu = os.cpus()[0]?.model ?? "unknown";
  const machine = `${cpu}, ${os.platform()} ${os.release()} ${os.arch()}, ${Math.round(os.totalmem() / 2 ** 30)} GB, Node ${process.version}`;
  const lines = [
    "",
    "§4.4a measurements",
    `  machine: ${machine}`,
    `  TS verifier, ${RECORDS}-record chain, hash recomputation only : ${chainWalk.median.toFixed(2)} ms  (min ${chainWalk.min.toFixed(2)}, max ${chainWalk.max.toFixed(2)})   threshold < 50 ms`,
    `  the same chain including per-record Ed25519 verification      : ${fullWalk.median.toFixed(2)} ms  (min ${fullWalk.min.toFixed(2)}, max ${fullWalk.max.toFixed(2)})   no threshold in v0.1`,
    `  epoch root build, 256 leaves                                  : ${treeBuild.median.toFixed(2)} ms  (min ${treeBuild.min.toFixed(2)}, max ${treeBuild.max.toFixed(2)})   reported, no threshold (D-137)`,
    `  inclusion proof verification (per proof, 100 per run)         : ${(proofVerify.median / 100).toFixed(4)} ms                       reported, no threshold (D-137)`,
    "",
  ];
  console.log(lines.join("\n"));

  // §4.4a keeps one wall-clock bound and it is this one: the 1,000-record chain walk under 50 ms,
  // asserted here because this test runs on the CI runner rather than against a machine description.
  assert.ok(chainWalk.median < 50, `§4.4a: 1,000-record chain walk took ${chainWalk.median.toFixed(2)} ms`);
  // The epoch-root and proof-verification bounds were removed from §4.4a by D-137, after two machines
  // matching its description measured 7 ms and 17.6-19.5 ms for the Rust equivalent. These two rows are
  // implementation-independent, so the removal applies here as well: the figures are reported above and
  // nothing is asserted. A review found these assertions still live after the amendment (PR #59, round
  // two, High 2) — they would have failed on a slow runner against bounds the specification no longer
  // states.
});
