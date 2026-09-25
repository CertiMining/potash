/**
 * One handler per committed vector. `vectors.test.ts` enumerates the directory and fails if any
 * `*.json` vector has no entry here, so "every vector" is enforced by the suite rather than
 * claimed by its author.
 */
import assert from "node:assert/strict";
import { fromHex, toHex, utf8 } from "../src/bytes.ts";
import { keccak256, ed25519Verify } from "../src/hash.ts";
import { canonicalize, canonicalizeBytes } from "../src/canonical.ts";
import {
  applyRecord,
  assetCommitment,
  commit,
  genesisHead,
  isWellFormedPayloadUri,
  leafPreimageOf,
  type ChainState,
} from "../src/chain.ts";
import {
  assetPreimage,
  genesisHeadPreimage,
  leafPreimage,
  nodePreimage,
  paddingLeafPreimage,
  prfPreimage,
  realLeafPreimage,
  spiPreimage,
  stepHeadPreimage,
  readTagged,
} from "../src/preimage.ts";
import { TAG_HEAD, TAG_LEAF } from "../src/tags.ts";
import {
  buildEpoch,
  epochKey,
  paddingLeaf,
  proofFor,
  realLeaf,
  slotFromSeed,
  slotSeed,
  verifyInclusion,
  verifyInclusionForHeight,
  type InclusionProof,
} from "../src/tree.ts";
import { decodePromise, encodePromise, promiseKept, spiDigest, verifyPromise } from "../src/promise.ts";
import {
  ASSET_COMMITMENT,
  GENESIS_HEAD,
  assertBytes,
  big,
  chainFromJson,
  expectRefusal,
  loadVector,
  num,
  recordFromJson,
} from "./support.ts";

type Handler = (v: any) => void;

function proofFromJson(p: any): InclusionProof {
  return {
    height: num(p.height),
    siblings: p.siblings.map((s: string) => fromHex(s, 32)),
    slotIndex: num(p.slot_index),
    epoch: big(p.epoch ?? "0"),
  };
}

function realSet(v: any): Array<{ submissionId: Uint8Array; leaf: Uint8Array }> {
  return v.inputs.real.map((r: any) => ({
    submissionId: fromHex(r.submission_id, 16),
    leaf: fromHex(r.leaf, 32),
  }));
}

// ---------------------------------------------------------------- KAT-03

/**
 * KAT-03 is an output, not an input: every preimage here is built from the vector's `fields` and
 * then compared against its `preimage`. The recorded `preimage` is never handed to the hasher.
 */
const katO3: Handler = (v) => {
  const e = v.expected;
  const built: Record<string, Uint8Array> = {
    asset: assetPreimage(
      fromHex(e.asset.fields.jurisdiction, 4),
      fromHex(e.asset.fields.registry, 8),
      utf8(e.asset.fields.tenure),
    ),
    genesis_head: genesisHeadPreimage(
      fromHex(e.genesis_head.fields.asset_commitment, 32),
      num(e.genesis_head.fields.schema_version),
    ),
    leaf: leafPreimage(fromHex(e.leaf.fields.asset_commitment, 32), {
      seq: big(e.leaf.fields.seq),
      payloadDigest: fromHex(e.leaf.fields.payload_digest, 32),
      assessmentDigest: fromHex(e.leaf.fields.assessment_digest, 32),
      qpKey: fromHex(e.leaf.fields.qp_key, 32),
      category: num(e.leaf.fields.category),
      effectiveAt: big(e.leaf.fields.effective_at),
      changeIdentifiedAt: big(e.leaf.fields.change_identified_at),
    }),
    node: nodePreimage(fromHex(e.node.fields.left, 32), fromHex(e.node.fields.right, 32)),
    padding: paddingLeafPreimage(fromHex(e.padding.fields.prf_output, 32)),
    prf: prfPreimage(fromHex(e.prf.fields.k, 32), fromHex(e.prf.fields.x)),
    real_leaf: realLeafPreimage(fromHex(e.real_leaf.fields.leaf, 32)),
    spi: spiPreimage({
      leaf: fromHex(e.spi.fields.leaf, 32),
      submissionId: fromHex(e.spi.fields.submission_id, 16),
      acceptedEpoch: big(e.spi.fields.accepted_epoch),
      promisedEpoch: big(e.spi.fields.promised_epoch),
      maxMergeDelay: num(e.spi.fields.max_merge_delay),
    }),
    step_head: stepHeadPreimage(fromHex(e.step_head.fields.prev_head, 32), fromHex(e.step_head.fields.leaf, 32)),
  };

  // The PRF's recorded use code and length are part of what the writer must produce.
  const x = fromHex(e.prf.fields.x);
  assert.equal(x[0], fromHex(e.prf.fields.use_code, 1)[0], "prf: x does not begin with its use code");
  assert.equal(x.length, num(e.prf.fields["len(x)"]), "prf: len(x) disagrees with x");

  for (const [name, preimage] of Object.entries(built)) {
    const expected = e[name];
    assert.ok(expected !== undefined, `KAT-03 carries no writer named ${name}`);
    assertBytes(preimage, expected.preimage, `${name}: built preimage differs from the vector's bytes`);
    assert.equal(preimage.length, num(expected.preimage_len), `${name}: preimage_len`);
    assert.equal(toHex(preimage.subarray(0, 8)), toHex(utf8(expected.tag)), `${name}: domain tag`);
    assertBytes(keccak256(preimage), expected.digest, `${name}: digest of the built preimage`);
  }
  assert.equal(Object.keys(built).length, Object.keys(e).length, "KAT-03 holds a writer this test does not build");
};

// ---------------------------------------------------------------- positives

const vP01: Handler = (v) => {
  const a = canonicalize(v.inputs.raw_tenure_a);
  const b = canonicalize(v.inputs.raw_tenure_b);
  assert.equal(new TextDecoder().decode(a), v.expected.canonical_tenure, "raw_tenure_a canonicalizes");
  assert.equal(new TextDecoder().decode(b), v.expected.canonical_tenure, "raw_tenure_b canonicalizes");
  const j = fromHex(v.inputs.jurisdiction, 4);
  const r = fromHex(v.inputs.registry, 8);
  assertBytes(assetPreimage(j, r, a), v.expected.asset_commitment_preimage, "asset commitment preimage");
  assertBytes(assetCommitment(j, r, a), v.expected.asset_commitment, "asset commitment from spelling a");
  assertBytes(assetCommitment(j, r, b), v.expected.asset_commitment, "asset commitment from spelling b");
};

const vP02: Handler = (v) => {
  const c = fromHex(v.inputs.asset_commitment, 32);
  const schema = num(v.inputs.schema_version);
  assertBytes(genesisHeadPreimage(c, schema), v.expected.genesis_preimage, "genesis preimage");
  assertBytes(genesisHead(c, schema), v.expected.genesis_head, "genesis head");
};

/** Walks the five records, checking every leaf, head, preimage and flag value on the way. */
function walkChainOfFive(v: any, from: ChainState, firstStep: number): ChainState {
  let state = from;
  const steps = v.expected.steps as any[];
  for (let i = firstStep; i < steps.length; i++) {
    const step = steps[i]!;
    const record = recordFromJson(step.record);
    const preimage = leafPreimageOf(state.assetCommitment, record);
    assertBytes(preimage, step.leaf_preimage, `step ${i + 1}: leaf preimage`);
    const applied = applyRecord(state, record);
    assertBytes(applied.leaf, step.leaf, `step ${i + 1}: leaf`);
    assertBytes(applied.head, step.head, `step ${i + 1}: head`);
    assert.equal(applied.flags, num(step.flags), `step ${i + 1}: flags`);
    assert.equal(record.seq, big(step.seq), `step ${i + 1}: seq`);
    state = commit(state, record, applied);
  }
  return state;
}

const vP03: Handler = (v) => {
  const c = fromHex(v.inputs.asset_commitment, 32);
  const state: ChainState = {
    assetCommitment: c,
    schemaVersion: num(v.inputs.schema_version),
    head: genesisHead(c, num(v.inputs.schema_version)),
    seq: 0n,
    lastEffectiveAt: null,
    sawResource: false,
    previousCategory: null,
  };
  const end = walkChainOfFive(v, state, 0);
  assertBytes(end.head, v.expected.head_after_five, "head after five records");
};

const vP04: Handler = (v) => {
  // INV-STATE-02: the records themselves live in V-P-03; this vector supplies only the state to
  // resume from, which is the point — a later holder recomputes from h₂ without the earlier leaves.
  const source = loadVector("V-P-03");
  const r = v.inputs.resumed_from;
  const state: ChainState = {
    assetCommitment: ASSET_COMMITMENT,
    schemaVersion: 1,
    head: fromHex(r.head, 32),
    seq: big(r.seq),
    lastEffectiveAt: big(r.last_effective_at),
    sawResource: r.saw_resource === true,
    previousCategory: num(r.previous_category),
  };
  const end = walkChainOfFive(source, state, Number(big(r.seq)));
  assertBytes(end.head, v.expected.head_after_five, "head recomputed from sequence two");
};

const vP09: Handler = (v) => {
  const record = recordFromJson(v.inputs.record);
  const state: ChainState = {
    assetCommitment: ASSET_COMMITMENT,
    schemaVersion: 1,
    head: GENESIS_HEAD,
    seq: 0n,
    lastEffectiveAt: null,
    sawResource: false,
    previousCategory: null,
  };
  assertBytes(leafPreimageOf(state.assetCommitment, record), v.expected.leaf_preimage, "leaf preimage");
  const applied = applyRecord(state, record);
  assertBytes(applied.leaf, v.expected.leaf, "leaf");
  assertBytes(applied.head, v.expected.head, "head");
  assert.equal(applied.flags, num(v.expected.flags), "flags");
};

const vP11: Handler = (v) => {
  const record = recordFromJson(v.inputs.record);
  const base: ChainState = {
    assetCommitment: ASSET_COMMITMENT,
    schemaVersion: 1,
    head: GENESIS_HEAD,
    seq: 0n,
    lastEffectiveAt: null,
    sawResource: false,
    previousCategory: null,
  };
  const flagged = applyRecord(base, record);
  assertBytes(flagged.leaf, v.expected.flagged.leaf, "flagged leaf");
  assert.equal(flagged.flags, num(v.expected.flagged.flags), "flagged flags");

  const seen = applyRecord({ ...base, sawResource: true }, record);
  assertBytes(seen.leaf, v.expected.unflagged.leaf, "unflagged leaf");
  assert.equal(seen.flags, num(v.expected.unflagged.flags), "unflagged flags");

  // INV-STATE-06a: the flag does not change the leaf digest.
  assert.equal(toHex(flagged.leaf), toHex(seen.leaf), "a flag changed the leaf digest");
};

// ---------------------------------------------------------------- epoch trees

function checkBuilt(v: any, expected: any, height: number, epoch: bigint, masterKey: Uint8Array): void {
  const built = buildEpoch(epoch, height, masterKey, realSet(v));
  assertBytes(built.root, expected.root, `H=${height}: root`);
  assertBytes(epochKey(masterKey, epoch), expected.epoch_key, `H=${height}: epoch key`);

  assert.equal(built.assignment.length, expected.assignment.length, `H=${height}: assignment length`);
  expected.assignment.forEach((a: any, i: number) => {
    const got = built.assignment[i]!;
    assertBytes(got.submissionId, a.submission_id, `H=${height}: assignment[${i}] identifier`);
    assert.equal(got.slot, num(a.slot), `H=${height}: assignment[${i}] slot`);
  });

  if (expected.leaves !== undefined) {
    assert.equal(built.leaves.length, expected.leaves.length, `H=${height}: leaf count`);
    expected.leaves.forEach((leafHex: string, i: number) => {
      assertBytes(built.leaves[i]!, leafHex, `H=${height}: leaf at slot ${i}`);
    });
  }

  for (const p of expected.proofs) {
    const chainLeaf = fromHex(p.leaf, 32);
    const recorded = proofFromJson(p.proof);
    const generated = proofFor(built, fromHex(p.submission_id, 16));
    assert.equal(generated.slotIndex, recorded.slotIndex, `H=${height}: generated slot for ${p.submission_id}`);
    assert.equal(generated.height, recorded.height, `H=${height}: generated height`);
    assert.equal(generated.siblings.length, height, `H=${height}: proof length tracks H`);
    generated.siblings.forEach((s, i) => {
      assertBytes(s, toHex(recorded.siblings[i]!), `H=${height}: sibling ${i} for ${p.submission_id}`);
    });
    verifyInclusion(chainLeaf, recorded, built.root);
    verifyInclusionForHeight(chainLeaf, recorded, built.root, height);
  }
}

const vP05: Handler = (v) => {
  const masterKey = fromHex(v.inputs.master_key, 32);
  const epoch = big(v.inputs.epoch);
  const height = num(v.inputs.height);
  const built = buildEpoch(epoch, height, masterKey, realSet(v));
  checkBuilt(v, v.expected, height, epoch, masterKey);
  assert.equal(built.leaves.length, num(v.inputs.capacity), "capacity");

  // Every hashing step behind the root, which is what this vector records.
  const s = v.expected.steps;
  const ke = epochKey(masterKey, epoch);
  assertBytes(keccak256(fromHex(s.epoch_key.preimage)), s.epoch_key.digest, "epoch key digest");
  assertBytes(ke, s.epoch_key.digest, "epoch key");

  const id = fromHex(v.inputs.real[0].submission_id, 16);
  const seed = slotSeed(ke, id);
  assertBytes(seed, s.slot_seed.digest, "slot seed digest");
  assert.equal(slotFromSeed(seed, height), num(s.slot_seed.slot), "slot from seed");

  const padSlot = num(s.padding_leaf.slot);
  assertBytes(paddingLeaf(ke, padSlot), s.padding_leaf.leaf.digest, `padding leaf at slot ${padSlot}`);

  const chainLeaf = fromHex(v.inputs.real[0].leaf, 32);
  assertBytes(realLeafPreimage(chainLeaf), s.real_leaf.preimage, "real leaf preimage");
  assertBytes(realLeaf(chainLeaf), s.real_leaf.digest, "real leaf digest");

  // The recorded path, level by level: the left and right at each step and the node they make.
  const proof = proofFor(built, id);
  let node = realLeaf(chainLeaf);
  s.path.forEach((level: any, i: number) => {
    const leafOnTheLeft = ((proof.slotIndex >> i) & 1) === 0;
    assert.equal(leafOnTheLeft, level.leaf_on_the_left, `path level ${i}: side`);
    const left = leafOnTheLeft ? node : proof.siblings[i]!;
    const right = leafOnTheLeft ? proof.siblings[i]! : node;
    assertBytes(left, level.left, `path level ${i}: left`);
    assertBytes(right, level.right, `path level ${i}: right`);
    assertBytes(nodePreimage(left, right), level.preimage, `path level ${i}: preimage`);
    node = keccak256(nodePreimage(left, right));
    assertBytes(node, level.digest, `path level ${i}: digest`);
    assert.equal(num(level.level), i, `path level ${i}: level index`);
  });
  assertBytes(node, v.expected.root, "the path reaches the root");
};

const vP06: Handler = (v) => {
  const masterKey = fromHex(v.inputs.master_key, 32);
  const epoch = big(v.inputs.epoch);
  const height = num(v.inputs.height);
  checkBuilt(v, v.expected, height, epoch, masterKey);

  // The vector records three of the 255 proofs; every one of them is checked here.
  const built = buildEpoch(epoch, height, masterKey, realSet(v));
  for (const entry of realSet(v)) {
    const proof = proofFor(built, entry.submissionId);
    assert.equal(proof.siblings.length, height, "proof length");
    verifyInclusionForHeight(entry.leaf, proof, built.root, height);
  }
};

const vP06b: Handler = (v) => {
  const masterKey = fromHex(v.inputs.master_key, 32);
  const epoch = big(v.inputs.epoch);
  for (const h of v.inputs.heights) {
    const height = num(h);
    const expected = v.expected[`H${height}`];
    assert.ok(expected !== undefined, `no expected block for H${height}`);
    checkBuilt(v, expected, height, epoch, masterKey);
  }
  // The same leaf set at two heights: the proof length tracks H exactly and the roots differ.
  assert.notEqual(v.expected.H4.root, v.expected.H12.root, "two heights produced one root");
};

// ---------------------------------------------------------------- promises

const vP10: Handler = (v) => {
  const e = v.expected;
  const promise = decodePromise(fromHex(e.promise.encoded));
  assertBytes(promise.leaf, e.promise.leaf, "promise leaf");
  assertBytes(promise.submissionId, e.promise.submission_id, "promise submission id");
  assert.equal(promise.acceptedEpoch, big(e.promise.accepted_epoch), "accepted epoch");
  assert.equal(promise.promisedEpoch, big(e.promise.promised_epoch), "promised epoch");
  assert.equal(promise.maxMergeDelay, num(e.promise.max_merge_delay), "max merge delay");
  assertBytes(promise.batcherKey, e.promise.batcher_key, "batcher key");
  assertBytes(promise.signature, e.promise.signature, "signature");
  assertBytes(encodePromise(promise), e.promise.encoded, "re-encoding the promise");

  assertBytes(
    spiPreimage({
      leaf: promise.leaf,
      submissionId: promise.submissionId,
      acceptedEpoch: promise.acceptedEpoch,
      promisedEpoch: promise.promisedEpoch,
      maxMergeDelay: promise.maxMergeDelay,
    }),
    v.inputs.spi_preimage,
    "SPI preimage",
  );
  assertBytes(spiDigest(promise), e.spi_digest, "SPI digest");

  // §1.6 signs the digest, not the preimage.
  assert.ok(
    ed25519Verify(promise.batcherKey, spiDigest(promise), promise.signature),
    "the promise's signature does not verify over the SPI digest",
  );
  const observed = big(v.inputs.observed_checkpoint_epoch_at_receipt);
  verifyPromise(promise, promise.batcherKey, observed);

  const satisfied = e.satisfied;
  promiseKept(promise, proofFromJson(satisfied.proof), {
    epoch: big(satisfied.epoch),
    root: fromHex(satisfied.root, 32),
  });

  const after = e.after_the_window;
  expectRefusal(
    () => promiseKept(promise, proofFromJson(after.proof), { epoch: big(after.epoch), root: fromHex(after.root, 32) }),
    after.expected,
    "a root published after the window",
  );
};

// ---------------------------------------------------------------- negatives

/** The common shape: one chain, one record, one expected code. */
function refuseRecord(v: any, record: any, expected: any, what: string): void {
  const state = chainFromJson(v.inputs.chain);
  expectRefusal(() => applyRecord(state, recordFromJson(record)), expected, what);
}

const vN01: Handler = (v) => refuseRecord(v, v.inputs.record, v.expected, "a record against the wrong head");

const vN02: Handler = (v) => {
  for (const c of v.expected.cases) refuseRecord(v, c.record, c.expected, c.case);
};

const vN03: Handler = (v) => {
  for (const c of v.expected.cases) {
    if (c.record === undefined) {
      // The 129-byte case: §1.3's rule returns false before a record exists.
      const uri = utf8(c.payload_uri);
      assert.equal(uri.length, num(c.payload_uri_len), `${c.case}: length`);
      assert.equal(isWellFormedPayloadUri(uri), false, `${c.case}: §1.3's rule accepted it`);
      // And a record carrying it reaches condition (f), because the URI is not in the leaf preimage.
      const carrier = { ...v.expected.cases[2].record, payload_uri: c.payload_uri };
      refuseRecord(v, carrier, c.expected, `${c.case}: carried by a record`);
    } else {
      assert.equal(isWellFormedPayloadUri(utf8(c.record.payload_uri)), false, `${c.case}: §1.3's rule accepted it`);
      refuseRecord(v, c.record, c.expected, c.case);
    }
  }
};

const vN04: Handler = (v) => refuseRecord(v, v.inputs.record, v.expected, "no qualified person's signature");
const vN05: Handler = (v) => refuseRecord(v, v.inputs.record, v.expected, "a signature over JSON");
const vN06: Handler = (v) => refuseRecord(v, v.inputs.record, v.expected, "an expected key that disagrees");

const vN07: Handler = (v) => {
  const state = chainFromJson(v.inputs.chain);
  const record = recordFromJson(v.inputs.record);
  const applied = applyRecord(state, record); // must not refuse
  assertBytes(applied.leaf, v.expected.leaf, "leaf");
  assertBytes(applied.head, v.expected.head, "head");
  assert.equal(applied.flags, num(v.expected.flags), "flags");
  assert.equal(v.expected.error, null, "the vector expects no error");
};

const vN07b: Handler = (v) => {
  for (const c of v.expected.cases) refuseRecord(v, c.record, c.expected, c.case);
};

const vN08: Handler = (v) => refuseRecord(v, v.inputs.record, v.expected, "an effective date that goes backwards");

const vN09: Handler = (v) => {
  const preimage = fromHex(v.inputs.preimage);
  expectRefusal(() => readTagged(preimage, TAG_HEAD), v.expected, `read as ${v.inputs.read_as}`);
  readTagged(preimage, TAG_LEAF); // under its own tag it reads cleanly
};

const vN13: Handler = (v) => {
  expectRefusal(
    () => genesisHead(fromHex(v.inputs.asset_commitment, 32), num(v.inputs.schema_version)),
    v.expected,
    "a schema this engine does not implement",
  );
};

const vN14: Handler = (v) => {
  const masterKey = fromHex(v.inputs.master_key, 32);
  const epoch = big(v.inputs.epoch);
  const height = num(v.inputs.height);
  const capacity = num(v.inputs.capacity);
  const count = num(v.inputs.submissions);
  const make = (n: number) =>
    Array.from({ length: n }, (_, i) => {
      const submissionId = new Uint8Array(16);
      new DataView(submissionId.buffer).setUint32(0, i, true);
      return { submissionId, leaf: keccak256(submissionId) };
    });

  // The tree refuses more than C leaves.
  expectRefusal(
    () => buildEpoch(epoch, height, masterKey, make(count)),
    v.expected.tree_asked_to_build_c_plus_one,
    `${count} real submissions into ${capacity} slots`,
  );
  // At exactly C it builds, so the refusal is capacity and not something else.
  assert.equal(buildEpoch(epoch, height, masterKey, make(capacity)).leaves.length, capacity, "C leaves build");

  // The batcher never asks: it queues the excess and promises the next epoch it can meet. What a
  // verifier can check of that is the promise itself — its binding, its signature and its policy.
  const b = v.expected.batcher;
  const promise = decodePromise(fromHex(b.submission_past_capacity.encoded));
  assertBytes(encodePromise(promise), b.submission_past_capacity.encoded, "re-encoding the promise");
  assert.equal(promise.acceptedEpoch, epoch, "accepted epoch");
  assert.equal(promise.promisedEpoch, big(b.promised_epoch), "promised epoch");
  assert.equal(promise.promisedEpoch, promise.acceptedEpoch + 1n, "the next epoch the batcher can meet");
  verifyPromise(promise, fromHex(b.submission_past_capacity.batcher_key, 32), epoch);
  assert.equal(num(b.dropped), 0, "nothing is dropped");
  // `overflow_queue_len` is a batcher property; this verifier holds no queue and does not assert it.
  assert.equal(num(b.overflow_queue_len), 1, "the vector records one queued submission");
};

function treeNegative(v: any, run: (proof: InclusionProof, root: Uint8Array, c: any) => void): void {
  const leaf = fromHex(v.inputs.leaf, 32);
  // The valid proof in the same vector must verify, or the negative cases prove nothing.
  verifyInclusion(leaf, { ...proofFromJson(v.inputs.valid_proof) }, fromHex(v.inputs.root, 32));
  for (const c of v.expected.cases) run(proofFromJson(c.proof), fromHex(c.root, 32), c);
}

const vN15: Handler = (v) => {
  const leaf = fromHex(v.inputs.leaf, 32);
  treeNegative(v, (proof, root, c) => expectRefusal(() => verifyInclusion(leaf, proof, root), c.expected, c.case));
};

const vN16: Handler = (v) => {
  const leaf = fromHex(v.inputs.leaf, 32);
  treeNegative(v, (proof, root, c) => expectRefusal(() => verifyInclusion(leaf, proof, root), c.expected, c.case));
};

const vN16b: Handler = (v) => {
  const leaf = fromHex(v.inputs.leaf, 32);
  treeNegative(v, (proof, root, c) =>
    expectRefusal(
      () => verifyInclusionForHeight(leaf, proof, root, num(c.configured_height)),
      c.expected,
      c.case,
    ),
  );
};

const vN17: Handler = (v) => {
  const leaf = fromHex(v.inputs.leaf, 32);
  treeNegative(v, (proof, root, c) => expectRefusal(() => verifyInclusion(leaf, proof, root), c.expected, c.case));
};

const vN20: Handler = (v) => refuseRecord(v, v.inputs.record, v.expected, "a sequence counter with nowhere to go");

const vN21: Handler = (v) => {
  for (const raw of v.inputs.raw_tenures) {
    expectRefusal(() => canonicalize(raw), v.expected[raw], `tenure ${JSON.stringify(raw)}`);
    expectRefusal(() => canonicalizeBytes(utf8(raw)), v.expected[raw], `tenure bytes ${JSON.stringify(raw)}`);
  }
};

const vN23: Handler = (v) => {
  // Both (a) and (f) fail; the earlier condition decides.
  assert.equal(isWellFormedPayloadUri(utf8(v.inputs.record.payload_uri)), false, "(f) should also fail here");
  refuseRecord(v, v.inputs.record, v.expected, "a record failing both (a) and (f)");
};

const vN24: Handler = (v) => {
  // The schema gate precedes (a), and (a) would also fail.
  assert.notEqual(v.inputs.record.prev_head, v.inputs.chain.head, "(a) should also fail here");
  refuseRecord(v, v.inputs.record, v.expected, "ext_commitment beside a wrong head");
};

const vN25: Handler = (v) => {
  const record = recordFromJson(v.inputs.record);
  assert.equal(record.expectedQpKey, null, "no expected key is supplied");
  assert.equal(
    ed25519Verify(record.qpKey, leafPreimageOf(ASSET_COMMITMENT, record), record.signature!),
    false,
    "the signature must not verify under the claimed key",
  );
  refuseRecord(v, v.inputs.record, v.expected, "a signature by another key, with no expected key");
};

export const HANDLERS: Record<string, Handler> = {
  "KAT-03": katO3,
  "V-P-01": vP01,
  "V-P-02": vP02,
  "V-P-03": vP03,
  "V-P-04": vP04,
  "V-P-05": vP05,
  "V-P-06": vP06,
  "V-P-06b": vP06b,
  "V-P-09": vP09,
  "V-P-10": vP10,
  "V-P-11": vP11,
  "V-N-01": vN01,
  "V-N-02": vN02,
  "V-N-03": vN03,
  "V-N-04": vN04,
  "V-N-05": vN05,
  "V-N-06": vN06,
  "V-N-07": vN07,
  "V-N-07b": vN07b,
  "V-N-08": vN08,
  "V-N-09": vN09,
  "V-N-13": vN13,
  "V-N-14": vN14,
  "V-N-15": vN15,
  "V-N-16": vN16,
  "V-N-16b": vN16b,
  "V-N-17": vN17,
  "V-N-20": vN20,
  "V-N-21": vN21,
  "V-N-23": vN23,
  "V-N-24": vN24,
  "V-N-25": vN25,
};
