/**
 * §2.5 packages, assembled here because no committed vector is one.
 *
 * The record is V-P-09's. The epoch it is anchored in is built with V-P-05's and V-P-06's own
 * master key and epoch numbers, with the record's leaf added to their real sets: the vectors carry
 * no tree that holds this leaf, so the tree is built rather than quoted. The builder is the same
 * code the committed vectors pin — `vectors.test.ts` reproduces V-P-05's and V-P-06's recorded
 * roots, assignments and proofs with it — so what is assembled here rests on checked bytes.
 */
import { base64Encode, fromHex, toHex } from "../src/bytes.ts";
import { keccak256 } from "../src/hash.ts";
import { advanceHead } from "../src/chain.ts";
import { leafPreimageOf } from "../src/chain.ts";
import { buildEpoch, proofFor, type BuiltEpoch } from "../src/tree.ts";
import type { DisclosurePackage } from "../src/disclosure.ts";
import { GENESIS_HEAD, ASSET_COMMITMENT, loadVector, recordFromJson } from "./support.ts";

export const RECORD_SUBMISSION_ID = fromHex("0x02000000000000000000000000000000", 16);

export function recordLeaf(): { leaf: Uint8Array; preimage: Uint8Array; record: any } {
  const v = loadVector("V-P-09");
  const record = recordFromJson(v.inputs.record);
  const preimage = leafPreimageOf(ASSET_COMMITMENT, record);
  return { leaf: keccak256(preimage), preimage, record: v.inputs.record };
}

/** The V-P-05 epoch with the record's leaf added beside the vector's own. */
export function epochHoldingRecord(): BuiltEpoch {
  const v = loadVector("V-P-05");
  const { leaf } = recordLeaf();
  const real = [
    ...v.inputs.real.map((r: any) => ({ submissionId: fromHex(r.submission_id, 16), leaf: fromHex(r.leaf, 32) })),
    { submissionId: RECORD_SUBMISSION_ID, leaf },
  ];
  return buildEpoch(BigInt(v.inputs.epoch), Number(v.inputs.height), fromHex(v.inputs.master_key, 32), real);
}

/** The V-P-06 epoch, filled to capacity by the record's leaf: 255 vector leaves plus this one. */
export function fullEpochHoldingRecord(): BuiltEpoch {
  const v = loadVector("V-P-06");
  const { leaf } = recordLeaf();
  const real = [
    ...v.inputs.real.map((r: any) => ({ submissionId: fromHex(r.submission_id, 16), leaf: fromHex(r.leaf, 32) })),
    { submissionId: RECORD_SUBMISSION_ID, leaf },
  ];
  return buildEpoch(BigInt(v.inputs.epoch), Number(v.inputs.height), fromHex(v.inputs.master_key, 32), real);
}

export function packageFrom(built: BuiltEpoch): DisclosurePackage {
  const { preimage, record } = recordLeaf();
  const proof = proofFor(built, RECORD_SUBMISSION_ID);
  const leaf = keccak256(preimage);
  return {
    schema: "certimining/v1/disclosure",
    record: {
      seq: Number(record.seq),
      category: Number(record.category),
      effective_at: Number(record.effective_at),
      change_identified_at: Number(record.change_identified_at),
      payload_digest: record.payload_digest,
      assessment_digest: record.assessment_digest,
      qp_key: record.qp_key,
      payload_uri: record.payload_uri,
      flags: 0,
    },
    preimage_borsh: base64Encode(preimage),
    chain: {
      prev_head: toHex(GENESIS_HEAD),
      head: toHex(advanceHead(GENESIS_HEAD, leaf)),
      genesis: toHex(GENESIS_HEAD),
    },
    qp_signature: record.signature,
    inclusion: {
      epoch: proof.epoch.toString(),
      height: proof.height,
      slot_index: proof.slotIndex,
      siblings: proof.siblings.map((s) => toHex(s)),
    },
    anchor: {
      solana_tx: "5".repeat(64),
      solana_slot: 0,
      ots_receipt_digest: `0x${"00".repeat(32)}`,
    },
  };
}

/** A deep copy, so one case's tampering never reaches another's package. */
export function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}
