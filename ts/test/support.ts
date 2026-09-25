/**
 * Test-side helpers: where the vectors are, how a vector's JSON turns into engine inputs, and how
 * a refusal is asserted. Nothing here is reachable from the verifier's own code path.
 */
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fromHex, toHex, utf8 } from "../src/bytes.ts";
import { RegistryFailure } from "../src/errors.ts";
import type { RecordLeafInput, ChainState } from "../src/chain.ts";

export const VECTORS_DIR = path.join(import.meta.dirname, "..", "..", "vectors");

/**
 * The asset commitment every record vector's signature was made under. The vectors' `chain` blocks
 * do not carry it, and a leaf preimage cannot be built without it; V-P-01, V-P-02, V-P-03 and
 * KAT-03 all name this one value. See SPEC-DEFECTS.md, "§4.3 vectors omit `c`".
 */
export const ASSET_COMMITMENT = fromHex("0xb98ec7078b78f238301c0fbe1089665cf5fc7e44434352a5c93791e2d15ab5dd", 32);
export const GENESIS_HEAD = fromHex("0xf80403f2aef86bad9181fed9d0c92c314ea0199950caa000351c4fb6192b511c", 32);
/** RFC 8032 §7.1's published specification test key, which the vectors' notes name. */
export const QP_KEY = fromHex("0xd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", 32);

export function vectorFiles(): string[] {
  return readdirSync(VECTORS_DIR).filter((f) => f.endsWith(".json")).sort();
}

export function readVectorText(file: string): string {
  return readFileSync(path.join(VECTORS_DIR, file), "utf8");
}

export function loadVector(id: string): any {
  return JSON.parse(readVectorText(`${id}.json`));
}

export function num(v: string | number): number {
  return typeof v === "number" ? v : Number.parseInt(v, 10);
}

export function big(v: string | number): bigint {
  return BigInt(typeof v === "number" ? v : v.trim());
}

/** A vector's `record` block as §2.2's `RecordLeafInput`. */
export function recordFromJson(r: any): RecordLeafInput {
  return {
    prevHead: fromHex(r.prev_head, 32),
    seq: big(r.seq),
    payloadDigest: fromHex(r.payload_digest, 32),
    assessmentDigest: fromHex(r.assessment_digest, 32),
    qpKey: fromHex(r.qp_key, 32),
    expectedQpKey: r.expected_qp_key === null || r.expected_qp_key === undefined ? null : fromHex(r.expected_qp_key, 32),
    signature: r.signature === null || r.signature === undefined ? null : fromHex(r.signature, 64),
    category: num(r.category),
    effectiveAt: big(r.effective_at),
    changeIdentifiedAt: big(r.change_identified_at),
    payloadUri: utf8(r.payload_uri),
    extCommitment: r.ext_commitment === null || r.ext_commitment === undefined ? null : fromHex(r.ext_commitment, 32),
  };
}

/** A vector's `chain` block as §2.2's chain state, with the asset commitment the corpus implies. */
export function chainFromJson(c: any): ChainState {
  return {
    assetCommitment: ASSET_COMMITMENT,
    schemaVersion: 1,
    head: fromHex(c.head, 32),
    seq: big(c.seq),
    lastEffectiveAt: c.last_effective_at === undefined ? null : big(c.last_effective_at),
    sawResource: c.saw_resource === true,
    previousCategory: c.previous_category === undefined ? null : num(c.previous_category),
  };
}

/** Asserts that `fn` refuses with exactly the code and name a vector's `expected` block names. */
export function expectRefusal(fn: () => unknown, expected: { error: string; error_name: string }, what: string): void {
  let threw: unknown;
  try {
    fn();
  } catch (e) {
    threw = e;
  }
  assert.ok(threw !== undefined, `${what}: expected ${expected.error} ${expected.error_name}, but nothing was refused`);
  assert.ok(
    threw instanceof RegistryFailure,
    `${what}: expected a RegistryFailure, got ${threw instanceof Error ? threw.stack : String(threw)}`,
  );
  const f = threw as RegistryFailure;
  assert.equal(
    `0x${f.code.toString(16).padStart(2, "0")}`,
    expected.error.toLowerCase(),
    `${what}: wrong code (${f.message})`,
  );
  assert.equal(f.codeName, expected.error_name, `${what}: wrong code name (${f.message})`);
}

export function assertBytes(actual: Uint8Array, expectedHex: string, what: string): void {
  assert.equal(toHex(actual), expectedHex.toLowerCase(), what);
}
