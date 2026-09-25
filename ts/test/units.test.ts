/**
 * The parts no committed vector reaches: §2.4's address derivation and account decoding, the
 * promise policy of §1.6, canonicalization's edges, and the preimage ceiling of §2.2.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { concat, fromHex, toHex, u16le, u64le, utf8, base64Decode, base64Encode } from "../src/bytes.ts";
import { RegistryFailure, PackageFailure, REGISTRY_CODES, codeName } from "../src/errors.ts";
import { MAX_PREIMAGE_LEN, PreimageSink, prfPreimage } from "../src/preimage.ts";
import { canonicalize, canonicalizeBytes } from "../src/canonical.ts";
import { assetCommitment, isWellFormedPayloadUri } from "../src/chain.ts";
import { isOnCurve, sha256 } from "../src/hash.ts";
import { base58Decode, base58Encode } from "../src/solana/base58.ts";
import { createProgramAddress, deriveCheckpointAddress, deriveLogConfigAddress, findProgramAddress } from "../src/solana/pda.ts";
import {
  CHECKPOINT_DISCRIMINATOR,
  CHECKPOINT_LEN,
  LOG_CONFIG_DISCRIMINATOR,
  accountDiscriminator,
  anchorStatus,
  decodeCheckpointAccount,
  decodeLogConfig,
} from "../src/solana/accounts.ts";
import { DEVNET_PROGRAM_ID, fetchCheckpoint, fetchRoot } from "../src/solana/rpc.ts";
import { MAX_MERGE_DELAY, decodePromise, verifyPromise } from "../src/promise.ts";
import { loadVector } from "./support.ts";

test("§2.4's published discriminators are SHA-256 of a published string, and these are they", () => {
  assert.equal(toHex(accountDiscriminator("LogConfig")), "0x1cf0757f1aa6bf37");
  assert.equal(toHex(accountDiscriminator("CheckpointAccount")), "0x4d1199cb01ec4759");
  assert.equal(toHex(LOG_CONFIG_DISCRIMINATOR), "0x1cf0757f1aa6bf37");
  assert.equal(toHex(CHECKPOINT_DISCRIMINATOR), "0x4d1199cb01ec4759");
  assert.equal(toHex(sha256(utf8("account:LogConfig")).slice(0, 8)), "0x1cf0757f1aa6bf37");
});

test("base58 round-trips every Solana address shape, leading zeros included", () => {
  for (const s of [DEVNET_PROGRAM_ID, "11111111111111111111111111111111", "SysvarRent111111111111111111111111111111111"]) {
    const bytes = base58Decode(s);
    assert.equal(bytes.length, 32, s);
    assert.equal(base58Encode(bytes), s);
  }
  assert.throws(() => base58Decode("0OIl"), TypeError);
});

test("§2.4's PDAs derive deterministically, land off the curve, and depend on the epoch", () => {
  const programId = base58Decode(DEVNET_PROGRAM_ID);
  const config = deriveLogConfigAddress(programId);
  assert.equal(config.address.length, 32);
  assert.equal(isOnCurve(config.address), false, "a program address must be off the curve");
  assert.deepEqual(deriveLogConfigAddress(programId), config, "derivation is not deterministic");

  const a = deriveCheckpointAddress(programId, 20361n);
  const b = deriveCheckpointAddress(programId, 20362n);
  assert.notEqual(toHex(a.address), toHex(b.address), "two epochs share an address");
  assert.equal(isOnCurve(a.address), false);
  assert.ok(a.bump <= 255 && a.bump >= 0);

  // The bump found is the canonical one: every higher bump is on the curve.
  for (let bump = 255; bump > a.bump; bump--) {
    assert.equal(createProgramAddress([utf8("cm_ckpt"), u64le(20361n), Uint8Array.of(bump)], programId), null);
  }
  assert.throws(() => findProgramAddress([new Uint8Array(33)], programId), RangeError);
});

function checkpointBytes(fields: { epoch: bigint; root: Uint8Array; receipt?: Uint8Array }): Uint8Array {
  const data = new Uint8Array(CHECKPOINT_LEN);
  data.set(CHECKPOINT_DISCRIMINATOR, 0);
  data.set(u16le(1), 8);
  data.set(u64le(fields.epoch), 10);
  data.set(fields.root, 18);
  data.set(u64le(123456n), 50);
  data.set(u64le(1760000000n), 58);
  if (fields.receipt) data.set(fields.receipt, 66);
  data[98] = fields.receipt ? 1 : 0;
  data[99] = 254;
  return data;
}

test("§2.4's CheckpointAccount decodes at the stated offsets, and refuses anything else", () => {
  const root = fromHex(`0x${"ab".repeat(32)}`, 32);
  const decoded = decodeCheckpointAccount(checkpointBytes({ epoch: 20361n, root }));
  assert.equal(decoded.schemaVersion, 1);
  assert.equal(decoded.epoch, 20361n);
  assert.equal(toHex(decoded.root), toHex(root));
  assert.equal(decoded.publishedSlot, 123456n);
  assert.equal(decoded.publishedUnix, 1760000000n);
  assert.equal(decoded.anchorKind, 0);
  assert.equal(decoded.bump, 254);
  assert.equal(anchorStatus(decoded), "single", "INV-ANCH-05: no receipt yet");
  assert.equal(anchorStatus(decodeCheckpointAccount(checkpointBytes({ epoch: 1n, root, receipt: root }))), "dual");

  assert.throws(() => decodeCheckpointAccount(new Uint8Array(CHECKPOINT_LEN)), PackageFailure); // wrong discriminator
  assert.throws(() => decodeCheckpointAccount(checkpointBytes({ epoch: 1n, root }).slice(0, 105)), PackageFailure);
  const asLogConfig = new Uint8Array(68);
  asLogConfig.set(LOG_CONFIG_DISCRIMINATOR, 0);
  asLogConfig[50] = 8;
  assert.equal(decodeLogConfig(asLogConfig).treeHeight, 8);
  assert.throws(() => decodeCheckpointAccount(asLogConfig), PackageFailure);
});

test("fetching a root speaks JSON-RPC and refuses an account that is not the one asked for", async () => {
  const programId = base58Decode(DEVNET_PROGRAM_ID);
  const root = fromHex(`0x${"cd".repeat(32)}`, 32);
  const expectedAddress = base58Encode(deriveCheckpointAddress(programId, 20361n).address);

  let sawAddress = "";
  const stub = (payload: unknown): typeof fetch =>
    (async (_url: string, init: any) => {
      const body = JSON.parse(init.body);
      assert.equal(body.method, "getAccountInfo");
      sawAddress = body.params[0];
      assert.equal(body.params[1].encoding, "base64");
      return { ok: true, json: async () => payload } as any;
    }) as unknown as typeof fetch;

  const ok = await fetchRoot(20361n, {
    fetchImpl: stub({
      result: { value: { data: [base64Encode(checkpointBytes({ epoch: 20361n, root })), "base64"], owner: DEVNET_PROGRAM_ID } },
    }),
  });
  assert.equal(sawAddress, expectedAddress, "the verifier read an address it did not derive");
  assert.equal(toHex(ok.root), toHex(root));
  assert.equal(ok.epoch, 20361n);

  await assert.rejects(
    fetchCheckpoint(20361n, {
      fetchImpl: stub({
        result: { value: { data: [base64Encode(checkpointBytes({ epoch: 20362n, root })), "base64"], owner: DEVNET_PROGRAM_ID } },
      }),
    }),
    (e: unknown) => e instanceof PackageFailure && e.failure === "RootEpochMismatch",
  );

  await assert.rejects(
    fetchCheckpoint(20361n, {
      fetchImpl: stub({
        result: { value: { data: [base64Encode(checkpointBytes({ epoch: 20361n, root })), "base64"], owner: "11111111111111111111111111111111" } },
      }),
    }),
    (e: unknown) => e instanceof PackageFailure && e.failure === "RootUnavailable",
  );

  await assert.rejects(
    fetchCheckpoint(20361n, { fetchImpl: stub({ result: { value: null } }) }),
    (e: unknown) => e instanceof PackageFailure && e.failure === "RootUnavailable",
  );
});

test("§2.2's preimage ceiling returns 0x0C rather than growing", () => {
  const sink = new PreimageSink();
  sink.write(new Uint8Array(MAX_PREIMAGE_LEN));
  assert.throws(() => sink.write(Uint8Array.of(1)), (e: unknown) => e instanceof RegistryFailure && e.code === 0x0c);
  // The PRF's own writer is bounded by the same ceiling.
  assert.throws(
    () => prfPreimage(new Uint8Array(32), new Uint8Array(256)),
    (e: unknown) => e instanceof RegistryFailure && e.code === 0x0c,
  );
});

test("§1.3's canonicalization: NFKD first, then a to z, then the filter, then the bounds", () => {
  const text = (b: Uint8Array) => new TextDecoder().decode(b);
  assert.equal(text(canonicalize("bc-tenure 1043-a")), "BCTENURE1043A");
  assert.equal(text(canonicalize("ﬁle-7")), "FILE7", "NFKD runs before the filter");
  assert.equal(text(canonicalize("①②")), "12", "compatibility digits decompose");
  assert.equal(text(canonicalize("café-9")), "CAFE9", "a combining mark is dropped, not the letter");
  // Idempotent on its own output.
  const once = canonicalize("bc-tenure 1043-a");
  assert.equal(toHex(canonicalizeBytes(once)), toHex(once));

  for (const bad of ["", "   ", "-_./", "œæß"]) {
    assert.throws(() => canonicalize(bad), (e: unknown) => e instanceof RegistryFailure && e.code === 0x11, bad);
  }
  assert.throws(() => canonicalize("A".repeat(65)), (e: unknown) => e instanceof RegistryFailure && e.code === 0x11);
  assert.doesNotThrow(() => canonicalize("A".repeat(64)));
  assert.throws(() => canonicalize("A".repeat(257)), (e: unknown) => e instanceof RegistryFailure && e.code === 0x11);
  assert.throws(
    () => canonicalizeBytes(Uint8Array.of(0xff, 0xfe, 0x41)),
    (e: unknown) => e instanceof RegistryFailure && e.code === 0x11,
    "invalid UTF-8",
  );
  // `commitment` refuses a raw spelling outright, so one can never be committed.
  assert.throws(
    () => assetCommitment(fromHex("0x43414243", 4), fromHex("0x4d544f3030303031", 8), utf8("bc-tenure 1043-a")),
    (e: unknown) => e instanceof RegistryFailure && e.code === 0x11,
  );
});

test("§1.3's payload_uri rule accepts three schemes and nothing else", () => {
  const ok = ["ipfs://a", "https://a", "ar://a", `ipfs://${"a".repeat(121)}`];
  const no = ["ipfs://", "ar://", "https://", "ftp://a", "IPFS://a", "ipfs://a b", "ipfs://a\u0000", "ipfs://é", "", `ipfs://${"a".repeat(122)}`];
  for (const s of ok) assert.equal(isWellFormedPayloadUri(utf8(s)), true, s);
  for (const s of no) assert.equal(isWellFormedPayloadUri(utf8(s)), false, JSON.stringify(s));
  assert.equal(utf8(ok[3]!).length, 128, "the longest accepted URI is exactly 128 bytes");
});

test("§1.6's promise policy: the key holder does not choose the policy it is judged against", () => {
  const v = loadVector("V-P-10");
  const promise = decodePromise(fromHex(v.expected.promise.encoded));
  const key = promise.batcherKey;
  const observed = 20500n;
  verifyPromise(promise, key, observed); // the vector's own promise stands

  const wrongKey = new Uint8Array(32).fill(7);
  assert.throws(() => verifyPromise(promise, wrongKey, observed), (e: unknown) => e instanceof RegistryFailure && e.code === 0x08);

  // A policy value outside §1.6 is refused rather than authenticated, however well it is signed.
  assert.throws(
    () => verifyPromise({ ...promise, maxMergeDelay: 3 }, key, observed),
    (e: unknown) => e instanceof RegistryFailure && e.code === 0x17,
  );
  assert.equal(MAX_MERGE_DELAY, 2);
  assert.throws(
    () => verifyPromise({ ...promise, promisedEpoch: promise.acceptedEpoch + 3n }, key, observed),
    (e: unknown) => e instanceof RegistryFailure && e.code === 0x17,
  );
  // Backdating: an acceptance epoch later than the counterparty observed.
  assert.throws(
    () => verifyPromise(promise, key, observed - 1n),
    (e: unknown) => e instanceof RegistryFailure && e.code === 0x17,
  );
  // One epoch behind is allowed, because a promise can arrive across an epoch boundary.
  verifyPromise(promise, key, observed + 1n);
  assert.throws(
    () => verifyPromise(promise, key, observed + 2n),
    (e: unknown) => e instanceof RegistryFailure && e.code === 0x17,
  );
  // A signature that does not verify is 0x07.
  const broken = { ...promise, signature: new Uint8Array(promise.signature) };
  broken.signature[0] = broken.signature[0]! ^ 0x01;
  assert.throws(() => verifyPromise(broken, key, observed), (e: unknown) => e instanceof RegistryFailure && e.code === 0x07);
});

test("§2.1's code space is exactly what the document lists, 0x09 included and reserved", () => {
  assert.equal(Object.keys(REGISTRY_CODES).length, 21);
  assert.equal(REGISTRY_CODES.CategorySequenceUnsupported, 0x09);
  assert.equal(codeName(0x09), "CategorySequenceUnsupported");
  assert.equal(codeName(0x99), undefined);
});

test("base64 in and out is strict, because a fail-closed verifier cannot guess", () => {
  const bytes = Uint8Array.from([0, 1, 2, 250, 255]);
  assert.equal(toHex(base64Decode(base64Encode(bytes))), toHex(bytes));
  for (const bad of ["a", "ab", "abc", "****", "AA=A", "A A=", "AB==AB==", "/w=", "AAAA=" ]) {
    assert.throws(() => base64Decode(bad), TypeError, JSON.stringify(bad));
  }
  assert.throws(() => base64Decode("AB=="), TypeError, "non-canonical padding bits");
  // The refusal must come from the character itself, not from the length falling short: a
  // decoder that skipped the character would refuse here too, and for the wrong reason.
  assert.throws(() => base64Decode("AA*A"), /invalid character/, "an invalid character is named");
  assert.equal(toHex(base64Decode("AA==")), "0x00");
  assert.equal(base64Encode(concat([utf8("hi")])), "aGk=");
});
