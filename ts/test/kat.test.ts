/**
 * §4.1's KAT-01 and KAT-02, which pin the two primitives this verifier takes from a library.
 * `npm test` runs this file first and stops if it fails, as §4.1 requires.
 *
 * What is and is not a published constant here is marked. The specification names published
 * vectors for the 135/136/137-byte rate boundary without carrying them, and neither the document
 * nor `vectors/` contains them, so those three lengths are checked against Node's own SHA-3
 * implementation instead: `keccak_256` and `sha3_256` in this library are one sponge over one
 * Keccak-f[1600] permutation at one rate, differing only in the pad byte, so agreement with
 * OpenSSL at exactly those lengths exercises the absorption boundary the row is about. It is a
 * cross-implementation check, not the published KAT, and is labelled as such (SPEC-DEFECTS.md).
 */
import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { keccak_256, sha3_256 } from "@noble/hashes/sha3.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { fromHex, toHex, utf8 } from "../src/bytes.ts";
import { ed25519Verify, keccak256 } from "../src/hash.ts";

test("KAT-01: Keccak-256 against published vectors", () => {
  assert.equal(
    toHex(keccak256(new Uint8Array(0))),
    "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
    "Keccak-256 of the empty string",
  );
  assert.equal(
    toHex(keccak256(utf8("abc"))),
    "0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
    "Keccak-256 of \"abc\"",
  );
});

test("KAT-01: the rate boundary at 135, 136 and 137 bytes", () => {
  for (const len of [1, 135, 136, 137, 272]) {
    const input = new Uint8Array(len).map((_, i) => (i * 37 + 11) & 0xff);
    // Same sponge, same rate, different pad byte: OpenSSL is the independent side.
    assert.equal(
      toHex(sha3_256(input)),
      `0x${createHash("sha3-256").update(input).digest("hex")}`,
      `SHA3-256 at ${len} bytes disagrees with OpenSSL`,
    );
    // Keccak-256 is that sponge with the other pad byte, and must not equal it.
    assert.notEqual(toHex(keccak256(input)), toHex(sha3_256(input)), `Keccak and SHA-3 agreed at ${len} bytes`);
    // One-shot and incremental absorption agree across the boundary.
    const streamed = keccak_256.create();
    for (let i = 0; i < input.length; i += 7) streamed.update(input.subarray(i, i + 7));
    assert.equal(toHex(streamed.digest()), toHex(keccak256(input)), `streaming disagrees at ${len} bytes`);
  }
});

test("KAT-02: Ed25519 against RFC 8032 §7.1", () => {
  const cases = [
    {
      name: "TEST 1",
      secret: "0x9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
      public: "0xd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
      message: "0x",
      signature:
        "0xe5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    },
    {
      name: "TEST 2",
      secret: "0x4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
      public: "0x3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
      message: "0x72",
      signature:
        "0x92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    },
  ];
  for (const c of cases) {
    const secret = fromHex(c.secret, 32);
    const publicKey = fromHex(c.public, 32);
    const message = fromHex(c.message);
    const signature = fromHex(c.signature, 64);
    assert.equal(toHex(ed25519.getPublicKey(secret)), c.public, `${c.name}: public key`);
    assert.equal(toHex(ed25519.sign(message, secret)), c.signature, `${c.name}: signature`);
    assert.equal(ed25519Verify(publicKey, message, signature), true, `${c.name}: verification`);

    // A flipped bit anywhere must not verify.
    const badSig = new Uint8Array(signature);
    badSig[0] = badSig[0]! ^ 0x01;
    assert.equal(ed25519Verify(publicKey, message, badSig), false, `${c.name}: a flipped signature bit verified`);
    const badKey = new Uint8Array(publicKey);
    badKey[0] = badKey[0]! ^ 0x01;
    assert.equal(ed25519Verify(badKey, message, signature), false, `${c.name}: a flipped key bit verified`);
  }
  // Malformed inputs are a verification failure, never an exception the caller has to catch.
  assert.equal(ed25519Verify(new Uint8Array(31), new Uint8Array(0), new Uint8Array(64)), false);
  assert.equal(ed25519Verify(new Uint8Array(32), new Uint8Array(0), new Uint8Array(63)), false);
  assert.equal(ed25519Verify(new Uint8Array(32).fill(0xff), new Uint8Array(0), new Uint8Array(64).fill(0xff)), false);
});
