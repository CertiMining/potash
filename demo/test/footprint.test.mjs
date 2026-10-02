/**
 * The demo's own tests (S4).
 *
 * Two things need checking and neither is checked anywhere else. The footprint Scene 1 lays out has to
 * be the layout the verifier reads, or the scene would be diffing a shape of its own invention. And
 * the fixtures have to match their manifest, which is the mechanism D-126 relies on to stop a scene
 * being tuned.
 *
 * These run under `node --test` from the repository root and need no browser: the page's logic is in
 * plain ES modules for exactly that reason.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
  ACCOUNT_FIELDS,
  CHECKPOINT_LEN,
  INSTRUCTION_FIELDS,
  INSTRUCTION_LEN,
  checkpointAccount,
  diff,
  fieldAt,
  publishInstruction,
} from "../footprint.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const DEMO = join(HERE, "..");

// The verifier's decoder, from source. `npm test` in `ts/` runs the same modules, so this needs no
// build step; `scripts/demo.sh` builds `demo/build/` for the browser, and the test does not depend on
// that having happened.
const { decodeCheckpointAccount, CHECKPOINT_DISCRIMINATOR, CHECKPOINT_LEN: VERIFIER_LEN } = await import(
  join(DEMO, "../ts/src/solana/accounts.ts")
);
const { toHex, fromHex } = await import(join(DEMO, "../ts/src/bytes.ts"));

const ROOT = fromHex(`0x${"ab".repeat(32)}`, 32);
const RECEIPT = fromHex(`0x${"cd".repeat(32)}`, 32);

function account(overrides = {}) {
  return checkpointAccount({
    discriminator: CHECKPOINT_DISCRIMINATOR,
    epoch: 20723n,
    root: ROOT,
    // Not the announced log's slot or time. This fixture used to carry epoch 20723's **real**
    // publication slot beside the fabricated root and receipt digest above — a live provenance value
    // lending credibility to data published nowhere, which is the defect LIVE-VALUES.txt exists to
    // refuse. A review found it (PR #57, round one, High); both halves of the gate had exited 0,
    // because decimal values could not be listed at all. They can now, and these two are visibly
    // synthetic so no reader mistakes them for provenance. The real figure is deliberately not quoted
    // here: writing it into this file would put it straight back, and the gate refuses it — which it
    // did, on the first attempt at this comment.
    publishedSlot: 111111111n,
    publishedUnix: 1111111111n,
    receiptDigest: RECEIPT,
    anchorKind: 1,
    bump: 255,
    ...overrides,
  });
}

test("the account the demo lays out is the account the verifier decodes", () => {
  assert.equal(CHECKPOINT_LEN, VERIFIER_LEN, "the two files disagree about the account's length");
  const bytes = account();
  assert.equal(bytes.length, 106, "§2.4 fixes CheckpointAccount at 106 bytes");

  const decoded = decodeCheckpointAccount(bytes);
  assert.equal(decoded.schemaVersion, 1);
  assert.equal(decoded.epoch, 20723n);
  assert.equal(toHex(decoded.root), toHex(ROOT));
  assert.equal(decoded.publishedSlot, 111111111n);
  assert.equal(decoded.publishedUnix, 1111111111n);
  assert.equal(toHex(decoded.receiptDigest), toHex(RECEIPT));
  assert.equal(decoded.anchorKind, 1);
  assert.equal(decoded.bump, 255);
});

test("every offset in the account belongs to exactly one named field, and the fields tile it", () => {
  // A gap would be a byte the scene could not name; an overlap would let one byte be reported twice.
  let cursor = 0;
  for (const field of ACCOUNT_FIELDS) {
    assert.equal(field.at, cursor, `${field.name} starts at ${field.at}, not ${cursor}`);
    cursor += field.len;
  }
  assert.equal(cursor, CHECKPOINT_LEN, "the fields do not add up to the account's length");
  for (let i = 0; i < CHECKPOINT_LEN; i++) {
    assert.ok(fieldAt(ACCOUNT_FIELDS, i) !== undefined, `offset ${i} belongs to no field`);
  }

  cursor = 0;
  for (const field of INSTRUCTION_FIELDS) {
    assert.equal(field.at, cursor, `${field.name} starts at ${field.at}, not ${cursor}`);
    cursor += field.len;
  }
  assert.equal(cursor, INSTRUCTION_LEN, "§1.8 fixes the instruction data at 48 bytes");
});

test("the fields marked as permitted to differ are exactly §4.4's closed list", () => {
  // V-Z-01 names six in the account and two arguments in the instruction. Written out here so that
  // widening the list in `footprint.js` fails this test, which is what §4.3 means by the list being
  // amended in the specification rather than in the code.
  assert.deepEqual(
    ACCOUNT_FIELDS.filter((f) => f.mayDiffer !== undefined).map((f) => f.name).sort(),
    ["bump", "epoch", "published_slot", "published_unix", "receipt_digest", "root"],
  );
  assert.deepEqual(
    INSTRUCTION_FIELDS.filter((f) => f.mayDiffer !== undefined).map((f) => f.name).sort(),
    ["epoch", "root"],
  );
  const reasons = new Set(
    [...ACCOUNT_FIELDS, ...INSTRUCTION_FIELDS].filter((f) => f.mayDiffer).map((f) => f.mayDiffer),
  );
  assert.deepEqual(
    [...reasons].sort(),
    ["a pseudorandom digest", "the epoch number", "the publication schedule"],
    "a permit cites a reason §4.3 does not give",
  );
});

test("a byte outside the list is reported as unpermitted, not merely as different", () => {
  // The scene's verdict depends on this: if `diff` reported such a byte as permitted, Scene 1 would
  // display a pass where the property had failed.
  const clean = account();
  const tampered = account();
  tampered[98] = 2; // anchor_kind, which V-Z-01 does not permit to vary
  const d = diff(ACCOUNT_FIELDS, clean, tampered);
  assert.deepEqual(d.offsets, [98]);
  assert.deepEqual(d.unpermitted, [98]);

  const permitted = account({ root: fromHex(`0x${"ef".repeat(32)}`, 32) });
  const d2 = diff(ACCOUNT_FIELDS, clean, permitted);
  assert.ok(d2.offsets.length > 0, "a different root should differ somewhere");
  assert.deepEqual(d2.unpermitted, [], "a differing root is permitted: it is a digest");
  assert.deepEqual([...d2.byField.keys()], ["root"]);
});

test("two publications differing only in record count differ only inside root", () => {
  // The scene's own claim, checked here against the layout rather than against a browser. The roots
  // stand in for two epochs holding different numbers of real records; what matters is that a
  // different root moves nothing the list forbids.
  const one = account({ root: fromHex(`0x${"11".repeat(32)}`, 32) });
  const many = account({ root: fromHex(`0x${"22".repeat(32)}`, 32) });
  assert.equal(one.length, many.length);
  const d = diff(ACCOUNT_FIELDS, one, many);
  assert.deepEqual(d.unpermitted, []);
  assert.deepEqual([...d.byField.keys()], ["root"]);

  const ixOne = publishInstruction({ discriminator: CHECKPOINT_DISCRIMINATOR, epoch: 20723n, root: fromHex(`0x${"11".repeat(32)}`, 32) });
  const ixMany = publishInstruction({ discriminator: CHECKPOINT_DISCRIMINATOR, epoch: 20723n, root: fromHex(`0x${"22".repeat(32)}`, 32) });
  assert.equal(ixOne.length, INSTRUCTION_LEN);
  assert.equal(ixMany.length, INSTRUCTION_LEN);
  assert.deepEqual(diff(INSTRUCTION_FIELDS, ixOne, ixMany).unpermitted, []);
});

test("a length difference is a failure, never a diff of some bytes", () => {
  const d = diff(ACCOUNT_FIELDS, account(), account().slice(0, 100));
  assert.equal(d.lengthDiffers, true);
  assert.deepEqual(d.offsets, []);
});

test("every fixture matches the manifest the demo checks it against", () => {
  const dir = join(DEMO, "fixtures");
  const manifest = readFileSync(join(dir, "MANIFEST.sha256"), "utf8");
  const lines = manifest.split("\n").filter((l) => l.trim() !== "");
  assert.equal(lines.length, 4, "the manifest should cover three fixtures and the README");
  for (const line of lines) {
    const [hash, mode, name] = line.trim().split(/\s+/);
    const body = readFileSync(join(dir, name));
    assert.equal(createHash("sha256").update(body).digest("hex"), hash, `${name}: sha256`);
    assert.equal(mode, "0644", `${name}: recorded mode`);
  }
});

test("no fixture carries a field §2.5 does not list, and none carries a real registry code", () => {
  const dir = join(DEMO, "fixtures");
  for (const name of ["disclosure.json", "tampered.json"]) {
    const pkg = JSON.parse(readFileSync(join(dir, name), "utf8"));
    assert.deepEqual(
      Object.keys(pkg).sort(),
      ["anchor", "chain", "inclusion", "preimage_borsh", "qp_signature", "record", "schema"],
      `${name} carries a field §2.5 does not list, which a conforming verifier refuses`,
    );
    // §4.4's V-Z-05 applies to a demo as much as to a test: no tenure, jurisdiction or registry value
    // in clear. The synthetic ones are not in the package at all — they are inside `c`, which is
    // inside the signed preimage and nowhere else (INV-DISC-01).
    const text = readFileSync(join(dir, name), "utf8");
    for (const forbidden of ["DEMO0000", "demo-tenure", "DEMOTENURE0001X", "CABC"]) {
      assert.ok(!text.includes(forbidden), `${name} carries ${forbidden} in clear`);
    }
  }
});
