/**
 * The one test that touches a network. It is skipped unless CERTIMINING_DEVNET=1 is set, so it
 * never runs in CI and never runs by default: `npm test` does not reach devnet, and `npm run
 * test:net` does.
 *
 * It asserts nothing about what the deployment currently holds, because that changes; it asserts
 * that the address this verifier derives is the account the cluster answers for, and that what
 * comes back decodes at §2.4's offsets.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { toHex } from "../src/bytes.ts";
import { base58Encode } from "../src/solana/base58.ts";
import { deriveCheckpointAddress, deriveLogConfigAddress } from "../src/solana/pda.ts";
import { placeEpoch, utcDayIndex } from "../src/solana/accounts.ts";
import { DEVNET_PROGRAM_ID, DEVNET_RPC_URL, fetchCheckpoint, fetchLogConfig } from "../src/solana/rpc.ts";
import { base58Decode } from "../src/solana/base58.ts";
import { MAX_HEIGHT, MIN_HEIGHT } from "../src/tree.ts";

const enabled = process.env.CERTIMINING_DEVNET === "1";

test("devnet: the log's configuration and its latest checkpoint decode as §2.4 lays them out", { skip: !enabled }, async () => {
  const programId = base58Decode(DEVNET_PROGRAM_ID);
  console.log(`\n  program   ${DEVNET_PROGRAM_ID}`);
  console.log(`  rpc       ${DEVNET_RPC_URL}`);
  console.log(`  LogConfig ${base58Encode(deriveLogConfigAddress(programId).address)}`);

  const config = await fetchLogConfig();
  assert.ok(config.treeHeight >= MIN_HEIGHT && config.treeHeight <= MAX_HEIGHT, `tree_height ${config.treeHeight}`);
  console.log(
    `  schema ${config.schemaVersion}, tree_height ${config.treeHeight}, start_epoch ${config.startEpoch}, last_epoch ${config.lastEpoch}`,
  );

  // §1.4 and D-109: a conforming `initialize` writes the day index the chain reported, and
  // `last_epoch` as `start_epoch - 1`. A log that does not satisfy that was initialized under an
  // earlier version of this document. The verifier reads such an account rather than refusing it
  // (SPEC-DEFECTS.md D-15), so the test reports the state instead of asserting conformance.
  const today = utcDayIndex(BigInt(Math.floor(Date.now() / 1000)));
  console.log(`  today is day ${today}; the log places it as ${placeEpoch(config, today).kind}`);
  if (config.startEpoch === 0n) {
    console.log(
      "  NOTE: start_epoch is 0, which no conforming initialize under v0.1.18 could write." +
        " This deployment predates §1.4's epoch clock (D-109).",
    );
  }

  const checkpoint = await fetchCheckpoint(config.lastEpoch);
  console.log(`  epoch ${checkpoint.epoch} root ${toHex(checkpoint.root)} slot ${checkpoint.publishedSlot}`);
  console.log(`  checkpoint address ${base58Encode(deriveCheckpointAddress(programId, config.lastEpoch).address)}\n`);
  assert.equal(checkpoint.epoch, config.lastEpoch);
  assert.equal(checkpoint.root.length, 32);
});
