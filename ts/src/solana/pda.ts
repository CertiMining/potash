/**
 * §2.4's program-derived addresses. Address derivation is the step that decides which account is
 * even being read, so it lives here rather than in an SDK the counterparty would have to trust.
 *
 * **Provenance.** §2.4 now states the derivation, citing Solana as its author rather than restating it
 * as the document's own: the hash input `SHA-256( seed₀ ‖ … ‖ seedₙ ‖ bump ‖ program_id ‖
 * "ProgramDerivedAddress" )`, and the largest single-byte bump from 255 downwards whose result is not
 * a point on the Ed25519 curve. The seed count and length constraints below are the platform's, which
 * the paragraph says in terms. Through the first version of that paragraph the derivation was absent
 * from the document and this code had it from platform knowledge, which SPEC-DEFECTS.md SD-17 records;
 * the version after that printed `… ‖ program_id ‖ bump ‖ …`, the wrong way round, and could not have
 * fetched the log. Both addresses the correction publishes are pinned in `test/units.test.ts`, the
 * right one and the erroneous one, so neither this code nor that paragraph can move again unnoticed.
 */
import { concat, u64le, utf8 } from "../bytes.ts";
import { isOnCurve, sha256 } from "../hash.ts";

export const PDA_MARKER = utf8("ProgramDerivedAddress");
export const SEED_LOG_CONFIG = utf8("cm_cfg");
export const SEED_CHECKPOINT = utf8("cm_ckpt");
export const MAX_SEED_LEN = 32;
export const MAX_SEEDS = 16;

export function createProgramAddress(seeds: Uint8Array[], programId: Uint8Array): Uint8Array | null {
  if (seeds.length > MAX_SEEDS) throw new RangeError("too many seeds");
  for (const s of seeds) if (s.length > MAX_SEED_LEN) throw new RangeError("seed is longer than 32 bytes");
  if (programId.length !== 32) throw new RangeError("program id must be 32 bytes");
  const address = sha256(concat([...seeds, programId, PDA_MARKER]));
  return isOnCurve(address) ? null : address;
}

export function findProgramAddress(seeds: Uint8Array[], programId: Uint8Array): { address: Uint8Array; bump: number } {
  for (let bump = 255; bump >= 0; bump--) {
    const address = createProgramAddress([...seeds, Uint8Array.of(bump)], programId);
    if (address !== null) return { address, bump };
  }
  throw new Error("no off-curve address for these seeds");
}

/** `LogConfig` PDA, seeds ["cm_cfg"]. */
export function deriveLogConfigAddress(programId: Uint8Array): { address: Uint8Array; bump: number } {
  return findProgramAddress([SEED_LOG_CONFIG], programId);
}

/** `CheckpointAccount` PDA, seeds ["cm_ckpt", epoch_le]. */
export function deriveCheckpointAddress(programId: Uint8Array, epoch: bigint): { address: Uint8Array; bump: number } {
  return findProgramAddress([SEED_CHECKPOINT, u64le(epoch)], programId);
}
