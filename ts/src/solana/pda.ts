/**
 * §2.4's program-derived addresses. Address derivation is the step that decides which account is
 * even being read, so it lives here rather than in an SDK the counterparty would have to trust.
 *
 * A program address is `SHA-256(seeds ‖ bump ‖ program_id ‖ "ProgramDerivedAddress")` taken as a
 * 32-byte point that must lie off the Ed25519 curve; the canonical bump is the highest one that
 * produces such a point.
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
