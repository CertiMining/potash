/**
 * Fetching a root. JSON-RPC over `fetch`, which both runtimes have, with the address derived here
 * and the account decoded here: no Solana SDK sits between the counterparty and the bytes.
 */
import { type Digest } from "../bytes.ts";
import { type CheckpointAccount, type LogConfig } from "./accounts.ts";
/** The deployment this verifier was written against (§"Fetching a root"). */
export declare const DEVNET_PROGRAM_ID = "HS82CAXgVykfVniBzPp9eArDfVLmFYcik3evyAx7iVZB";
export declare const DEVNET_RPC_URL = "https://api.devnet.solana.com";
export type RpcOptions = {
    rpcUrl?: string;
    programId?: string;
    commitment?: "processed" | "confirmed" | "finalized";
    /** Injected so a test can drive the decoder without a network. Defaults to the global `fetch`. */
    fetchImpl?: typeof fetch;
};
/** Reads `LogConfig`, whose `tree_height` is the configured `H` a proof is judged against. */
export declare function fetchLogConfig(options?: RpcOptions): Promise<LogConfig>;
/**
 * Fetches one epoch's checkpoint. The account's own `epoch` is checked against the epoch asked
 * for: an account that answers for a different epoch is refused rather than read.
 */
export declare function fetchCheckpoint(epoch: bigint, options?: RpcOptions): Promise<CheckpointAccount>;
export declare function fetchRoot(epoch: bigint, options?: RpcOptions): Promise<{
    epoch: bigint;
    root: Digest;
}>;
