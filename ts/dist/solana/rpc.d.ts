/**
 * Fetching a root. JSON-RPC over `fetch`, which both runtimes have, with the address derived here
 * and the account decoded here: no Solana SDK sits between the counterparty and the bytes.
 */
import { type Digest } from "../bytes.ts";
import { type CheckpointAccount, type LogConfig } from "./accounts.ts";
/** The deployment this verifier was written against (§"Fetching a root"). */
export declare const DEVNET_PROGRAM_ID = "jzJzgKWMo7QhCADuVSGT2cT5VkHjhHEz5tkgDugL3no";
export declare const SUPERSEDED_PROGRAM_ID = "HS82CAXgVykfVniBzPp9eArDfVLmFYcik3evyAx7iVZB";
export declare const DEVNET_RPC_URL = "https://api.devnet.solana.com";
export type RpcOptions = {
    rpcUrl?: string;
    programId?: string;
    commitment?: "processed" | "confirmed" | "finalized";
    /** Injected so a test can drive the decoder without a network. Defaults to the global `fetch`. */
    fetchImpl?: typeof fetch;
    /**
     * The log's configuration, when the caller already holds it. Supplied, an absent checkpoint is
     * classified without a second round trip; absent, it is fetched only when a checkpoint is missing
     * and the reason has to be named (INV-ANCH-02).
     */
    logConfig?: LogConfig;
};
/** Reads `LogConfig`, whose `tree_height` is the configured `H` a proof is judged against. */
export declare function fetchLogConfig(options?: RpcOptions): Promise<LogConfig>;
/**
 * Fetches one epoch's checkpoint. The account's own `epoch` is checked against the epoch asked
 * for: an account that answers for a different epoch is refused rather than read. An absent
 * account is refused with the reason it is absent, which INV-ANCH-02 makes a client's job.
 */
export declare function fetchCheckpoint(epoch: bigint, options?: RpcOptions): Promise<CheckpointAccount>;
export declare function fetchRoot(epoch: bigint, options?: RpcOptions): Promise<{
    epoch: bigint;
    root: Digest;
}>;
