/**
 * Fetching a root. JSON-RPC over `fetch`, which both runtimes have, with the address derived here
 * and the account decoded here: no Solana SDK sits between the counterparty and the bytes.
 */
import { type Digest, base64Decode } from "../bytes.ts";
import { PackageFailure } from "../errors.ts";
import { base58Decode, base58Encode } from "./base58.ts";
import { type CheckpointAccount, type LogConfig, decodeCheckpointAccount, decodeLogConfig, placeEpoch } from "./accounts.ts";
import { deriveCheckpointAddress, deriveLogConfigAddress } from "./pda.ts";

/** The deployment this verifier was written against (§"Fetching a root"). */
// The announced devnet deployment. `HS82CAXgVykfVniBzPp9eArDfVLmFYcik3evyAx7iVZB` was announced
// first and is superseded: its log was initialized under the pre-D-109 rule, so its sequence begins
// at epoch 1 rather than a UTC day index, and its epoch 1 carries a receipt digest standing for no
// OpenTimestamps receipt in a field that is write-once. Neither is repairable in place, which is why
// there is a second address. Both are kept here because the superseded one is still readable by
// anyone and is the account this verifier's own SPEC-DEFECTS D-15 was written against.
export const DEVNET_PROGRAM_ID = "jzJzgKWMo7QhCADuVSGT2cT5VkHjhHEz5tkgDugL3no";
export const SUPERSEDED_PROGRAM_ID = "HS82CAXgVykfVniBzPp9eArDfVLmFYcik3evyAx7iVZB";
export const DEVNET_RPC_URL = "https://api.devnet.solana.com";

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

type AccountFetch = { data: Uint8Array; owner: string } | null;

async function getAccountInfo(address: Uint8Array, options: RpcOptions): Promise<AccountFetch> {
  const rpcUrl = options.rpcUrl ?? DEVNET_RPC_URL;
  const doFetch = options.fetchImpl ?? globalThis.fetch;
  if (typeof doFetch !== "function") throw new Error("no fetch in this runtime");
  const response = await doFetch(rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "getAccountInfo",
      params: [base58Encode(address), { encoding: "base64", commitment: options.commitment ?? "confirmed" }],
    }),
  });
  if (!response.ok) {
    throw new PackageFailure("RootUnavailable", `RPC returned HTTP ${response.status}`);
  }
  const body = (await response.json()) as {
    error?: { message?: string };
    result?: { value?: { data?: [string, string]; owner?: string } | null };
  };
  if (body.error) throw new PackageFailure("RootUnavailable", `RPC error: ${body.error.message ?? "unknown"}`);
  const value = body.result?.value;
  if (value === null || value === undefined) return null;
  const data = value.data;
  if (!Array.isArray(data) || data[1] !== "base64") {
    throw new PackageFailure("RootUnavailable", "RPC returned an account in an encoding this verifier did not ask for");
  }
  return { data: base64Decode(data[0]!), owner: value.owner ?? "" };
}

function programIdBytes(options: RpcOptions): Uint8Array {
  return base58Decode(options.programId ?? DEVNET_PROGRAM_ID);
}

/** Reads `LogConfig`, whose `tree_height` is the configured `H` a proof is judged against. */
export async function fetchLogConfig(options: RpcOptions = {}): Promise<LogConfig> {
  const programId = programIdBytes(options);
  const { address } = deriveLogConfigAddress(programId);
  const account = await getAccountInfo(address, options);
  if (account === null) throw new PackageFailure("RootUnavailable", "no LogConfig account at the derived address");
  if (account.owner !== (options.programId ?? DEVNET_PROGRAM_ID)) {
    throw new PackageFailure("RootUnavailable", `LogConfig is owned by ${account.owner}`);
  }
  return decodeLogConfig(account.data);
}

/**
 * Names the reason a checkpoint account is absent, which INV-ANCH-02 requires a client to do:
 * an epoch before `start_epoch` is a day the log did not exist for and is not a gap, an epoch the
 * sequence has already reached and cannot answer for is the gap that is evidence of failure, and
 * an epoch past `last_epoch` is one the sequence has not reached yet.
 */
async function refuseMissingCheckpoint(epoch: bigint, options: RpcOptions): Promise<never> {
  let config: LogConfig;
  try {
    config = options.logConfig ?? (await fetchLogConfig(options));
  } catch (e) {
    throw new PackageFailure(
      "RootUnavailable",
      `no checkpoint account for epoch ${epoch}, and the log's configuration could not be read either: ${
        e instanceof Error ? e.message : String(e)
      }`,
    );
  }
  const placement = placeEpoch(config, epoch);
  switch (placement.kind) {
    case "before-log-start":
      throw new PackageFailure(
        "EpochBeforeLogStart",
        `epoch ${epoch} precedes the log's start_epoch ${placement.startEpoch}: a day the log did not exist for, not a gap`,
      );
    case "inside-published-range":
      throw new PackageFailure(
        "CheckpointSequenceGap",
        `epoch ${epoch} lies inside the published sequence ${placement.startEpoch}..${placement.lastEpoch} and has no checkpoint account`,
      );
    case "not-yet-published":
      throw new PackageFailure(
        "CheckpointNotYetPublished",
        `the sequence has reached epoch ${placement.lastEpoch}; epoch ${epoch} has not been published`,
      );
  }
}

/**
 * Fetches one epoch's checkpoint. The account's own `epoch` is checked against the epoch asked
 * for: an account that answers for a different epoch is refused rather than read. An absent
 * account is refused with the reason it is absent, which INV-ANCH-02 makes a client's job.
 */
export async function fetchCheckpoint(epoch: bigint, options: RpcOptions = {}): Promise<CheckpointAccount> {
  const programIdText = options.programId ?? DEVNET_PROGRAM_ID;
  const programId = base58Decode(programIdText);
  const { address } = deriveCheckpointAddress(programId, epoch);
  const account = await getAccountInfo(address, options);
  if (account === null) return refuseMissingCheckpoint(epoch, options);
  if (account.owner !== programIdText) {
    throw new PackageFailure("RootUnavailable", `checkpoint account is owned by ${account.owner}, not the program`);
  }
  const checkpoint = decodeCheckpointAccount(account.data);
  if (checkpoint.epoch !== epoch) {
    throw new PackageFailure("RootEpochMismatch", `account at the epoch-${epoch} address carries epoch ${checkpoint.epoch}`);
  }
  return checkpoint;
}

export async function fetchRoot(epoch: bigint, options: RpcOptions = {}): Promise<{ epoch: bigint; root: Digest }> {
  const checkpoint = await fetchCheckpoint(epoch, options);
  return { epoch: checkpoint.epoch, root: checkpoint.root };
}
