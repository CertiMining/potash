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
// The announced devnet deployment (D-88). Two earlier ones were retired; both are still readable on
// devnet, and the reasons are below so a reader who finds three program ids knows what each was.
export const DEVNET_PROGRAM_ID = "By5XeTsCS4Qf17U9EuGUTzEFz29wQdFFeqJtfhnFQkZB";

/// The two deployments this one replaced, newest first. D-88 records what each was; both are readable
/// on devnet and neither should be verified against.
///
/// `jzJz…` was retired because a compressed privacy run spent 200 days of epoch numbering in 200
/// minutes, leaving its sequence 209 days ahead of the calendar. `HS82…` was retired because its
/// epoch 1 carries a receipt digest standing for no OpenTimestamps receipt in a write-once field, and
/// because its log began at epoch 1 rather than a UTC day index.
export const SUPERSEDED_PROGRAM_IDS = [
  "jzJzgKWMo7QhCADuVSGT2cT5VkHjhHEz5tkgDugL3no",
  "HS82CAXgVykfVniBzPp9eArDfVLmFYcik3evyAx7iVZB",
] as const;
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
 * Names the reason a checkpoint account is absent, which §1.4 requires a client to distinguish.
 *
 * An epoch before `start_epoch` is a day the log did not exist for, and reporting it as a failure
 * would accuse a batcher of not publishing before it was deployed. Inside the published range
 * INV-ANCH-02 runs unbroken and only the owning program can allocate an address there, so an
 * absent account is evidence about the response rather than about the log: the answers did not come
 * from one view of the chain. Past `last_epoch` the sequence has not reached the epoch, and the
 * failure an on-chain read can show is lag, which needs a clock the verifier does not hold.
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
        "InconsistentChainView",
        `epoch ${epoch} lies inside the published sequence ${placement.startEpoch}..${placement.lastEpoch}, which runs unbroken, ` +
          "so an absent account means these answers did not come from one view of the chain",
      );
    case "not-yet-published":
      throw new PackageFailure(
        "CheckpointNotYetPublished",
        `the sequence has reached epoch ${placement.lastEpoch}; epoch ${epoch} has not been published. ` +
          "Lag is measured against a day index the caller supplies, with lagAgainst",
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
