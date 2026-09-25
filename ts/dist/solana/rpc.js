/**
 * Fetching a root. JSON-RPC over `fetch`, which both runtimes have, with the address derived here
 * and the account decoded here: no Solana SDK sits between the counterparty and the bytes.
 */
import { base64Decode } from "../bytes.js";
import { PackageFailure } from "../errors.js";
import { base58Decode, base58Encode } from "./base58.js";
import { decodeCheckpointAccount, decodeLogConfig } from "./accounts.js";
import { deriveCheckpointAddress, deriveLogConfigAddress } from "./pda.js";
/** The deployment this verifier was written against (§"Fetching a root"). */
export const DEVNET_PROGRAM_ID = "HS82CAXgVykfVniBzPp9eArDfVLmFYcik3evyAx7iVZB";
export const DEVNET_RPC_URL = "https://api.devnet.solana.com";
async function getAccountInfo(address, options) {
    const rpcUrl = options.rpcUrl ?? DEVNET_RPC_URL;
    const doFetch = options.fetchImpl ?? globalThis.fetch;
    if (typeof doFetch !== "function")
        throw new Error("no fetch in this runtime");
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
    const body = (await response.json());
    if (body.error)
        throw new PackageFailure("RootUnavailable", `RPC error: ${body.error.message ?? "unknown"}`);
    const value = body.result?.value;
    if (value === null || value === undefined)
        return null;
    const data = value.data;
    if (!Array.isArray(data) || data[1] !== "base64") {
        throw new PackageFailure("RootUnavailable", "RPC returned an account in an encoding this verifier did not ask for");
    }
    return { data: base64Decode(data[0]), owner: value.owner ?? "" };
}
function programIdBytes(options) {
    return base58Decode(options.programId ?? DEVNET_PROGRAM_ID);
}
/** Reads `LogConfig`, whose `tree_height` is the configured `H` a proof is judged against. */
export async function fetchLogConfig(options = {}) {
    const programId = programIdBytes(options);
    const { address } = deriveLogConfigAddress(programId);
    const account = await getAccountInfo(address, options);
    if (account === null)
        throw new PackageFailure("RootUnavailable", "no LogConfig account at the derived address");
    if (account.owner !== (options.programId ?? DEVNET_PROGRAM_ID)) {
        throw new PackageFailure("RootUnavailable", `LogConfig is owned by ${account.owner}`);
    }
    return decodeLogConfig(account.data);
}
/**
 * Fetches one epoch's checkpoint. The account's own `epoch` is checked against the epoch asked
 * for: an account that answers for a different epoch is refused rather than read.
 */
export async function fetchCheckpoint(epoch, options = {}) {
    const programIdText = options.programId ?? DEVNET_PROGRAM_ID;
    const programId = base58Decode(programIdText);
    const { address } = deriveCheckpointAddress(programId, epoch);
    const account = await getAccountInfo(address, options);
    if (account === null) {
        throw new PackageFailure("RootUnavailable", `no checkpoint account for epoch ${epoch}`);
    }
    if (account.owner !== programIdText) {
        throw new PackageFailure("RootUnavailable", `checkpoint account is owned by ${account.owner}, not the program`);
    }
    const checkpoint = decodeCheckpointAccount(account.data);
    if (checkpoint.epoch !== epoch) {
        throw new PackageFailure("RootEpochMismatch", `account at the epoch-${epoch} address carries epoch ${checkpoint.epoch}`);
    }
    return checkpoint;
}
export async function fetchRoot(epoch, options = {}) {
    const checkpoint = await fetchCheckpoint(epoch, options);
    return { epoch: checkpoint.epoch, root: checkpoint.root };
}
