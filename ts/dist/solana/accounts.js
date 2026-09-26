/**
 * §2.4's two account layouts, and the Anchor discriminator each opens with.
 *
 * The discriminator is the first eight bytes of `SHA-256("account:" ‖ N)` for the struct name `N`.
 * §2.4 publishes both constants; this file computes them instead of copying them, which is the
 * point the section makes about not being required to trust the two values.
 */
import { readI64le, readU16le, readU64le, toHex, utf8 } from "../bytes.js";
import { PackageFailure } from "../errors.js";
import { sha256 } from "../hash.js";
export function accountDiscriminator(structName) {
    return sha256(utf8(`account:${structName}`)).slice(0, 8);
}
export const LOG_CONFIG_DISCRIMINATOR = accountDiscriminator("LogConfig");
export const CHECKPOINT_DISCRIMINATOR = accountDiscriminator("CheckpointAccount");
export const LOG_CONFIG_LEN = 68;
export const CHECKPOINT_LEN = 106;
function checkAccount(data, expectedLen, discriminator, what) {
    if (data.length !== expectedLen) {
        throw new PackageFailure("RootUnavailable", `${what} is ${data.length} bytes, and §2.4 fixes it at ${expectedLen}`);
    }
    for (let i = 0; i < 8; i++) {
        if (data[i] !== discriminator[i]) {
            throw new PackageFailure("RootUnavailable", `${what} carries ${toHex(data.subarray(0, 8))}, not ${toHex(discriminator)}`);
        }
    }
}
export function decodeLogConfig(data) {
    checkAccount(data, LOG_CONFIG_LEN, LOG_CONFIG_DISCRIMINATOR, "LogConfig");
    return {
        schemaVersion: readU16le(data, 8),
        authority: data.slice(10, 42),
        lastEpoch: readU64le(data, 42),
        treeHeight: data[50],
        bump: data[51],
    };
}
export function decodeCheckpointAccount(data) {
    checkAccount(data, CHECKPOINT_LEN, CHECKPOINT_DISCRIMINATOR, "CheckpointAccount");
    return {
        schemaVersion: readU16le(data, 8),
        epoch: readU64le(data, 10),
        root: data.slice(18, 50),
        publishedSlot: readU64le(data, 50),
        publishedUnix: readI64le(data, 58),
        receiptDigest: data.slice(66, 98),
        anchorKind: data[98],
        bump: data[99],
    };
}
/** INV-ANCH-05: until anchor B is attached the client reports "single"; after, "dual". */
export function anchorStatus(checkpoint) {
    return checkpoint.receiptDigest.every((b) => b === 0) ? "single" : "dual";
}
