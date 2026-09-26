/**
 * §2.4's two account layouts, and the Anchor discriminator each opens with.
 *
 * The discriminator is the first eight bytes of `SHA-256("account:" ‖ N)` for the struct name `N`.
 * §2.4 publishes both constants; this file computes them instead of copying them, which is the
 * point the section makes about not being required to trust the two values.
 */
import { type Digest } from "../bytes.ts";
export declare function accountDiscriminator(structName: string): Uint8Array;
export declare const LOG_CONFIG_DISCRIMINATOR: Uint8Array<ArrayBufferLike>;
export declare const CHECKPOINT_DISCRIMINATOR: Uint8Array<ArrayBufferLike>;
export declare const LOG_CONFIG_LEN = 68;
export declare const CHECKPOINT_LEN = 106;
export type LogConfig = {
    schemaVersion: number;
    authority: Uint8Array;
    lastEpoch: bigint;
    treeHeight: number;
    bump: number;
};
export type CheckpointAccount = {
    schemaVersion: number;
    epoch: bigint;
    root: Digest;
    publishedSlot: bigint;
    publishedUnix: bigint;
    receiptDigest: Digest;
    anchorKind: number;
    bump: number;
};
export declare function decodeLogConfig(data: Uint8Array): LogConfig;
export declare function decodeCheckpointAccount(data: Uint8Array): CheckpointAccount;
/** INV-ANCH-05: until anchor B is attached the client reports "single"; after, "dual". */
export declare function anchorStatus(checkpoint: CheckpointAccount): "single" | "dual";
