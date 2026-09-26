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
/** §1.4: an epoch is a UTC day index, `floor(unix_seconds / 86400)`. */
export declare const EPOCH_SECONDS = 86400n;
export declare function utcDayIndex(unixSeconds: bigint): bigint;
export type LogConfig = {
    schemaVersion: number;
    authority: Uint8Array;
    lastEpoch: bigint;
    treeHeight: number;
    bump: number;
    /**
     * §1.4, D-109: the UTC day index the chain reported at `initialize`. A log begins here, and
     * `last_epoch` was written as `start_epoch - 1`, so the first publication is `start_epoch`
     * itself. It occupies eight of the sixteen bytes v0.1.16's table showed as reserved.
     */
    startEpoch: bigint;
    /** §2.6 reserves the remaining eight bytes and nothing in this TCU reads them. */
    reserved: Uint8Array;
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
/**
 * Where an epoch falls against the log's own life (INV-ANCH-02, §1.4, D-109).
 *
 * `publish_checkpoint` accepts `last_epoch + 1` only, and the sequence begins at `start_epoch`, so
 * an epoch with no checkpoint account is one of three different things and a client that reported
 * them alike would accuse a batcher of failing to publish before it was deployed.
 */
export type EpochPlacement = {
    kind: "before-log-start";
    startEpoch: bigint;
} | {
    kind: "inside-published-range";
    startEpoch: bigint;
    lastEpoch: bigint;
} | {
    kind: "not-yet-published";
    lastEpoch: bigint;
};
export declare function placeEpoch(config: LogConfig, epoch: bigint): EpochPlacement;
/** INV-ANCH-05: until anchor B is attached the client reports "single"; after, "dual". */
export declare function anchorStatus(checkpoint: CheckpointAccount): "single" | "dual";
