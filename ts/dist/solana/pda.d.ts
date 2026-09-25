export declare const PDA_MARKER: Uint8Array<ArrayBufferLike>;
export declare const SEED_LOG_CONFIG: Uint8Array<ArrayBufferLike>;
export declare const SEED_CHECKPOINT: Uint8Array<ArrayBufferLike>;
export declare const MAX_SEED_LEN = 32;
export declare const MAX_SEEDS = 16;
export declare function createProgramAddress(seeds: Uint8Array[], programId: Uint8Array): Uint8Array | null;
export declare function findProgramAddress(seeds: Uint8Array[], programId: Uint8Array): {
    address: Uint8Array;
    bump: number;
};
/** `LogConfig` PDA, seeds ["cm_cfg"]. */
export declare function deriveLogConfigAddress(programId: Uint8Array): {
    address: Uint8Array;
    bump: number;
};
/** `CheckpointAccount` PDA, seeds ["cm_ckpt", epoch_le]. */
export declare function deriveCheckpointAddress(programId: Uint8Array, epoch: bigint): {
    address: Uint8Array;
    bump: number;
};
