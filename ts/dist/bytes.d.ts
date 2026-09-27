export type Digest = Uint8Array;
/** Strict hex decode. Rejects odd length, stray characters, and a wrong length when one is named. */
export declare function fromHex(s: string, expectedLen?: number): Uint8Array;
export declare function toHex(b: Uint8Array): string;
export declare function concat(parts: Uint8Array[]): Uint8Array;
export declare function bytesEqual(a: Uint8Array, b: Uint8Array): boolean;
/** Lexicographic byte order: -1, 0 or 1. */
export declare function compareBytes(a: Uint8Array, b: Uint8Array): number;
export declare function u16le(v: number): Uint8Array;
export declare function u64le(v: bigint): Uint8Array;
export declare function i64le(v: bigint): Uint8Array;
export declare function readU16le(b: Uint8Array, off: number): number;
export declare function readU64le(b: Uint8Array, off: number): bigint;
export declare function readI64le(b: Uint8Array, off: number): bigint;
export declare function utf8(s: string): Uint8Array;
/** UTF-8 decode that refuses invalid input rather than substituting U+FFFD. */
export declare function utf8StrictDecode(b: Uint8Array): string;
/**
 * Strict base64 decode. No whitespace, no URL alphabet, padding required and canonical.
 * Written out rather than taken from the platform so the refusal set is the same in
 * every runtime: `atob` tolerates input a fail-closed verifier should not accept.
 */
export declare function base64Decode(s: string): Uint8Array;
export declare function base64Encode(b: Uint8Array): string;
