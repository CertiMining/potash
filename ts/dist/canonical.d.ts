export declare const MAX_RAW_TENURE_BYTES = 256;
export declare const MAX_CANONICAL_TENURE_BYTES = 64;
/** Raw bytes in, which may not be valid UTF-8; invalid input is 0x11 (§2.2 `canonicalize_bytes`). */
export declare function canonicalizeBytes(raw: Uint8Array): Uint8Array;
/** §2.2 `canonicalize`: the string form. The 256-byte bound is measured on the UTF-8 encoding. */
export declare function canonicalize(rawTenure: string): Uint8Array;
/** True when `t` is already exactly what canonicalization would produce. */
export declare function isCanonicalTenure(t: Uint8Array): boolean;
