import type { Digest } from "./bytes.ts";
export declare function keccak256(data: Uint8Array): Digest;
/** §2.4 only: Solana program-address derivation and the Anchor account discriminator. */
export declare function sha256(data: Uint8Array): Uint8Array;
/**
 * Ed25519 as RFC 8032 names it in §1.1: `zip215: false` selects the RFC's own verification
 * equation and its canonical-encoding checks rather than the looser ZIP-215 rule.
 */
export declare function ed25519Verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean;
/** True when the 32 bytes decode as an Ed25519 curve point. §2.4's PDA must not (it is off-curve). */
export declare function isOnCurve(pointBytes: Uint8Array): boolean;
