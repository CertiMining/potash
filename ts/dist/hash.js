/**
 * The one hash family (INV-PRIM-01) and the one signature scheme (§1.1), named at the edge so
 * every call site below hashes and verifies through the same two functions.
 *
 * SHA-256 lives here too and is deliberately walled off: it is used only to derive a program
 * address and an Anchor account discriminator in §2.4, neither of which is a log digest. No
 * record, head, tree node, PRF output or promise ever touches it.
 */
import { keccak_256 } from "@noble/hashes/sha3.js";
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";
import { ed25519 } from "@noble/curves/ed25519.js";
export function keccak256(data) {
    return keccak_256(data);
}
/** §2.4 only: Solana program-address derivation and the Anchor account discriminator. */
export function sha256(data) {
    return nobleSha256(data);
}
/**
 * Ed25519 as RFC 8032 names it in §1.1: `zip215: false` selects the RFC's own verification
 * equation and its canonical-encoding checks rather than the looser ZIP-215 rule.
 */
export function ed25519Verify(publicKey, message, signature) {
    if (publicKey.length !== 32 || signature.length !== 64)
        return false;
    try {
        return ed25519.verify(signature, message, publicKey, { zip215: false });
    }
    catch {
        // A malformed key or signature is a verification failure, not an exception the caller handles.
        return false;
    }
}
/** True when the 32 bytes decode as an Ed25519 curve point. §2.4's PDA must not (it is off-curve). */
export function isOnCurve(pointBytes) {
    if (pointBytes.length !== 32)
        return false;
    try {
        ed25519.Point.fromBytes(pointBytes);
        return true;
    }
    catch {
        return false;
    }
}
