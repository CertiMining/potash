/**
 * §1.3's canonical tenure `T`: NFKD, then uppercasing of a to z only, then removal of every
 * character other than A–Z and 0–9. Raw input over 256 bytes, invalid UTF-8, or a result that is
 * empty or longer than 64 bytes is 0x11 (V-N-21).
 */
import { utf8, utf8StrictDecode } from "./bytes.js";
import { RegistryFailure } from "./errors.js";
export const MAX_RAW_TENURE_BYTES = 256;
export const MAX_CANONICAL_TENURE_BYTES = 64;
/** Raw bytes in, which may not be valid UTF-8; invalid input is 0x11 (§2.2 `canonicalize_bytes`). */
export function canonicalizeBytes(raw) {
    if (raw.length > MAX_RAW_TENURE_BYTES) {
        throw new RegistryFailure("CanonicalizationFailed", `raw tenure is ${raw.length} bytes, over ${MAX_RAW_TENURE_BYTES}`);
    }
    let decoded;
    try {
        decoded = utf8StrictDecode(raw);
    }
    catch {
        throw new RegistryFailure("CanonicalizationFailed", "raw tenure is not valid UTF-8");
    }
    return canonicalizeDecoded(decoded);
}
/** §2.2 `canonicalize`: the string form. The 256-byte bound is measured on the UTF-8 encoding. */
export function canonicalize(rawTenure) {
    return canonicalizeBytes(utf8(rawTenure));
}
function canonicalizeDecoded(s) {
    const decomposed = s.normalize("NFKD");
    const out = [];
    for (const ch of decomposed) {
        const cp = ch.codePointAt(0);
        // Uppercase a to z, and nothing else.
        const upper = cp >= 0x61 && cp <= 0x7a ? cp - 0x20 : cp;
        // Keep A–Z and 0–9, and nothing else.
        if ((upper >= 0x41 && upper <= 0x5a) || (upper >= 0x30 && upper <= 0x39))
            out.push(upper);
    }
    if (out.length === 0) {
        throw new RegistryFailure("CanonicalizationFailed", "canonical tenure is empty");
    }
    if (out.length > MAX_CANONICAL_TENURE_BYTES) {
        throw new RegistryFailure("CanonicalizationFailed", `canonical tenure is ${out.length} bytes, over ${MAX_CANONICAL_TENURE_BYTES}`);
    }
    return Uint8Array.from(out);
}
/** True when `t` is already exactly what canonicalization would produce. */
export function isCanonicalTenure(t) {
    try {
        const again = canonicalizeBytes(t);
        if (again.length !== t.length)
            return false;
        for (let i = 0; i < t.length; i++)
            if (again[i] !== t[i])
                return false;
        return true;
    }
    catch {
        return false;
    }
}
