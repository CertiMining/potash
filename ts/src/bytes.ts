// Byte helpers. No Node-only API is used here, so this file runs unchanged in a browser.

export type Digest = Uint8Array; // always 32 bytes

const HEX_RE = /^(0x)?[0-9a-fA-F]*$/;

/** Strict hex decode. Rejects odd length, stray characters, and a wrong length when one is named. */
export function fromHex(s: string, expectedLen?: number): Uint8Array {
  if (typeof s !== "string" || !HEX_RE.test(s)) throw new TypeError(`not hex: ${String(s)}`);
  const body = s.startsWith("0x") || s.startsWith("0X") ? s.slice(2) : s;
  if (body.length % 2 !== 0) throw new TypeError(`odd-length hex: ${s}`);
  const out = new Uint8Array(body.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(body.slice(i * 2, i * 2 + 2), 16);
  if (expectedLen !== undefined && out.length !== expectedLen) {
    throw new TypeError(`expected ${expectedLen} bytes, got ${out.length}`);
  }
  return out;
}

export function toHex(b: Uint8Array): string {
  let s = "0x";
  for (const byte of b) s += byte.toString(16).padStart(2, "0");
  return s;
}

export function concat(parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/** Lexicographic byte order: -1, 0 or 1. */
export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i]! !== b[i]!) return a[i]! < b[i]! ? -1 : 1;
  }
  return a.length === b.length ? 0 : (a.length < b.length ? -1 : 1);
}

export function u16le(v: number): Uint8Array {
  if (!Number.isInteger(v) || v < 0 || v > 0xffff) throw new RangeError(`u16 out of range: ${v}`);
  return new Uint8Array([v & 0xff, (v >>> 8) & 0xff]);
}

export function u64le(v: bigint): Uint8Array {
  if (v < 0n || v > 0xffff_ffff_ffff_ffffn) throw new RangeError(`u64 out of range: ${v}`);
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, v, true);
  return b;
}

export function i64le(v: bigint): Uint8Array {
  if (v < -(2n ** 63n) || v > 2n ** 63n - 1n) throw new RangeError(`i64 out of range: ${v}`);
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigInt64(0, v, true);
  return b;
}

export function readU16le(b: Uint8Array, off: number): number {
  return new DataView(b.buffer, b.byteOffset, b.byteLength).getUint16(off, true);
}

export function readU64le(b: Uint8Array, off: number): bigint {
  return new DataView(b.buffer, b.byteOffset, b.byteLength).getBigUint64(off, true);
}

export function readI64le(b: Uint8Array, off: number): bigint {
  return new DataView(b.buffer, b.byteOffset, b.byteLength).getBigInt64(off, true);
}

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

/** UTF-8 decode that refuses invalid input rather than substituting U+FFFD. */
export function utf8StrictDecode(b: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: true }).decode(b);
}

const B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * Strict base64 decode. No whitespace, no URL alphabet, padding required and canonical.
 * Written out rather than taken from the platform so the refusal set is the same in
 * every runtime: `atob` tolerates input a fail-closed verifier should not accept.
 */
export function base64Decode(s: string): Uint8Array {
  if (typeof s !== "string") throw new TypeError("base64: not a string");
  if (s.length % 4 !== 0) throw new TypeError("base64: length is not a multiple of four");
  let pad = 0;
  if (s.endsWith("==")) pad = 2;
  else if (s.endsWith("=")) pad = 1;
  const body = pad === 0 ? s : s.slice(0, s.length - pad);
  if (body.includes("=")) throw new TypeError("base64: padding inside the body");
  const out = new Uint8Array((s.length / 4) * 3 - pad);
  let o = 0;
  let acc = 0;
  let bits = 0;
  for (const ch of body) {
    const v = B64_ALPHABET.indexOf(ch);
    if (v < 0) throw new TypeError(`base64: invalid character ${JSON.stringify(ch)}`);
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
  }
  // Canonical padding: the bits the final group does not use must be zero.
  if (bits > 0 && (acc & ((1 << bits) - 1)) !== 0) throw new TypeError("base64: non-canonical padding bits");
  if (o !== out.length) throw new TypeError("base64: short decode");
  return out;
}

export function base64Encode(b: Uint8Array): string {
  let out = "";
  for (let i = 0; i < b.length; i += 3) {
    const b0 = b[i]!;
    const b1 = i + 1 < b.length ? b[i + 1]! : 0;
    const b2 = i + 2 < b.length ? b[i + 2]! : 0;
    out += B64_ALPHABET[b0 >> 2];
    out += B64_ALPHABET[((b0 & 3) << 4) | (b1 >> 4)];
    out += i + 1 < b.length ? B64_ALPHABET[((b1 & 15) << 2) | (b2 >> 6)] : "=";
    out += i + 2 < b.length ? B64_ALPHABET[b2 & 63] : "=";
  }
  return out;
}
