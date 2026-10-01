/**
 * Base58 (Bitcoin alphabet) for Solana addresses. Not a cryptographic primitive and not on the
 * verifier's trust path: it only turns 32 bytes into the text a JSON-RPC call carries, and back.
 */
const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function base58Encode(bytes: Uint8Array): string {
  if (bytes.length === 0) return "";
  const digits: number[] = []; // little-endian base-58 digits
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i++) {
      carry += digits[i]! << 8;
      digits[i] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let out = "";
  for (const b of bytes) {
    if (b !== 0) break;
    out += ALPHABET[0];
  }
  for (let i = digits.length - 1; i >= 0; i--) out += ALPHABET[digits[i]!];
  return out;
}

export function base58Decode(s: string): Uint8Array {
  if (typeof s !== "string" || s.length === 0) throw new TypeError("base58: empty");
  const magnitude: number[] = []; // little-endian base-256 digits
  for (const ch of s) {
    const value = ALPHABET.indexOf(ch);
    if (value < 0) throw new TypeError(`base58: invalid character ${JSON.stringify(ch)}`);
    let carry = value;
    for (let i = 0; i < magnitude.length; i++) {
      carry += magnitude[i]! * 58;
      magnitude[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      magnitude.push(carry & 0xff);
      carry >>= 8;
    }
  }
  while (magnitude.length > 0 && magnitude[magnitude.length - 1] === 0) magnitude.pop();
  let leadingZeros = 0;
  for (const ch of s) {
    if (ch !== ALPHABET[0]) break;
    leadingZeros += 1;
  }
  const out = new Uint8Array(leadingZeros + magnitude.length);
  for (let i = 0; i < magnitude.length; i++) out[leadingZeros + i] = magnitude[magnitude.length - 1 - i]!;
  return out;
}
