# Canonicalization of tenure identifiers

The asset commitment `c` binds a record chain to one mineral tenure (TCU-02 §1.3). The same tenure must always produce the same `c`, so its identifier is first reduced to one canonical form, `T`. This document states the rules that `certimining-core` implements (`AssetIdentity`, E-02) and the limits of what they achieve.

## The rules

A raw tenure identifier becomes `T` in this order:

1. **Input checks.** More than 256 bytes of raw input is refused (D-25). Bytes that are not valid UTF-8 are refused (D-24).
2. **Unicode NFKD.** Compatibility decomposition separates accents from their letters and folds compatibility forms, such as full-width letters, circled digits and ligatures, into their plain equivalents (D-22).
3. **ASCII uppercase.** Only a to z are uppercased. No other character is case-mapped (D-23).
4. **Filter.** Every character other than A–Z and 0–9 is removed.
5. **Bounds.** The result must be 1 to 64 bytes. An empty result and a longer one are both refused.

Every refusal is error `0x11`, `CanonicalizationFailed`. The rules are idempotent: canonicalizing `T` returns `T`.

## Examples

| Raw identifier | `T` | Why |
|---|---|---|
| `bc-tenure 1043-a` | `BCTENURE1043A` | Lowercase letters are uppercased; the hyphens and the space are removed (V-P-01) |
| `BC_TENURE1043A` | `BCTENURE1043A` | The underscore is removed, so this spelling matches the one above (V-P-01) |
| `Mine Élan 12` | `MINEELAN12` | NFKD keeps `E` from `É`, so the accented and plain spellings agree |
| `Ｂ①ﬁ` | `B1FI` | A full-width B, a circled one and the fi ligature fold to ASCII |
| `Cœur 7` | `CUR7` | `œ` has no decomposition and is removed; see Limits |
| `straße 3` | `STRAE3` | `ß` has no decomposition and is removed; see Limits |
| `-_./` | refused, `0x11` | Nothing remains after the filter (V-N-21) |

## The commitment

`c = Keccak256(TAG_ASSET ‖ J ‖ R ‖ len(T) ‖ T)`, where `TAG_ASSET` is the 8 bytes `CMv1ASST`, `J` is a 4-byte jurisdiction code, `R` is an 8-byte registry code, and `len(T)` is the length of `T` as a little-endian `u16`. `commitment` refuses any `T` that is not already canonical, so a raw spelling can never be committed by mistake (D-26). `c` is a local identifier: it never appears on-chain or leaves the issuer's control, except inside a disclosure package the issuer chooses to release (INV-STATE-03).

What `J` and `R` mean, and the namespace their codes come from, are not defined here; `commitment` takes them as bytes.

## Stability

NFKD comes from `unicode-normalization` 0.1.25, whose tables pin Unicode 17.0.0. The canonical form of a character therefore changes only if that pin changes. Only a to z are case-mapped, so the compiler's own Unicode tables play no part, and every build, native or on-chain, gives the same `T`. Changing any rule that changes any `T` is a new schema version under INV-FWD-01.

## Limits

These rules narrow the identity attack surface; they do not close it (RES-06).

- Letters with no compatibility decomposition, such as `œ`, `æ` and `ß`, are removed rather than transliterated. `Cœur 7` gives `CUR7` while `Coeur 7` gives `COEUR7`, so those two spellings produce different commitments.
- Letters outside A to Z, such as Greek or Cyrillic, are removed entirely.
- Two identifiers that differ only in removed characters produce the same `T`. `BC-1043` and `BC 1043` are intended to match. A registry whose identifiers differ only in punctuation would need its own rule.
- Nothing here detects two chains built for one physical asset under different spellings. That is asset equivocation (§0, RES-01), which this design cannot carry.
