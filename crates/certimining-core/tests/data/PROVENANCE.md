# Provenance of `ShortMsgKAT_256.txt` (D-10)

- **Source archive:** `https://keccak.team/obsolete/KeccakKAT-3.zip`, listed on `https://keccak.team/archives.html` as the Keccak team's known-answer and Monte Carlo test results as of round 3 of the SHA-3 competition. Retrieved 17 September 2026.
- **Archive SHA-256:** `af92d22d23527a0d168a6bbe70b28c840a43bba5bcea828a6d9a5e7ad79378ce` (16,946,525 bytes).
- **File in the archive:** `KeccakKAT/ShortMsgKAT_256.txt`, dated 14 January 2011.
- **File SHA-256:** `741862f92342010311504202d7b304955fa28aa03a752633a5e83f971f014851` (707,143 bytes). CI checks this hash before KAT-01 runs (`scripts/ci.sh kat01-offchain`).
- **Form:** committed unmodified. `.gitattributes` marks it `-text` so git never rewrites its line endings.
- **Why this source:** it is Keccak-256 with the original padding, which `sha3::Keccak256` and Solana's hasher implement. XKCP publishes FIPS 202 SHA3-256 vectors, whose padding and digests differ.

# Provenance of `rfc8032_7.1.txt` (D-45)

- **Source:** `https://www.rfc-editor.org/rfc/rfc8032.txt`, the RFC Editor's authoritative text of RFC 8032, *Edwards-Curve Digital Signature Algorithm (EdDSA)*. Retrieved 21 September 2026.
- **Full document SHA-256:** `ed63657ff389301282b169b0abde9b5dd2c7e4d524fdfa5da6ff3094fc93c4c3` (103,210 bytes).
- **Extraction:** `sed -n '1295,1499p' rfc8032.txt > rfc8032_7.1.txt`, which is §7.1 in full, from its heading to the line before §7.2.
- **File SHA-256:** `0717d570f83753773c492e9157bb1407754bf16e3cf9b8be317b2f7c71b42d67` (5,218 bytes). CI checks this hash before KAT-02 runs.
- **Form:** committed unmodified, line endings included. `.gitattributes` marks it `-text` so git never rewrites them.
- **What it covers:** the five Ed25519 vectors of §7.1 — the empty message, one byte, two bytes, 1,023 bytes, and SHA-512("abc") — each with its secret key, public key, message and signature.
- **Why this source:** RFC 8032 is the specification §1.1 names, and its own vectors are the primary record. A crate's test suite would test the crate against itself.
