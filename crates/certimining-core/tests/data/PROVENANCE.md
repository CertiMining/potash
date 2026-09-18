# Provenance of `ShortMsgKAT_256.txt` (D-10)

- **Source archive:** `https://keccak.team/obsolete/KeccakKAT-3.zip`, listed on `https://keccak.team/archives.html` as the Keccak team's known-answer and Monte Carlo test results as of round 3 of the SHA-3 competition. Retrieved 17 September 2026.
- **Archive SHA-256:** `af92d22d23527a0d168a6bbe70b28c840a43bba5bcea828a6d9a5e7ad79378ce` (16,946,525 bytes).
- **File in the archive:** `KeccakKAT/ShortMsgKAT_256.txt`, dated 14 January 2011.
- **File SHA-256:** `741862f92342010311504202d7b304955fa28aa03a752633a5e83f971f014851` (707,143 bytes). CI checks this hash before KAT-01 runs (`scripts/ci.sh kat01-offchain`).
- **Form:** committed unmodified. `.gitattributes` marks it `-text` so git never rewrites its line endings.
- **Why this source:** it is Keccak-256 with the original padding, which `sha3::Keccak256` and Solana's hasher implement. XKCP publishes FIPS 202 SHA3-256 vectors, whose padding and digests differ.
