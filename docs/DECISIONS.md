# Decisions

Build decisions for CertiMining, numbered from D-03. **D-01 and D-02 are recorded in Appendix B of the spec, [TCU-02](TCU-02_CertiMining_Anchored_Log_v0.1.md#appendix-b--decision-log), and the numbering continues from there.** The process that produces these entries is step S0 in [STANDARD-STEPS.md](STANDARD-STEPS.md).

Each entry states the decision, its ground and its class. A security necessity names the property that breaks without it, a cost judgment names what it saves, and a preference is convention or taste. A decision that changes a contract amends TCU-02 in the same pull request.

## D-03 · The S6 asset-identifier rule is proven by a privacy test

**Date:** 17 Sep 2026 · **Unit:** every unit, from E-01 · **Class:** owner's ruling

**Decision.** The S6 requirement that nothing identifying an asset reaches the chain, a log or an error message is verified by a privacy test in each unit it touches, never by code review alone. In E-01 the test asserts that `RegistryError` is a fieldless two-byte code, so no error value can carry record or asset content.

**Ground.** It is the load-bearing property of this build. Review can miss a leak; a test that fails on one cannot.

## D-04 · Workspace layout

**Date:** 17 Sep 2026 · **Unit:** E-01 · **Class:** cost judgment

**Decision.** One Cargo workspace at the repository root. `crates/certimining-core` joins now; `crates/certimining-log`, `programs/certimining-checkpoint` (Anchor's convention) and `xtask/` join later.

**Ground.** The Anchor program joins at E-08 without moving any file.

## D-05 · Hash interface

**Date:** 17 Sep 2026 · **Unit:** E-01 · **Class:** cost judgment

**Decision.** The `Hasher` trait exposes one call that hashes a list of byte slices without allocating.

**Ground.** It matches `sol_keccak256`, which takes a list of slices, and the incremental interface of off-chain Keccak crates. The preimage writers of E-03 build on it.

## D-06 · Off-chain Keccak

**Date:** 17 Sep 2026 · **Unit:** E-01 · **Class:** cost judgment · **Status:** settled at S1

**Decision.** RustCrypto `sha3` 0.10.8 with default features off, through its `Keccak256` type, behind `feature = "native"`.

**Rejected.** `sha3` 0.12.0, which is edition 2024 with `rust-version = 1.85`, cannot build with the on-chain compiler, and would add a second `sha3` line. `tiny-keccak`, whose last release is 2.0.2 of April 2020 (crates.io).

**Ground.** 0.10.8 is the implementation Solana's hasher runs off-chain, so the project carries one Keccak implementation, which is worth more than a newer version number (owner, 17 Sep 2026). It is `#![no_std]` and builds with rustc 1.79.

## D-07 · On-chain Keccak

**Date:** 17 Sep 2026 · **Unit:** E-01 · **Class:** cost judgment, within the crate-root ban on `unsafe` (INV-ERR-01) · **Status:** ruled at S1; its ground depends on D-15, which is open

**Decision.** Solana's `solana-keccak-hasher` 2.2.1 with default features, behind `feature = "solana"`. Its optional `sha3` feature stays off.

**Rejected.** 3.1.0, whose dependencies require rustc 1.81 (`five8_core` 1.0.0) and 1.89 (`solana-hash` 4.6.0), so it does not build with platform-tools v1.43. The full `solana-program` crate, which brings the whole Solana SDK into core, and a direct syscall binding, which needs `unsafe`.

**Ground.** Built with the pinned platform-tools v1.43 (rustc 1.79.0), 2.2.1 produces a working program.

## D-08 · KAT-01 covers the on-chain path from E-01

**Date:** 17 Sep 2026 · **Unit:** E-01 · **Class:** security necessity · **Status:** settled at S1 (option A)

**Finding at S1.** The substitution is real. Off-chain, `solana-keccak-hasher` 2.2.1 computes Keccak in software with `sha3` 0.10.8; only a build for `target_os = "solana"` calls the `sol_keccak256` syscall (`src/lib.rs`, lines 128 to 138). A native test of the `solana` feature therefore says nothing about on-chain behaviour.

**Decision.** KAT-01 covers both paths from E-01: natively on both off-chain paths, and inside the Solana runtime through `sol_keccak256`, using a minimal on-chain harness that E-01 builds. #8 keeps the runtime-equivalence check for the full vector set; only the primitive check moves earlier.

**Ground (owner, 17 Sep 2026).** KAT-01 exists to stop a wrong hash reaching production, and the on-chain path is the only one production runs. Checking it only at E-08 would leave it unchecked from day 1 to day 10 while E-05 generates vectors from the off-chain implementation; if the syscall disagreed, every vector committed in that window would be wrong and consistent with itself. Nothing downstream inherits from an unchecked primitive.

**Evidence at S1.** A probe program built with the pinned platform-tools ran the five KAT-01 cases through `sol_keccak256` on the Agave 4.2 runtime (`litesvm` 0.16.0) and matched all five, at 235 to 293 compute units. The probe is not committed; the E-01 harness reproduces it.

## D-09 · How KAT-01 runs first

**Date:** 17 Sep 2026 · **Unit:** E-01 · **Class:** security necessity

**Decision.** KAT-01 runs first in CI: the off-chain run first, then the on-chain run through the harness (D-08). Every other job depends on both.

**Rejected.** A build-script check, which would test a separate build-time copy of the hash code rather than the code under test.

**Ground.** KAT-01 must check the code that actually runs.

## D-10 · KAT-01 provenance

**Date:** 17 Sep 2026 · **Unit:** E-01 · **Class:** security necessity · **Status:** settled at S1

**Decision.** KAT-01's expected values come from the Keccak team's known-answer package from round 3 of the SHA-3 competition, vendored byte for byte.

**Source.** `https://keccak.team/obsolete/KeccakKAT-3.zip`, listed on `https://keccak.team/archives.html` as the known-answer and Monte Carlo test results as of round 3 of the SHA-3 competition. Archive SHA-256 `af92d22d23527a0d168a6bbe70b28c840a43bba5bcea828a6d9a5e7ad79378ce` (16,946,525 bytes). The vendored file is `KeccakKAT/ShortMsgKAT_256.txt`, SHA-256 `741862f92342010311504202d7b304955fa28aa03a752633a5e83f971f014851` (707,143 bytes), dated 14 January 2011 in the archive. Its header names the algorithm Keccak and the Keccak team as submitter, and it holds every message length from 0 to 2,047 bits, including the five KAT-01 cases (0, 8, 1,080, 1,088 and 1,096 bits).

**Why the round-3 package and not XKCP.** XKCP, the Keccak team's current code package, publishes known-answer files for FIPS 202 SHA3-256, whose padding differs and whose digests therefore differ, and none for Keccak-256 with the original padding. KAT-01 needs the original-padding Keccak-256 that `sha3::Keccak256` and Solana's hasher implement. The older source is chosen deliberately, and the padding is the reason.

**Form.** The file is committed unmodified, with `.gitattributes` marking it `-text` so git never rewrites its line endings. Only in that form does its SHA-256 match the source.

**Owner's condition (17 Sep 2026).** If no primary source covers all five cases, work stops and the owner decides. The gap is never filled from a secondary source, a blog or another implementation's fixtures.

**Ground.** A vector set is only as good as its provenance, and everything downstream inherits from KAT-01. Values produced by this repository's own code would agree only with themselves.

## D-11 · Compiler pins

**Date:** 17 Sep 2026 · **Unit:** E-01 · **Class:** cost judgment

**Decision.** `rust-toolchain.toml` pins Rust 1.95.0. Miri runs on nightly-2026-06-15. CI uses the same compilers.

**Ground.** CI and the development machine build with identical compilers.

## D-12 · CI supply chain

**Date:** 17 Sep 2026 · **Unit:** E-01 · **Class:** security necessity

**Decision.** Every GitHub Action is pinned to a full commit SHA. cargo-deny 0.20.2 and Miri are installed at pinned versions with cargo and rustup, not through third-party actions.

**Ground.** A tag can be moved to new code, and that code runs with the repository's token.

## D-13 · cargo-deny policy and the project licence

**Date:** 17 Sep 2026 · **Unit:** E-01 · **Class:** preference for the allow-list; the licence is deliberately left open

**Decision.** Advisories deny. crates.io is the only allowed source. The licence allow-list is MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, Unicode-3.0, Zlib and CC0-1.0, extended per crate at S1. The project's own crates are `publish = false` and declare no licence.

**Ground.** The project licence stays open until E-15 by the owner's ruling of 17 Sep 2026. It is not guessed in the meantime.

## D-14 · `no_std` is proven by a bare-metal build

**Date:** 17 Sep 2026 · **Unit:** E-01 · **Class:** required by the spec (§2); the target is a preference

**Decision.** CI builds `certimining-core` for `thumbv7em-none-eabihf`, a target without the standard library, once with no features and once with `native`. The target is added to the pinned 1.95.0 toolchain with rustup.

**Ground.** A host build succeeds even when a dependency pulls in the standard library, so it cannot prove `no_std`. The `no_std` claim carries the chain-agnostic argument and was untested; a bare-metal build is the cheapest real proof (owner, 17 Sep 2026).

## D-15 · Solana toolchain line

**Date:** 17 Sep 2026 · **Unit:** E-01 onward · **Status:** open, with the owner

**Question.** Stay on the pinned Solana CLI 2.1.0, platform-tools v1.43 and Anchor 0.31.1, or move to the line the clusters run.

**Facts found at S1.**
- Devnet and mainnet RPC nodes report `solana-core` 4.3.0-rc.0 (`getVersion`, 17 Sep 2026).
- Anchor's current release is 1.2.0 (4 Sep 2026, Solana 3.x crates, `rust-version = 1.89`). The current platform-tools release is v1.51.1 (15 Sep 2026).
- Platform-tools v1.43 compiles with rustc 1.79.0 and emits SBPF v0 programs.
- `solana-program` 2.1.21 cannot share a dependency graph with `solana-keccak-hasher` 2.2.1: it pins `solana-sanitize` to 2.1.21, and the hasher needs 2.2.1 or later. `solana-program` 2.2.1 fails to build with platform-tools v1.43, whose Cargo cannot parse the manifest of a current transitive dependency (`toml_parser` 1.1.3).
- A v1.43 program that avoids `solana-program` loads and runs on the Agave 4.2 runtime (D-08 evidence).
