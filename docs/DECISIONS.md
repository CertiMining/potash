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

**Date:** 17 Sep 2026 · **Unit:** E-01 · **Class:** cost judgment

**Decision.** RustCrypto `sha3`, through its `Keccak256` type, behind `feature = "native"`. S1 fixes the exact version; 0.12.0 is current on crates.io as of 17 Sep 2026. It is compiled off-chain only, so the Solana compiler's limit in D-07 does not apply to it.

**Rejected.** `tiny-keccak`, whose last release is 2.0.2 of April 2020 (crates.io).

**Ground.** A maintained crate sits beneath every digest. KAT-01 checks it either way.

## D-07 · On-chain Keccak

**Date:** 17 Sep 2026 · **Unit:** E-01 · **Class:** cost judgment, within the crate-root ban on `unsafe` (INV-ERR-01)

**Decision.** Solana's `solana-keccak-hasher` behind `feature = "solana"`, at 2.2.1 or 3.1.0, whichever builds with the Solana compiler; S1 fixes the version. Solana CLI 2.1.0 builds on-chain code with rustc 1.79.0 (`rustup run solana rustc --version`), so core under this feature stays on edition 2021 and on dependencies that build with 1.79.

**Rejected.** The full `solana-program` crate, which brings the whole Solana SDK into core, and a direct syscall binding, which needs `unsafe`.

**Ground.** It is the smallest dependency that reaches `sol_keccak256`.

## D-08 · What "both feature sets compile" means

**Date:** 17 Sep 2026 · **Unit:** E-01 · **Class:** security necessity · **Status:** open until S1 verifies its premise

**Decision.** `native` builds with Rust 1.95.0. `solana` builds for the Solana target with rustc 1.79.0, as its own CI job.

**Ground.** If Solana's hasher substitutes a software implementation off-chain, a native-only build never compiles the on-chain path, and a native-only test proves nothing about on-chain behaviour.

**Owner's condition (17 Sep 2026).** S1 verifies whether the substitution is real before anything builds on this decision. If it is real, this entry becomes a decision about how KAT-01 covers both paths rather than a CI-job arrangement, and it returns to the owner.

## D-09 · How KAT-01 runs first

**Date:** 17 Sep 2026 · **Unit:** E-01 · **Class:** security necessity

**Decision.** KAT-01 is the first CI job, and every other job depends on it.

**Rejected.** A build-script check, which would test a separate build-time copy of the hash code rather than the code under test.

**Ground.** KAT-01 must check the code that actually runs.

## D-10 · KAT-01 provenance

**Date:** 17 Sep 2026 · **Unit:** E-01 · **Class:** security necessity

**Decision.** KAT-01's expected values come from the Keccak team's published known-answer file for Keccak-256 with the original padding. The file is vendored with its source URL and SHA-256 and must cover the empty, 1-byte, and 135-, 136- and 137-byte cases.

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
