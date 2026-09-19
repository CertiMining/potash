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

**Premise re-checked after D-15 (17 Sep 2026).** With `solana-keccak-hasher` 3.1.0 the resolved graph still holds exactly one `sha3`, version 0.10.8, shared by the native path and the hasher's off-chain path (`cargo tree -i sha3`).

## D-07 · On-chain Keccak

**Date:** 17 Sep 2026 · **Unit:** E-01 · **Class:** cost judgment, within the crate-root ban on `unsafe` (INV-ERR-01) · **Status:** settled at S1, after D-15

**Decision.** Solana's `solana-keccak-hasher` 3.1.0 behind `feature = "solana"`, with the hasher's own `sha3` feature enabled. Without that feature, 3.1.0's `hashv` panics off-chain (`src/lib.rs`, lines 45 to 49), which INV-ERR-01 forbids. On-chain the feature has no effect, because its `sha3` dependency is declared for non-Solana targets only.

**Rejected.** 2.2.1, which builds but belongs to the superseded 2.x dependency chain. The full `solana-program` crate, which brings the whole Solana SDK into core, and a direct syscall binding, which needs `unsafe`.

**Ground.** Built with platform-tools v1.54 (rustc 1.89.0), 3.1.0 produces a working program, and it is the maintained dependency chain (owner's ruling of 17 Sep 2026: take 3.1.0 if the re-pinned compiler builds it).

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

**S9-03 (Codex review, 18 Sep 2026).** `scripts/ci.sh all` ran the remaining groups after a KAT-01 failure, so a local run was not CI verbatim. It now stops at the first KAT-01 failure, as CI does; the later groups stay independent of one another, as CI's jobs are.

## D-10 · KAT-01 provenance

**Date:** 17 Sep 2026 · **Unit:** E-01 · **Class:** security necessity · **Status:** settled at S1

**Decision.** KAT-01's expected values come from the Keccak team's known-answer package from round 3 of the SHA-3 competition, vendored byte for byte.

**Source.** `https://keccak.team/obsolete/KeccakKAT-3.zip`, listed on `https://keccak.team/archives.html` as the known-answer and Monte Carlo test results as of round 3 of the SHA-3 competition. Archive SHA-256 `af92d22d23527a0d168a6bbe70b28c840a43bba5bcea828a6d9a5e7ad79378ce` (16,946,525 bytes). The vendored file is `KeccakKAT/ShortMsgKAT_256.txt`, SHA-256 `741862f92342010311504202d7b304955fa28aa03a752633a5e83f971f014851` (707,143 bytes), dated 14 January 2011 in the archive. Its header names the algorithm Keccak and the Keccak team as submitter, and it holds every message length from 0 to 2,047 bits, including the five KAT-01 cases (0, 8, 1,080, 1,088 and 1,096 bits).

**Why the round-3 package and not XKCP.** XKCP, the Keccak team's current code package, publishes known-answer files for FIPS 202 SHA3-256, whose padding differs and whose digests therefore differ, and none for Keccak-256 with the original padding. KAT-01 needs the original-padding Keccak-256 that `sha3::Keccak256` and Solana's hasher implement. The older source is chosen deliberately, and the padding is the reason.

**Form.** The file is committed unmodified, with `.gitattributes` marking it `-text` so git never rewrites its line endings. Only in that form does its SHA-256 match the source.

**Owner's condition (17 Sep 2026).** If no primary source covers all five cases, work stops and the owner decides. The gap is never filled from a secondary source, a blog or another implementation's fixtures.

**Ground.** A vector set is only as good as its provenance, and everything downstream inherits from KAT-01. Values produced by this repository's own code would agree only with themselves.

## D-11 · Compiler pins

**Date:** 17 Sep 2026 · **Unit:** E-01 · **Class:** cost judgment · **Status:** amended at S1 by D-15

**Decision.** `rust-toolchain.toml` pins Rust 1.95.0. Miri runs on `nightly-2026-06-16`, the dated channel named in the installed toolchain's manifest; its compiler prints `rustc 1.98.0-nightly (01dfd7924 2026-06-15)`. An earlier version of this entry said nightly-2026-06-15, a date taken from that printed string rather than from the manifest; corrected at S3. On-chain builds use `cargo-build-sbf` 4.1.0 from Agave 4.2.2, with platform-tools v1.54. CI uses the same compilers.

**Versions as the installed tools print them (17 Sep 2026).** `rustc 1.95.0 (59807616e 2026-04-14)`; `cargo 1.95.0 (f2d3ce0bd 2026-03-21)`; `rustc 1.98.0-nightly (01dfd7924 2026-06-15)`; `miri 0.1.0 (01dfd79246 2026-06-15)`; `cargo-deny 0.20.2`; `cargo-build-sbf 4.1.0` / `platform-tools v1.54` / `rustc 1.89.0`; the platform-tools compiler itself prints `rustc 1.89.0-dev`. Version facts in this log are read from the installed tool and recorded as printed, never taken from a release page.

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

**Date:** 17 Sep 2026 · **Unit:** E-01 onward · **Class:** cost judgment · **Status:** settled at S1 (re-pin now)

**Decision.** The Solana toolchain moves from Solana CLI 2.1.0, platform-tools v1.43 and Anchor 0.31.1 to Agave 4.2.2, the current stable release. On-chain builds use its `cargo-build-sbf` 4.1.0 with platform-tools v1.54 (rustc 1.89.0), tests run on the Agave 4.2.2 runtime crates, and Anchor moves to 1.2.0, which E-08's S1 installs and verifies. The toolchain is installed for this project only; the machine-wide Solana install is not changed.

**Ground (owner, 17 Sep 2026).** Nothing is built, so the change will never be cheaper. Deferring would spend E-01 to E-07 against a toolchain known to fail at E-08 and land the migration beside the Anchor program. It is also D-08's logic one level up: a check against something other than the production path proves nothing reliable, and the old pin was about 18 months behind the clusters.

**Facts behind it.** On the old pin, `solana-program` 2.1.21 could not share a dependency graph with the 2.2.1 hasher, because it pins `solana-sanitize` to 2.1.21; `solana-program` 2.2.1 did not build, because platform-tools v1.43's Cargo cannot parse the manifest of a current transitive dependency. Anchor 1.2.0 requires rustc 1.89.

**How it is installed.** `cargo-build-sbf` 4.1.0 uninstalls any other rustup toolchain whose name contains "solana" before linking its own (`src/toolchain.rs`, lines 384 to 411 of the 4.1.0 crate). This project therefore runs it against a project-private `RUSTUP_HOME`. Platform-tools v1.54 sits in its own version directory of the Solana tools cache.

**Evidence.** A harness-shaped program built this way, SBPF v0 with `#![forbid(unsafe_code)]` at its crate root, ran the five KAT-01 cases through `sol_keccak256` on the Agave 4.2.2 runtime and matched all five, at 304 to 362 compute units.

**Why 4.2.2 and not the release candidate (owner, 17 Sep 2026).** Matching the runtime crates the tests run on matters more than matching the cluster, and a release candidate can change underneath a pin. The installed CLI prints `solana-cli 4.2.2 (src:c9c6f328; feat:21b0d33a, client:Agave)`.

**Condition on the step to 4.3.** Devnet and mainnet RPC nodes report 4.3.0-rc.0. The step from 4.2.2 is met on devnet at first deployment (E-08, E-09). If it shows any behavioural difference, that is a decision for the owner, not a fix.

**S9-02 (Codex review, 18 Sep 2026).** `scripts/build-sbf.sh` accepted an override for its private `RUSTUP_HOME`, which could point it at the machine-wide one. The override is gone, and the script refuses to run if the private home resolves to the machine-wide one.

## D-16 · On-chain test runner

**Date:** 17 Sep 2026 · **Unit:** E-01, reused by E-08 and E-09 · **Class:** cost judgment · **Status:** settled at S1

**Decision.** `litesvm` 0.16.0, a dev-dependency that runs programs in-process on the Agave runtime crates (resolved to 4.2.2).

**Rejected.** `solana-program-test` 4.2.2, the official harness, which is heavier and asynchronous.

**Not evaluated.** `mollusk-svm` 0.14 and 0.15. No comparison was made, and none should be read into this entry.

**Ground (owner, 17 Sep 2026).** One runtime serving E-01, E-08 and E-09 is worth more than a marginal comparison. At S1 it loaded the harness program and returned its return data and compute units for all five cases, and it runs whole transactions, which V-Z-01 at #9 needs.

**Dependency check.** Its dependency tree trips D-13's advisory gate; see D-18.

## D-17 · Harness program shape

**Date:** 17 Sep 2026 · **Unit:** E-01 · **Class:** security necessity · **Status:** settled at S1

**Decision.** The harness program at `programs/core-harness` uses `solana-program-entrypoint` 3.1.1 and the safe `set_return_data` of `solana-cpi` 3.1.0, the same 3.x line as Anchor 1.2.0. It is test infrastructure and is never deployed.

**Rejected.** A raw entrypoint, which needs `unsafe` in the crate, and the full `solana-program` crate.

**Ground.** The harness keeps `#![forbid(unsafe_code)]` at its crate root with no exception. An exception granted once for a harness tends to be cited later for something that is not one (owner, 17 Sep 2026). Verified at S1: the probe built with the attribute in place and matched all five cases.

**Compute.** The five cases cost 304 to 362 compute units through this shape, against a 15,000 unit budget for `publish_checkpoint`. Hashing is nowhere near the constraint; if that budget ever tightens, look first at account writes and constraint checks.

## D-18 · Advisory exceptions for the test runtime

**Date:** 17 Sep 2026 · **Unit:** E-01 · **Class:** cost judgment; naming the exceptions one by one is a security necessity · **Status:** settled at S1 (owner, 18 Sep 2026)

**Finding.** Under D-13's policy, `cargo deny check` over E-01's dependency graph as ruled (335 crates) passes licences and sources and fails advisories on five unmaintained crates: `paste` (RUSTSEC-2024-0436), `libsecp256k1` (RUSTSEC-2025-0161), `ansi_term` (RUSTSEC-2021-0139), `derivative` (RUSTSEC-2024-0388) and `bincode` (RUSTSEC-2025-0141). All five are reached only through `litesvm` 0.16.0; no shipped crate reaches any of them (`cargo tree -i <crate> -e normal`). The same run reports no vulnerability, unsound or yanked advisory.

**Decision.** `deny.toml` lists exactly these five advisory IDs as exceptions, each with the reason that only the test runtime reaches it. Vulnerability, unsound and yanked advisories take no exceptions, and any advisory not on the list fails CI.

**Rejected.** Scoping unmaintained checks to direct dependencies, or excluding dev-dependencies from the check. Either would let the next advisory through unseen.

**Ground.** It keeps the runner chosen in D-16 while the gate still catches the next advisory.

**Revisit if.** Any of the five gains a vulnerability, unsound or yanked advisory. A shipped crate starts to reach one of them (`cargo tree -i <crate> -e normal` shows a path). A new advisory appears anywhere in the tree: CI fails, and the answer is a decision, never a new line added to `deny.toml`. A `litesvm` release drops them, and the exceptions come out. E-16 reviews the list before submission.

**S9-01 (Codex review, 18 Sep 2026).** cargo-deny 0.20.2 checks unsound advisories in workspace crates only unless told otherwise (`src/advisories/cfg.rs`, line 282), so a transitive unsound advisory would have passed. `deny.toml` now sets `unsound = "all"`, and states `unmaintained = "all"` explicitly. The five exceptions are unchanged.

## D-19 · Default feature is `native`

**Date:** 18 Sep 2026 · **Unit:** E-01 · **Class:** cost judgment · **Status:** settled at S2

**Decision.** `certimining-core` declares `default = ["native"]`. The harness program, and later any on-chain crate, depends on core with `default-features = false` and turns on only what it needs.

**Ground.** A plain `cargo test` runs off-chain with no extra flags.

**Revisit if.** An on-chain build's dependency tree ever contains `sha3`, which means a crate forgot `default-features = false`; or a consumer needs core with no hasher by default.

## D-20 · Two named hashers

**Date:** 18 Sep 2026 · **Unit:** E-01 · **Class:** security necessity · **Status:** settled at S2

**Decision.** The `native` feature provides `NativeKeccak` and the `solana` feature provides `SolanaKeccak`, two separate types implementing the `Hasher` trait (D-05). Both features may be on at once, and calling code names the hasher it uses. No function picks a hasher at compile time.

**Ground.** D-08 checks both off-chain paths in the same run, which a single compile-time choice cannot reach. If Cargo merged the features in a harness build, a single function could also quietly run the software hash where the on-chain one was meant to be tested.

**Revisit if.** A later unit needs code that chooses a hasher implicitly, or the two types ever disagree on any input (KAT-01, and V-P-08 from E-11, would show it).

## D-21 · Where INV-ERR-01's gates apply

**Date:** 18 Sep 2026 · **Unit:** every unit, from E-01 · **Class:** cost judgment; the unsafe addition is a preference · **Status:** settled (owner, 18 Sep 2026)

**Decision.** INV-ERR-01's clippy gates (`unwrap_used`, `expect_used`, `indexing_slicing`, `arithmetic_side_effects`) sit at the crate root of every library and program crate, and so govern shipped code. Test files may assert, unwrap and index. `unsafe` is forbidden in every target, tests included, through `[lints.rust] unsafe_code = "forbid"` in each package's `Cargo.toml`.

**Rejected.** Putting the four clippy gates on tests too, which costs readability in code that never ships. Forbidding panics in tests altogether, which would leave a test able to fail only through error-handling code, where one mistake, such as an early `return Ok(())`, turns a failing check into a silent pass.

**Ground (owner, 18 Sep 2026).** The gates exist to stop shipped code from panicking on bad input. Tests are what catches those problems, and a test is most trustworthy when it fails loudly. No test needs `unsafe`, so forbidding it there costs nothing.

**Revisit if.** A test ever needs `unsafe`, which is a decision rather than a lint exception; or test helper code moves into a shipped crate, where the gates then apply to it.

## D-22 · Normalization is NFKD

**Date:** 18 Sep 2026 · **Unit:** E-02 · **Class:** security necessity · **Status:** settled at S0 (owner, 18 Sep 2026)

**Decision.** Canonicalization applies Unicode NFKD, not the NFKC that TCU-02 first named. The spec is amended to match (v0.1.3).

**Ground.** With the filter that keeps only A–Z and 0–9, NFKC removes an accented letter entirely: "Mine Élan 12" canonicalizes to `MINELAN12` while "Mine Elan 12" gives `MINEELAN12`, one tenure with two identities, the split RES-06 names. NFKD separates the accent from its letter, so both give `MINEELAN12`.

**Limitation.** Letters with no compatibility decomposition, such as œ, æ and ß, are removed under either form: "Cœur 7" gives `CUR7`, while "Coeur 7" gives `COEUR7`.

**Revisit if.** Real tenure identifiers turn out to carry such letters. A transliteration table then becomes a decision, and a new schema version under INV-FWD-01 if it changes any canonical form.

## D-23 · Uppercase is ASCII-only

**Date:** 18 Sep 2026 · **Unit:** E-02 · **Class:** security necessity · **Status:** settled at S0 (owner, 18 Sep 2026)

**Decision.** Only a to z are uppercased. Every other character reaches the filter unchanged, and the filter removes it.

**Ground.** Full Unicode uppercase follows the compiler's Unicode tables. Rust 1.95.0 reports Unicode 17.0.0 through `char::UNICODE_VERSION`, and the on-chain compiler may carry another version, so two builds could canonicalize one input differently. ASCII-only uppercase depends on nothing but the pinned normalization tables, so the native build, the on-chain build and the TS verifier (E-11) agree.

**Cost.** "straße 3" gives `STRAE3`, not `STRASSE3`.

**Revisit if.** A tenure registry in scope uses letters that Unicode uppercasing would map into A–Z.

## D-24 · A bytes entry point

**Date:** 18 Sep 2026 · **Unit:** E-02 · **Class:** required by the spec's own acceptance (E-02, F-02) · **Status:** settled at S0 (owner, 18 Sep 2026)

**Decision.** `AssetIdentity::canonicalize_bytes(&[u8])` accepts raw bytes and returns `0x11` on invalid UTF-8; `canonicalize(&str)` calls it. §2.2 is amended to list it.

**Ground.** A Rust `&str` cannot hold invalid UTF-8, yet E-02 and F-02 require canonicalization never to panic on it.

**Revisit if.** F-02's fuzzing (E-12) finds any input on which the two entry points disagree.

## D-25 · The raw input is capped at 256 bytes

**Date:** 18 Sep 2026 · **Unit:** E-02 · **Class:** security necessity; the value is a preference · **Status:** settled at S0 (owner, 18 Sep 2026)

**Decision.** `canonicalize_bytes` rejects raw input longer than 256 bytes with `0x11`, before normalizing. §1.8 is amended.

**Ground.** The spec bounded the output at 64 bytes but not the input, and S6 requires limits where input is read. Normalization's work and buffering grow with its input.

**Revisit if.** A real tenure identifier needs more than 256 bytes of raw input.

## D-26 · `commitment` accepts only a canonical tenure

**Date:** 18 Sep 2026 · **Unit:** E-02 · **Class:** security necessity · **Status:** settled at S0 (owner, 18 Sep 2026)

**Decision.** `commitment(J, R, T)` returns `0x11` unless `T` is already canonical: 1 to 64 bytes, each A–Z or 0–9. §1.3 is amended.

**Ground.** A caller who skipped `canonicalize` would otherwise commit a raw spelling and split the identity without any error.

**Revisit if.** The canonical alphabet changes, which is a new schema version under INV-FWD-01.

## D-27 · Three new crates

**Date:** 18 Sep 2026 · **Unit:** E-02 · **Class:** cost judgment · **Status:** settled at S0 (owner, 18 Sep 2026); versions confirmed at S1

**Decision.** `unicode-normalization` 0.1.25 for NFKD. `heapless` 0.9.3 for the fixed-capacity result type that §2.2 names. `proptest` 1.11.0, test-only, for the property tests, reused at E-12.

**Rejected.** `icu_normalizer` 2.3.0, which carries far more data than one normalization form needs; hand-written normalization tables; hand-rolled random testing.

**Revisit if.** `unicode-normalization` lags Unicode in a way that changes the canonical form of any character that decomposes into A–Z or 0–9, or `proptest`'s dependency tree trips D-13's policy.
