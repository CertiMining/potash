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

**Confirmed at S1 (18 Sep 2026).** `Cargo.lock` resolves `unicode-normalization` 0.1.25, `tinyvec` 1.13.3, `heapless` 0.9.3 and `proptest` 1.11.0. `unicode-normalization`'s tables pin Unicode 17.0.0 (`src/tables.rs`, line 18), and it needs an allocator (`extern crate alloc`, `src/lib.rs`, line 48), so core is `no_std` with `alloc`. Both bare-metal builds (D-14) and the Solana build still pass, and the harness program stays at 11,464 bytes because it never calls canonicalization. `cargo deny check` passes with the new graph; no licence had to be added.

## D-28 · Leaf and head field widths

**Date:** 19 Sep 2026 · **Unit:** E-03 · **Class:** cost judgment · **Status:** settled at S0 (owner, 19 Sep 2026)

**Decision.** In the leaf preimage `category` is a `u8`, and `effective_at` and `change_identified_at` are signed 64-bit Unix seconds. `seq` is the `u64` of §2.2 and `schema_version` the `u16` of §2.4, so the leaf preimage is 161 bytes and the two head preimages are 42 and 72. §1.3 is amended with the table (v0.1.4).

**Ground.** §1.3 fixed each field's order and left three widths unwritten, which S0 forbids guessing. V-N-07b expects a category of 255 to be rejected, so the field has to hold 255. Solana's clock is a signed 64-bit Unix time, and E-04 compares record times against it.

**Rejected.** Unsigned timestamps, which would disagree with the on-chain clock at the one place the two meet.

**Revisit if.** A verifier or an index needs unsigned times, or a category range wider than a byte. Either is a new schema version under INV-FWD-01, never an edit.

## D-29 · The SPI's two unnamed types

**Date:** 19 Sep 2026 · **Unit:** E-03 · **Class:** cost judgment · **Status:** settled at S0 (owner, 19 Sep 2026)

**Decision.** `SubmissionId` is `[u8; 16]`, and `max_merge_delay` is a `u8` inside the SPI preimage, which is 65 bytes. §1.6 and §2.3 are amended (v0.1.4).

**Ground.** §2.3 used `SubmissionId` without defining it and §1.6 gave the delay no width. Sixteen bytes is the usual width for a unique identifier, and INV-SPI-01 fixes the delay at 2 while §1.8 caps it, so one byte carries it. E-07 widens it for arithmetic against a `u64` epoch.

**Rejected.** A 32-byte identifier, which doubles the field for no property it gains.

**Revisit if.** The batcher has to accept identifiers minted elsewhere, or a deployment needs a merge delay above 255 epochs.

## D-30 · The checkpoint writer waits for its consumer

**Date:** 19 Sep 2026 · **Unit:** E-03 · **Class:** cost judgment · **Status:** settled at S0 (owner, 19 Sep 2026)

**Decision.** E-03 writes no checkpoint preimage. `TAG_CKPT` stays reserved and unused, the checkpoint entry in issue #3's task list is marked N/A with this reason, and the writer arrives with whatever first reads one, at E-08 or E-10.

**Ground.** §1.2 lists the tag and no section says what the preimage holds. Nothing consumes one: the program stores the root and OpenTimestamps stamps the root. Writing a layout now would freeze a guess into schema 1, and INV-FWD-01 makes changing a schema-1 digest a new schema version.

**Revisit if.** E-08 or E-10 needs a checkpoint digest. Its layout is then a decision with a spec amendment, not a fix.

## D-31 · The Merkle tags are written here

**Date:** 19 Sep 2026 · **Unit:** E-03 · **Class:** cost judgment · **Status:** settled at S0 (owner, 19 Sep 2026)

**Decision.** E-03 also provides the writers for `TAG_MTL0`, the real leaf, and `TAG_MTN1`, the internal node, whose formulas §1.4 fixes. E-06 builds the tree on them. This widens issue #3's task list, with the owner's ruling.

**Ground.** Both are tagged preimages, which is what this unit closes for every call site. Their formulas are settled, so leaving them out would have E-06 re-deriving preimage code this module already holds.

**Revisit if.** E-06 needs a leaf or node shape §1.4 does not give.

## D-32 · `Preimage::digest` names its hasher

**Date:** 19 Sep 2026 · **Unit:** E-03 · **Class:** cost judgment · **Status:** settled at S0 (owner, 19 Sep 2026)

**Decision.** `fn digest<H: Hasher>(&self) -> Result<Digest>`. §2.2 is amended (v0.1.4).

**Ground.** The published signature took no hasher, so it would have had to pick one implicitly, which D-20 forbids. A type parameter names the hasher at each call site and keeps the method where §2.2 puts it.

**Rejected.** A free function taking both, which moves the method out of the trait for nothing; a hasher chosen by feature, which is the implicit choice D-20 rules out.

**Revisit if.** A caller needs `dyn Preimage`. A trait with a generic method has no object form, though `write_preimage` keeps the `dyn` sink the spec names.

## D-33 · `PreimageSink` is a fixed-capacity buffer

**Date:** 19 Sep 2026 · **Unit:** E-03 · **Class:** cost judgment · **Status:** settled at S0 (owner, 19 Sep 2026)

**Decision.** `PreimageSink` has one method, `write(&mut self, bytes: &[u8]) -> Result<()>`. The sink this crate provides collects bytes in a fixed buffer of `MAX_PREIMAGE_LEN`, which is 256, and returns `0x0C` if a preimage would exceed it. `digest` hashes the collected bytes in one call. §2.2 is amended (v0.1.4).

**Ground.** The `Hasher` of D-05 takes its input as a list of slices in one call, because that is what `sol_keccak256` takes; there is no incremental hash on-chain, so a preimage has to be collected before it is hashed. §2.5's disclosure package carries those same bytes. The largest preimage in schema 1 is the 161-byte leaf, and a test holds every writer below the cap.

**Rejected.** A sink collecting slices rather than bytes, which saves a 161-byte copy at the cost of lifetimes through `dyn`; an incremental hasher, which the on-chain syscall does not offer.

**Revisit if.** A schema-1 preimage approaches 256 bytes, or a caller needs to hash something larger than a record.

## D-34 · Borsh is a test oracle, not a dependency

**Date:** 19 Sep 2026 · **Unit:** E-03 · **Class:** cost judgment · **Status:** settled at S0 (owner, 19 Sep 2026)

**Decision.** The writers are hand-written and `certimining-core` takes no Borsh dependency in the shipped path. `borsh` is a test-only dependency, and KAT-03 asserts that each writer's bytes equal Borsh's encoding of the same fields. Where the two disagree, INV-ENC-04's `u16` prefix governs, which §1.2 now states (v0.1.4).

**Ground.** INV-ENC-02 names Borsh, INV-ENC-04 names a `u16` length prefix, and Borsh frames a byte string with a `u32`, so the rules disagree exactly where E-02 already shipped the `u16` form under §1.3. Keeping Borsh out of the digest path leaves no serialization framework or derive macro in the on-chain build, and the agreement between the two is proven rather than assumed.

**Rejected.** Deriving the preimages with Borsh, which needs a carve-out for the tenure's prefix in any case.

**Revisit if.** A params struct needs a type whose Borsh form is not a fixed-width scalar or a fixed-size array, such as an enum or an option, or E-11's verifier disagrees on any vector.

## D-35 · Where KAT-03's fixtures come from

**Date:** 19 Sep 2026 · **Unit:** E-03 · **Class:** cost judgment · **Status:** settled at S0 (owner, 19 Sep 2026)

**Decision.** In E-03, KAT-03 builds its expected bytes inside the test from the spec's field order, with each tag written as a literal. The committed fixtures under `vectors/`, with `MANIFEST.sha256`, arrive with the generator at E-05, and KAT-03 then reads them from there. Issue #3 records that its KAT-03 is proven against test-built bytes rather than committed files.

**Ground.** §4.2 forbids hand-authored vectors and E-05 owns the generator, so committing fixtures now would either pre-empt that contract or place hand-made bytes under `vectors/`.

**Revisit if.** E-05 slips behind E-04, which would leave KAT-03 without committed fixtures for longer than one unit.

## D-36 · Reading a tag

**Date:** 19 Sep 2026 · **Unit:** E-03 · **Class:** cost judgment · **Status:** settled at S0 (owner, 19 Sep 2026)

**Decision.** The tag reader returns `0x05` when fewer than eight bytes are present, and `0x0B` when eight bytes are present but are not the expected tag (V-N-09, V-N-18).

**Ground.** V-N-18 fixes `0x05` for a truncated buffer, and `0x0B` is `DomainTagMismatch`, which is exactly the second case. Neither path panics.

**Revisit if.** A caller has to tell a short buffer from a wrong tag in a context where `0x05` is ambiguous.

## D-37 · The QP signature covers the leaf preimage, not the digest

**Date:** 21 Sep 2026 · **Unit:** E-04 · **Class:** security necessity · **Status:** settled at S0 (owner, 21 Sep 2026)

**Decision.** `σ` covers the 161-byte leaf preimage. §1.3's condition (c) is amended to say so (v0.1.5).

**Ground.** The spec contradicted itself. Condition (c) passed `leafₙ₊₁`, the digest, while INV-ENC-03 says signatures are over Borsh canonical bytes and V-N-05 exists to reject a signature over any other encoding. §2.5's disclosure package carries `preimage_borsh` precisely so a verifier can recompute those bytes and check the signature against them.

**Rejected.** Signing the digest, which would verify against bytes no artifact carries and would put E-11's verifier on a different rule from the engine.

**Revisit if.** A QP's signing hardware can only sign a 32-byte value. That is a new schema version under INV-FWD-01, never an edit.

## D-38 · Ed25519 verification is a named trait with no on-chain implementation

**Date:** 21 Sep 2026 · **Unit:** E-04 · **Class:** security necessity · **Status:** settled at S0 (owner, 21 Sep 2026)

**Decision.** A `Verifier` trait, named by the caller exactly as the hasher is (D-20), with one implementation behind `feature = "native"`. The Solana build carries none. §2.2 is amended (v0.1.5).

**Ground.** INV-PRIM-02 keeps signature checks out of the program. A feature-gated implementation makes that true by construction rather than by review, and keeps signature code out of the on-chain binary.

**Rejected.** An unconditional dependency, which would put verification code on-chain against INV-PRIM-02; verification left entirely to the caller, which would leave V-N-04, V-N-05 and V-N-06 with no path through the engine.

**Revisit if.** A deployment needs on-chain verification. That changes INV-PRIM-02 and is a spec decision, not a build flag.

## D-39 · Ed25519 crate

**Date:** 21 Sep 2026 · **Unit:** E-04 · **Class:** cost judgment · **Status:** settled at S0 (owner, 21 Sep 2026); version confirmed at S1

**Decision.** `ed25519-dalek`, behind `feature = "native"`, with default features off. Tests sign with fixed secret keys, so no random number generator enters the build. The exact version is recorded at S1, and if the Solana crates already resolve one, that line is reused rather than adding a second.

**Rejected.** `ed25519-compact`, which is smaller but far less used and less reviewed.

**Revisit if.** An advisory lands on it, which is D-18's process, or the on-chain build ever needs verification (D-38).

## D-40 · What a record input holds

**Date:** 21 Sep 2026 · **Unit:** E-04 · **Class:** cost judgment · **Status:** settled at S0 (owner, 21 Sep 2026)

**Decision.** `RecordLeafInput` carries the leaf fields other than `c`, which the chain holds, plus `prev_head`, an optional signature, an optional expected QP key, `payload_uri` of at most 128 bytes, and `ext_commitment`, the §2.6 hook, which is always absent in v0.1 and never hashed. §2.2 is amended with the struct (v0.1.5).

**Ground.** Three signatures named the type and nothing defined it, which S0 forbids guessing. §2.6 already promises `ext_commitment`, and adding it later would change a struct every caller builds.

**Revisit if.** TCU-03 needs the hook to carry something the field's shape cannot hold.

## D-41 · Where `0x06`, `0x07` and `0x08` divide

**Date:** 21 Sep 2026 · **Unit:** E-04 · **Class:** cost judgment · **Status:** settled at S0 (owner, 21 Sep 2026)

**Decision.** An absent signature is `0x06`. A signature that fails under the record's own `qp_key` is `0x07`. When the record carries an expected QP key and it differs from `qp_key`, the transition returns `0x08` before any verification runs. §1.3 is amended (v0.1.5).

**Ground.** A signature made by the wrong key simply fails to verify, so nothing inside one record distinguishes V-N-06 from V-N-05. The expected key puts the question of which QP was authorized where the caller can answer it, and gives `0x08` a real path rather than leaving a documented code dead.

**Revisit if.** A deployment carries a registry of authorized QP keys, which would move the comparison inside the engine.

## D-42 · When `CATEGORY_DOWNGRADE` fires

**Date:** 21 Sep 2026 · **Unit:** E-04 · **Class:** owner's domain ruling · **Status:** settled at S0 (owner, 21 Sep 2026)

**Decision.** Flag bit 1 is set when the record's category is lower than the previous record's category in the same chain, and never on the first record. §1.3 is amended (v0.1.5).

**Ground.** The spec named the bit and never said what set it. Comparing against the previous record is the rule a reader can check by eye against two filings.

**Limitation.** Categories 0 to 2 are resource confidence levels and 3 to 4 are reserve levels, so a return from Probable to Measured sets the bit, which is the case worth noticing, while a conversion from Measured to Probable does not. Like bit 0 it is an observation and never rejects (INV-STATE-06a).

**Revisit if.** A working QP says the numeric ladder misreads their practice, or the bit fires on a large share of real filings, which would make it noise. The same reopen conditions as D-01.

## D-43 · What "well-formed" means for `payload_uri`

**Date:** 21 Sep 2026 · **Unit:** E-04 · **Class:** security necessity in shape, cost judgment in detail · **Status:** settled at S0 (owner, 21 Sep 2026)

**Decision.** One to 128 bytes, printable ASCII only, beginning with `ipfs://`, `https://` or `ar://`, with at least one byte after the scheme and no whitespace or control byte. Nothing further is parsed. §1.3 is amended (v0.1.5).

**Ground.** Condition (f) said "well-formed" and left it undefined, while V-N-03 expects a 129-byte value, a non-ASCII value and an unknown scheme each to return `0x05`. The engine resolves no URI, so every further parsing rule is a way to reject legitimate work.

**Revisit if.** A submitter needs a scheme outside the three, which is a spec change.

## D-44 · What the chain carries between records

**Date:** 21 Sep 2026 · **Unit:** E-04 · **Class:** cost judgment · **Status:** settled at S0 (owner, 21 Sep 2026)

**Decision.** `c`, the schema version, the head, the sequence number, the last effective date, whether any earlier record carried category 1 or 2, and the previous record's category. Fixed size, no allocation.

**Ground.** Both flag rules need history rather than just the head: bit 0 asks whether a resource record ever preceded, and bit 1 compares against the previous category. Two values answer both, and a growing history would not fit a `no_std` crate.

**Revisit if.** A later flag needs more of the chain's past than these two values carry.

## D-45 · KAT-02's vectors and their provenance

**Date:** 21 Sep 2026 · **Unit:** E-04 · **Class:** security necessity · **Status:** settled at S0 (owner, 21 Sep 2026)

**Decision.** RFC 8032 §7.1's vectors, taken from the RFC text at rfc-editor.org, vendored with a `PROVENANCE.md` recording the source, the retrieval date and the file's SHA-256, as D-10 requires of KAT-01. If the primary source does not cover the cases the tests need, the work stops and comes back rather than using a secondary source.

**Rejected.** Vectors from the crate's own test suite, which would test the crate against itself.

**Revisit if.** RFC 8032 is superseded.

## D-46 · The fixed digests V-P-02, V-P-03 and V-P-04 expect

**Date:** 21 Sep 2026 · **Unit:** E-04 · **Class:** cost judgment · **Status:** settled at S0 (owner, 21 Sep 2026)

**Decision.** E-04's tests prove the relationships: genesis is deterministic for a given `c` and schema version, a five-record chain recomputes from `h₂` forward to the same `h₅` (INV-STATE-02), and a flagged record has the same leaf digest as an unflagged one. The committed values under `vectors/`, with their manifest, arrive with the generator at E-05, under D-35.

**Ground.** §4.2 forbids hand-authored vectors and E-05 owns the generator.

**Revisit if.** E-05 slips behind E-06, leaving two units without committed vectors.

## D-47 · `apply` returns what the transition produced

**Date:** 21 Sep 2026 · **Unit:** E-04 · **Class:** owner's ruling, against my recommendation · **Status:** settled at S0 (owner, 21 Sep 2026)

**Decision.** `apply` returns `Applied { leaf, head, flags }`, marked `#[must_use]`, and there is no `flags` accessor. `head` and `seq` stay as accessors, because those are chain state. §2.2 is amended (v0.1.5).

**Ground (the owner's).** A `flags` accessor would return "the flags of the record just applied", so its answer would depend on call order: before an `apply`, after a refused one, or after a second one, it returns flags belonging to a different record, with nothing in the types to prevent it. It would also make the chain carry a value that is not chain state but a leftover from the last call, and that is the kind of fault that surfaces later as a disclosure package showing the wrong flag against the right record. One transition produces three outputs, so it returns the three together; a refused transition returns nothing, and there is no stale value to read. `#[must_use]` makes the compiler complain if a caller drops the leaf, which is the value the batching path depends on. The published signature was four days old with no implementers, so this was the cheapest moment to change it.

**Rejected.** Returning the leaf with a `flags` accessor, which I had recommended; returning the head, which duplicates `head()` and makes the caller hash the record twice to get the leaf.

**Revisit if.** A caller needs only one of the three values in a hot loop and the struct shows a measurable cost.

## D-48 · The first stage a record fails decides its code

**Date:** 21 Sep 2026 · **Unit:** E-04 · **Class:** cost judgment, with an interoperability argument · **Status:** settled at S9 round 1 (owner, 21 Sep 2026)

**Decision.** A record passes four stages, and the earliest one it fails returns its code: decode, then the schema gate, then conditions (a) to (f) in the order §1.3 lists them, then the commit. Condition (f) is rewritten to name what it covers, the category range and the payload URI. A buffer that fails to decode is refused at decode, because it has no fields to judge. §1.3 and §4.3 are amended, with V-N-23 for the precedence within stage 3 (v0.1.6).

**Ground.** The implementation checked field shapes before condition (a), so a record with both a wrong head and a broken URI returned `0x05` where §1.3's order gives `0x03`, and the documentation claimed an order the code did not follow. The list in §1.3 is the published contract, E-11 re-implements from it, and V-P-08 compares the two implementations' accept and reject behaviour, so a precedence difference is exactly the kind of divergence that check exists to catch.

**Cost.** A record with a malformed field is hashed and its signature checked before the cheap range check refuses it. The work is bounded, at 161 fixed bytes, and no state moves either way.

**Revisit if.** A profile shows the ordering costs something real on a path that matters, which would be a spec change rather than a reordering in code.

## D-49 · A record carrying the extension hook is refused at the schema gate

**Date:** 21 Sep 2026 · **Unit:** E-04 · **Class:** security necessity · **Status:** settled at S9 round 1 (owner, 21 Sep 2026)

**Decision.** A record whose `ext_commitment` is set returns `0x0F`, judged at the schema gate before condition (a), not among the field checks of (f). §1.3 and §4.3 are amended, with V-N-24 (v0.1.6).

**Ground.** Under INV-FWD-01 any extension arrives as a new schema version, so a record carrying an `ext_commitment` is asking for schema 2, which this engine does not implement. That is what `0x0F` means, and it is why the check belongs with the schema version rather than with the shape of a field: the field is well formed, and the schema it implies is the part this engine cannot honour. Accepting the record with the field dropped would leave the caller believing an extension had been committed when nothing was, which surfaces only when someone relies on it.

**Rejected.** Ignoring the field, which is the literal reading of "always absent, never hashed" and the smallest change, but moves the risk onto every later caller. Returning `0x05`, which would describe the record as malformed when it is not.

**Revisit if.** TCU-03 lands and schema 2 exists, at which point the gate admits it rather than refusing it.

## D-50 · Clippy runs in every feature set

**Date:** 22 Sep 2026 · **Unit:** E-05 · **Class:** security necessity · **Status:** settled at S0 (owner, 22 Sep 2026)

**Decision.** The `checks` group runs `cargo clippy --workspace --all-targets -- -D warnings` once per feature set, matching the four `cargo test` runs: no default features, default, `solana` alone, and all features.

**Ground.** Code behind a feature gate is only linted when that feature is compiled, so two of the four builds were never linted. E-04 proved the gap with a live example: unused imports sat in the two builds without `native` while clippy, running only on the default and all-features builds, reported nothing. The bare-metal `no_std` build that D-14 made load-bearing is exactly where an unlinted warning or a dead path can hide.

**Cost.** Roughly twenty seconds per CI run.

**Revisit if.** The workspace grows enough that four lint passes dominate the group's time, which would be a scheduling change rather than a coverage one.

## D-51 · The generator emits every vector whose inputs exist, positive and negative

**Date:** 22 Sep 2026 · **Unit:** E-05 · **Class:** security necessity · **Status:** settled at S0 (owner, 22 Sep 2026)

**Decision.** `gen-vectors` emits one file per vector whose inputs exist at the time it runs, on both sides of the contract. Today that is the positive vectors V-P-01, V-P-02, V-P-03, V-P-04, V-P-09 and V-P-11, the negative vectors E-04 implements — V-N-01 to V-N-08, V-N-13, V-N-20, V-N-21 — and the two precedence vectors V-N-23 and V-N-24. A negative vector's expected output is its error code. KAT-03's Borsh fixtures are emitted here too, replacing the bytes E-03's test builds for itself (D-35). Nothing whose inputs belong to a later unit is emitted, and each later unit adds its own; the manifest lists exactly the files present.

**Ground (the owner's).** The committed vector set is what E-11's TypeScript verifier checks itself against, and agreeing on what to accept is only half the contract: the verifier has to refuse the same records with the same codes. That matters most for V-N-23 and V-N-24, which exist so the two implementations must agree on *precedence* rather than only on individual codes. A vector absent from E-05's output is one nothing downstream ever tests.

**Rejected.** Positives only, which was my proposal. Placeholder files for vectors whose inputs do not exist, which CI cannot tell from real ones.

**Revisit if.** A later unit changes an error code, which S2 forbids: a new condition takes a new code.

## D-52 · The vector format, and how 64-bit integers are written

**Date:** 22 Sep 2026 · **Unit:** E-05 · **Class:** security necessity · **Status:** settled at S0 (owner, 22 Sep 2026)

**Decision.** One JSON file per vector id. Byte strings are lowercase hex with a `0x` prefix, as §2.5 renders them. `u64` and `i64` values are written as decimal strings.

**Ground.** E-11's verifier is JavaScript, where a JSON number is a double, so any value above 2^53 reads back wrong. V-N-20 turns on `u64::MAX` exactly, and a vector that cannot express it cannot test it.

**Rejected.** Integers as JSON numbers, which reads more naturally and fails silently at the top of the range.

**Revisit if.** The verifier gains a JSON parser with exact integers, which would make this a preference rather than a requirement.

## D-53 · What makes regeneration deterministic

**Date:** 22 Sep 2026 · **Unit:** E-05 · **Class:** security necessity · **Status:** settled at S0 (owner, 22 Sep 2026)

**Decision.** Keys sorted, two-space indentation, LF endings, a trailing newline, and nothing environmental in any file: no timestamps, no toolchain versions, no paths, no iteration order that depends on a hash map. `MANIFEST.sha256` holds `sha256` lines sorted by path.

**Ground.** The unit's own acceptance criterion is that regeneration is deterministic across two machines. Anything environmental in a file guarantees two machines disagree, and a manifest over unstable files proves nothing.

**Revisit if.** A vector needs a value that cannot be made reproducible, which would be a decision about that vector rather than about the format.

## D-54 · Where `xtask` lives

**Date:** 22 Sep 2026 · **Unit:** E-05 · **Class:** cost judgment · **Status:** settled at S0 (owner, 22 Sep 2026)

**Decision.** A new workspace member, `xtask/`, with a repository-level `.cargo/config.toml` aliasing `xtask` so that `cargo xtask gen-vectors` is the command §3 names. `default-members` is unchanged, so a plain build and the bare-metal builds still compile `certimining-core` alone.

**Ground.** D-04 reserved `xtask/` for this, and the alias is what the specification's command line assumes. The crate is host-only and uses `std`; keeping it out of `default-members` keeps it away from the `no_std` proof.

**Revisit if.** The tool grows enough to deserve its own binary name.

## D-55 · Where the vectors' inputs come from

**Date:** 22 Sep 2026 · **Unit:** E-05 · **Class:** security necessity · **Status:** settled at S0 (owner, 22 Sep 2026)

**Decision.** The specification's own strings for V-P-01, and RFC 8032 §7.1's published test key wherever a signature is needed. Each vector file names that key for what it is, a specification test key. No generated keys and no random values anywhere in the set.

**Ground.** The published key is deterministic by construction, and its private half is public, so anyone can reproduce a signature over any vector. A generated key committed to a public repository is indistinguishable from a real one to a later reader.

**Owner's condition (22 Sep 2026).** The same labelling applies wherever the key is shown in the demo, not only inside the vector files: nothing may read as a real qualified person's identity. Recorded as an acceptance criterion on issue #14.

**Revisit if.** A vector needs a signature the published key cannot produce.

## D-56 · What CI checks about the vectors

**Date:** 22 Sep 2026 · **Unit:** E-05 · **Class:** security necessity · **Status:** settled at S0 (owner, 22 Sep 2026)

**Decision.** Both checks run: the manifest is verified against the committed files, and the generator is re-run into a temporary directory and its output compared byte for byte with what is committed.

**Ground.** The manifest alone passes when someone edits a vector and updates the manifest to match. Only regeneration catches that, and "hand-editing a vector fails CI" is the unit's acceptance criterion.

**Revisit if.** Regeneration becomes slow enough to need its own job rather than a step.

## D-57 · JSON belongs to the tool, never to the engine

**Date:** 22 Sep 2026 · **Unit:** E-05 · **Class:** cost judgment · **Status:** settled at S0 (owner, 22 Sep 2026)

**Decision.** JSON belongs to `xtask` alone. In the build, `serde_json` 1.0.151 is its only direct dependency and `serde` 1.0.229 arrives transitively through it, both at the versions already in `Cargo.lock`. `certimining-core` takes neither, and E-03's test that reads the digest path's source for string formatting and JSON keeps passing. KAT-03's fixtures therefore land in plain text as well, so the core crate's tests read them without a JSON parser.

**Amended 22 Sep 2026.** The decision first named both crates as direct dependencies. Only `serde_json` is needed, so that is what the build has; the substance, that JSON stays in the tool and never reaches the engine, is unchanged.

**Ground.** INV-ENC-03 makes JSON a display format, never a source of truth, and issue #3's criterion keeps it out of the digest path. A generator is display.

**Rejected.** Writing JSON by hand, which avoids a dependency and invites quoting faults in the artifact two implementations compare themselves against.

## D-58 · Vectors carry preimages, not only digests

**Date:** 22 Sep 2026 · **Unit:** E-05 · **Class:** cost judgment · **Status:** settled at S0 (owner, 22 Sep 2026)

**Decision.** Every hashing step in a vector records both the preimage bytes and the digest they produce.

**Ground.** An independent implementation that disagrees needs to know whether it built the wrong bytes or hashed the right ones wrongly, and V-P-08 is exactly that comparison. The digests alone would leave every disagreement ambiguous.

**Cost.** Larger files: a leaf preimage is 161 bytes, so 322 characters of hex per record.

**Revisit if.** The set grows enough for file size to matter, which would argue for splitting rather than for dropping the preimages.

## D-59 · The PRF's input encoding

**Date:** 23 Sep 2026 · **Unit:** E-06 · **Class:** security necessity · **Status:** settled at S0 (owner, 23 Sep 2026)

**Decision.** In `PRF(k, x) = Keccak256(TAG_PRF ‖ k ‖ len(x) ‖ x)`, `len(x)` is a `u16` little-endian, as INV-ENC-04 requires of every length prefix in this system. The key is 32 bytes. The three inputs `x` carry their use code first and then one field: the epoch as a `u64` little-endian for `0x01`, the submission identifier's sixteen bytes for `0x02`, and the slot index as a `u16` little-endian for `0x03`. So `x` is 9, 17 and 3 bytes, and the three preimages are 51, 59 and 45 bytes.

**Ground.** §1.1 gave the construction and no widths. E-11's verifier is written from the specification and never reads this engine, so a width left unstated is a divergence that would not surface until V-P-08 compared the two.

**Rejected.** A `u32` prefix, which is Borsh's own framing for a byte string and is exactly what INV-ENC-04 overrides.

**Revisit if.** A fourth PRF use needs an input wider than the `u16` prefix can carry, which would be a decision about that use.

## D-60 · Slot assignment: reduction, order and probing

**Date:** 23 Sep 2026 · **Unit:** E-06 · **Class:** security necessity · **Status:** settled at S0 (owner, 23 Sep 2026)

**Decision.** Four rules, and one code assignment noted below.

1. **Reduction.** The PRF output is read as a little-endian integer, which INV-ENC-02 already requires of every integer here, and reduced modulo `C`. Because `C` is a power of two this is the low `H` bits, which lie in the digest's first two bytes.
2. **Order.** Real submissions are assigned in ascending order of submission identifier. One set of submissions therefore produces one tree, whatever order the caller supplies them in.
3. **Probing.** The probe steps upward by one slot and wraps at `C`, taking the first free slot it meets.
4. **Overflow.** More real submissions than `C` in one epoch is `0x12`, which is V-N-14.

**Ground.** Rule 2 is the load-bearing one. Under assignment in the caller's order, the same epoch built by the batcher and by an independent implementation can differ by iteration order alone, and V-P-08 compares those two byte for byte. Rule 1 is INV-ENC-02 applied rather than a new choice, written down because an implementation reading the digest as big-endian would produce a different tree from the same inputs.

**Owner's attention (23 Sep 2026).** Two submissions carrying the same identifier in one epoch return `0x05`. §2.1 offers no code for a malformed submission set, and INV-ERR-01's discipline forbids inventing one, so the generic malformed-input code carries it: the set is malformed, and `proof` could answer for neither of the two. This is the one judgement in this entry the owner has not ruled on. Overruling it changes one line of §1.4 and one test.

**Revisit if.** An epoch ever needs to hold two submissions under one identifier, which would be a change to §1.6's promise model rather than to the tree.

## D-61 · Where the tree lives

**Date:** 23 Sep 2026 · **Unit:** E-06 · **Class:** cost judgment · **Status:** settled at S0 (owner, 23 Sep 2026)

**Decision.** A new workspace member, `crates/certimining-log`, `no_std` with `alloc`, depending on `certimining-core`. It holds the epoch tree, the inclusion proof and the inclusion verifier, and E-07's batcher joins it. The PRF stays in `certimining-core` beside the other §1.2 tag writers, because it is a §1.1 primitive that allocates nothing. No new external crate enters the build: `heapless` 0.9.3 is already pinned and carries the proof's siblings, and nothing else is needed.

**Ground.** §2 already draws this line. A tree at `H = 16` holds 65,536 leaves, which `heapless` cannot carry, so the builder needs an allocator; keeping that out of `certimining-core` protects the bare-metal build D-14 made load-bearing. The log crate is built for `thumbv7em-none-eabihf` as well, so the option of verifying an inclusion proof in a constrained environment stays open and is tested rather than asserted.

**Rejected.** Putting the tree in `certimining-core`, which would bring an allocating builder into the crate whose `no_std` proof is a claim the submission makes.

**Revisit if.** The batcher at E-07 needs `std`, which would put the batcher in a third crate rather than move the tree.

## D-62 · What `BuiltEpoch` holds

**Date:** 23 Sep 2026 · **Unit:** E-06 · **Class:** security necessity · **Status:** settled at S0 (owner, 23 Sep 2026)

**Decision.** The epoch number, the height, the root, every slot's leaf digest, and the mapping from submission identifier to slot that proof generation needs. Nothing marks a slot as real or padding. Internal nodes are an implementation detail of the builder, not part of the contract.

**Ground.** §2.3 named the type and never defined it. A real-or-padding marker per slot would put the answer V-Z-02 is trying to guess inside the structure under test, where a later test could reach it by accident.

**Cost.** Proof generation reads the mapping, which does name the slots holding real leaves. That is inherent, because a proof is for a real leaf. V-Z-02's classifier is given a root and a leaf set and never a built epoch, which is a property of the test's signature rather than of its discipline.

**Revisit if.** A caller needs to know how full an epoch was, which is a volume signal and would need INV-TREE-04 revisited first.

## D-63 · How the epoch key is held in tests

**Date:** 23 Sep 2026 · **Unit:** E-06 · **Class:** security necessity · **Status:** settled at S0 (owner, 23 Sep 2026)

**Decision.** A published specification test master key, `b"CMv1 TEST MASTER KEY, NOT SECRET"`, declared in the tests and in the generator and labelled for what it is. Every `k_e` in a test or a vector is derived from it through the real `0x01 ‖ e_le` path, and every vector that shows it carries the note D-55 requires.

**Ground.** INV-TREE-05 keeps a real `k_e` unpublished, so a published test key is the only honest way to commit a tree vector at all. Deriving through the real path keeps `k_e = PRF(k_master, 0x01 ‖ e_le)` under test rather than bypassed, and a key whose bytes spell out what it is cannot be mistaken for a real one by a later reader.

**Also settled.** `build`'s `key` argument is `k_master`, not `k_e`. The tree already knows which epoch it is for, so deriving inside `build` puts INV-TREE-05's derivation on the only path that produces a tree and makes reusing one epoch's key for another impossible.

**Rejected.** Handing `k_e` to the builder directly, which leaves the derivation untested. Zero bytes, which read as an uninitialised value rather than a deliberate one.

**Revisit if.** A test needs two master keys, which would name the second the same way.

## D-64 · The proof's shape and how it is checked

**Date:** 23 Sep 2026 · **Unit:** E-06 · **Class:** cost judgment · **Status:** settled at S0 (owner, 23 Sep 2026)

**Decision.** Siblings run from the leaf upward, exactly `height` of them, and the path is taken from `slot_index` with bit 0 first: a clear bit means the leaf is the left child at that level. `verify` checks everything a proof can be checked for on its own — `4 ≤ height ≤ 16`, one sibling per level, `slot_index < 2^height`, and the root recomputed from the leaf — and returns `0x13` on any failure. The configured height is a second input rather than a field, so a caller holding its log's `H` calls `verify_for_height`, where a proof whose `height` disagrees is `0x13` before any hashing. That is V-N-16b. Both functions are pure, which is INV-IFACE-01.

**Also settled.** `verify` takes the chain leaf `leafₙ` and applies `TAG_MTL0` itself, rather than taking the tagged leaf the tree holds. A caller cannot then omit the tag, which is the same reason E-03 keeps every preimage out of call sites.

**Ground.** Leaf-first ordering is the convention E-11 will be written against, and §1.8's "exactly `H` siblings" reads in that direction. The height check needs an input `verify` does not have, and adding a log handle to the verifier would break the offline property INV-IFACE-01 exists to protect.

**Owner's attention (23 Sep 2026).** Asking an epoch for a proof of a submission it does not hold returns `0x13`. There is no such inclusion proof, so the proof-path code carries it. This is the second judgement of the two noted in this unit.

**Revisit if.** A caller needs to distinguish "not in this epoch" from "proof does not verify", which would need a new code under §2.1's rule that new conditions take new numbers.

## D-65 · The privacy tests are committed before the implementation

**Date:** 23 Sep 2026 · **Unit:** E-06 · **Class:** security necessity · **Status:** settled at S0 (owner, 23 Sep 2026)

**Decision.** Two commits. The first carries the privacy tests and a stub whose every entry point refuses with one fixed error under a loud marker, so the tests fail and CI is red on that commit by design. The second carries the implementation and turns them green. The unit's record on the issue links both commit identifiers and says the red run was intended.

**Ground.** Issue #6 requires the privacy tests before the implementation, and S4 requires it of anything touching the epoch tree. A claim about commit order that cannot be checked is not evidence; a branch whose history shows the order is. One red run is the price of making the sequence verifiable.

**Cost.** The branch holds one commit that does not build green. The pull request's head is green, and CI on the merge commit runs the whole suite.

**Revisit if.** Nothing. This is how every unit touching the tree or the on-chain surface is built from here.

## D-66 · What the privacy thresholds mean

**Date:** 23 Sep 2026 · **Unit:** E-06 · **Class:** security necessity · **Status:** settled at S0 (owner, 23 Sep 2026, with the classifier specified at the owner's instruction)

**Decision.** V-Z-02 and V-Z-04 get stated statistics and a stated adversary, written into §4.4 where a reader can judge them.

**V-Z-02's classifier** is given an epoch's root and all `C` leaf digests in slot order, no key, and unlimited compute. It runs, at minimum, per-position byte statistics across the leaf set and a structural-regularity check over each digest: deviation from the set's per-position byte mean, population count, zero-byte count, leading-zero bits, longest run of equal bytes, distinct byte values, a chi-squared statistic over nibbles, and Hamming distance to the adjacent slots. Every feature is scored on its own and the combined score is scored as well, and each must pass.

**V-Z-02's statistic** is a distinguishing game rather than raw accuracy: each trial presents one real and one padding leaf from a freshly built epoch and the classifier names the real one. Successes must not leave a two-sided binomial test at α = 0.001 against p = 1/2. Raw accuracy over an epoch holding one real leaf and 255 padding leaves is 255/256 for a classifier that answers "padding" every time and learns nothing, so accuracy alone cannot carry this test; the pair game removes the base rate. A balanced epoch, `C/2` real, is classified leaf by leaf as a second form, where accuracy is meaningful and the same band applies.

**V-Z-04's bound** is a number. Pearson correlation of slot index against submission order, against issuer index and against time within epoch must satisfy `|r| < 0.05` at the sample size CI runs, and `|r| < 0.02` over the full 10,000 epochs. Both are conservative: at CI's sample size the standard error is about 0.006, so the bound is eight standard errors out, and a real positional leak produces a correlation near 1.

**What runs where.** CI runs a reduced sample with the power to catch a leak: 200 epochs for V-Z-02 and 400 for V-Z-04. The full 10,000-epoch run of V-Z-04 is a release gate, ignored by default, run before submission and recorded on issue #16. A post-deadline issue against milestone 5 strengthens the classifier.

**Measured after the fact (23 Sep 2026).** The full run costs 1.96 seconds in a release build and 140.91 seconds in the debug build CI uses, rather than the hours the wording implied when this was settled. It stays a release gate under this decision; whether to promote it into CI at that price is the owner's to take, and the numbers are in the unit's record.

**Ground.** A release blocker whose pass condition is settled after the implementation's numbers are visible is a test written to pass. Naming the adversary in the specification lets a reader judge how hard the test tries, which an accuracy figure alone does not.

**Cost.** About six seconds in the `checks` group, measured rather than estimated: the three tests
run in 5.6 to 5.9 seconds on the reference laptop in a debug build.

**Revisit if.** The classifier is strengthened post-deadline and the band needs restating for a larger sample.
