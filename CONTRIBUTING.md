# Contributing

## Vectors are generated, never edited

Everything under `vectors/` is output. It is produced by

```sh
cargo xtask gen-vectors
```

**The generator never deletes.** It writes into a directory it creates, and refuses one that already
holds files. To replace a committed set you remove it yourself first, which keeps the deletion a
deliberate act:

```sh
rm -rf vectors && cargo xtask gen-vectors
```

Then commit what it wrote, including `vectors/MANIFEST.sha256`. Each manifest line carries the
SHA-256, the file mode and the name, so a vector that was edited and one that became executable or
unreadable both fail the check.

**Editing a file under `vectors/` by hand will fail CI.** Two checks stand in the way, and they
catch different mistakes:

- `shasum -a 256 -c MANIFEST.sha256` catches an edited vector.
- Regenerating into a temporary directory and comparing catches an edit whose manifest was updated
  to match, and a generator that has drifted from the output committed beside it.

Both run in the `vectors` group: `scripts/ci.sh vectors`.

## What a vector contains

Byte strings are lowercase hex with a `0x` prefix. **Integers are decimal strings**, because the
TypeScript verifier of E-11 reads these files and a JSON number there is a double, which would
misread any value above 2^53. Keys are sorted, indentation is two spaces, and nothing environmental
appears in a file: no timestamps, no toolchain versions, no paths. That is what makes regeneration
identical on another machine.

Every hashing step records its preimage as well as its digest, so an implementation that disagrees
can tell whether it built the wrong bytes or hashed the right ones wrongly.

**The epoch-tree vectors carry the whole tree where they can.** V-P-05 records every leaf of its
epoch and every hashing step behind its one proof: the epoch key, the slot seed, the leaf as it enters
the tree, a padding leaf beside it, and each node up the path. V-P-06 records every leaf, the whole
assignment and three proofs in full, and verifies all 255 while it is generated. Above 256 slots the
leaf set is left out and the root, the assignment and the proofs are kept, which is why V-P-06b's
`H = 12` half is shorter than its `H = 4` half. The master key in these files is a specification test
key whose bytes spell out what it is; a real `k_master` never appears in this repository.

**The promise vectors carry both halves of what §1.6 signs.** V-P-10 records the SPI preimage and the
digest, because the signature covers the digest and an implementation that signed the preimage instead
would look correct until it met this file. It also records one promise accepted at the last epoch the
merge delay allows and the same proof refused one epoch later, which is the rebuttal window. V-N-14 is
answered by two layers and says which: the tree returns `0x12`, and the batcher queues instead. The
batcher's key in these files is RFC 8032 §7.1's published test key, and no real batcher key exists
anywhere here, because the engine has no place to keep one.

**Vector identifiers come from §4.3 and §4.2, never from this repository.** Where the specification
gives one identifier to several inputs, such as V-N-02's gap and replay, the file carries them as
cases under that one identifier. A new identifier is declared in the specification first, as V-N-25
was, and never invented here as a suffix.

**The generator holds its own copy of the specification's values.** `xtask/src/spec.rs` carries the
domain tags, the canonical form of V-P-01, every preimage layout and §1.8's limits, transcribed by
hand and read from nothing. The generator checks the engine against them and stops if they disagree,
so an engine that has drifted cannot write its drift into the committed set.

**Two kinds of expectation, with different authority.** A positive vector's digests lock the
engine's output: no document can state a digest, and what stands behind them is KAT-01 and the
independent re-implementation at E-11. A negative vector's error code, and every assertion §4.2
makes — that two spellings agree, that a recomputed head matches, that a flag does not move a digest
— come from the specification. The generator writes those from §4.3's table and §4.2's claims, runs
the engine, and **fails generation if the engine disagrees**. A generator that recorded whatever the
engine returned would enshrine an engine's mistake as the correct answer, and the TypeScript verifier
would then be obliged to reproduce it.

Where a signature is needed, the key is **RFC 8032 §7.1's published specification test key**, named
as such in every file that shows it. Its private half is public, so anyone can reproduce any
signature in the set. No generated key and no real key belongs in this repository.

## Running the checks

`scripts/ci.sh all` is the pipeline CI runs, verbatim. Individual groups:

| Group | What it does |
|---|---|
| `kat01-offchain`, `kat01-onchain` | Keccak-256 against the published vectors, off-chain then on the Solana runtime. A failure stops the build. |
| `kat02` | Ed25519 against RFC 8032 §7.1. |
| `vectors` | The manifest, and regeneration. |
| `checks` | Formatting, clippy and the tests, in each of the four feature sets, for both engine crates, and the bare-metal `no_std` builds. |
| `miri` | The engine crates under Miri. The statistical privacy tests and every tree above `H = 8` are ignored there and run in `checks` instead. Miri interprets a hash in about a tenth of a second, so a tree at `H = 12` costs minutes and one at `H = 16` costs hours, while the shorter trees execute the same code with a shorter loop. Miri is looking for undefined behaviour, not for arithmetic. |
| `bench-band` | §4.4a's wall-clock measures on this runner against `benches/BASELINE.toml`, failing past the band (D-132). Not §4.4a's wall-clock absolutes, which no longer exist (D-137): `scripts/ci.sh thresholds` measures those figures and reports them with the machine named, and is `#[ignore]`d and run before submission. An absent baseline entry fails and prints what it measured. |
| `deny` | Advisories, licences, sources and bans, over **two** graphs: the workspace, and `fuzz/`, which is its own Cargo workspace and therefore invisible to a root `cargo deny check` (`cargo deny list \| grep -c libfuzzer` answers 0). Both use the same `deny.toml`, so tooling is not held to a looser policy than shipped code. |
| `ts` | The independent TypeScript verifier of E-11: its supply-chain gate, its typecheck and build, and its run of every committed vector. `cargo deny` reads `Cargo.lock` and sees no npm package, so `scripts/ts-gate.sh` carries the same discipline for `ts/package-lock.json` — advisories at high or above, and a closed licence list in `ts/LICENCES.allow` (D-93). |

Clippy runs once per feature set, because code behind a feature gate is only linted when that
feature is compiled.

`thresholds` and `bench` are not in `all` either, and since D-137 the reason is the same for both:
**neither asserts a performance threshold.** Both can still fail a correctness control — `thresholds`
cross-checks the chain walk against the state machine, verifies a proof and pins its workload, and any
of those failing fails the run. `thresholds` measures §4.4a's wall-clock figures and names the machine;
`bench` reports the Criterion distributions behind them. §4.4a's wall-clock bounds were removed after two
machines matching its own description measured 7 ms and 17.6–19.5 ms, so there is nothing left there to
gate on. What gates is `bench-band`, which is in `all`, and the compute figures in `kat01-onchain`.
`docs/performance.md` says which mechanism covers each of §4.4a's rows.

`fuzz` is not in `all` and has no row above, because it is not part of the push pipeline: §4.5's five
targets run nightly in `.github/workflows/fuzz.yml`, and `scripts/ci.sh fuzz` is that job verbatim.
`docs/fuzzing.md` says what each target establishes and what its iteration count cost.

**Never change the working tree under a running verification, and that includes switching branches.**
The narrow version of this rule said only "never edit a script while it is running", and the narrow
version was not enough: on 2 Oct 2026 a `scripts/ci.sh all` run on one branch had the tree switched to
another beneath it, and reported `deny: exit 1` and `bench-band: exit 101` — the first because the other
branch's `deny.toml` lacked an exception while `fuzz/` sat untracked beside it, the second for a group
that branch does not define. The run had executed against two different trees and its summary looked
like an ordinary set of results. **A verification is only evidence about the tree that stood still for
it.** Finish the run, or use a second checkout.

The original and narrower case, which is the same failure in a smaller shape:

**Never edit a script while it is running.** Bash reads a script incrementally, so changing the file
under a live run shifts where it continues from. Editing `scripts/ci.sh` during a `scripts/ci.sh fuzz`
run on 1 Oct 2026 made the shell fall out of `fuzz()` and execute `kat01-onchain`, `checks` and `miri`
in sequence — groups nobody had asked for, in a run whose output was being read as a measurement.
Nothing was corrupted that time. The failure mode is that a run reports a result for work other than
the work requested, which is indistinguishable from a passing run. Wait for the run, or branch the
edit; a copy of the script elsewhere is not a workaround, because its first act is
`cd "$(dirname "$0")/.."` and from another directory that resolves outside the repository.

## Editing the specification

**Every scripted edit to `docs/TCU-02_CertiMining_Anchored_Log_v0.1.md` asserts that it matched.**
A `str.replace` whose search string has gone stale changes nothing and reports nothing, so the file
keeps its old text while the commit message describes the new one. That happened: two edits meant to
move the version line matched nothing, the line sat at `0.1.15` through four commits, and the
document carried §1.4's epoch clock, §2.4's `start_epoch`, INV-ANCH-02's start clause and V-N-26
without saying so. The content was right every time; the claim was only ever in the commit messages.

**Assert the match, write, then read the file back.** Asserting before the write is necessary and not
sufficient, which three incidents have now shown. Twice the assertion was there and the text still did
not move; the third time a script made four substitutions, asserted on the fifth, raised — and
discarded all four, because the single `write_text` came after them. A run that ends in an exception
has written nothing, and an assertion that guards a write it never reaches guards nothing.

So:

1. **Assert the match before replacing.** In Python, `assert old in s` before `s.replace(old, new, 1)`.
2. **Write after every substitution, not once at the end.** A later mismatch then cannot silently
   discard an earlier success.
3. **Read the file back and confirm the new text is in it.** `grep -c` on the result, not the exit
   code of the tool that was supposed to produce it.
4. **For anything a viewer sees, check the artifact as served**, not the file on disk — load the page
   and look for the sentence. The fourth step is what caught the discarded edits; it is a rule rather
   than a reflex because the first three had all passed.

With
`sed -i`, check the file afterwards rather than trusting the exit code, which is zero for a pattern
that matched nothing. The same holds for `docs/DECISIONS.md` and for any file whose text is the
record rather than the code.

**Branches do not number the specification (D-103).** Three branches amending one document cannot
number linearly, and two of them both claimed `v0.1.18`. A branch's version line reads
`<what main holds> plus unmerged amendments on this branch`, and its in-text notes say "on this
branch, unmerged" or "before this branch". One spec-only pull request then assigns the next number to
everything merged since.

**That pass has been run once, and the markers are a debt until it is.** `main` carried twelve of
them — eleven in-text notes and the version line — for as long as it took anyone to read the document
as a reader would, which is what E-16's claim sweep eventually did. On `main` each one says a part of
the document is not in the repository, which is false there and misleading in the artifact a reader
meets first. **v0.2.0** consolidated all of them: it is the number for everything merged since
v0.1.14, and the branch-local numbers 0.1.15 to 0.1.19 were never released. So: a branch may carry
markers, `main` may not, and the consolidating pull request is owed the moment a branch with markers
merges — not at some later tidy-up.

## Rewriting a stacked branch

Units stack: E-14 sits on E-11, E-15 sat on E-10. When the branch underneath moves, the one above is
rebased, and a rebase means a force push. The question came up at every rebase, so it is settled here.

**`--force-with-lease` is allowed on a stacked branch when no review round is open against its posted
head and nobody else commits to it. Never on a branch whose head is under review** (owner, 28 Sep
2026).

The reason for the second half is what a review round is: a reviewer is reading a specific commit, and
moving the ground under them wastes the round and produces findings against text that no longer
exists. That is the same failure as reviewing a branch mid-rebase, which is why a head is posted and
then left alone until the charter comes back.

`--force-with-lease` rather than `--force`, always: it refuses when the remote has moved since the
last fetch, which is exactly the case where somebody else has committed and the first condition no
longer holds.

A branch nobody has reviewed and nobody else touches is yours to rewrite. `scripts/merge-ready.sh`
refuses a branch that is behind its base, so the rebase is not optional — the choice is when, not
whether.

## No live value in a synthetic artifact

**No value from a live deployment appears in any synthetic artifact, fixture, or page constant, ever.**
Not a program id, not an address, not a published root, not a receipt digest, not a transaction
signature. A synthetic artifact that carries one is asserting a provenance it does not have, and a
reader who recognises the value is the person it misleads.

This rule exists because E-14's demo fixture carried the announced log's real transaction signature and
slot in its `anchor` block, beside an epoch root built for the demo and published nowhere — and the
signature and the slot came from two different publications. It was written that way because real
values looked more concrete. **Fabricated provenance is the worst class of defect this repository can
hold, and it is the kind an author cannot see in their own work**, which is what an independent review
round is for.

The distinction to draw is about subject, not about intent. An artifact whose subject *is* the
announced deployment may name it — V-P-12 checks §2.4's derivation against that deployment and a vector
that could not name it would check nothing. An artifact that merely looked better for carrying a piece
of one may not.

**Where it is enforced.** `LIVE-VALUES.txt` lists what the deployment holds and `LIVE-VALUES.exempt`
records the pairs that are legitimate, with a reason each. `cargo xtask gen-vectors` and
`cargo xtask gen-demo` scan every file before writing a byte and fail on an unrecorded match, and an
exemption naming a value the list does not hold fails too rather than sitting dead. The list reaches
32-byte values, base58 identifiers, and decimals of six digits or more — the last so that a publication
slot or a unix timestamp is covered, which a review found they were not. Block heights are still out of
scope.

**And two classes cannot be enforced at all, which changes what the rule asks of you.** A PDA bump is
0-255 and an epoch is a five-digit day index; listing either would fire on unrelated text wherever it
appeared. So for short values the rule is checked by a reader, and it reads (owner, 4 Oct 2026):

> A short live value may not appear in a synthetic artifact **unless the artifact's subject is the
> announced deployment**, and the use is recorded in `LIVE-VALUES.txt` by file, value and occurrence.

The exception is not a loophole; it is the same subject test as above, which V-P-12 needs and the demo's
epoch needs. What it forbids is the unrecorded use — a short live value sitting in an artifact because
it looked more concrete. The recorded uses are listed in `LIVE-VALUES.txt` beside the rule, and a short
live value you find that is not on that list is a finding. H-20 makes the matcher token-aware so these
can be listed and gated like the rest; when it lands, the carve-out and that list are withdrawn
together.

## Filing to Post-deadline hardening

A defect found before the submission deadline that is not going to be fixed before it goes to the
**Post-deadline hardening** milestone, and it goes there as an issue titled `H-nn · …`, numbered in
filing order. H-01 to H-17 exist. The number is part of the title rather than a label, so it appears
wherever the issue is linked, and a decision or a comment that defers something says which H it
deferred to — `docs/DECISIONS.md` and the unit records do that by linking the issue and naming it.

**What goes there, under the shipping posture:** a Medium or a Low from a review round, a defect whose
fix would ripple past the unit that found it, and a question that should not be decided quickly
because a deadline is not a reason to decide it at all (H-16 is one of those). **What does not:** a
High against code, which reopens its unit, and anything touching §4.4's privacy tests or a claim the
repository makes about itself. Those two do not bend.

An H issue states what was found, how it was found, and what would close it. A deferred defect with no
reproduction is a note, and a note is not a filing.

## A dependency no gate covers

Anchor B's receipts are created and upgraded by the **OpenTimestamps reference client**, pinned at
**v0.7.2**, LGPL-3.0, installed in a private virtual environment at
`~/.local/share/potash/ots-venv` and invoked as a process rather than linked (D-115). It is the only
implementation that both submits to calendars and upgrades once Bitcoin confirms.

`cargo deny` reads `Cargo.lock` and `scripts/ts-gate.sh` reads `ts/package-lock.json`. **Neither sees
this.** It is a third supply-chain surface, it is named here rather than left for a reader to notice,
and what mitigates it is not a gate: every receipt it produces is **parsed** by the
`opentimestamps` crate — the OpenTimestamps project's own Rust library, which cannot create a
receipt — before anything computes a digest over it, and this repository then checks the parsed
result: that the start digest is the root that was stamped, and that a Bitcoin attestation is present
rather than only a calendar's promise (`crates/certimining-client/src/ots.rs`, `verify_receipt`).

**Not "verified".** Checking the attestation against Bitcoin means recomputing the path to a block's
merkle root, which needs a header source this client does not have
(H-12, [#48](https://github.com/CertiMining/potash/issues/48)); the function's own documentation says a
forged attestation passes. That does not make the dependency safe, and it does not make a receipt
proven. It makes the artefact *parseable and partly checkable* by something that did not produce it.

## The privacy release gate

§4.4's V-Z-02, V-Z-03 and V-Z-04 are release blockers and run in `checks` at the sample sizes D-66
fixes. V-Z-04's full 10,000-epoch run takes about two seconds in a release build and two and a half
minutes in the debug build `checks` uses, so it is ignored by default and run before submission:

```sh
cargo test --release -p certimining-log -- --ignored
```

Its three correlations are recorded on issue #16. The bound there is 0.02, against 0.05 at the sample
CI runs.

## Miri's durations are not elapsed time

`scripts/ci.sh all` prints each group's `test result` lines under its exit code. For every group except
`miri` those durations are wall clock. Miri's are not.

Miri runs with host isolation by default, and its own README says clocks "are replaced by deterministic
'fake' implementations". `Instant::now()` inside a Miri run therefore reads a simulated clock, and
libtest reports that. Two consequences, both of which look like faults until you know the cause:

- **The figures repeat exactly.** The same tests report the same durations to the hundredth of a second
  across runs, machines and directories, because the clock is deterministic. Real timings never do
  that, which is how this was eventually noticed — after being seen and dismissed twice.
- **They sum to more than the group takes.** Measured directly with `/usr/bin/time -p`: nineteen test
  binaries reported 67.4 minutes between them while the group ran in 46.0, a ratio of 1.46. On
  GitHub's runner the same group takes 48m37s of real time, because real time depends on the machine
  and simulated time does not.

Nothing depends on them: a group's verdict comes from the command's exit status, not from these lines.
But this summary gets quoted as evidence, so it now says which numbers are measurements. If you want a
real figure for how long Miri takes, time the group from outside:

```sh
/usr/bin/time -p scripts/ci.sh miri
```

## The defect this repository keeps finding

Every independent review round so far has found at least one instance of a single defect, and it has
never once been found by running the suite. It is this:

> **An instrument that maps its own failed observation onto the value its acceptance predicate
> rewards.**

Not a wrong answer — a *non*-answer, converted into the right-looking one. The measurement does not
happen, and what the absence produces is indistinguishable from success. Every gate in this repository
is built to fail loudly, and this is the one way a gate stays silent while measuring nothing.

It is worth stating plainly because the shape is not obvious until you have seen it several times, and
because the suite cannot find it. These are the instances this repository's own review record names:

| What failed | What it reported |
|---|---|
| `pearson` over a constant series | `0.0` — the *best* possible answer for §4.4's bound |
| the same helper, in its other role, returning `None` | a release predicate that accepted `None` |
| a feature whose standard deviation is zero | `0.0` for every row, so every pair tied |
| ties, under a tie-break that alternates | exactly 50%, which is ideal indistinguishability |
| `assert_indistinguishable` with zero trials | the band `[0, 0]`, which zero successes sits inside |
| a pair of one leaf with itself | a tie, and so the ideal rate again |
| `saturating_sub` on an impossible slot reading | a delay of `0` |
| a benchmark that timed closures and discarded their results | `0.0000 ms`, comfortably inside the band |
| an expected value taken from the thing under test | both sides moved together, so the check held |
| a fixture size read from a mutable constant | a 16-leaf build published under a 256-leaf row name |
| a fixture pinned in one executable, built again in another | a false distribution, exit 0 |
| a `NaN` baseline | a `NaN` limit, and `now > NaN` is false |
| a `f64::MAX` baseline | an infinite limit, which nothing exceeds |
| nine feature columns that were nine copies of one byte | all nine "varied", and the control scored 1.0000 |

Several of those were introduced *by the fix for the one above it*. That is the characteristic
progression: the repair addresses the instance and leaves the class, because the class is a habit of
thought rather than a line of code.

**The test that finds it.** Break the thing the instrument watches, not the thing it reports, and
require the instrument to notice:

- Make the operation a no-op and keep its signature. Does the timing fall to zero and pass?
- Make the input degenerate — one value, zero rows, zero trials, a self-pair. Does the statistic come
  back as the ideal rather than as a refusal?
- Make the fixture a fraction of the size its label claims. Does the label change with it?
- Ask what the oracle is built from. If it is built from the subject, mutating the subject moves both
  and nothing fails.
- Ask what the control could be satisfied by other than the thing it claims to prove.

**A new assertion owes a demonstration that it can fail.** Not that it passes — a dead assertion passes
too. When you add one, break the property it guards, record the failure message in the commit, and
restore. Every fix in the table above carries that demonstration, and the ones that did not are why the
next round found the next instance.

**And the specific habit to distrust: a degenerate sample is a defect, not a result.** If the data
cannot answer the question, the honest output is a refusal naming what collapsed. It is never the value
that means "the property holds", however convenient the arithmetic makes that substitution look.

## Run before submission, because nothing else will

Two checks are `#[ignore]`d on purpose and will not run themselves. An ignored test that nobody is told
to run is an ignored test that never runs, so both belong on the submission checklist rather than in a
comment:

```sh
cargo test --release -p certimining-log -- --ignored   # V-Z-04's full 10,000-epoch run
scripts/ci.sh thresholds                               # §4.4a's wall-clock figures, to be read and recorded
```

The second **asserts no performance threshold** (D-137): §4.4a's wall-clock bounds were removed after two
machines matching its own description measured 7 ms and 17.6–19.5 ms. Its correctness controls still fail
loudly — the chain-walk cross-check, the proof verification, the pinned workload — but no figure it prints
can. It measures and reports with the machine named, so its output has to be read rather than trusted to a
green tick, which is exactly why it is on a checklist. The
compute figures are the ones asserted absolutely, in CI, and `bench-band` holds the runner to its own
previous numbers. `docs/performance.md` says
which mechanism covers each of §4.4a's rows, and `scripts/ci.sh fuzz` is the third thing CI does not
run on a push, for a different reason: it has its own nightly workflow.
## Anchoring the repository head

§3's E-16 requires the submitted commit to be timestamped on Bitcoin with its receipt committed.
`anchors/0001-0258f51.txt` was produced by hand in September and nothing recorded how, which left a
one-shot step on the submission commit with no runbook. It is a command now:

```sh
scripts/anchor-repo.sh                    # on a clean tree, at the commit being submitted
```

It refuses a dirty tree, because a manifest naming a commit that is not what is on disk is evidence of
nothing. It numbers itself from the anchors already present, writes the commit, the tree hash and the
digests of the documents a counterparty reads, and stamps the manifest against the OpenTimestamps
calendars.

**The receipt it writes is not the one to commit.** It carries calendar attestations only; Bitcoin
confirmation takes hours, the same budgeted wait D-112 describes for an epoch. Hours later:

```sh
ots upgrade anchors/NNNN-xxxxxxx.txt.ots
ots info anchors/NNNN-xxxxxxx.txt.ots | grep -i bitcoin    # it must name a block
```

Commit the upgraded receipt. The commit the manifest names is the parent of the commit that carries
it — the manifest cannot contain its own hash — so a reader checks out the named commit and recomputes
the tree from there.
