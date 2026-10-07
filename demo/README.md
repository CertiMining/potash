# The demo — three scenes

```bash
scripts/demo.sh
```

That installs the verifier's two dependencies from the committed lock file, compiles it for a
browser, checks the fixtures against their manifest, runs the demo's tests and serves the page on
`http://localhost:8730`. `PORT=…` moves it. Node 24 or later is the only requirement.

## What each scene is

**Scene 1 — the public view does not say how much you filed.** An epoch is a Merkle tree of fixed
height 8: 256 slots, always full, real submissions in pseudorandom slots under the epoch key and
padding in the rest. Move the control from 0 to 255 real records and watch the `CheckpointAccount`
and the `publish_checkpoint` instruction stay the same length, the same layout, and differ only
inside `root`. The trees are built in the browser as you move it.

**Scene 2 — a counterparty verifies offline.** The independent TypeScript verifier recomputes the
leaf from the signed bytes, checks the qualified person's signature over them, and walks the
inclusion proof to a root obtained separately. Every check it ran is listed, including the one that
does not say `pass`.

**Scene 3 — one byte moves and the log notices.** The same package with the low bit of
`payload_digest` flipped, in the signed preimage and in the hex displayed beside it, so the two
halves still agree and the signature is what refuses it. The epoch root is unchanged throughout.

## The status page

`http://localhost:8730/status.html`, served by the same command. Where the three scenes are offline
and synthetic on purpose, this one reads Solana devnet in your browser through the verifier this
repository ships: the last published epoch against your own UTC day index, and a row per epoch with
its root, its slot and whether anchor B has attached.

It is read-only. It holds no key, publishes nothing, and has no path to the batcher. It is **not an
operator console** — no alerting, no scheduling, no control — and the daily cycle is still run by
hand (D-117, [#49](https://github.com/CertiMining/potash/issues/49)), so a non-zero distance is a
person being late rather than a process that failed. The page says all of that on itself.

Every outlined region explains itself on hover, and **Take the tour** walks the five explanations in
order for a reader who skipped them. `demo/test/status.test.mjs` fails if a region has no
explanation or an explanation has no region, because a tour that silently skips what a newcomer is
looking at is worse than no tour.

The failure it is built around is the one a status page gets wrong: an unreachable endpoint renders
as an empty table, which reads exactly like a log that has published nothing. Those are opposite
facts, so a read that fails says so and the counts are cleared.

## What this is not

It is a demonstration, not a test, and the repository's tests are the authority for every property it
shows:

| Scene shows | The test that decides it |
|---|---|
| Record count moves no byte outside §4.4's closed list | `programs/certimining-checkpoint/tests/privacy.rs`, under LiteSVM against the real program |
| The verifier's checks and refusals | `ts/test/`, 79 tests and 52 mutations |
| The footprint layout matches §2.4 | `demo/test/footprint.test.mjs`, round-tripped through the verifier's own decoder |

Three limits are on screen rather than here, because a reader of the page is who needs them: the
count-hiding property is computational and rests on the batcher's key custody (RES-09, RES-03); a
package past `seq` 1 does not establish its own position in the chain; and Scene 3 shows detection,
not prevention, and says nothing about who altered the record.

## The build, and why there is no bundler

`ts/tsconfig.build.json` already emits browser-shaped ES modules with no Node API in them. The only
thing a browser cannot resolve is the three bare specifiers into `@noble/hashes` and `@noble/curves`,
and both packages are plain ES modules whose internal imports are relative — so the import map in
`index.html` maps two prefixes and the whole graph resolves. `scripts/demo.sh`'s build step is a copy.

That was D-124's open question. The decision took a bundler as the price of Scene 2 being real
verification; the stack check at S1 found the price was zero, and the licence gate sees nothing new.
Running the verifier in a browser also closes issue #44, which recorded that the browser path was
typechecked and never executed.

`demo/build/` is generated and not committed. Everything else here is.

## The fixtures

`cargo xtask gen-demo` writes `demo/fixtures/`. They come from the Rust engine, not from the verifier
that checks them, so Scene 2 is not a program checking its own output. Every file is hashed in
`MANIFEST.sha256`; `scripts/demo.sh` checks the hashes before serving and the page checks them again
before any scene runs, so a scene cannot be tuned by editing a file. `demo/fixtures/README.md` says
what each one is and carries the labels the packages themselves cannot hold — §2.5's field list is
closed, so a note added to a package would make it unverifiable.

To check them, run `scripts/ci.sh vectors`: it regenerates into a temporary directory and diffs, so a
fixture the engine would not produce fails the build. The bare `cargo xtask gen-demo` refuses here,
because the committed fixtures are already in its default destination; it prints the command to use.

## Identifiers and keys

Nothing here is real. The tenure identifier is synthetic, `DEMO0000` is not a registry, and the
signing key is the public half of RFC 8032 §7.1's TEST 1 key, whose private half that document
publishes — it stands for no qualified person and credentials nobody. The epoch key is published so
the page can build epochs at all; in a deployment it never leaves the batcher (INV-STATE-03, RES-03),
and the page says so where the scene relies on it.
