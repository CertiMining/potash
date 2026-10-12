# The demo — three scenes

```bash
scripts/demo.sh
```

Builds the verifier for a browser, checks the fixtures against their manifest, runs the demo's
tests, serves `http://localhost:8730` (`PORT=…` moves it). Node 24 or later.

## The three scenes

**1 — the public view does not say how much you filed.** An epoch is a Merkle tree of height 8:
256 slots, always full, real submissions in pseudorandom slots under the epoch key and padding in
the rest. Move the control from 0 to 255 real records; the `CheckpointAccount` and the
`publish_checkpoint` instruction keep their length and layout, differing only inside `root`. The
trees build in the browser as you move it.

**2 — a counterparty verifies offline.** The independent TypeScript verifier recomputes the leaf
from the signed bytes, checks the qualified person's signature over them, and walks the inclusion
proof to a root obtained separately. Every check it ran is listed, including the one that does not
say `pass`.

**3 — one byte moves and the log notices.** The same package with the low bit of `payload_digest`
flipped in both the signed preimage and the hex beside it, so the two agree and the signature is
what refuses it. The epoch root never changes.

## The status page

`http://localhost:8730/status.html`, same command. The scenes are synthetic; this one reads Solana
devnet in your browser through the verifier this repository ships: the last published epoch against
your own UTC day index, then a row per epoch with its root, slot and anchor-B status.

Read-only: no key, publishes nothing, no path to the batcher, and **not an operator console** — no
alerting, scheduling or control. The daily cycle is run by hand (D-117,
[#49](https://github.com/CertiMining/potash/issues/49)), so a non-zero distance is a person being
late.

Every outlined region explains itself on hover, and **Take the tour** walks the five explanations in
order; `demo/test/status.test.mjs` fails if either side is missing.

It is built around the failure a status page gets wrong: an unreachable endpoint renders as an empty
table, which reads like a log that published nothing. A read that fails says so and clears the
counts.

## What this is not

A demonstration, not a test. The repository's tests are the authority for every property it shows:

| Scene shows | The test that decides it |
|---|---|
| Record count moves no byte outside §4.4's closed list | `programs/certimining-checkpoint/tests/privacy.rs`, under LiteSVM against the real program |
| The verifier's checks and refusals | `ts/test/`, 79 tests and 52 mutations |
| The footprint layout matches §2.4 | `demo/test/footprint.test.mjs`, round-tripped through the verifier's own decoder |

Three limits are stated on screen rather than here, because a reader of the page is who needs them:
count-hiding is computational and rests on the batcher's key custody (RES-09, RES-03); a package past
`seq` 1 does not establish its own position in the chain; and Scene 3 shows detection, not
prevention.

## Build and fixtures

No bundler: `ts/tsconfig.build.json` emits browser-shaped ES modules and an import map in
`index.html` resolves the bare specifiers into `@noble/hashes` and `@noble/curves`, so the build step
is a copy (D-124). `demo/build/` is generated, not committed.

`cargo xtask gen-demo` writes `demo/fixtures/` from the Rust engine, not the verifier that checks
them, so Scene 2 is not a program checking its own output. Every file is hashed in `MANIFEST.sha256`,
checked before serving and again before any scene runs; `scripts/ci.sh vectors` regenerates and
diffs. `demo/fixtures/README.md` carries the labels the packages cannot hold — §2.5's field list is
closed.

## Identifiers and keys

Nothing here is real. The tenure identifier is synthetic, `DEMO0000` is not a registry, and the
signing key is the public half of RFC 8032 §7.1's TEST 1 key, whose private half that document
publishes: it stands for no qualified person. The epoch key is published so the page can build epochs
at all; in a deployment it never leaves the batcher (INV-STATE-03, RES-03).
