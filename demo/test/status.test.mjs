/**
 * The status page's tests (S4).
 *
 * The page's job is to report a running deployment to someone who cannot check it themselves, so the
 * failure that matters is not a wrong number — it is a *missing* number rendered as a fine one. An
 * unreachable endpoint and a log that published nothing both produce an empty table, and those are
 * opposite facts. Every test below exists because some version of that confusion is cheap to ship.
 *
 * These run under `node --test` from the repository root and need no browser: the page's decisions
 * are in a plain ES module for exactly that reason.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
  EXPLANATIONS,
  EXPLAINED_REGIONS,
  epochRows,
  lagReport,
  short,
  summarise,
} from "../status-model.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const DEMO = join(HERE, "..");

// **Synthetic day indices (H-20, #60).** These were real: day indices the announced deployment
// and the one superseded on 25 September both published. Nothing in this file is about either of
// them — it exercises the status model's arithmetic, and what the assertions check is the
// differences between these numbers rather than the dates. The old values are not named here,
// because naming them would put them back in the file.
const config = { startEpoch: 40000n, lastEpoch: 40002n };
const ok = (status) => ({ status, root: "ab".repeat(32), publishedSlot: 500000000n });

test("the distance is reported, and nothing grades it", () => {
  const behind = lagReport(40008n, 40010n);
  assert.equal(behind.days, 2n);
  assert.equal(behind.state, "behind");
  // The ruling belongs to whoever holds the clock (§1.4), so the sentence must not deliver one.
  for (const verdict of ["unhealthy", "broken", "failing", "stale", "degraded"]) {
    assert.ok(!behind.sentence.toLowerCase().includes(verdict), `the sentence rules on the lag: ${verdict}`);
  }
  assert.ok(behind.sentence.includes("by hand"), "a hand-run cycle's lateness must be attributed to a person");

  assert.equal(lagReport(40010n, 40010n).state, "level");
  assert.equal(lagReport(40010n, 40010n).days, 0n);
});

test("an epoch ahead of the calendar is called out rather than shown as level", () => {
  const ahead = lagReport(40211n, 40010n);
  assert.equal(ahead.state, "ahead");
  assert.equal(ahead.days, -201n);
  // D-88: a compressed run put an earlier deployment 209 days ahead and cost it. If this ever
  // renders, the page must not round it down to "fine".
  assert.ok(ahead.sentence.includes("D-88"));
});

test("every published epoch gets a row, in order", () => {
  const rows = epochRows(config, new Map([
    [40000n, ok("dual")], [40001n, ok("dual")], [40002n, ok("single")],
  ]));
  assert.deepEqual(rows.map((r) => r.epoch), [40000n, 40001n, 40002n]);
  assert.deepEqual(rows.map((r) => r.state), ["dual", "dual", "single"]);
  assert.deepEqual(summarise(rows), { total: 3, dual: 2, single: 1, unanswered: 0 });
});

test("an epoch whose account did not arrive is unanswered, never absent and never healthy", () => {
  const rows = epochRows(config, new Map([
    [40000n, ok("dual")], [40001n, new Error("timeout")], [40002n, ok("single")],
  ]));
  assert.equal(rows.length, 3, "a row is owed for every epoch in the published range");
  assert.equal(rows[1].state, "unanswered");
  // INV-ANCH-02 makes the published range unbroken and only the owning program can allocate an
  // address inside it, so a missing account is evidence about the answer, not about the log.
  assert.match(rows[1].detail, /about the response rather than about the log/);
  assert.equal(summarise(rows).unanswered, 1);
});

test("a read that returned nothing at all is not a log that published nothing", () => {
  const rows = epochRows(config, new Map());
  assert.equal(rows.length, 3);
  assert.ok(rows.every((r) => r.state === "unanswered"), "an empty map means unanswered, not empty");
  assert.equal(summarise(rows).dual, 0);
  assert.equal(summarise(rows).unanswered, 3);
});

test("the tour covers every outlined region, and outlines every region it covers", () => {
  const html = readFileSync(join(DEMO, "status.html"), "utf8");
  // Every element carrying `data-explain` must have an id with an explanation behind it.
  const outlined = [...html.matchAll(/id="([a-z-]+)"\s+data-explain/g)].map((m) => m[1]);
  assert.ok(outlined.length > 0, "the page outlines nothing");
  assert.deepEqual(
    [...outlined].sort(),
    [...EXPLAINED_REGIONS].sort(),
    "a region without an explanation, or an explanation with no region, is a tour that lies about its coverage",
  );
});

test("nothing on the page claims more than the architecture carries", () => {
  // **`compliant` without `compliance`, and the tour without the page (review of #107, M2).** The
  // first version matched `compliant` only, so "It assures regulatory compliance" — §4.6's forbidden
  // phrase, close to verbatim — passed, and it read `EXPLANATIONS` while the page's own prose went
  // unchecked. §4.6 is enforced repository-wide by `scripts/claim-check.sh`; this is the scoped
  // check for the page, and a scoped check that misses the phrase it is scoped to is not one.
  const banned = /\bfraud\b|double[- ]pledge|guarantee|prevents?\b|immutable|complian(t|ce)/i;
  const html = readFileSync(join(DEMO, "status.html"), "utf8").replace(/<!--[\s\S]*?-->/g, "");
  const sources = [
    ["status.html", html],
    ...EXPLANATIONS.map((e) => [`the tour's "${e.id}"`, `${e.title} ${e.body}`]),
  ];
  for (const [where, text] of sources) {
    const hit = banned.exec(text);
    assert.equal(hit, null, `${where} overclaims: ${hit?.[0]}`);
  }
});

test("neither the page nor the tour claims to verify anything", () => {
  // The page runs the verifier's account decoder, not its verification path: it walks no proof and
  // checks no signature. The first draft said "the same verifier a counterparty would run", which
  // invites a reader to believe verification is happening here. It is not, and Scene 2 is where it is.
  const html = readFileSync(join(DEMO, "status.html"), "utf8");
  const tour = EXPLANATIONS.map((e) => `${e.title} ${e.body}`).join(" ");
  for (const [where, text] of [["status.html", html], ["the tour", tour]]) {
    assert.ok(
      /walks no proof and checks no signature/.test(text),
      `${where} does not say what it declines to check`,
    );
    assert.ok(
      !/same verifier a counterparty would run/.test(text),
      `${where} claims to be the verifier a counterparty runs, and it is the decoder half`,
    );
  }
});

test("the page says dual is the receipt's own claim, and says devnet", () => {
  const html = readFileSync(join(DEMO, "status.html"), "utf8");
  assert.match(html, /Nothing here checks a Bitcoin\s+block header against Bitcoin/);
  assert.match(html, /Devnet/);
  assert.match(html, /not an operator console/i);
});

// **A root is shortened to one `0x`, whichever spelling it arrives in (found by looking at the page).**
// `short` lived in `status.js`, beside the DOM, where no test here could import it. It prepended `0x`
// to a value that already carried one, so every row of the live epoch table read
// `0x0xdc349d…6d0791` while all seventeen of these tests passed. The fix moved the function into the
// module these tests can reach, which is the part worth keeping.
test("a root is shortened to one 0x, whichever spelling it arrives in", () => {
  // Synthetic, and deliberately so: the first draft of this test used a real published epoch
  // root, and `cargo xtask check-live-values` refused the file — by the bare spelling, which it
  // could not see until the repair for the review of PR #121 taught it that `0x` is a convention of
  // the list rather than part of the value.
  const bare = "0123456789abcdef".repeat(4);
  assert.equal(short(bare), "0x01234567…abcdef");
  assert.equal(short(`0x${bare}`), "0x01234567…abcdef", "a prefixed root must not gain a second 0x");
  assert.equal(short(`0X${bare}`), "0x01234567…abcdef", "including the upper-case spelling");
});

test("a shortened root carries exactly one 0x", () => {
  for (const spelling of ["ab".repeat(32), `0x${"ab".repeat(32)}`]) {
    const out = short(spelling);
    assert.equal(out.match(/0x/gi).length, 1, `${out} should carry one prefix`);
    assert.match(out, /^0x[0-9a-f]{8}…[0-9a-f]{6}$/, `${out} should be 0x, eight, ellipsis, six`);
  }
});
