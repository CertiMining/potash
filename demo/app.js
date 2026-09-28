/**
 * E-14's three scenes.
 *
 * Everything here runs in the viewer's browser: the epoch trees in Scene 1 are built by the same
 * TypeScript verifier that Scene 2 uses to verify a package, compiled to `build/verifier/`. Nothing
 * is precomputed and nothing is a recording.
 *
 * What the scenes do **not** do is stand in for the repository's tests. `privacy.rs` is the authority
 * for V-Z-01 and `ts/test/` for the verifier; each scene says which test it is showing, so a viewer
 * who wants the proof rather than the demonstration knows where to look.
 */
import { toHex, fromHex } from "./build/verifier/bytes.js";
import { buildEpoch } from "./build/verifier/tree.js";
import { verifyDisclosureJson } from "./build/verifier/disclosure.js";
import { keccak256, sha256 } from "./build/verifier/hash.js";
import { CHECKPOINT_DISCRIMINATOR } from "./build/verifier/solana/accounts.js";
import {
  ACCOUNT_FIELDS,
  CHECKPOINT_LEN,
  INSTRUCTION_FIELDS,
  INSTRUCTION_LEN,
  checkpointAccount,
  diff,
  publishInstruction,
} from "./footprint.js";

const $ = (id) => document.getElementById(id);
const plural = (n) => `${n} record${n === 1 ? "" : "s"}`;
const text = (el, s) => {
  el.textContent = s;
};

/**
 * Anchor's two discriminators, computed here rather than copied.
 *
 * §2.4 states the account rule as `SHA-256("account:" \u2016 StructName)`, and the verifier already
 * derives `CheckpointAccount`'s from it. The instruction rule, `SHA-256("global:" \u2016 name)`, is
 * Anchor's published convention and not in the specification, which is why it is written out with its
 * source named. Both are constants across record counts either way, which is the only property
 * Scene 1 needs of them.
 */
const ACCOUNT_DISCRIMINATOR = CHECKPOINT_DISCRIMINATOR;
const INSTRUCTION_DISCRIMINATOR = sha256(new TextEncoder().encode("global:publish_checkpoint")).slice(0, 8);

/**
 * One epoch's publication, everything fixed except how many real records the epoch held.
 *
 * `epoch`, the slot, the timestamp and the receipt digest are constants here. They are all fields
 * V-Z-01 permits to differ, so letting them move would make the diff unreadable without proving
 * anything: the question is whether the *record count* moves a byte.
 */
const FIXED = {
  epoch: 20723n,
  height: 8,
  masterKey: fromHex("0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a", 32),
  // Synthetic, and visibly so. An earlier version held the announced log's real slot and receipt
  // digest here, which put values a reader might recognise into an account that was never published.
  // Nothing claimed they were real, which is not the same as their not looking it.
  publishedSlot: 500000000n,
  publishedUnix: 1790500000n,
  receiptDigest: fromHex(`0x${"ab".repeat(32)}`, 32),
  anchorKind: 1,
  bump: 255,
};

/** `count` synthetic submissions, so the tree is built from a real set rather than described. */
function realSet(count) {
  const real = [];
  for (let i = 0; i < count; i++) {
    const submissionId = new Uint8Array(16);
    const leaf = new Uint8Array(32);
    new DataView(submissionId.buffer).setBigUint64(0, BigInt(i), true);
    new DataView(leaf.buffer).setBigUint64(0, BigInt(i) ^ 0x3c3c3c3c3c3c3c3cn, true);
    leaf[8] = 0x77;
    real.push({ submissionId, leaf });
  }
  return real;
}

function publication(count) {
  const started = performance.now();
  const built = buildEpoch(FIXED.epoch, FIXED.height, FIXED.masterKey, realSet(count));
  const buildMs = performance.now() - started;
  const account = checkpointAccount({
    discriminator: ACCOUNT_DISCRIMINATOR,
    epoch: FIXED.epoch,
    root: built.root,
    publishedSlot: FIXED.publishedSlot,
    publishedUnix: FIXED.publishedUnix,
    receiptDigest: FIXED.receiptDigest,
    anchorKind: FIXED.anchorKind,
    bump: FIXED.bump,
  });
  const instruction = publishInstruction({
    discriminator: INSTRUCTION_DISCRIMINATOR,
    epoch: FIXED.epoch,
    root: built.root,
  });
  return { count, built, account, instruction, buildMs };
}

function byteRow(bytes, other, fields) {
  const frag = document.createDocumentFragment();
  for (let i = 0; i < bytes.length; i++) {
    const span = document.createElement("span");
    span.className = "byte";
    if (other && bytes[i] !== other[i]) span.classList.add("differs");
    const field = fields.find((f) => i >= f.at && i < f.at + f.len);
    span.title = field ? `${field.name} @ ${i}` : `offset ${i}`;
    span.textContent = bytes[i].toString(16).padStart(2, "0");
    frag.append(span);
  }
  return frag;
}

// ------------------------------------------------------------------ Scene 1

let baseline = null;

function renderScene1() {
  const count = Number($("count").value);
  text($("count-label"), String(count));
  const a = baseline ?? publication(1);
  const b = publication(count);

  text($("s1-left-count"), `${a.count} record${a.count === 1 ? "" : "s"}`);
  text($("s1-right-count"), `${b.count} record${b.count === 1 ? "" : "s"}`);

  const accountDiff = diff(ACCOUNT_FIELDS, a.account, b.account);
  const ixDiff = diff(INSTRUCTION_FIELDS, a.instruction, b.instruction);

  $("s1-account-a").replaceChildren(byteRow(a.account, b.account, ACCOUNT_FIELDS));
  $("s1-account-b").replaceChildren(byteRow(b.account, a.account, ACCOUNT_FIELDS));
  $("s1-ix-a").replaceChildren(byteRow(a.instruction, b.instruction, INSTRUCTION_FIELDS));
  $("s1-ix-b").replaceChildren(byteRow(b.instruction, a.instruction, INSTRUCTION_FIELDS));

  const rows = [
    ["account size", `${a.account.length} bytes`, `${b.account.length} bytes`],
    ["instruction length", `${a.instruction.length} bytes`, `${b.instruction.length} bytes`],
    ["tree leaves", String(1 << FIXED.height), String(1 << FIXED.height)],
    ["proof length", `${FIXED.height} siblings`, `${FIXED.height} siblings`],
    ["build time, this browser", `${a.buildMs.toFixed(1)} ms`, `${b.buildMs.toFixed(1)} ms`],
    ["root", toHex(a.built.root).slice(0, 18) + "…", toHex(b.built.root).slice(0, 18) + "…"],
  ];
  $("s1-shape").replaceChildren(
    ...rows.map(([what, left, right]) => {
      const tr = document.createElement("tr");
      for (const [i, cell] of [what, left, right].entries()) {
        const td = document.createElement("td");
        td.textContent = cell;
        if (i > 0) td.className = "mono";
        tr.append(td);
      }
      return tr;
    }),
  );

  const fields = [...accountDiff.byField.keys()].sort();
  const verdict = $("s1-verdict");
  verdict.classList.remove("bad", "good");
  if (accountDiff.lengthDiffers || ixDiff.lengthDiffers) {
    verdict.classList.add("bad");
    text(verdict, "The two publications are different lengths. That is a failure of the property, not a demonstration of it.");
  } else if (accountDiff.unpermitted.length > 0 || ixDiff.unpermitted.length > 0) {
    verdict.classList.add("bad");
    const where = [...accountDiff.unpermitted, ...ixDiff.unpermitted].slice(0, 12).join(", ");
    text(verdict, `Bytes differ outside §4.4's closed list, at offsets ${where}. §4.3 says such a byte is a failure and that the list is amended in the specification, never in the test.`);
  } else {
    verdict.classList.add("good");
    const named = fields.length === 0 ? "nothing at all" : fields.join(", ");
    const why =
      a.count === b.count
        ? "the same record count builds the same tree, so there is nothing to differ"
        : fields.length === 0
          ? "two different record counts produced the same root, which at 256 bits is a collision and not something this page should have found"
          : "every one of them a field §4.4's closed list permits, because a Merkle root is a digest";
    text(
      verdict,
      `${plural(a.count)} against ${plural(b.count)}: the account and the instruction data are the same length with the same field layout, and the only bytes that differ are in ${named} — ${why}.`,
    );
  }
}

// ------------------------------------------------------------------ fixtures

async function loadFixtures() {
  const names = ["disclosure.json", "tampered.json", "root.json", "README.md"];
  const manifestText = await (await fetch("./fixtures/MANIFEST.sha256")).text();
  const expected = new Map(
    manifestText
      .split("\n")
      .filter((l) => l.trim() !== "")
      .map((l) => {
        const [hash, , name] = l.trim().split(/\s+/);
        return [name, hash];
      }),
  );
  const files = {};
  const digests = [];
  for (const name of names) {
    const body = await (await fetch(`./fixtures/${name}`)).text();
    const actual = [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(body)))]
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    // D-126: a fixture whose hash has moved stops the demo. A scene that could be tuned by editing a
    // file is not evidence of anything.
    if (actual !== expected.get(name)) {
      throw new Error(`fixtures/${name}: sha256 ${actual} does not match the manifest's ${expected.get(name)}`);
    }
    files[name] = body;
    digests.push(`${name} ${actual.slice(0, 16)}…`);
  }
  return { files, digests };
}

// ------------------------------------------------------------------ Scenes 2 and 3

function renderReport(el, report) {
  const list = document.createElement("ul");
  list.className = "checks";
  for (const check of report.checks) {
    const li = document.createElement("li");
    li.className = `check ${check.status}`;
    const status = document.createElement("span");
    status.className = "status";
    status.textContent = check.status;
    li.append(status, document.createTextNode(" " + check.name));
    if (check.detail !== undefined && check.status !== "pass") {
      const d = document.createElement("div");
      d.className = "detail";
      d.textContent = check.detail;
      li.append(d);
    }
    list.append(li);
  }
  const frag = document.createDocumentFragment();
  frag.append(list);
  for (const note of report.notes) {
    const p = document.createElement("p");
    p.className = "note";
    p.textContent = note;
    frag.append(p);
  }
  el.replaceChildren(frag);
}

function renderScene2(fixtures) {
  const meta = JSON.parse(fixtures.files["root.json"]);
  const root = { epoch: BigInt(meta.epoch), root: fromHex(meta.root, 32) };
  const report = verifyDisclosureJson(fixtures.files["disclosure.json"], {
    root,
    configuredHeight: Number(meta.height),
  });
  const verdict = $("s2-verdict");
  verdict.classList.toggle("good", report.ok);
  verdict.classList.toggle("bad", !report.ok);
  text(
    verdict,
    report.ok
      ? "Verified: the signature holds over the bytes, the recomputed leaf is in the epoch the proof names, and that epoch's root is the one obtained separately."
      : `Refused: ${report.failure?.message ?? "unknown"}`,
  );
  renderReport($("s2-report"), report);
  text($("s2-root"), `${toHex(root.root)} (epoch ${meta.epoch})`);
  return { root, height: Number(meta.height) };
}

function renderScene3(fixtures, ctx) {
  const report = verifyDisclosureJson(fixtures.files["tampered.json"], {
    root: ctx.root,
    configuredHeight: ctx.height,
  });
  const verdict = $("s3-verdict");
  verdict.classList.toggle("bad", report.ok);
  verdict.classList.toggle("good", !report.ok);
  text(
    verdict,
    report.ok
      ? "The altered package verified. That is a failure of the demonstration."
      : `Refused: ${report.failure?.message ?? "unknown"}`,
  );
  renderReport($("s3-report"), report);

  // The root is the same object Scene 2 verified against, unchanged, which is the second half of what
  // this scene shows: detection does not require the log to react.
  text($("s3-root"), toHex(ctx.root.root));
  const original = JSON.parse(fixtures.files["disclosure.json"]);
  const altered = JSON.parse(fixtures.files["tampered.json"]);
  const rows = [
    ["payload_digest", original.record.payload_digest, altered.record.payload_digest],
    ["qp_signature", original.qp_signature.slice(0, 26) + "…", altered.qp_signature.slice(0, 26) + "…"],
    ["epoch root", toHex(ctx.root.root).slice(0, 26) + "…", toHex(ctx.root.root).slice(0, 26) + "…"],
  ];
  $("s3-compare").replaceChildren(
    ...rows.map(([what, before, after]) => {
      const tr = document.createElement("tr");
      const label = document.createElement("td");
      label.textContent = what;
      const b = document.createElement("td");
      b.className = "mono";
      b.textContent = before;
      const a = document.createElement("td");
      a.className = "mono";
      a.textContent = after;
      if (before !== after) a.classList.add("differs");
      tr.append(label, b, a);
      return tr;
    }),
  );
}

// ------------------------------------------------------------------ boot

async function main() {
  // One discarded build first. Without it the baseline absorbs the engine's warm-up and the table
  // reads as though an epoch holding one record takes longer to build than one holding 255 — an
  // artefact of this browser, and exactly the kind of misreading a scene should not invite.
  publication(1);
  // A fixed baseline of one record, so every comparison is against the same left-hand side and the
  // viewer is changing exactly one thing.
  baseline = publication(1);
  $("count").addEventListener("input", renderScene1);
  renderScene1();

  try {
    const fixtures = await loadFixtures();
    text($("fixture-digests"), fixtures.digests.join("  ·  "));
    const ctx = renderScene2(fixtures);
    renderScene3(fixtures, ctx);
  } catch (e) {
    for (const id of ["s2-verdict", "s3-verdict"]) {
      const el = $(id);
      el.classList.add("bad");
      text(el, String(e instanceof Error ? e.message : e));
    }
  }

  // A visible self-check, because a page that computes nothing looks the same as one that does.
  const empty = toHex(keccak256(new Uint8Array(0)));
  text(
    $("selfcheck"),
    `Keccak-256 of the empty string, computed here: ${empty}${
      empty === "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470" ? " — KAT-01's published value" : " — WRONG"
    }`,
  );
}

main();
