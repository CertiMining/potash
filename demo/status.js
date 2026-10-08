/**
 * The status page's browser half: read the chain, render it, run the tour.
 *
 * Everything it decides is in `status-model.js` and tested there. What is here is fetching and DOM,
 * and the one rule it must not break is that a failed read never renders as a healthy log. An
 * endpoint that times out and a log that published nothing produce the same empty table unless
 * something insists on the difference, so every failure path below writes a failure.
 */
import { toHex } from "./build/verifier/bytes.js";
import { fetchLogConfig, fetchCheckpoint, DEVNET_RPC_URL } from "./build/verifier/solana/rpc.js";
import { anchorStatus, utcDayIndex } from "./build/verifier/solana/accounts.js";
import { lagReport, epochRows, summarise, EXPLANATIONS } from "./status-model.js";

const $ = (id) => document.getElementById(id);

/**
 * **Through `textContent`, because the text is the endpoint's (review of #107, M1).** This built the
 * failure row with `innerHTML` and an interpolated `e.message`, so a response-controlled error could
 * put markup and event handlers into this page's origin. The message is worth showing — it is how a
 * reader tells a dead endpoint from a dead log — and nothing about showing it requires parsing it as
 * HTML.
 */
function failure(message) {
  $("lag-note").className = "note bad";
  $("lag-note").textContent = message;
  const row = document.createElement("tr");
  const cell = document.createElement("td");
  cell.colSpan = 4;
  cell.textContent = message;
  row.append(cell);
  $("rows").replaceChildren(row);
  $("counts").replaceChildren();
}

/** Everything interpolated into markup goes through this, whatever this page believes its source is. */
function esc(value) {
  return String(value).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] ?? c);
}

function short(hex) {
  return `0x${hex.slice(0, 8)}…${hex.slice(-6)}`;
}

async function read() {
  $("lag-note").className = "note";
  $("lag-note").textContent = "Reading the chain…";

  let config;
  try {
    config = await fetchLogConfig();
  } catch (e) {
    // The log's own configuration is the one account everything else is derived from. Without it
    // there is nothing to say, and saying nothing would look like an empty log.
    failure(`Could not read the log's configuration from ${DEVNET_RPC_URL}: ${e.message}. Nothing below is current.`);
    return;
  }

  const today = utcDayIndex(BigInt(Math.floor(Date.now() / 1000)));
  const lag = lagReport(config.lastEpoch, today);
  $("lag-note").className = `note ${lag.state}`;
  $("lag-note").textContent = lag.sentence;

  const checkpoints = new Map();
  for (let e = BigInt(config.startEpoch); e <= BigInt(config.lastEpoch); e++) {
    try {
      const account = await fetchCheckpoint(e, { logConfig: config });
      checkpoints.set(e, {
        status: anchorStatus(account),
        root: toHex(account.root),
        publishedSlot: account.publishedSlot,
      });
    } catch (err) {
      checkpoints.set(e, err instanceof Error ? err : new Error(String(err)));
    }
  }

  const rows = epochRows(config, checkpoints);
  const counts = summarise(rows);

  $("counts").innerHTML = [
    ["total", counts.total, "epochs published"],
    ["dual", counts.dual, "with a receipt attached"],
    ["single", counts.single, "awaiting anchor B"],
    ...(counts.unanswered > 0 ? [["unanswered", counts.unanswered, "no account returned"]] : []),
  ].map(([k, n, label]) => `<div><span class="n">${esc(n)}</span><span class="k">${esc(label)}</span></div>`).join("");

  $("rows").innerHTML = rows.map((r) => {
    if (r.state === "unanswered") {
      // `detail` is this page's own prose, but it is built beside values that are not, so it goes
      // through the same escaping as everything else rather than relying on where it came from.
      return `<tr><td class="mono">${esc(r.epoch)}</td><td colspan="3"><span class="pill unanswered">unanswered</span> — ${esc(r.detail)}</td></tr>`;
    }
    return `<tr>
      <td class="mono">${esc(r.epoch)}</td>
      <td class="mono" title="${esc(r.root)}">${esc(short(r.root))}</td>
      <td class="mono">${esc(r.publishedSlot)}</td>
      <td><span class="pill ${r.state}">${r.state}</span></td>
    </tr>`;
  }).join("");
}

/* ---- the explanations, on hover and as a tour ---------------------------------------------- */

const BY_ID = new Map(EXPLANATIONS.map((e) => [e.id, e]));
let pinned = null;

function popover(entry, { step } = {}) {
  const el = document.createElement("div");
  el.className = "pop";
  const h = document.createElement("h4");
  h.textContent = entry.title;
  const p = document.createElement("p");
  p.textContent = entry.body;
  el.append(h, p);
  if (step) {
    const bar = document.createElement("div");
    bar.className = "step";
    const count = document.createElement("span");
    count.textContent = `${step.index + 1} of ${step.total}`;
    const next = document.createElement("button");
    next.type = "button";
    next.textContent = step.index + 1 === step.total ? "Done" : "Next";
    next.addEventListener("click", step.onNext);
    const stop = document.createElement("button");
    stop.type = "button";
    stop.textContent = "Stop";
    stop.addEventListener("click", step.onStop);
    bar.append(count, stop, next);
    el.append(bar);
    // A tour step should be reachable by keyboard the moment it appears.
    queueMicrotask(() => next.focus());
  }
  return el;
}

function clear() {
  document.querySelectorAll(".pop").forEach((n) => n.remove());
  document.querySelectorAll("[data-explain].lit").forEach((n) => n.classList.remove("lit"));
}

function show(id, step) {
  clear();
  const host = $(id);
  const entry = BY_ID.get(id);
  if (!host || !entry) return;
  host.classList.add("lit");
  host.append(popover(entry, { step }));
  if (step) host.scrollIntoView({ block: "center", behavior: "smooth" });
}

for (const entry of EXPLANATIONS) {
  const host = $(entry.id);
  if (!host) continue;
  host.setAttribute("tabindex", "0");
  const open = () => { if (pinned === null) show(entry.id); };
  const close = () => { if (pinned === null) clear(); };
  host.addEventListener("mouseenter", open);
  host.addEventListener("mouseleave", close);
  host.addEventListener("focus", open);
  host.addEventListener("blur", close);
}

function tourStep(index) {
  pinned = index;
  show(EXPLANATIONS[index].id, {
    index,
    total: EXPLANATIONS.length,
    onNext: () => (index + 1 < EXPLANATIONS.length ? tourStep(index + 1) : stopTour()),
    onStop: stopTour,
  });
}

function stopTour() {
  pinned = null;
  clear();
  $("tour").focus();
}

$("tour").addEventListener("click", () => tourStep(0));
$("refresh").addEventListener("click", read);
document.addEventListener("keydown", (e) => { if (e.key === "Escape" && pinned !== null) stopTour(); });

read();
