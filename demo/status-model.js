/**
 * What the status page says, separated from how it says it.
 *
 * Everything here is pure: no DOM, no fetch, no clock. The page supplies the chain's answers and the
 * browser's day index; this turns them into rows and sentences. That split is what lets
 * `demo/test/status.test.mjs` check the failure path, which is the path a status page gets wrong —
 * an unreachable endpoint rendered as an empty table reads exactly like a log that has published
 * nothing, and those are opposite facts.
 *
 * The page is read-only by construction: nothing in this file or its caller signs, submits or holds
 * a key, and there is no code path to the batcher. A reader should not have to take that on trust,
 * so the page says it too.
 */

/** The epoch an announced log began at is a fact about the deployment, not a constant to assume. */
export const UNKNOWN = Symbol("not read yet");

/**
 * §1.4: the client reports the distance and the ruling belongs to whoever holds the clock. So this
 * returns the distance and a sentence that does not grade it, and the page prints the hand-run
 * caveat beside it rather than calling a late day a fault.
 */
export function lagReport(lastEpoch, currentDayIndex) {
  const days = BigInt(currentDayIndex) - BigInt(lastEpoch);
  if (days < 0n) {
    return {
      days,
      state: "ahead",
      sentence:
        `The sequence is ${-days} day(s) ahead of this browser's UTC day index. An epoch ahead of ` +
        `the calendar is what cost an earlier deployment (D-88); if this ever shows, suspect the ` +
        `clock this page is running on before suspecting the log.`,
    };
  }
  if (days === 0n) {
    return {
      days,
      state: "level",
      sentence: "The last published epoch is this browser's UTC day index.",
    };
  }
  return {
    days,
    state: "behind",
    sentence:
      `The last published epoch is ${days} day(s) behind this browser's UTC day index. The cycle is ` +
      `run by hand (D-117), so this is a person's lateness and not a process that failed. Whether ` +
      `that distance is acceptable is a ruling, and this page does not make it.`,
  };
}

/**
 * One row per epoch the log claims to have published, in order.
 *
 * `checkpoints` is a map from epoch to the decoded account, or to a failure. An epoch inside the
 * published range whose account did not arrive is **not** rendered as absent: INV-ANCH-02 makes the
 * range unbroken and only the owning program can allocate an address there, so a missing account
 * there is evidence about the answer rather than about the log.
 */
export function epochRows(config, checkpoints) {
  const rows = [];
  for (let e = BigInt(config.startEpoch); e <= BigInt(config.lastEpoch); e++) {
    const got = checkpoints.get(e);
    if (got === undefined || got instanceof Error) {
      rows.push({
        epoch: e,
        state: "unanswered",
        detail:
          "inside the published range and this page did not get an account for it, which is a " +
          "statement about the response rather than about the log",
      });
      continue;
    }
    rows.push({
      epoch: e,
      state: got.status,
      root: got.root,
      publishedSlot: got.publishedSlot,
      detail: got.status === "dual"
        ? "a root on Solana and a receipt digest attached"
        : "a root on Solana; anchor B has not attached",
    });
  }
  return rows;
}

/** Counts the page prints above the table, derived from the rows rather than from a second source. */
export function summarise(rows) {
  const counts = { total: rows.length, dual: 0, single: 0, unanswered: 0 };
  for (const r of rows) counts[r.state] += 1;
  return counts;
}

/**
 * The explanations, in tour order. Every one is anchored to a region id the page renders, and
 * `status.test.mjs` fails if a region has no explanation or an explanation has no region — a tour
 * that silently skips the thing a newcomer is looking at is worse than no tour.
 */
export const EXPLANATIONS = [
  {
    id: "what-this-is",
    title: "What you are looking at",
    body:
      "A read-only view of a log that is running. Every number below was read from Solana devnet by " +
      "your browser just now, with the account decoder the verifier ships. It reads the chain and " +
      "decodes what it finds; it walks no proof and checks no signature, so nothing here is " +
      "verification — Scene 2 is. This page holds no key, publishes nothing, and cannot change " +
      "anything.",
  },
  {
    id: "lag",
    title: "Distance, not a verdict",
    body:
      "An epoch is a UTC day index. This compares the last published epoch against your browser's " +
      "day index and reports the distance. It does not rule on it: the cycle is run by hand, and " +
      "whether a late day matters is a judgement that needs a clock the verifier deliberately does " +
      "not hold.",
  },
  {
    id: "counts",
    title: "Single and dual",
    body:
      "Dual means a root is on Solana and an OpenTimestamps receipt digest is attached to it. " +
      "Single means the root is on Solana and anchor B has not attached yet, which is the budgeted " +
      "wait while Bitcoin confirms, not a degradation.",
  },
  {
    id: "table",
    title: "One row per epoch",
    body:
      "The epoch number, the 32-byte root, the Solana slot the publication landed in, and whether " +
      "anchor B has attached. The record count that epoch held is not here, because it is not on " +
      "chain — that is the whole point of the design, and the demo's first scene shows it.",
  },
  {
    id: "limits",
    title: "What this does not tell you",
    body:
      "It does not check any Bitcoin block header against Bitcoin, so dual is the receipt's own " +
      "claim. It is not an operator console: no alerting, no scheduling, no control. It reads one " +
      "endpoint, so it shows one view of the chain. And it is devnet.",
  },
];

/** Ids the page must render for the tour to be honest about covering them. */
export const EXPLAINED_REGIONS = EXPLANATIONS.map((e) => e.id);
