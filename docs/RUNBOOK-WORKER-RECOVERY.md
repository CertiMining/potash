# Worker recovery runbook

For the Anchor-B worker on **local staging and Solana devnet only**. It neither deploys to mainnet
nor decides that an OpenTimestamps claim is true; `confirm-anchor-b` against Bitcoin headers is a
separate step and this runbook never substitutes for it.

This is the recovery half of [`RUNBOOK-DEVNET-ANCHORING.md`](RUNBOOK-DEVNET-ANCHORING.md), which
operates the cycle. That document's "Recovery and missed epochs" is the ordered procedure once you
know what is wrong. **This one is for finding out which of five things is wrong**, and it is keyed on
the alert that woke you.

## How to use it

Each section is one alert from `certimining_client::alert::Alert` (#252, criterion 5). Find the one
you were paged on and work down it.

**The service manager assumed is systemd, and the units are committed** at
[`deploy/systemd/`](../deploy/systemd/): `certimining-anchor-b-worker.service` and the
`certimining-alert@.service` its `OnFailure=` reaches. Nothing here requires systemd to *diagnose* an
incident — every command below is the worker's own tooling — but which component raises which alert
does depend on it, and until 1 November 2026 this document named five alerts that nothing raised at
all (H-95, #300). Two of them cannot be raised by the worker: a live process cannot report its own
silence, and a process that exits on its first refusal cannot count three in a row.

| alert | raised by | how it reaches you |
|---|---|---|
| `ProcessSilent` | systemd `WatchdogSec=1800` in the worker's unit, fed by `sd_notify` after each successful observation | the unit fails its watchdog and is restarted; the journal carries the gap |
| `RepeatedRefusal` | systemd `Restart=on-failure` with `StartLimitBurst=3`, then `OnFailure=certimining-alert@%n.service` | once the start limit is reached, not once per refusal — a restart leaves the unit in `auto-restart`, and only the burst puts it in `failed` |
| `PublicationMissed` | the worker, each cycle | `anchor-b-worker: ALERT PublicationMissed: …` on stderr, so the journal |
| `SequenceLag` | the worker, each cycle | the same |
| `ReceiptUnconfirmed` | the worker, each cycle | the same |

On a host with no service manager — a worker run by hand — the worker says so at start
(`no readiness notification sent`, `no WATCHDOG_USEC`) and the first two rows are raised by nothing.
That is a supported way to run it and an unsupervised one; the worker states which you have rather
than leaving the two indistinguishable.

Every section has the same four parts:

- **It means** — what the condition establishes, and what it does not.
- **Diagnose** — exact commands. Read their output; do not infer from the fact that they ran.
- **Safe retry** — the one action that cannot make the state worse.
- **Resolved when** — the observation that ends the incident. Nothing else ends it.

**Before any of them, preserve the evidence.** Copy the worker's logs, the handoff files, the receipt
directory and the pending receipt somewhere outside the working tree. A recovery that destroys the
state it recovered from cannot be reviewed, and three of the five conditions below are indistinguishable
from each other after a restart.

## `ProcessSilent`

**Raised by** systemd, not the worker: `WatchdogSec=1800` in `deploy/systemd/certimining-anchor-b-worker.service`, fed by `sd_notify` after each successful observation of the chain. A live process cannot report its own silence. If the host has no service manager, nothing raises this.

**It means** the worker has not reported inside its grace. It does not mean the log is behind: a
process can die immediately after a successful publication and nothing is owed.

**Diagnose**

```sh
scripts/devnet-anchoring-cycle.sh preflight worker     # custody and configuration first
scripts/devnet-anchoring-cycle.sh reconcile <epoch>    # the last epoch believed complete
```

`preflight worker` fails closed on a key at any mode but `0600`, on a configuration naming another
role's private file, and on an identity collision. Those are the failures that make a restart unsafe,
so they are checked before the restart and not after it.

**Safe retry** Restart the worker. It holds no state: `next_step` derives the next action from the
config account and the receipt directory, so a restart repeats nothing and skips nothing. If
`preflight worker` failed, correct that first — restarting into a custody fault is how a worker
acquires an authority it should not hold.

**Resolved when** the process reports again *and* `reconcile` on the current epoch returns without a
failure. A process that is alive and publishing nothing is `PublicationMissed`, not this.

## `PublicationMissed`

**Raised by** the worker, each cycle, as `anchor-b-worker: ALERT PublicationMissed: …` on stderr and so in the journal.

**It means** an epoch's publication time has passed by more than the grace and the log has not
reached it. **The worker may be entirely healthy.** This is the condition H-90 (#293) needed: the
worker computed the correct wait, slept to it, woke and refused, every epoch, while answering and
reporting normally. Nothing else would have caught it.

**Diagnose**

```sh
scripts/devnet-anchoring-cycle.sh reconcile <epoch>    # the epoch named in the alert
scripts/devnet-anchoring-cycle.sh preflight worker
```

Then read the worker's own last decision from its log. If it is a `Refuse`, this is really
`RepeatedRefusal` and that section applies. If it is a `Wait` whose time has passed, the worker is
asleep against a clock that has moved and a restart re-observes.

**Safe retry** Restart the worker and watch for one full decision. Do not publish by hand to catch
up: the sequence is contiguous by construction and a hand-published epoch the worker did not observe
is how `last_submitted` and the receipt directory diverge.

**Resolved when** the named epoch appears in the log with `reconcile` returning clean, and the worker
makes its *next* scheduled publication unaided. One recovered epoch is not evidence that the schedule
works; the following one is.

## `SequenceLag`

**Raised by** the worker, each cycle, as `anchor-b-worker: ALERT SequenceLag: …`.

**It means** the log is further behind the newest publishable epoch than the policy allows. The
worker will refuse rather than replay an unbounded backlog, which is deliberate (`EpochSlipExceeded`).

**Diagnose**

```sh
scripts/devnet-anchoring-cycle.sh reconcile <first-missing-epoch>
```

Establish the **first** missing epoch, not the last. Recovery runs forward from it.

**Safe retry** None that is automatic. `WorkerPolicy::PRODUCTION` recovers one slipped epoch; a wider
backlog is an operator procedure, one epoch at a time in ascending order, each with its own handoff
from the batcher. Never raise `max_epoch_slip` to clear a backlog — the barrier exists so that an
unattended process cannot replay an arbitrary history, and widening it at the moment it fires removes
exactly the protection it was placed for.

**Resolved when** every epoch from the first missing one to the newest publishable reconciles clean,
in order, and the worker then waits rather than refuses.

## `ReceiptUnconfirmed`

**Raised by** the worker, each cycle, as `anchor-b-worker: ALERT ReceiptUnconfirmed: …`. It needs the pending receipt's modification time; an unreadable receipt makes the age unknown and this alert unraisable rather than raisable against a time of zero.

**It means** a submitted receipt has gone past its budget without Bitcoin confirming it. INV-ANCH-04
budgets this wait; the alert fires when the wait itself is the news. **An unconfirmed receipt is not
a failure** and must not be deleted or resubmitted.

**Diagnose**

```sh
cargo run -p certimining-client --features ots --bin confirm-anchor-b
```

This reads the receipt against Bitcoin headers. A receipt only a calendar stands behind is not
attachable, and `Cluster::attach` refuses it — that refusal is correct and is not the fault.

**Safe retry** Wait. The worker retries the attach on every observation and records nothing until the
receipt confirms, which is what makes the retry free.

**Resolved when** `confirm-anchor-b` names a Bitcoin block for the receipt and the epoch reaches
`Dual`. If the calendar has lost the submission entirely, that is an escalation, not a retry: a
second submission for the same epoch produces a second receipt and the attach field is write-once.

## `RepeatedRefusal`

**Raised by** systemd, not the worker: `Restart=on-failure` with `StartLimitBurst=3`, then `OnFailure=certimining-alert@%n.service`. It arrives **once the start limit is reached, not once per refusal** — a unit being restarted sits in `auto-restart`, and only the burst puts it in `failed`. The worker exits on its first refusal, so it cannot count three.

**It means** the worker has refused the same way repeatedly, so the state is one it must not act on
and no amount of restarting changes that. The refusal names which.

**Diagnose** Read the refusal from the alert, then the matching check:

| refusal | what it says | first command |
|---|---|---|
| `LastBeforeStart` | the config reports a `last_epoch` more than one below `start_epoch` | `reconcile <start_epoch>` |
| `LogAheadOfCalendar` | the log has published past today | `reconcile <last_epoch>` |
| `EpochSlipExceeded` | the backlog is wider than the policy allows | see `SequenceLag` above |
| `AwaitingAttachOutsideLog` | the receipt directory names an epoch the log has not published | `reconcile <awaiting_attach>` |
| `SubmissionAheadOfLog` | the receipt directory is ahead of the chain | `reconcile <last_submitted>` |
| `AttachmentAheadOfSubmission` | an attach is pending for an epoch never submitted | inspect the receipt directory |
| `Unschedulable` | an epoch's publication time cannot be represented | escalate; this is not an operational fault |

**Safe retry** None. Every refusal above is the worker declining to act on a state it cannot reconcile,
and restarting re-reads the same state. Three of them — `AwaitingAttachOutsideLog`,
`SubmissionAheadOfLog`, `AttachmentAheadOfSubmission` — mean the receipt directory and the chain
disagree, and the chain is the record.

**Resolved when** the disagreement is explained and corrected at its source, and the worker's next
decision is not a refusal. **An explanation is required.** A refusal that stops after a file was moved,
with nobody able to say why the file was there, is unresolved evidence and escalates.

## What never to do

Delete or overwrite a pending receipt. Overwrite a differing handoff. Reuse one identity for two roles
to speed recovery. Substitute the deploy authority for the worker payer. Raise `max_epoch_slip`,
widen a grace, or edit `WorkerPolicy` to clear a live incident. Publish an epoch by hand that the
worker is expected to publish. Each of these converts a detected fault into an undetectable one.

## Escalation

Escalate to the human operator when: any refusal in the table has no explanation; a calendar has lost
a submission; `preflight` fails for a reason the configuration does not explain; or a recovery would
require any action in the list above. This runbook carries no authority to merge, close an issue, or
deploy.

## Cold-run record

#252's sixth criterion requires a second person to cold-run this document — someone who did not write
it, following it without asking the author what a step means. That has **not** happened. Until it
does, this runbook is unverified against the only test that matters for a runbook, and the record says
so rather than implying otherwise. Each cold-run is recorded below with its date, who ran it, and
every step that had to be explained.

| date | who | steps that needed explaining |
|---|---|---|
| — | — | not yet cold-run |
