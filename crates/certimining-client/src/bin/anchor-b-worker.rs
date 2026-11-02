// SPDX-License-Identifier: MIT OR Apache-2.0
//! The anchor-B worker (H-13, issue #49), which D-117 described before it existed.
//!
//! **This process decides nothing.** Every decision is [`certimining_client::next_step`], a function
//! from observed state to one action, tested across calendars no real run would reach in a year. This
//! file observes, calls it, performs the one step it returns, and sleeps. A worker that decided inside
//! its own loop could only be checked by running it against a cluster for days, which is how the
//! by-hand cycle it replaces came to miss seven days with nobody noticing.
//!
//! **It never builds an epoch and never reads `k_master`** (D-139). It publishes a root the batcher
//! produced, from a signed handoff, and refuses to run without a valid one. RES-03 rests count-hiding
//! entirely on that key's custody; D-117 makes the checkpoint authority the one unattended
//! authorisation key, and it can be, because compromising it buys a wrong root rather than the
//! retrospective record count of every epoch the log has published. D-143 adds a separate fee-only
//! payer, which carries no program authority and must not be the deploy/upgrade key.
//!
//! ```text
//! CERTIMINING_RPC=https://api.devnet.solana.com \
//! CERTIMINING_BATCHER_KEY=<64 hex characters> \
//! CERTIMINING_WORKER_PAYER=/path/to/worker-payer.json \
//! CERTIMINING_CHECKPOINT_AUTHORITY=/path/to/checkpoint-authority.json \
//! CERTIMINING_HANDOFFS=/path/to/handoffs \
//!     cargo run -p certimining-client --features cluster,ots --bin anchor-b-worker
//! ```
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use certimining_client::{
    alerts,
    cluster::{AttachRefused, Cluster},
    day_index, next_step_with_policy, notify, refuse_a_readable_key, sequence_lag, AnchorB,
    AnchorStatus, Handoff, Observed, PendingReceipt, PublishFailed, ReferenceClient, Refusal,
    Schedule, Step, Supervision, Thresholds, WorkerPolicy,
};
use certimining_core::{DalekVerifier, Digest};
use solana_keypair::Keypair;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Everything the worker is configured with, read once at start so a half-configured run refuses
/// before it touches a cluster rather than in the middle of a cycle.
struct Config {
    rpc: String,
    authority: PathBuf,
    payer: PathBuf,
    batcher_key: [u8; 32],
    handoffs: PathBuf,
    ots: PathBuf,
    receipts: PathBuf,
}

fn env(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} is not set"))
}

fn hex32(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim();
    if s.len() != 64 {
        return Err(format!("expected 64 hex characters, found {}", s.len()));
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        let at = i.checked_mul(2).ok_or("index overflow")?;
        let end = at.checked_add(2).ok_or("index overflow")?;
        let pair = s.get(at..end).ok_or("short hex")?;
        *slot = u8::from_str_radix(pair, 16).map_err(|e| format!("{pair}: {e}"))?;
    }
    Ok(out)
}

impl Config {
    fn from_env() -> Result<Self, String> {
        let home = env("HOME")?;
        Ok(Self {
            rpc: env("CERTIMINING_RPC")?,
            authority: PathBuf::from(env("CERTIMINING_CHECKPOINT_AUTHORITY")?),
            // D-143: an unattended worker must not hold the deploy/upgrade authority just to pay
            // transaction fees. There is deliberately no fallback to deploy-keypair.json.
            payer: PathBuf::from(env("CERTIMINING_WORKER_PAYER")?),
            batcher_key: hex32(&env("CERTIMINING_BATCHER_KEY")?)
                .map_err(|e| format!("CERTIMINING_BATCHER_KEY: {e}"))?,
            handoffs: PathBuf::from(env("CERTIMINING_HANDOFFS")?),
            ots: PathBuf::from(
                std::env::var("OTS")
                    .unwrap_or(format!("{home}/.local/share/potash/ots-venv/bin/ots")),
            ),
            receipts: PathBuf::from(
                std::env::var("CERTIMINING_RECEIPTS")
                    .unwrap_or(format!("{home}/.local/state/potash/receipts")),
            ),
        })
    }
}

/// Loads a Solana keypair, refusing any mode but 0600 first (D-117, S6).
///
/// The bytes are never returned as text, never printed and never logged. A failure names the path,
/// which is not a secret, and nothing else.
fn signer(path: &Path) -> Result<Keypair, String> {
    refuse_a_readable_key(path)?;
    let raw = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut bytes = Vec::new();
    for field in raw
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split(',')
        .filter(|s| !s.trim().is_empty())
    {
        bytes.push(
            field
                .trim()
                .parse::<u8>()
                .map_err(|e| format!("{}: {e}", path.display()))?,
        );
    }
    Keypair::try_from(&bytes[..]).map_err(|e| format!("{}: {e:?}", path.display()))
}

/// The root for one epoch, from a handoff this worker verified itself.
///
/// **The worker publishes nothing it cannot verify.** A handoff is a file, and without the signature
/// anything able to write that file would choose what the log publishes (D-139).
fn root_for(config: &Config, epoch: u64) -> Result<Digest, String> {
    let path = config.handoffs.join(format!("{epoch}.handoff"));
    let bytes = std::fs::read(&path).map_err(|e| {
        format!(
            "{}: {e}. The worker does not build roots and will not invent one (D-139).",
            path.display()
        )
    })?;
    let handoff = Handoff::decode(&bytes).map_err(|e| format!("{}: {e:?}", path.display()))?;
    handoff
        .verify::<DalekVerifier>(&config.batcher_key, epoch)
        .map_err(|e| format!("{}: {e:?}", path.display()))
}

/// What the worker can see: the log's own configuration, and which epochs it has stamped.
fn observe(
    cluster: &Cluster,
    anchor_b: &ReferenceClient,
    now: i64,
    today: u64,
) -> Result<Observed, String> {
    let lag = sequence_lag(cluster, &cluster.program_id(), today, today)
        .map_err(|e| format!("the log's configuration: {e:?}"))?;

    // The highest epoch whose receipt exists on disk, and the lowest the chain still calls single.
    // An epoch with a receipt that the chain reports as single is one waiting to attach.
    let mut last_submitted = None;
    let mut awaiting_attach = None;
    let mut epoch = lag.start_epoch;
    while epoch <= lag.last_published {
        if anchor_b.receipt_path(epoch).exists() {
            last_submitted = Some(epoch);
            if awaiting_attach.is_none() {
                match cluster.status(epoch) {
                    Ok(AnchorStatus::Single) => awaiting_attach = Some(epoch),
                    Ok(_) => {}
                    Err(e) => return Err(format!("epoch {epoch}'s status: {e:?}")),
                }
            }
        }
        epoch = match epoch.checked_add(1) {
            Some(next) => next,
            None => break,
        };
    }

    Ok(Observed {
        now,
        today,
        start_epoch: lag.start_epoch,
        last_epoch: lag.last_published,
        awaiting_attach,
        last_submitted,
    })
}

/// When the pending receipt was lodged with the calendars, from the file this worker wrote.
///
/// Its modification time is the only record of the submission instant there is: the calendars are
/// asked again on every cycle and answer about the receipt, not about when it was handed over. A
/// missing or unreadable receipt gives `None`, which makes `ReceiptUnconfirmed` unraisable rather
/// than raisable against a time of zero — an unknown age must not read as an infinite one.
///
/// The split of the five conditions between this process and the service manager lives in
/// `Supervision::from_worker`, with the test that pins it.
fn receipt_submitted_at(anchor_b: &ReferenceClient, observed: &Observed) -> Option<i64> {
    let epoch = observed.awaiting_attach?;
    let path = anchor_b.receipt_path(epoch);
    let modified = std::fs::metadata(&path).and_then(|m| m.modified()).ok()?;
    let since = modified.duration_since(UNIX_EPOCH).ok()?;
    i64::try_from(since.as_secs()).ok()
}

/// Why the worker stopped, in the terms the record uses.
fn why(refusal: Refusal) -> String {
    match refusal {
        Refusal::LogAheadOfCalendar { last_epoch, today } => format!(
            "the log's last epoch is {last_epoch} and today is day {today}. An epoch is a UTC day \
             index, so a log ahead of the calendar is not early, it is wrong, and the next \
             publication could only deepen it. This is the state that cost an earlier deployment \
             209 days (D-88)."
        ),
        Refusal::LastBeforeStart {
            last_epoch,
            start_epoch,
        } => format!(
            "the configuration reports last_epoch {last_epoch} below start_epoch {start_epoch}, \
             which no sequence this program writes can produce. Either the observation is wrong or \
             the account is not this log's."
        ),
        Refusal::Unschedulable { epoch } => {
            format!("epoch {epoch} has no publication time the schedule can represent.")
        }
        Refusal::EpochSlipExceeded {
            last_epoch,
            today,
            max_epoch_slip,
        } => format!(
            "the log's last epoch is {last_epoch} and today is {today}, beyond the unattended \
             recovery limit of {max_epoch_slip}. Reconcile the first missing epoch and obtain an \
             operator ruling before replaying a wider backlog."
        ),
        Refusal::AwaitingAttachOutsideLog {
            awaiting_attach,
            start_epoch,
            last_epoch,
        } => format!(
            "the receipt state awaits epoch {awaiting_attach}, outside the published log range \
             {start_epoch}..={last_epoch}."
        ),
        Refusal::SubmissionAheadOfLog {
            last_submitted,
            last_epoch,
        } => format!(
            "the receipt state claims submission through epoch {last_submitted}, ahead of the log's \
             last epoch {last_epoch}."
        ),
        Refusal::AttachmentAheadOfSubmission {
            awaiting_attach,
            last_submitted,
        } => format!(
            "epoch {awaiting_attach} awaits attachment but the submission record ends at \
             {last_submitted:?}."
        ),
    }
}

fn retry_partition(
    policy: WorkerPolicy,
    consecutive_failures: &mut u32,
    operation: &str,
    error: &str,
) -> Result<(), String> {
    *consecutive_failures = consecutive_failures.saturating_add(1);
    let Some(delay) = policy.partition_retry_delay(*consecutive_failures) else {
        return Err(format!(
            "{operation}: {error}; partition retry budget of {} exhausted",
            policy.partition_retry_limit
        ));
    };
    eprintln!(
        "anchor-b-worker: {operation}: {error}; re-observing after {}s ({}/{})",
        delay.as_secs(),
        *consecutive_failures,
        policy.partition_retry_limit
    );
    std::thread::sleep(delay);
    Ok(())
}

fn run() -> Result<(), String> {
    let config = Config::from_env()?;
    let policy = WorkerPolicy::PRODUCTION;

    // **Before anything reaches a cluster or a calendar.** D-117: the worker refuses to start on a
    // key it should not read. Both keys, because a readable payer is the same disclosure as a
    // readable authority.
    let authority = signer(&config.authority)?;
    let payer = signer(&config.payer)?;

    let anchor_b = ReferenceClient {
        executable: config.ots.clone(),
        receipts: config.receipts.clone(),
    };
    // The pin exists to be asked. Four versions of this check were wrong before the current one, each
    // looser than it looked, and a fake reporting v9.9.9 once completed a submission.
    let version = anchor_b.check_version()?;
    // And what it *is*, not only what it says (H-17). A self-report can be framed; a wrapper that
    // prints the right bytes and shells out elsewhere passes the line above and fails this one.
    let pinned = anchor_b.check_fingerprint()?;

    let cluster = Cluster::new_with_timeout(
        config.rpc.clone(),
        certimining_checkpoint::ID,
        policy.rpc_timeout,
    );
    println!("anchor-b-worker: program  {}", cluster.program_id());
    println!("anchor-b-worker: ots      {version}, {pinned} sources matching OTS-CLIENT.sha256");
    println!("anchor-b-worker: handoffs {}", config.handoffs.display());
    println!("anchor-b-worker: receipts {}", config.receipts.display());
    println!(
        "anchor-b-worker: batcher  {}",
        config
            .batcher_key
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );

    // **Readiness, after the checks that would refuse to start and not before (H-95, issue #300).**
    // `Type=notify` holds the unit in `activating` until this arrives, so a process that announced
    // readiness and then exited on a custody fault would have reported itself healthy for the
    // interval in between. Everything above this line is a refusal that must happen first.
    //
    // An unset `NOTIFY_SOCKET` is the ordinary state of a worker run by hand and is not a failure. It
    // is printed either way, because a worker that silently skipped its watchdog would look exactly
    // like one whose watchdog works.
    match notify::ready("starting the anchor-B cycle") {
        Ok(()) => println!("anchor-b-worker: notified the service manager that it is ready"),
        Err(e) => println!("anchor-b-worker: no readiness notification sent — {e}"),
    }

    // **Whether the configured watchdog can be satisfied by this worker's own cadence.** A
    // `WatchdogSec` shorter than one poll interval plus one RPC timeout kills a healthy worker on
    // schedule, and that is a watchdog configured without reference to the thing it watches. The
    // numbers are printed rather than assumed sound, so the unit file can be read against them.
    let cadence = policy.poll_interval.saturating_add(policy.rpc_timeout);
    match notify::watchdog_interval() {
        Some(interval) if interval <= cadence => println!(
            "anchor-b-worker: WARNING WatchdogSec is {}s and one cycle can take {}s (poll {} plus \
             rpc timeout {}). A healthy worker will be killed on schedule; raise WatchdogSec.",
            interval.as_secs(),
            cadence.as_secs(),
            policy.poll_interval.as_secs(),
            policy.rpc_timeout.as_secs()
        ),
        Some(interval) => println!(
            "anchor-b-worker: watchdog {}s, one cycle at most {}s",
            interval.as_secs(),
            cadence.as_secs()
        ),
        None => println!(
            "anchor-b-worker: no WATCHDOG_USEC, so ProcessSilent is raised by nothing for this run"
        ),
    }

    let mut consecutive_failures = 0u32;
    loop {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("a clock before 1970: {e}"))?
            .as_secs();
        let now = i64::try_from(seconds).map_err(|e| format!("a clock beyond i64: {e}"))?;
        let today = day_index(now).ok_or("a clock before 1970 has no day index")?;

        let observed = match observe(&cluster, &anchor_b, now, today) {
            Ok(observed) => {
                consecutive_failures = 0;
                observed
            }
            Err(error) => {
                retry_partition(
                    policy,
                    &mut consecutive_failures,
                    "fresh state observation failed",
                    &error,
                )?;
                continue;
            }
        };

        // **The three supervision conditions this process can see (H-95, issue #300).** Before this,
        // `alerts()` was called by nothing outside its own test module: it computed five conditions
        // against committed thresholds, passed eleven tests, and no operator could ever have been
        // told any of them. `RUNBOOK-WORKER-RECOVERY.md` was keyed on alerts nothing raised.
        let supervision = Supervision::from_worker(now, receipt_submitted_at(&anchor_b, &observed));
        for alert in alerts(
            Schedule::DEPLOYED,
            &observed,
            &supervision,
            Thresholds::DEPLOYED,
        ) {
            eprintln!("anchor-b-worker: ALERT {alert}");
        }

        // **The watchdog is fed here and not at the top of the loop.** A keepalive sent before the
        // work of a cycle reports only that the process was scheduled. Feeding it where the chain was
        // read means a worker that cannot see the chain stops feeding and `WatchdogSec` fires, which
        // is what `ProcessSilent` is for. The observation failure above continues without feeding,
        // deliberately.
        if let Err(e) = notify::alive(&format!(
            "epoch {} published, day {}",
            observed.last_epoch, observed.today
        )) {
            if !matches!(e, notify::Refused::NotSupervised) {
                eprintln!("anchor-b-worker: watchdog not fed — {e}");
            }
        }

        match next_step_with_policy(Schedule::DEPLOYED, &observed, policy) {
            Step::Refuse(r) => return Err(why(r)),

            Step::Wait { until } => {
                let ahead = until.saturating_sub(now).max(0);
                consecutive_failures = 0;
                let nap = Duration::from_secs(u64::try_from(ahead).unwrap_or(0))
                    .min(policy.poll_interval);
                println!("anchor-b-worker: nothing due, {ahead}s until the next publication time");
                std::thread::sleep(nap);
            }

            Step::Publish { epoch } => {
                let root = root_for(&config, epoch)?;
                let anchored = match cluster.publish(
                    epoch,
                    root,
                    &payer,
                    &authority,
                    policy.publish_attempts.saturating_sub(1),
                ) {
                    Ok(anchored) => anchored,
                    Err(PublishFailed::OutOfAttempts | PublishFailed::Unreachable(_)) => {
                        retry_partition(
                            policy,
                            &mut consecutive_failures,
                            "checkpoint publication did not settle",
                            &format!("epoch {epoch}"),
                        )?;
                        continue;
                    }
                    Err(error) => return Err(format!("epoch {epoch}: {error:?}")),
                };
                consecutive_failures = 0;
                println!(
                    "anchor-b-worker: published epoch {epoch}, slot {}, signature {}",
                    anchored.published_slot, anchored.signature
                );
            }

            Step::Submit { epoch } => {
                let root = root_for(&config, epoch)?;
                let pending = match anchor_b.submit(epoch, &root) {
                    Ok(pending) => pending,
                    Err(error) => {
                        retry_partition(
                            policy,
                            &mut consecutive_failures,
                            "calendar submission failed",
                            &format!("epoch {epoch}: {error}"),
                        )?;
                        continue;
                    }
                };
                consecutive_failures = 0;
                println!(
                    "anchor-b-worker: stamped epoch {epoch}, receipt at {}",
                    pending.path.display()
                );
            }

            Step::Attach { epoch } => {
                let root = root_for(&config, epoch)?;
                let pending = PendingReceipt {
                    epoch,
                    root,
                    path: anchor_b.receipt_path(epoch),
                };
                match anchor_b.upgrade(&pending) {
                    // **Not a failure.** INV-ANCH-04 budgets hours for Bitcoin, and the attach field
                    // is write-once (D-112): attaching a calendar's promise would spend the single
                    // opportunity on something nothing outside OpenTimestamps stands behind.
                    Ok(None) => {
                        println!(
                            "anchor-b-worker: epoch {epoch} is single; Bitcoin has not confirmed yet"
                        );
                        consecutive_failures = 0;
                        std::thread::sleep(policy.poll_interval);
                    }
                    Ok(Some(_)) => {
                        let receipt = std::fs::read(&pending.path)
                            .map_err(|e| format!("{}: {e}", pending.path.display()))?;
                        let (digest, claim) =
                            match cluster.attach(epoch, &receipt, &payer, &authority) {
                                Ok(attached) => attached,
                                Err(AttachRefused::Cluster(error)) => {
                                    retry_partition(
                                        policy,
                                        &mut consecutive_failures,
                                        "receipt attachment did not settle",
                                        &format!("epoch {epoch}: {error}"),
                                    )?;
                                    continue;
                                }
                                Err(error) => return Err(format!("epoch {epoch}: {error:?}")),
                            };
                        consecutive_failures = 0;
                        println!(
                            "anchor-b-worker: attached epoch {epoch}, block {}, digest {}",
                            claim.height,
                            digest
                                .iter()
                                .map(|b| format!("{b:02x}"))
                                .collect::<String>()
                        );
                    }
                    Err(error) => {
                        retry_partition(
                            policy,
                            &mut consecutive_failures,
                            "receipt upgrade failed",
                            &format!("epoch {epoch}: {error}"),
                        )?;
                        continue;
                    }
                }
            }
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("anchor-b-worker: {e}");
            eprintln!(
                "anchor-b-worker: stopping rather than continuing on a state it must not act on."
            );
            ExitCode::FAILURE
        }
    }
}
