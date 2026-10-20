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
//! entirely on that key's custody; D-117 makes the checkpoint authority the one key that runs
//! unattended, and it can be, because compromising it buys a wrong root rather than the retrospective
//! record count of every epoch the log has published.
//!
//! ```text
//! CERTIMINING_RPC=https://api.devnet.solana.com \
//! CERTIMINING_BATCHER_KEY=<64 hex characters> \
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
    cluster::Cluster, day_index, next_step, refuse_a_readable_key, sequence_lag, AnchorB,
    AnchorStatus, Handoff, Observed, PendingReceipt, ReferenceClient, Refusal, Schedule, Step,
};
use certimining_core::{DalekVerifier, Digest};
use solana_keypair::Keypair;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The longest the worker sleeps before looking at the world again.
///
/// A step may say to wait until tomorrow; waking sooner costs one account read and means stopping
/// the process does not take a day to be noticed.
const MAX_SLEEP: Duration = Duration::from_secs(300);

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
        let base = PathBuf::from(&home).join(".config/certimining");
        Ok(Self {
            rpc: env("CERTIMINING_RPC")?,
            authority: base.join("checkpoint-authority.json"),
            payer: base.join("deploy-keypair.json"),
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
    }
}

fn run() -> Result<(), String> {
    let config = Config::from_env()?;

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

    let cluster = Cluster::new(config.rpc.clone(), certimining_checkpoint::ID);
    println!("anchor-b-worker: program  {}", cluster.program_id());
    println!("anchor-b-worker: ots      {version}");
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

    loop {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("a clock before 1970: {e}"))?
            .as_secs();
        let now = i64::try_from(seconds).map_err(|e| format!("a clock beyond i64: {e}"))?;
        let today = day_index(now).ok_or("a clock before 1970 has no day index")?;

        let observed = observe(&cluster, &anchor_b, now, today)?;

        match next_step(Schedule::DEPLOYED, &observed) {
            Step::Refuse(r) => return Err(why(r)),

            Step::Wait { until } => {
                let ahead = until.saturating_sub(now).max(0);
                let nap = Duration::from_secs(u64::try_from(ahead).unwrap_or(0)).min(MAX_SLEEP);
                println!("anchor-b-worker: nothing due, {ahead}s until the next publication time");
                std::thread::sleep(nap);
            }

            Step::Publish { epoch } => {
                let root = root_for(&config, epoch)?;
                let anchored = cluster
                    .publish(epoch, root, &payer, &authority, 3)
                    .map_err(|e| format!("epoch {epoch}: {e:?}"))?;
                println!(
                    "anchor-b-worker: published epoch {epoch}, slot {}, signature {}",
                    anchored.published_slot, anchored.signature
                );
            }

            Step::Submit { epoch } => {
                let root = root_for(&config, epoch)?;
                let pending = anchor_b
                    .submit(epoch, &root)
                    .map_err(|e| format!("epoch {epoch}: {e}"))?;
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
                        std::thread::sleep(MAX_SLEEP);
                    }
                    Ok(Some(_)) => {
                        let receipt = std::fs::read(&pending.path)
                            .map_err(|e| format!("{}: {e}", pending.path.display()))?;
                        let (digest, claim) = cluster
                            .attach(epoch, &receipt, &payer, &authority)
                            .map_err(|e| format!("epoch {epoch}: {e:?}"))?;
                        println!(
                            "anchor-b-worker: attached epoch {epoch}, block {}, digest {}",
                            claim.height,
                            digest
                                .iter()
                                .map(|b| format!("{b:02x}"))
                                .collect::<String>()
                        );
                    }
                    Err(e) => return Err(format!("epoch {epoch}: {e}")),
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
