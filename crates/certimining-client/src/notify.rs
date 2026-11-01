// SPDX-License-Identifier: MIT OR Apache-2.0
//! The service manager's readiness and watchdog channel (H-95, issue #300).
//!
//! **Why this exists.** `alert.rs` computes five supervision conditions and three of them are facts
//! about the log, derivable inside the worker's own loop. The other two are facts about the *process*
//! and cannot honestly be raised from inside it: a live process cannot report its own silence, and a
//! process that exits on its first refusal cannot count three in a row. The owner's ruling of
//! 1 November 2026 puts those two where the operating system already tracks them — `WatchdogSec` with
//! `sd_notify` for `ProcessSilent`, and `Restart=on-failure` with `StartLimitBurst=3` and `OnFailure=`
//! for `RepeatedRefusal` — and this module is the worker's half of the first one.
//!
//! **The protocol, which is small enough to implement rather than depend on.** `sd_notify` writes a
//! datagram of newline-separated `KEY=value` lines to the `AF_UNIX` socket named by `NOTIFY_SOCKET`.
//! `READY=1` answers `Type=notify`; `WATCHDOG=1` resets the `WatchdogSec` timer. `std` has
//! `UnixDatagram`, so no crate enters the dependency graph and neither the licence nor the advisory
//! gate gains a line to clear.
//!
//! **The one thing `std` cannot reach, said rather than hidden.** A `NOTIFY_SOCKET` beginning `@` is
//! in Linux's abstract namespace, whose address is a leading NUL byte that `Path` cannot carry, and
//! reaching it needs `libc` — which this crate forbids by `#![forbid(unsafe_code)]`. systemd writes a
//! filesystem path for a service's notify socket, so this is a configuration this deployment does not
//! produce; it is refused by name instead of being treated as a successful send. A watchdog fed by a
//! call that silently did nothing is the defect class this module was written under.
//!
//! **Unix only, and unconditionally so.** There is no `cfg(not(unix))` fallback, because
//! `cargo metadata`'s own coverage gate refuses a `cfg` operator it cannot reduce to a feature set
//! and fails closed rather than under-count the tests behind it — which it did to the first version
//! of this module, correctly. Nothing builds this crate for a non-Unix target: the bare-metal target
//! is `certimining-core`, the deployment is Linux and the development hosts are macOS, so a second
//! implementation would be unreachable code kept honest by nobody. A port would add the `cfg` back
//! deliberately and teach the gate the operator in the same change.
//!
//! **An unset `NOTIFY_SOCKET` is not an error and is not success either.** It means the worker is not
//! running under a service manager, which is the ordinary case for a developer running it by hand.
//! `Refused::NotSupervised` says so, and the caller is expected to print it once, because a worker
//! that silently skips its watchdog is indistinguishable from one whose watchdog works.

use std::path::{Path, PathBuf};

/// Why a notification did not reach a service manager.
///
/// Every arm is a thing the caller should say out loud. None of them is a reason to stop working: a
/// worker with no watchdog still publishes, it just is not supervised, and the operator needs to know
/// which of those two they have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// `NOTIFY_SOCKET` is unset or empty: there is no service manager listening. The ordinary state
    /// of a worker run by hand.
    NotSupervised,
    /// `NOTIFY_SOCKET` names a socket in Linux's abstract namespace, which needs a leading NUL byte
    /// that `Path` cannot express and `libc` to send. Refused rather than reported as sent.
    AbstractSocket(String),
    /// The socket is named and a filesystem path, and writing to it failed.
    Unwritable { path: String, error: String },
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotSupervised => write!(
                f,
                "NOTIFY_SOCKET is unset, so no service manager is listening and this process has no \
                 watchdog. ProcessSilent cannot be raised for it."
            ),
            Self::AbstractSocket(raw) => write!(
                f,
                "NOTIFY_SOCKET is {raw:?}, an abstract-namespace socket. Reaching it needs a leading \
                 NUL address and libc, which this crate forbids, so nothing was sent. Configure the \
                 unit so systemd supplies a filesystem path."
            ),
            Self::Unwritable { path, error } => {
                write!(f, "NOTIFY_SOCKET {path:?} could not be written: {error}")
            }
        }
    }
}

/// The socket a raw `NOTIFY_SOCKET` value names.
///
/// Pure, so the three refusals above are decided by a test rather than by arranging process
/// environment, which is global and cannot be varied safely by a test running beside others.
fn socket_from(raw: &str) -> Result<PathBuf, Refused> {
    if raw.is_empty() {
        return Err(Refused::NotSupervised);
    }
    if raw.starts_with('@') {
        return Err(Refused::AbstractSocket(raw.to_owned()));
    }
    Ok(PathBuf::from(raw))
}

/// Sends one datagram to a named socket.
///
/// Separate from the environment so that the test below is a real round trip against a real socket
/// rather than an assertion about a predicate. That distinction is the whole of H-95: `alert.rs`
/// passed eleven tests while nothing called it.
pub fn send_to(socket: &Path, message: &str) -> Result<(), Refused> {
    use std::os::unix::net::UnixDatagram;

    let unbound = UnixDatagram::unbound().map_err(|e| Refused::Unwritable {
        path: socket.display().to_string(),
        error: e.to_string(),
    })?;
    unbound
        .send_to(message.as_bytes(), socket)
        .map_err(|e| Refused::Unwritable {
            path: socket.display().to_string(),
            error: e.to_string(),
        })?;
    Ok(())
}

/// Sends `lines` to whatever `NOTIFY_SOCKET` names.
pub fn notify(lines: &str) -> Result<(), Refused> {
    let raw = std::env::var("NOTIFY_SOCKET").unwrap_or_default();
    let socket = socket_from(&raw)?;
    send_to(&socket, lines)
}

/// `READY=1` with a status line, which answers `Type=notify`.
///
/// Until this arrives systemd holds the unit in `activating`, so `OnFailure=` and the ordering of
/// anything `After=` this unit are both waiting on it. It is sent once the worker has finished the
/// checks that would make it refuse to start, and not before: a process that announced readiness and
/// then exited on a custody fault would have reported itself healthy for the interval in between.
pub fn ready(status: &str) -> Result<(), Refused> {
    notify(&format!("READY=1\nSTATUS={status}\n"))
}

/// `WATCHDOG=1` with a status line, which resets `WatchdogSec`.
///
/// **Sent after a successful observation, never at the top of the loop.** A keepalive sent before the
/// work of a cycle reports that the process is scheduled, which is not what `ProcessSilent` is for —
/// a worker spinning on a retry path it cannot leave would feed the watchdog indefinitely while
/// making no progress, and the watchdog would be an instrument that passes by looking at nothing.
/// Feeding it only where the chain was read means a worker that cannot see the chain stops feeding
/// and `WatchdogSec` fires, which is the condition an operator needs to hear about.
pub fn alive(status: &str) -> Result<(), Refused> {
    notify(&format!("WATCHDOG=1\nSTATUS={status}\n"))
}

/// The watchdog interval systemd set, from `WATCHDOG_USEC`.
///
/// Reported so the worker can say whether its own cadence can satisfy it. A `WatchdogSec` shorter
/// than one poll interval plus one RPC timeout would kill a healthy worker on schedule, which is the
/// failure mode of a watchdog configured without reference to the thing it watches, so the number is
/// printed at start rather than assumed to be sound.
pub fn watchdog_interval() -> Option<std::time::Duration> {
    let raw = std::env::var("WATCHDOG_USEC").ok()?;
    let micros: u64 = raw.trim().parse().ok()?;
    Some(std::time::Duration::from_micros(micros))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unset_socket_is_not_supervised_rather_than_an_error() {
        assert_eq!(socket_from(""), Err(Refused::NotSupervised));
    }

    /// **The configuration `std` cannot reach.** It must be refused by name: a watchdog whose feed
    /// silently did nothing is worse than one that is absent, because the absence is visible.
    #[test]
    fn an_abstract_socket_is_refused_and_not_reported_as_sent() {
        let refused = socket_from("@/org/freedesktop/systemd1/notify");
        assert_eq!(
            refused,
            Err(Refused::AbstractSocket(
                "@/org/freedesktop/systemd1/notify".to_owned()
            ))
        );
        let rendered = match refused {
            Err(e) => e.to_string(),
            Ok(_) => panic!("an abstract socket must not parse as a path"),
        };
        assert!(
            rendered.contains("nothing was sent"),
            "the operator has to be told nothing was sent: {rendered}"
        );
    }

    #[test]
    fn a_filesystem_path_is_the_socket_it_names() {
        assert_eq!(
            socket_from("/run/systemd/notify"),
            Ok(PathBuf::from("/run/systemd/notify"))
        );
    }

    /// **A real datagram to a real socket**, which is the point. H-95 was a module whose eleven tests
    /// all passed while nothing called it, so this one binds a socket, sends through the same
    /// function the worker calls, and reads the bytes back.
    ///
    /// Under `/tmp` rather than `std::env::temp_dir()` because a `sockaddr_un` path is capped near
    /// 104 bytes and macOS puts the temporary directory under a long `/var/folders/…` prefix. A test
    /// that skipped itself on a long path would be the thing this module exists to stop.
    #[test]
    fn a_notification_arrives_at_the_socket_it_names() {
        use std::os::unix::net::UnixDatagram;

        let dir = PathBuf::from(format!("/tmp/certimining-h95-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        match std::fs::create_dir_all(&dir) {
            Ok(()) => {}
            Err(e) => panic!("{}: {e}", dir.display()),
        }
        let socket_path = dir.join("notify");

        let listener = match UnixDatagram::bind(&socket_path) {
            Ok(listener) => listener,
            Err(e) => panic!("{}: {e}", socket_path.display()),
        };

        match send_to(&socket_path, "WATCHDOG=1\nSTATUS=epoch 20745 published\n") {
            Ok(()) => {}
            Err(e) => panic!("the send must reach a socket that exists: {e}"),
        }

        let mut buf = [0u8; 256];
        let read = match listener.recv(&mut buf) {
            Ok(read) => read,
            Err(e) => panic!("the datagram must arrive: {e}"),
        };
        let got = match buf.get(..read) {
            Some(bytes) => String::from_utf8_lossy(bytes).into_owned(),
            None => panic!("the read length is within the buffer by construction"),
        };
        assert_eq!(got, "WATCHDOG=1\nSTATUS=epoch 20745 published\n");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A socket nothing is listening on is a failure the caller reports, not a panic and not a
    /// silent success.
    #[test]
    fn a_socket_that_does_not_exist_is_unwritable_rather_than_fine() {
        let missing = PathBuf::from(format!(
            "/tmp/certimining-h95-absent-{}/notify",
            std::process::id()
        ));
        match send_to(&missing, "WATCHDOG=1\n") {
            Err(Refused::Unwritable { .. }) => {}
            other => panic!("writing to a socket that is not there must be refused: {other:?}"),
        }
    }
}
