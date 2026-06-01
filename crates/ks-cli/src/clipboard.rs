//! Clipboard write with automatic timed clear.
//!
//! The timed clear runs in a **detached child process**, never a background
//! thread: this CLI is short-lived, so a thread would die the instant the command
//! returns and the secret would linger on the clipboard forever. The helper
//! re-executes this same binary as `ks __clipclear <secs>`, receiving the value
//! over **stdin** (never argv or the environment, both readable by same-user
//! processes), then clears the clipboard after the TTL only if it still holds
//! that value.
//!
//! Who *sets* the clipboard differs by platform, because their clipboard
//! ownership models are opposite:
//!
//! - **Windows**: the clipboard is global and survives the writing process, but a
//!   spawned helper writes to an isolated window-station clipboard the user's
//!   session never sees. So the invoking process (which is on the interactive
//!   station) sets the value, and the helper only waits and clears. The helper
//!   must NOT hold the clipboard open while waiting — an open clipboard blocks
//!   every other process, including the user's paste.
//! - **X11/Wayland**: the clipboard's contents live only as long as the owning
//!   process, so the helper must set the value AND stay alive to serve it for the
//!   whole TTL before clearing.

use std::io::Write as _;
use std::process::{Command, Stdio};
use std::time::Duration;

use arboard::Clipboard;
use ks::{Error, Result};

/// Hidden subcommand name for the detached clear helper (handled in `main`).
pub const CLEAR_ARG: &str = "__clipclear";

/// Copies `value` to the system clipboard for `clear_secs` seconds, then arranges
/// for it to be cleared (see the module docs for the platform split).
///
/// Returns the configured `clear_secs` for display.
///
/// # Errors
/// Returns [`Error::Io`] if neither the helper nor the in-process fallback can
/// reach the system clipboard.
pub fn copy_with_autoclear(value: &str, clear_secs: u64) -> Result<u64> {
    // On Windows the value must be placed by this interactive-station process; the
    // helper only clears. On X11 the helper sets and holds. See module docs.
    let set_here = cfg!(windows);
    if set_here {
        let mut cb = Clipboard::new().map_err(clip_err)?;
        cb.set_text(value.to_owned()).map_err(clip_err)?;
    }

    if spawn_helper(value, clear_secs) {
        return Ok(clear_secs);
    }

    // Fallback when the helper cannot be spawned: make sure the value is at least
    // on the clipboard. The timed clear is then best-effort only.
    if !set_here {
        let mut cb = Clipboard::new().map_err(clip_err)?;
        cb.set_text(value.to_owned()).map_err(clip_err)?;
    }
    Ok(clear_secs)
}

/// Spawns the detached `ks __clipclear <secs>` helper, handing it the value over
/// stdin. Returns `true` if the helper was launched.
fn spawn_helper(value: &str, clear_secs: u64) -> bool {
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    let mut cmd = Command::new(exe);
    cmd.arg(CLEAR_ARG)
        .arg(clear_secs.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    detach(&mut cmd);
    // Deliberately not waited on: the helper outlives us and clears on its own.
    if let Ok(mut child) = cmd.spawn()
        && let Some(mut stdin) = child.stdin.take()
    {
        stdin.write_all(value.as_bytes()).ok();
        drop(stdin);
        return true;
    }
    false
}

/// Entry point for the detached helper (`ks __clipclear <secs>`): reads the value
/// from stdin, then clears the clipboard after `secs` **only if** it still holds
/// that value (so we never discard something the user copied since).
///
/// On non-Windows it also (re)sets the value first and holds it for the whole TTL,
/// because X11 clipboards live only as long as their owning process. On Windows
/// the invoking process already placed the value on the shared clipboard. Silent.
pub fn run_clear_daemon(secs: u64) {
    use std::io::Read as _;
    let mut value = String::new();
    if std::io::stdin().read_to_string(&mut value).is_err() {
        return;
    }

    #[cfg(windows)]
    {
        // The invoking process already placed the value on the shared clipboard.
        // Crucially we must NOT keep a `Clipboard` open while waiting: on Windows
        // an open clipboard blocks every other process (including the user's
        // paste) from reading it. So wait first, then open only to clear.
        wait(secs);
        if let Ok(mut cb) = Clipboard::new()
            && let Ok(current) = cb.get_text()
            && current == value
        {
            cb.set_text(String::new()).ok();
        }
    }

    #[cfg(not(windows))]
    {
        // X11/Wayland: clipboard contents live only as long as the owning process,
        // so we must set the value and keep this process (and the owning
        // `Clipboard`) alive for the whole TTL before clearing.
        let Ok(mut cb) = Clipboard::new() else { return };
        if cb.set_text(value.clone()).is_err() {
            return;
        }
        wait(secs);
        if let Ok(current) = cb.get_text()
            && current == value
        {
            cb.set_text(String::new()).ok();
        }
        drop(cb);
    }
}

fn wait(secs: u64) {
    #[expect(
        clippy::disallowed_methods,
        reason = "this helper process exists solely to wait out the clipboard TTL; a blocking sleep is the whole point"
    )]
    std::thread::sleep(Duration::from_secs(secs));
}

fn clip_err(e: impl std::fmt::Display) -> Error {
    Error::Io(std::io::Error::other(e.to_string()))
}

/// Detaches `cmd` so it survives this process exiting and shell job control.
#[cfg(unix)]
fn detach(cmd: &mut Command) {
    use std::os::unix::process::CommandExt as _;
    // A new process group detaches the child from the terminal's job control,
    // so Ctrl-C in the parent shell will not also kill the pending clear.
    cmd.process_group(0);
}

#[cfg(windows)]
fn detach(cmd: &mut Command) {
    use std::os::windows::process::CommandExt as _;
    // CREATE_NO_WINDOW: the helper runs without flashing a console window. It still
    // inherits our interactive window station (so it can clear the same clipboard
    // the user sees) and, like every Windows child, outlives this process.
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    cmd.creation_flags(CREATE_NO_WINDOW);
}

#[cfg(not(any(unix, windows)))]
fn detach(_cmd: &mut Command) {}
