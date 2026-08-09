//! Best-effort, process-wide hardening that keeps decrypted secrets off disk.
//!
//! [`harden`] is called once at startup and returns a [`HardenStatus`] recording
//! each measure. Failures are non-fatal by default (defence-in-depth on top of
//! `Zeroizing`/`secrecy`). With `KS_STRICT_HARDEN=1`, Unix core-dump disable and
//! debugger denial failures abort startup; mlock never fails closed (containers
//! without `CAP_IPC_LOCK`).
//!
//! Coverage by platform:
//!
//! - **Unix:** disables core dumps (`RLIMIT_CORE = 0`), locks pages into RAM
//!   (`mlockall`), and blocks debugger attachment (Linux `PR_SET_DUMPABLE=0`,
//!   macOS `PT_DENY_ATTACH` in release builds).
//! - **Windows:** suppresses the Windows Error Reporting crash dialog and fault
//!   dump (`SetErrorMode`). No process-wide page lock (documented exemption).
//!
//! All FFI lives in this module so the rest of the workspace stays
//! `#![deny(unsafe_code)]`.
#![allow(
    unsafe_code,
    reason = "process hardening (core-dump, swap, ptrace, crash-dump policy) requires libc / Windows FFI; every call is audited and documented with a SAFETY note"
)]

use std::sync::OnceLock;

/// Global status set once from `main` before clap.
static HARDEN: OnceLock<HardenStatus> = OnceLock::new();

/// Outcome of a single hardening measure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Measure {
    /// Measure applied successfully.
    Applied,
    /// Not applicable on this platform/build (with reason).
    Skipped(&'static str),
    /// Attempted but failed (with short reason).
    Failed(String),
}

impl Measure {
    /// Returns `true` if the measure is in a healthy (Applied or intentional Skipped) state.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        matches!(self, Self::Applied | Self::Skipped(_))
    }

    /// Human-readable status token.
    #[must_use]
    pub fn detail(&self) -> String {
        match self {
            Self::Applied => "applied".to_owned(),
            Self::Skipped(reason) => format!("skipped ({reason})"),
            Self::Failed(reason) => format!("failed ({reason})"),
        }
    }
}

/// Aggregate hardening status for the current process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardenStatus {
    /// Core dump suppression (`RLIMIT_CORE=0` / Windows error mode).
    pub core_dump: Measure,
    /// Memory lock (`mlockall` / skipped on Windows).
    pub mlock: Measure,
    /// Debugger attachment denial.
    pub debugger_deny: Measure,
    /// Platform label for doctor output.
    pub platform: &'static str,
}

impl HardenStatus {
    /// Returns `true` if strict mode would accept this status on Unix.
    ///
    /// Critical measures: `core_dump` and `debugger_deny` must not be `Failed`.
    /// `mlock` failures are never fatal.
    #[must_use]
    pub const fn satisfies_strict(&self) -> bool {
        !matches!(self.core_dump, Measure::Failed(_))
            && !matches!(self.debugger_deny, Measure::Failed(_))
    }
}

/// Applies all available hardening and stores the result in [`HARDEN`].
///
/// Returns a reference to the stored status. Subsequent calls return the same
/// status without re-applying (idempotent for the process lifetime).
pub fn harden() -> &'static HardenStatus {
    HARDEN.get_or_init(|| {
        #[cfg(unix)]
        {
            unix::harden()
        }
        #[cfg(windows)]
        {
            windows::harden()
        }
        #[cfg(not(any(unix, windows)))]
        {
            HardenStatus {
                core_dump: Measure::Skipped("unsupported platform"),
                mlock: Measure::Skipped("unsupported platform"),
                debugger_deny: Measure::Skipped("unsupported platform"),
                platform: "unknown",
            }
        }
    })
}

/// Returns the status from a prior [`harden`] call, if any.
#[must_use]
pub fn status() -> Option<&'static HardenStatus> {
    HARDEN.get()
}

/// Whether `KS_STRICT_HARDEN` is set to a truthy value.
#[must_use]
pub fn strict_requested() -> bool {
    matches!(
        std::env::var("KS_STRICT_HARDEN").as_deref(),
        Ok("1" | "true" | "TRUE" | "yes" | "YES")
    )
}

/// Reads an environment variable and removes it from the process environment,
/// returning its value if it was set and non-empty.
///
/// Must be called while the process is still single-threaded.
#[must_use]
#[allow(
    clippy::disallowed_methods,
    reason = "clearing a passphrase from the env is the intended security action here, and is safe because the process is single-threaded at call time"
)]
pub fn take_env(name: &str) -> Option<String> {
    let value = std::env::var(name).ok().filter(|v| !v.is_empty());
    // SAFETY: in edition 2024 `remove_var` is `unsafe` because concurrent env
    // mutation is UB. `ks` is single-threaded at the points this is called, so
    // no other thread can read or write the environment concurrently.
    unsafe {
        std::env::remove_var(name);
    }
    value
}

#[cfg(unix)]
mod unix {
    use super::{HardenStatus, Measure};

    pub fn harden() -> HardenStatus {
        HardenStatus {
            core_dump: disable_core_dumps(),
            mlock: lock_memory(),
            debugger_deny: deny_debugger(),
            platform: platform_name(),
        }
    }

    const fn platform_name() -> &'static str {
        if cfg!(target_os = "linux") {
            "linux"
        } else if cfg!(target_os = "macos") {
            "macos"
        } else {
            "unix"
        }
    }

    fn disable_core_dumps() -> Measure {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `setrlimit` reads the `rlimit` we pass by pointer and sets a
        // kernel limit. It neither retains the pointer nor touches our memory.
        let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &raw const limit) };
        if rc == 0 {
            Measure::Applied
        } else {
            Measure::Failed(errno_msg("setrlimit RLIMIT_CORE"))
        }
    }

    fn lock_memory() -> Measure {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `getrlimit` only writes the current limit into our local struct.
        let queried = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &raw mut limit) };
        if queried != 0 {
            return Measure::Failed(errno_msg("getrlimit RLIMIT_MEMLOCK"));
        }
        limit.rlim_cur = limit.rlim_max;
        // SAFETY: `setrlimit` reads our local struct and sets the kernel limit.
        let raised = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &raw const limit) };
        if raised != 0 {
            return Measure::Failed(errno_msg("setrlimit RLIMIT_MEMLOCK"));
        }
        let flags = if limit.rlim_max == libc::RLIM_INFINITY {
            libc::MCL_CURRENT | libc::MCL_FUTURE
        } else {
            libc::MCL_CURRENT
        };
        // SAFETY: `mlockall` takes a scalar flag; `MCL_FUTURE` is requested only
        // when the locked-memory limit is unlimited.
        let locked = unsafe { libc::mlockall(flags) };
        if locked == 0 {
            Measure::Applied
        } else {
            Measure::Failed(errno_msg("mlockall"))
        }
    }

    #[cfg(target_os = "linux")]
    fn deny_debugger() -> Measure {
        // SAFETY: `prctl` with `PR_SET_DUMPABLE` takes scalar arguments only.
        let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
        if rc == 0 {
            Measure::Applied
        } else {
            Measure::Failed(errno_msg("prctl PR_SET_DUMPABLE"))
        }
    }

    #[cfg(target_os = "macos")]
    fn deny_debugger() -> Measure {
        // PT_DENY_ATTACH — scalar args; returns -1/EBUSY if already denied.
        const PT_DENY_ATTACH: libc::c_int = 31;
        if cfg!(debug_assertions) {
            return Measure::Skipped("debug_assertions");
        }
        // SAFETY: null address; does not dereference process memory.
        let rc = unsafe { libc::ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) };
        if rc == 0 {
            return Measure::Applied;
        }
        let err = std::io::Error::last_os_error();
        // Already denied in this process is success for our purposes.
        if err.raw_os_error() == Some(libc::EBUSY) {
            Measure::Applied
        } else {
            Measure::Failed(format!("ptrace PT_DENY_ATTACH: {err}"))
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn deny_debugger() -> Measure {
        Measure::Skipped("unsupported unix target")
    }

    fn errno_msg(op: &str) -> String {
        let err = std::io::Error::last_os_error();
        format!("{op}: {err}")
    }
}

#[cfg(windows)]
mod windows {
    use windows_sys::Win32::System::Diagnostics::Debug::{
        SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SetErrorMode,
    };

    use super::{HardenStatus, Measure};

    pub fn harden() -> HardenStatus {
        // SAFETY: `SetErrorMode` takes a scalar flag and returns the previous
        // mode; it does not touch our memory.
        unsafe {
            SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
        }
        HardenStatus {
            core_dump: Measure::Applied,
            mlock: Measure::Skipped("no process-wide VirtualLock equivalent"),
            debugger_deny: Measure::Skipped("no portable equivalent"),
            platform: "windows",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harden_returns_status() {
        let s = harden();
        assert!(!s.platform.is_empty());
        // Second call is idempotent.
        let s2 = harden();
        assert_eq!(s.platform, s2.platform);
    }

    #[test]
    fn measure_detail_formats() {
        assert_eq!(Measure::Applied.detail(), "applied");
        assert_eq!(Measure::Skipped("reason").detail(), "skipped (reason)");
        assert!(Measure::Failed("x".into()).detail().contains("failed"));
    }
}
