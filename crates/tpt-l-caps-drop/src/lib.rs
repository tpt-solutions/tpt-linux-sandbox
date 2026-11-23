//! Ergonomic Linux capability dropping.
//!
//! Drop every capability except those explicitly kept. The drop covers the
//! bounding, ambient, permitted, effective and inheritable sets, so the
//! restriction survives `execve(2)`. Securebits are locked so the process
//! cannot regain root-like capabilities, and `no_new_privs` is set.
//!
//! # Example
//!
//! ```no_run
//! use tpt_l_caps_drop::CapsPolicy;
//!
//! CapsPolicy::new()
//!     .drop_all()
//!     .keep("CAP_NET_BIND_SERVICE")
//!     .apply()
//!     .expect("capability drop failed");
//! ```

#[cfg(not(target_os = "linux"))]
compile_error!("tpt-l-caps-drop only supports Linux");

use thiserror::Error;

/// A Linux capability name (e.g. `"CAP_NET_ADMIN"` or `"net_admin"`).
pub type CapName = String;

// Securebits from <linux/securebits.h>. Stable kernel ABI; defined here so the
// crate does not depend on libc exposing them.
const SECBIT_NOROOT: libc::c_ulong = 1 << 0;
const SECBIT_NOROOT_LOCKED: libc::c_ulong = 1 << 1;
const SECBIT_NO_SETUID_FIXUP: libc::c_ulong = 1 << 2;
const SECBIT_NO_SETUID_FIXUP_LOCKED: libc::c_ulong = 1 << 3;
const SECBIT_KEEP_CAPS_LOCKED: libc::c_ulong = 1 << 5;
const SECBIT_NO_CAP_AMBIENT_RAISE: libc::c_ulong = 1 << 6;
const SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED: libc::c_ulong = 1 << 7;

/// Errors produced by this crate.
#[derive(Debug, Error)]
pub enum CapsError {
    /// A capability name is not recognised.
    #[error("unknown capability: {0}")]
    UnknownCap(String),
    /// Capabilities were listed with `keep` but `drop_all` was not requested.
    #[error("keep() has no effect without drop_all(); call drop_all() or remove keep()")]
    KeepWithoutDrop,
    /// A capability set read/write operation failed.
    #[error("capability operation failed: {0}")]
    Operation(String),
}

/// Policy describing which capabilities to retain after dropping.
///
/// By default nothing is dropped. Call [`drop_all`](Self::drop_all) to clear
/// all sets, then use [`keep`](Self::keep) to retain specific capabilities.
#[derive(Debug, Default, Clone)]
pub struct CapsPolicy {
    keep: Vec<CapName>,
    drop_all_flag: bool,
}

impl CapsPolicy {
    /// Create a new policy — no capabilities are modified until [`apply`](Self::apply).
    pub fn new() -> Self {
        Self::default()
    }

    /// Drop every capability in the bounding, ambient, permitted, effective,
    /// and inheritable sets, except those explicitly listed via
    /// [`keep`](Self::keep).
    pub fn drop_all(mut self) -> Self {
        self.drop_all_flag = true;
        self
    }

    /// Retain capability `cap` even when `drop_all` is set.
    ///
    /// Accepts the full name (`"CAP_NET_ADMIN"`) or short name (`"net_admin"`);
    /// case-insensitive.
    pub fn keep(mut self, cap: impl Into<CapName>) -> Self {
        self.keep.push(cap.into());
        self
    }

    /// Apply the capability policy to the calling process.
    ///
    /// Also sets `no_new_privs` and locks securebits so that root-inside-the-
    /// namespace cannot regain capabilities through `execve`.
    ///
    /// # Errors
    ///
    /// Returns [`CapsError::KeepWithoutDrop`] if `keep` was used without
    /// `drop_all`, and [`CapsError::UnknownCap`] for unrecognised names.
    pub fn apply(self) -> Result<(), CapsError> {
        use caps::{CapSet, CapsHashSet};

        if !self.drop_all_flag {
            if self.keep.is_empty() {
                return Ok(());
            }
            return Err(CapsError::KeepWithoutDrop);
        }

        // Parse the keep list.
        let mut keep_set = CapsHashSet::new();
        for name in &self.keep {
            let cap = name
                .to_lowercase()
                .trim_start_matches("cap_")
                .to_uppercase();
            let cap = format!("CAP_{cap}");
            let parsed = cap
                .parse::<caps::Capability>()
                .map_err(|_| CapsError::UnknownCap(name.clone()))?;
            keep_set.insert(parsed);
        }

        // 1. Bounding set first: dropping it needs CAP_SETPCAP, which we may
        //    lose once the permitted set shrinks. Without this, execve would
        //    restore the dropped capabilities.
        let bounding = caps::read(None, CapSet::Bounding).map_err(op_err)?;
        for cap in bounding.difference(&keep_set) {
            caps::drop(None, CapSet::Bounding, *cap).map_err(op_err)?;
        }

        // 2. Lock securebits so uid 0 gets no implicit capabilities on exec.
        let securebits = SECBIT_NOROOT
            | SECBIT_NOROOT_LOCKED
            | SECBIT_NO_SETUID_FIXUP
            | SECBIT_NO_SETUID_FIXUP_LOCKED
            | SECBIT_KEEP_CAPS_LOCKED
            | SECBIT_NO_CAP_AMBIENT_RAISE
            | SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED;
        prctl(libc::PR_SET_SECUREBITS, securebits)?;

        // 3. Ambient set: nothing survives exec unless explicitly raised.
        prctl_args(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
            0,
            0,
        )?;

        // 4. Inheritable first (clearing is always allowed; raising it would
        //    need CAP_SETPCAP, which the next steps remove), then effective,
        //    then permitted.
        caps::set(None, CapSet::Inheritable, &CapsHashSet::new()).map_err(op_err)?;
        let permitted = caps::read(None, CapSet::Permitted).map_err(op_err)?;
        let new_set: CapsHashSet = permitted.intersection(&keep_set).copied().collect();
        caps::set(None, CapSet::Effective, &new_set).map_err(op_err)?;
        caps::set(None, CapSet::Permitted, &new_set).map_err(op_err)?;

        // 5. No setuid/file-capability escalation for this process tree.
        prctl_args(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0)?;

        Ok(())
    }
}

fn op_err(e: impl std::fmt::Display) -> CapsError {
    CapsError::Operation(e.to_string())
}

fn prctl(option: libc::c_int, arg: libc::c_ulong) -> Result<(), CapsError> {
    prctl_args(option, arg, 0, 0)
}

fn prctl_args(
    option: libc::c_int,
    a2: libc::c_ulong,
    a3: libc::c_ulong,
    a4: libc::c_ulong,
) -> Result<(), CapsError> {
    // SAFETY: prctl takes plain integer arguments and reads no pointers for
    // the options used here.
    let ret = unsafe { libc::prctl(option, a2, a3, a4) };
    if ret < 0 {
        return Err(op_err(std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keep_accumulates() {
        let p = CapsPolicy::new()
            .drop_all()
            .keep("CAP_NET_BIND_SERVICE")
            .keep("CAP_SETUID");
        assert!(p.drop_all_flag);
        assert_eq!(p.keep.len(), 2);
    }

    #[test]
    fn no_drop_by_default() {
        let p = CapsPolicy::new();
        assert!(!p.drop_all_flag);
    }

    #[test]
    fn keep_without_drop_all_is_an_error() {
        let err = CapsPolicy::new().keep("CAP_CHOWN").apply().unwrap_err();
        assert!(matches!(err, CapsError::KeepWithoutDrop));
    }

    /// Regression test: the drop must hold for the process and set no_new_privs.
    /// Runs in a forked child so the capability change cannot leak into the
    /// test harness.
    #[test]
    #[ignore = "changes process capabilities; run with --include-ignored"]
    fn drop_all_holds_in_forked_child() {
        // SAFETY: the child only calls the capability API, reads state, and
        // `_exit`s; it never returns into the test harness.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            // Dropping the bounding set needs CAP_SETPCAP. The CLI gets it by
            // entering a user namespace first, which grants full capabilities
            // inside that namespace. Do the same here, so the test also runs
            // as an unprivileged user.
            // SAFETY: the forked child is single-threaded, which unshare requires.
            if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
                unsafe { libc::_exit(3) };
            }
            let code = match CapsPolicy::new().drop_all().apply() {
                Ok(()) => {
                    let permitted = caps::read(None, caps::CapSet::Permitted).unwrap_or_default();
                    // SAFETY: PR_GET_NO_NEW_PRIVS takes no pointer arguments.
                    let nnp = unsafe {
                        libc::prctl(
                            libc::PR_GET_NO_NEW_PRIVS,
                            0 as libc::c_ulong,
                            0 as libc::c_ulong,
                            0 as libc::c_ulong,
                            0 as libc::c_ulong,
                        )
                    };
                    if permitted.is_empty() && nnp == 1 {
                        0
                    } else {
                        2
                    }
                }
                Err(_) => 1,
            };
            // SAFETY: _exit skips destructors, which must not run in a forked child.
            unsafe { libc::_exit(code) };
        }

        let mut status: libc::c_int = 0;
        // SAFETY: `status` is a valid out-pointer.
        unsafe { libc::waitpid(pid, &raw mut status, 0) };
        assert!(libc::WIFEXITED(status), "child did not exit normally");
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "capabilities were not fully dropped"
        );
    }

    #[test]
    fn unknown_cap_is_an_error() {
        let err = CapsPolicy::new()
            .drop_all()
            .keep("CAP_NOT_A_THING")
            .apply()
            .unwrap_err();
        assert!(matches!(err, CapsError::UnknownCap(_)));
    }
}
