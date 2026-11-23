//! Safe wrappers around `unshare(2)` for Linux namespaces.
//!
//! # Limitations
//!
//! - `unshare(2)` affects only the calling thread. Call [`NamespaceSet::apply`]
//!   before spawning threads. The user namespace cannot be created from a
//!   multi-threaded process; [`NamespaceError::MultiThreaded`] is returned.
//! - The PID namespace applies to *children* created afterwards, not to the
//!   calling process. Without a fork and an init process that reaps children,
//!   the PID namespace has no effect on the process that called `apply`.
//!
//! # Example
//!
//! ```no_run
//! use tpt_l_namespaces_rs::NamespaceSet;
//!
//! NamespaceSet::new()
//!     .user()
//!     .mount()
//!     .network()
//!     .apply()
//!     .expect("namespace setup failed");
//! ```

#[cfg(not(target_os = "linux"))]
compile_error!("tpt-l-namespaces-rs only supports Linux");

use thiserror::Error;

/// Errors produced by this crate.
#[derive(Debug, Error)]
pub enum NamespaceError {
    /// `unshare(2)` returned an error.
    #[error("unshare(2) failed: {0}")]
    Unshare(std::io::Error),
    /// Writing the UID or GID map failed.
    #[error("UID/GID map write failed: {0}")]
    UidMap(std::io::Error),
    /// A user namespace was requested from a multi-threaded process, which the
    /// kernel rejects with EINVAL.
    #[error("cannot create a user namespace from a multi-threaded process ({0} threads)")]
    MultiThreaded(usize),
    /// Reading the thread count from `/proc/self/task` failed.
    #[error("failed to count threads: {0}")]
    ThreadCount(std::io::Error),
}

/// Number of threads in the calling process, from `/proc/self/task`.
fn thread_count() -> Result<usize, NamespaceError> {
    std::fs::read_dir("/proc/self/task")
        .map(|dir| dir.filter_map(Result::ok).count())
        .map_err(NamespaceError::ThreadCount)
}

/// The set of Linux namespaces to unshare from the parent.
///
/// Start with [`new`](Self::new), add namespaces with the builder methods,
/// then call [`apply`](Self::apply).
#[derive(Debug, Default, Clone)]
pub struct NamespaceSet {
    pub(crate) user: bool,
    pub(crate) mount: bool,
    pub(crate) pid: bool,
    pub(crate) network: bool,
}

impl NamespaceSet {
    /// Create an empty set — nothing is unshared until at least one namespace
    /// is enabled.
    pub fn new() -> Self {
        Self::default()
    }

    /// Unshare the user namespace.
    ///
    /// Required for unprivileged sandboxing; enables UID/GID mapping so the
    /// process appears as root inside the namespace while remaining unprivileged
    /// outside it.
    pub fn user(mut self) -> Self {
        self.user = true;
        self
    }

    /// Unshare the mount namespace.
    pub fn mount(mut self) -> Self {
        self.mount = true;
        self
    }

    /// Returns `true` if the user namespace has been requested.
    #[must_use]
    pub fn has_user(&self) -> bool {
        self.user
    }

    /// Returns `true` if the mount namespace has been requested.
    #[must_use]
    pub fn has_mount(&self) -> bool {
        self.mount
    }

    /// Unshare the PID namespace. Affects children created after
    /// [`apply`](Self::apply); see the crate-level limitations.
    pub fn pid(mut self) -> Self {
        self.pid = true;
        self
    }

    /// Unshare the network namespace — the sandbox gets its own loopback-only
    /// network stack with no external access.
    pub fn network(mut self) -> Self {
        self.network = true;
        self
    }

    /// Apply the namespace configuration via `unshare(2)`.
    ///
    /// If a user namespace is requested, UID/GID maps are written immediately
    /// after the `unshare` call so the process retains a valid identity inside
    /// the new namespace.
    pub fn apply(self) -> Result<(), NamespaceError> {
        use nix::sched::{CloneFlags, unshare};
        use nix::unistd::{getgid, getuid};

        let mut flags = CloneFlags::empty();
        if self.user {
            flags |= CloneFlags::CLONE_NEWUSER;
        }
        if self.mount {
            flags |= CloneFlags::CLONE_NEWNS;
        }
        if self.pid {
            flags |= CloneFlags::CLONE_NEWPID;
        }
        if self.network {
            flags |= CloneFlags::CLONE_NEWNET;
        }

        if flags.is_empty() {
            return Ok(());
        }

        if self.user {
            let threads = thread_count()?;
            if threads > 1 {
                return Err(NamespaceError::MultiThreaded(threads));
            }
        }

        // Capture the real ids *before* unshare: after CLONE_NEWUSER they read
        // as the overflow id (65534) until the maps are written.
        let uid = getuid();
        let gid = getgid();

        unshare(flags)
            .map_err(|e| NamespaceError::Unshare(std::io::Error::from_raw_os_error(e as i32)))?;

        if self.user {
            // Must write "deny" to setgroups before gid_map (Linux 3.19+).
            std::fs::write("/proc/self/setgroups", "deny\n").map_err(NamespaceError::UidMap)?;
            std::fs::write("/proc/self/uid_map", format!("0 {uid} 1\n"))
                .map_err(NamespaceError::UidMap)?;
            std::fs::write("/proc/self/gid_map", format!("0 {gid} 1\n"))
                .map_err(NamespaceError::UidMap)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_set_is_valid() {
        let ns = NamespaceSet::new();
        assert!(!ns.user && !ns.mount && !ns.pid && !ns.network);
    }

    #[test]
    fn builder_flags() {
        let ns = NamespaceSet::new().user().mount().network();
        assert!(ns.user);
        assert!(ns.mount);
        assert!(!ns.pid);
        assert!(ns.network);
    }

    #[test]
    fn all_flags() {
        let ns = NamespaceSet::new().user().mount().pid().network();
        assert!(ns.user && ns.mount && ns.pid && ns.network);
    }

    #[test]
    fn counts_threads_in_test_process() {
        // The test harness runs tests on several threads, so the count is at
        // least one; this exercises the /proc/self/task reader.
        assert!(thread_count().unwrap() >= 1);
    }

    /// Regression test: uid/gid must be read before `unshare`, otherwise the
    /// uid_map write fails with EPERM. Runs in a forked child so the namespace
    /// change cannot leak into the test harness.
    #[test]
    #[ignore = "requires unprivileged user namespaces; run with --include-ignored"]
    fn user_namespace_apply_writes_maps_in_child() {
        use nix::sys::wait::{WaitStatus, waitpid};
        use nix::unistd::{ForkResult, fork};

        // SAFETY: the child only calls async-signal-safe-enough operations
        // (unshare, file writes) and then `_exit`s; it never returns into the
        // test harness.
        match unsafe { fork() }.expect("fork failed") {
            ForkResult::Child => {
                let code = match NamespaceSet::new().user().apply() {
                    Ok(()) => 0,
                    Err(_) => 1,
                };
                // SAFETY: _exit does not run destructors or atexit handlers.
                unsafe { libc::_exit(code) };
            }
            ForkResult::Parent { child } => {
                let status = waitpid(child, None).expect("waitpid failed");
                assert_eq!(status, WaitStatus::Exited(child, 0));
            }
        }
    }
}
