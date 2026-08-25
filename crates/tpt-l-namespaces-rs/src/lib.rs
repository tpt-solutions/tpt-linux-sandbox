//! Safe wrappers around `unshare(2)` and `clone3(2)` for Linux namespaces.
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

    /// Unshare the PID namespace.
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
        use nix::sched::{unshare, CloneFlags};
        use nix::unistd::{getgid, getuid};

        let mut flags = CloneFlags::empty();
        if self.user    { flags |= CloneFlags::CLONE_NEWUSER; }
        if self.mount   { flags |= CloneFlags::CLONE_NEWNS; }
        if self.pid     { flags |= CloneFlags::CLONE_NEWPID; }
        if self.network { flags |= CloneFlags::CLONE_NEWNET; }

        if flags.is_empty() {
            return Ok(());
        }

        unshare(flags)
            .map_err(|e| NamespaceError::Unshare(std::io::Error::from_raw_os_error(e as i32)))?;

        if self.user {
            let uid = getuid();
            let gid = getgid();
            // Must write "deny" to setgroups before gid_map (Linux 3.19+).
            std::fs::write("/proc/self/setgroups", "deny\n")
                .map_err(NamespaceError::UidMap)?;
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
}
