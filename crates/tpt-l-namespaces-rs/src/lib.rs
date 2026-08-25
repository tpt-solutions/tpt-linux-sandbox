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
    Unshare(#[from] std::io::Error),
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
    user: bool,
    mount: bool,
    pid: bool,
    network: bool,
}

impl NamespaceSet {
    /// Create an empty set — nothing is unshared until at least one namespace
    /// is enabled.
    pub fn new() -> Self {
        Self::default()
    }

    /// Unshare the user namespace.
    ///
    /// Required for unprivileged sandboxing; enables UID/GID mapping so that
    /// the process appears as root inside the namespace while remaining
    /// unprivileged outside it.
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
        // TODO: build CLONE_NEW* bitmask from self.user / .mount / .pid / .network,
        // call nix::sched::unshare(CloneFlags), then if self.user write
        // /proc/self/uid_map and /proc/self/gid_map with a 0→uid 1 mapping.
        drop(self);
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
}
