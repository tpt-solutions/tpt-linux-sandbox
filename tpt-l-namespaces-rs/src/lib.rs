//! Safe wrappers around clone3/unshare for user, mount, PID, and network namespaces.
//!
//! Includes UID/GID mapping for user namespaces.

#![deny(missing_docs)]

use libc::{c_int, pid_t, CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWNS,
           CLONE_NEWPID, CLONE_NEWUSER, CLONE_NEWUTS};
use std::fs;
use std::io;
use std::path::Path;
use thiserror::Error;
use tracing::{debug, info, warn};

/// Errors that can occur during namespace operations.
#[derive(Debug, Error)]
pub enum NamespaceError {
    /// The `unshare(2)` syscall failed.
    #[error("unshare failed: {0}")]
    UnshareFailed(io::Error),
    /// Failed to write UID/GID mapping.
    #[error("failed to write {0}: {1}")]
    MappingFailed(String, io::Error),
    /// The requested namespace is not supported.
    #[error("namespace not supported: {0}")]
    NotSupported(&'static str),
}

bitflags::bitflags! {
    /// Flags for namespace types that can be unshared.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct NamespaceFlags: c_int {
        /// Mount namespace — isolate filesystem mount points.
        const MOUNT = CLONE_NEWNS;
        /// PID namespace — isolate process IDs.
        const PID = CLONE_NEWPID;
        /// Network namespace — isolate network devices, stacks, ports.
        const NETWORK = CLONE_NEWNET;
        /// UTS namespace — isolate hostname and NIS domain name.
        const UTS = CLONE_NEWUTS;
        /// IPC namespace — isolate interprocess communication resources.
        const IPC = CLONE_NEWIPC;
        /// Cgroup namespace — isolate cgroup root directory.
        const CGROUP = CLONE_NEWCGROUP;
        /// User namespace — isolate user and group IDs.
        const USER = CLONE_NEWUSER;
    }
}

/// A builder for configuring which namespaces to unshare.
///
/// # Example
///
/// ```
/// use tpt_l_namespaces_rs::NamespaceSet;
///
/// let ns = NamespaceSet::new()
///     .user()
///     .mount()
///     .pid()
///     .network();
/// ```
#[derive(Debug, Clone, Default)]
pub struct NamespaceSet {
    flags: NamespaceFlags,
    uid_map: Option<(u32, u32, u32)>,
    gid_map: Option<(u32, u32, u32)>,
}

impl NamespaceSet {
    /// Creates a new empty `NamespaceSet`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Includes the user namespace (with optional UID/GID mapping).
    pub fn user(mut self) -> Self {
        self.flags |= NamespaceFlags::USER;
        self
    }

    /// Includes the mount namespace.
    pub fn mount(mut self) -> Self {
        self.flags |= NamespaceFlags::MOUNT;
        self
    }

    /// Includes the PID namespace.
    pub fn pid(mut self) -> Self {
        self.flags |= NamespaceFlags::PID;
        self
    }

    /// Includes the network namespace.
    pub fn network(mut self) -> Self {
        self.flags |= NamespaceFlags::NETWORK;
        self
    }

    /// Includes the UTS namespace.
    pub fn uts(mut self) -> Self {
        self.flags |= NamespaceFlags::UTS;
        self
    }

    /// Includes the IPC namespace.
    pub fn ipc(mut self) -> Self {
        self.flags |= NamespaceFlags::IPC;
        self
    }

    /// Includes the cgroup namespace.
    pub fn cgroup(mut self) -> Self {
        self.flags |= NamespaceFlags::CGROUP;
        self
    }

    /// Sets the UID map for the user namespace.
    ///
    /// `inside_uid` is the UID inside the namespace, `outside_uid` is the
    /// UID outside, and `count` is the number of consecutive IDs to map.
    pub fn uid_map(mut self, inside_uid: u32, outside_uid: u32, count: u32) -> Self {
        self.uid_map = Some((inside_uid, outside_uid, count));
        self
    }

    /// Sets the GID map for the user namespace.
    pub fn gid_map(mut self, inside_gid: u32, outside_gid: u32, count: u32) -> Self {
        self.gid_map = Some((inside_gid, outside_gid, count));
        self
    }

    /// Returns the combined `CLONE_NEW*` flags as a bitmask.
    pub fn flags(&self) -> c_int {
        self.flags.bits()
    }

    /// Applies the namespace unshare for the current thread.
    ///
    /// This is irreversible for the calling thread.
    pub fn apply(self) -> Result<(), NamespaceError> {
        let flags = self.flags();
        debug!(flags = flags, "unsharing namespaces");

        unsafe {
            if libc::unshare(flags) != 0 {
                return Err(NamespaceError::UnshareFailed(io::Error::last_os_error()));
            }
        }

        if flags & CLONE_NEWUSER != 0 {
            if let Some((inside, outside, count)) = self.uid_map {
                Self::write_uid_map(inside, outside, count)?;
            }
            if let Some((inside, outside, count)) = self.gid_map {
                Self::write_gid_map(inside, outside, count)?;
            }
        }

        info!("namespaces unshared successfully");
        Ok(())
    }

    fn write_uid_map(inside: u32, outside: u32, count: u32) -> Result<(), NamespaceError> {
        let mapping = format!("{inside} {outside} {count}");
        fs::write("/proc/self/uid_map", &mapping)
            .map_err(|e| NamespaceError::MappingFailed("/proc/self/uid_map".into(), e))?;
        debug!(mapping = mapping, "wrote UID map");
        Ok(())
    }

    fn write_gid_map(inside: u32, outside: u32, count: u32) -> Result<(), NamespaceError> {
        // Must first setgroups deny for user namespace
        fs::write("/proc/self/setgroups", "deny")
            .map_err(|e| warn!("failed to write setgroups deny: {e}"))
            .ok();

        let mapping = format!("{inside} {outside} {count}");
        fs::write("/proc/self/gid_map", &mapping)
            .map_err(|e| NamespaceError::MappingFailed("/proc/self/gid_map".into(), e))?;
        debug!(mapping = mapping, "wrote GID map");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_set_is_empty() {
        let ns = NamespaceSet::new();
        assert_eq!(ns.flags().bits(), 0);
    }

    #[test]
    fn user_flag_is_set() {
        let ns = NamespaceSet::new().user();
        assert!(ns.flags.contains(NamespaceFlags::USER));
    }

    #[test]
    fn mount_flag_is_set() {
        let ns = NamespaceSet::new().mount();
        assert!(ns.flags.contains(NamespaceFlags::MOUNT));
    }

    #[test]
    fn pid_flag_is_set() {
        let ns = NamespaceSet::new().pid();
        assert!(ns.flags.contains(NamespaceFlags::PID));
    }

    #[test]
    fn network_flag_is_set() {
        let ns = NamespaceSet::new().network();
        assert!(ns.flags.contains(NamespaceFlags::NETWORK));
    }

    #[test]
    fn combined_flags() {
        let ns = NamespaceSet::new().user().mount().pid().network();
        assert!(ns.flags.contains(NamespaceFlags::USER));
        assert!(ns.flags.contains(NamespaceFlags::MOUNT));
        assert!(ns.flags.contains(NamespaceFlags::PID));
        assert!(ns.flags.contains(NamespaceFlags::NETWORK));
    }

    #[test]
    fn uid_map_stored() {
        let ns = NamespaceSet::new().user().uid_map(0, 1000, 1);
        assert_eq!(ns.uid_map, Some((0, 1000, 1)));
    }

    #[test]
    fn gid_map_stored() {
        let ns = NamespaceSet::new().user().gid_map(0, 1000, 1);
        assert_eq!(ns.gid_map, Some((0, 1000, 1)));
    }
}
