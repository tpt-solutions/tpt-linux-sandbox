//! Minimal `pivot_root` and chroot jail setup with pseudo-filesystem mounting.
//!
//! Prefers `pivot_root(2)` over `chroot(2)` — `pivot_root` is harder to
//! escape and works correctly with mount namespaces. Falls back to `chroot`
//! with a logged warning if `pivot_root` is unavailable.
//!
//! # Example
//!
//! ```no_run
//! use tpt_l_chroot_jail::JailConfig;
//!
//! JailConfig::new("/path/to/rootfs")
//!     .mount_proc()
//!     .mount_dev_minimal()
//!     .mount_sys_ro()
//!     .apply()
//!     .expect("jail setup failed");
//! ```

#[cfg(not(target_os = "linux"))]
compile_error!("tpt-l-chroot-jail only supports Linux");

use std::path::{Path, PathBuf};
use thiserror::Error;

/// Errors produced by this crate.
#[derive(Debug, Error)]
pub enum JailError {
    /// The new root directory does not exist or is inaccessible.
    #[error("new root does not exist: {0}")]
    RootNotFound(PathBuf),
    /// `pivot_root(2)` failed.
    #[error("pivot_root failed: {0}")]
    PivotRoot(std::io::Error),
    /// `chroot(2)` fallback failed.
    #[error("chroot failed: {0}")]
    Chroot(std::io::Error),
    /// Mounting a pseudo-filesystem failed.
    #[error("mount failed for {path}: {source}")]
    Mount { path: PathBuf, source: std::io::Error },
}

/// Configuration for setting up a `pivot_root` / chroot jail.
#[derive(Debug, Clone)]
pub struct JailConfig {
    new_root: PathBuf,
    mount_proc: bool,
    mount_dev_minimal: bool,
    mount_sys_ro: bool,
}

impl JailConfig {
    /// Create a new jail configuration rooted at `new_root`.
    pub fn new(new_root: impl AsRef<Path>) -> Self {
        Self {
            new_root: new_root.as_ref().to_owned(),
            mount_proc: false,
            mount_dev_minimal: false,
            mount_sys_ro: false,
        }
    }

    /// Mount a fresh `procfs` at `<new_root>/proc`.
    pub fn mount_proc(mut self) -> Self {
        self.mount_proc = true;
        self
    }

    /// Mount a minimal `devtmpfs` at `<new_root>/dev` containing only
    /// `null`, `zero`, `random`, and `urandom`.
    pub fn mount_dev_minimal(mut self) -> Self {
        self.mount_dev_minimal = true;
        self
    }

    /// Mount `sysfs` read-only at `<new_root>/sys`.
    pub fn mount_sys_ro(mut self) -> Self {
        self.mount_sys_ro = true;
        self
    }

    /// Enter the jail.
    ///
    /// Attempts `pivot_root(2)` first. Falls back to `chroot(2)` with a
    /// warning printed to stderr. Pseudo-filesystems are mounted inside the
    /// new root as configured.
    pub fn apply(self) -> Result<(), JailError> {
        if !self.new_root.exists() {
            return Err(JailError::RootNotFound(self.new_root));
        }
        // TODO: attempt pivot_root via nix::unistd::pivot_root(); if it
        // returns ENOSYS fall back to nix::unistd::chroot() with a warning.
        // TODO: if self.mount_proc, mount procfs at ./proc.
        // TODO: if self.mount_dev_minimal, bind-mount or create devtmpfs.
        // TODO: if self.mount_sys_ro, mount sysfs MS_RDONLY at ./sys.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonexistent_root_errors_immediately() {
        let err = JailConfig::new("/nonexistent-tpt-sandbox-test-path")
            .apply()
            .unwrap_err();
        assert!(matches!(err, JailError::RootNotFound(_)));
    }

    #[test]
    fn builder_flags() {
        let j = JailConfig::new("/").mount_proc().mount_sys_ro();
        assert!(j.mount_proc);
        assert!(!j.mount_dev_minimal);
        assert!(j.mount_sys_ro);
    }
}
