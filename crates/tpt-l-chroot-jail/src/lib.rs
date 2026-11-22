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
    Mount {
        path: PathBuf,
        source: std::io::Error,
    },
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

    /// Mount a minimal `devtmpfs` at `<new_root>/dev`.
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
    /// warning if the call is unavailable (e.g. no mount namespace).
    pub fn apply(self) -> Result<(), JailError> {
        use nix::mount::{MsFlags, mount};

        if !self.new_root.exists() {
            return Err(JailError::RootNotFound(self.new_root.clone()));
        }

        // Mount pseudo-filesystems inside new_root before pivoting so they
        // exist in the new filesystem tree.
        if self.mount_proc {
            let target = self.new_root.join("proc");
            std::fs::create_dir_all(&target).ok();
            mount(
                Some("proc"),
                &target,
                Some("proc"),
                MsFlags::empty(),
                None::<&str>,
            )
            .map_err(|e| JailError::Mount {
                path: target,
                source: std::io::Error::from_raw_os_error(e as i32),
            })?;
        }

        if self.mount_sys_ro {
            let target = self.new_root.join("sys");
            std::fs::create_dir_all(&target).ok();
            mount(
                Some("sysfs"),
                &target,
                Some("sysfs"),
                MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
                None::<&str>,
            )
            .map_err(|e| JailError::Mount {
                path: target,
                source: std::io::Error::from_raw_os_error(e as i32),
            })?;
        }

        if self.mount_dev_minimal {
            let target = self.new_root.join("dev");
            std::fs::create_dir_all(&target).ok();
            mount(
                Some("devtmpfs"),
                &target,
                Some("devtmpfs"),
                MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
                Some("mode=755"),
            )
            .map_err(|e| JailError::Mount {
                path: target,
                source: std::io::Error::from_raw_os_error(e as i32),
            })?;
        }

        // Bind-mount new_root onto itself so it becomes a separate mount point,
        // which is required by pivot_root.
        mount(
            Some(&self.new_root),
            &self.new_root,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        )
        .map_err(|e| JailError::PivotRoot(std::io::Error::from_raw_os_error(e as i32)))?;

        // Create a temporary directory inside new_root to receive the old root.
        let put_old = self.new_root.join(".put_old");
        std::fs::create_dir_all(&put_old).map_err(|e| JailError::PivotRoot(e))?;

        // Try pivot_root; fall back to chroot on ENOSYS / EINVAL.
        match nix::unistd::pivot_root(&self.new_root, &put_old) {
            Ok(()) => {
                nix::unistd::chdir("/").map_err(|e| {
                    JailError::PivotRoot(std::io::Error::from_raw_os_error(e as i32))
                })?;
                // Unmount the old root lazily and remove the directory.
                nix::mount::umount2("/.put_old", nix::mount::MntFlags::MNT_DETACH).map_err(
                    |e| JailError::PivotRoot(std::io::Error::from_raw_os_error(e as i32)),
                )?;
                std::fs::remove_dir("/.put_old").ok();
            }
            Err(nix::errno::Errno::ENOSYS) | Err(nix::errno::Errno::EINVAL) => {
                eprintln!(
                    "tpt-l-chroot-jail: pivot_root(2) unavailable, \
                     falling back to chroot(2) (less secure)"
                );
                std::fs::remove_dir(&put_old).ok();
                nix::unistd::chroot(&self.new_root)
                    .map_err(|e| JailError::Chroot(std::io::Error::from_raw_os_error(e as i32)))?;
                nix::unistd::chdir("/")
                    .map_err(|e| JailError::Chroot(std::io::Error::from_raw_os_error(e as i32)))?;
            }
            Err(e) => {
                return Err(JailError::PivotRoot(std::io::Error::from_raw_os_error(
                    e as i32,
                )));
            }
        }

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
