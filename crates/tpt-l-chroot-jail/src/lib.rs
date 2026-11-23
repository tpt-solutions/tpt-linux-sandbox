//! Minimal `pivot_root` and chroot jail setup with pseudo-filesystem mounting.
//!
//! Uses `pivot_root(2)`, which is the stronger option. The jail first makes
//! the whole mount tree private, so mounts and unmounts inside the jail never
//! propagate to the host. A `chroot(2)` fallback exists only as an explicit
//! opt-in via [`JailConfig::allow_chroot_fallback`]: `chroot` is escapable by
//! any process that keeps `CAP_SYS_CHROOT`.
//!
//! Must run inside a new mount namespace. Otherwise the mount changes would
//! affect the host.
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
    /// A path inside the new root is a symlink or not a directory, so it
    /// cannot be used as a mount point safely.
    #[error("unsafe path inside new root (symlink or non-directory): {0}")]
    UnsafePath(PathBuf),
    /// `pivot_root(2)` failed, or was unavailable and fallback is disabled.
    #[error("pivot_root failed: {0}")]
    PivotRoot(std::io::Error),
    /// `chroot(2)` fallback failed.
    #[error("chroot failed: {0}")]
    Chroot(std::io::Error),
    /// Mounting a pseudo-filesystem failed.
    #[error("mount failed for {path}: {source}")]
    Mount {
        /// The mount target that failed.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// Creating or inspecting a path inside the new root failed.
    #[error("filesystem operation failed for {path}: {source}")]
    Io {
        /// The path that failed.
        path: PathBuf,
        /// The underlying I/O error.
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
    allow_chroot_fallback: bool,
}

/// Device nodes bind-mounted into the minimal `/dev`. Each comes from the host.
const DEV_NODES: &[&str] = &["null", "zero", "random", "urandom", "tty"];

impl JailConfig {
    /// Create a new jail configuration rooted at `new_root`.
    pub fn new(new_root: impl AsRef<Path>) -> Self {
        Self {
            new_root: new_root.as_ref().to_owned(),
            mount_proc: false,
            mount_dev_minimal: false,
            mount_sys_ro: false,
            allow_chroot_fallback: false,
        }
    }

    /// Mount a fresh `procfs` at `<new_root>/proc` (no suid, device or exec).
    pub fn mount_proc(mut self) -> Self {
        self.mount_proc = true;
        self
    }

    /// Mount a minimal `/dev` at `<new_root>/dev`: a private tmpfs containing
    /// bind-mounted `null`, `zero`, `random`, `urandom` and `tty` only. Other
    /// host devices are not visible.
    pub fn mount_dev_minimal(mut self) -> Self {
        self.mount_dev_minimal = true;
        self
    }

    /// Mount `sysfs` read-only at `<new_root>/sys`.
    pub fn mount_sys_ro(mut self) -> Self {
        self.mount_sys_ro = true;
        self
    }

    /// Allow falling back to `chroot(2)` when `pivot_root(2)` is unavailable.
    ///
    /// Off by default. `chroot` is weaker: it leaves the old root reachable and
    /// can be escaped by a process that holds `CAP_SYS_CHROOT`.
    pub fn allow_chroot_fallback(mut self) -> Self {
        self.allow_chroot_fallback = true;
        self
    }

    /// Enter the jail.
    ///
    /// # Errors
    ///
    /// Returns a [`JailError`] for the first step that fails. A mount or
    /// unmount failure is always an error, never silently ignored.
    pub fn apply(self) -> Result<(), JailError> {
        use nix::mount::{MntFlags, MsFlags, mount, umount2};
        use nix::unistd::{chdir, chroot, pivot_root};

        if !self.new_root.is_dir() {
            return Err(JailError::RootNotFound(self.new_root.clone()));
        }

        // Make every existing mount private before doing anything else. Under
        // shared propagation, pivot_root fails with EINVAL, and mounts made in
        // the jail would leak back to the host.
        mount(
            None::<&str>,
            "/",
            None::<&str>,
            MsFlags::MS_REC | MsFlags::MS_PRIVATE,
            None::<&str>,
        )
        .map_err(|e| mount_error(Path::new("/"), e))?;

        // Pseudo-filesystems are mounted inside new_root before pivoting, so
        // they exist in the new tree.
        if self.mount_proc {
            let target = self.new_root.join("proc");
            ensure_dir(&target)?;
            mount(
                Some("proc"),
                &target,
                Some("proc"),
                MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
                None::<&str>,
            )
            .map_err(|e| mount_error(&target, e))?;
        }

        if self.mount_sys_ro {
            let target = self.new_root.join("sys");
            ensure_dir(&target)?;
            mount(
                Some("sysfs"),
                &target,
                Some("sysfs"),
                MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
                None::<&str>,
            )
            .map_err(|e| mount_error(&target, e))?;
        }

        if self.mount_dev_minimal {
            self.mount_minimal_dev()?;
        }

        // pivot_root requires the new root to be a mount point. Bind-mount it
        // onto itself.
        mount(
            Some(&self.new_root),
            &self.new_root,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        )
        .map_err(|e| mount_error(&self.new_root, e))?;

        let put_old = self.new_root.join(".put_old");
        ensure_dir(&put_old)?;

        // pivot_root(".", ".put_old") is relative to the working directory, so
        // enter the new root first.
        chdir(&self.new_root).map_err(|e| JailError::PivotRoot(errno_io(e)))?;

        match pivot_root(".", ".put_old") {
            Ok(()) => {
                chdir("/").map_err(|e| JailError::PivotRoot(errno_io(e)))?;
                // Detach the old root. If this fails the host is still reachable,
                // so the failure is fatal.
                umount2("/.put_old", MntFlags::MNT_DETACH)
                    .map_err(|e| JailError::PivotRoot(errno_io(e)))?;
                std::fs::remove_dir("/.put_old").map_err(|source| JailError::Io {
                    path: PathBuf::from("/.put_old"),
                    source,
                })?;
            }
            Err(e @ (nix::errno::Errno::ENOSYS | nix::errno::Errno::EINVAL))
                if self.allow_chroot_fallback =>
            {
                eprintln!(
                    "tpt-l-chroot-jail: pivot_root(2) unavailable ({e}), \
                     falling back to chroot(2) as requested (less secure)"
                );
                let _ = std::fs::remove_dir(".put_old");
                chroot(".").map_err(|e| JailError::Chroot(errno_io(e)))?;
                chdir("/").map_err(|e| JailError::Chroot(errno_io(e)))?;
            }
            Err(e) => {
                return Err(JailError::PivotRoot(errno_io(e)));
            }
        }

        Ok(())
    }

    /// Build the minimal `/dev` described on [`mount_dev_minimal`](Self::mount_dev_minimal).
    fn mount_minimal_dev(&self) -> Result<(), JailError> {
        use nix::mount::{MsFlags, mount};

        let dev = self.new_root.join("dev");
        ensure_dir(&dev)?;
        mount(
            Some("tmpfs"),
            &dev,
            Some("tmpfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
            Some("mode=755,size=1m"),
        )
        .map_err(|e| mount_error(&dev, e))?;

        for name in DEV_NODES {
            let target = dev.join(name);
            ensure_file(&target)?;
            let source = Path::new("/dev").join(name);
            mount(
                Some(&source),
                &target,
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            )
            .map_err(|e| mount_error(&target, e))?;
        }
        Ok(())
    }
}

fn mount_error(path: &Path, e: nix::errno::Errno) -> JailError {
    JailError::Mount {
        path: path.to_path_buf(),
        source: errno_io(e),
    }
}

fn errno_io(e: nix::errno::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(e as i32)
}

/// Create `path` as a directory, refusing symlinks so a hostile rootfs cannot
/// redirect a mount to the host.
fn ensure_dir(path: &Path) -> Result<(), JailError> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => Ok(()),
        Ok(_) => Err(JailError::UnsafePath(path.to_path_buf())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(path).map_err(|source| JailError::Io {
                path: path.to_path_buf(),
                source,
            })
        }
        Err(source) => Err(JailError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Create `path` as an empty regular file (a bind-mount target), refusing
/// symlinks.
fn ensure_file(path: &Path) -> Result<(), JailError> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_file() => Ok(()),
        Ok(_) => Err(JailError::UnsafePath(path.to_path_buf())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => std::fs::File::create(path)
            .map(drop)
            .map_err(|source| JailError::Io {
                path: path.to_path_buf(),
                source,
            }),
        Err(source) => Err(JailError::Io {
            path: path.to_path_buf(),
            source,
        }),
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
        assert!(!j.allow_chroot_fallback);
    }

    #[test]
    fn chroot_fallback_is_opt_in() {
        assert!(
            JailConfig::new("/")
                .allow_chroot_fallback()
                .allow_chroot_fallback
        );
    }

    /// Checks run inside the jail. Returns 0 when the new root is in effect.
    fn check_inside_jail() -> i32 {
        if !Path::new("/marker").exists() {
            return 2;
        }
        if Path::new("/etc").exists() {
            return 3;
        }
        0
    }

    /// Regression test: pivot into a rootfs inside a user and mount namespace.
    /// Runs in a forked child, which changes its own root and mounts.
    #[test]
    #[ignore = "changes the process root and mounts; run with --include-ignored"]
    fn pivot_into_rootfs_in_forked_child() {
        let root = std::env::temp_dir().join(format!("tpt-jail-root-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("marker"), "inside\n").unwrap();

        // SAFETY: the child is single-threaded; it only unshares, pivots, checks
        // and `_exit`s.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let code = if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) } != 0 {
                3
            } else if JailConfig::new(&root).apply().is_err() {
                4
            } else {
                check_inside_jail()
            };
            // SAFETY: _exit skips destructors, which must not run in a forked child.
            unsafe { libc::_exit(code) };
        }

        let mut status: libc::c_int = 0;
        // SAFETY: `status` is a valid out-pointer.
        unsafe { libc::waitpid(pid, &raw mut status, 0) };
        let _ = std::fs::remove_dir_all(&root);
        assert!(libc::WIFEXITED(status), "child was killed");
        assert_eq!(libc::WEXITSTATUS(status), 0, "jail did not take effect");
    }

    #[test]
    fn ensure_dir_rejects_symlink() {
        let dir = std::env::temp_dir().join(format!("tpt-jail-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("target");
        std::fs::create_dir(&target).unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = ensure_dir(&link).unwrap_err();
        assert!(matches!(err, JailError::UnsafePath(_)));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
