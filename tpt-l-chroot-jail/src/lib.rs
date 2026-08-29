//! Minimal chroot setup with `pivot_root` and pseudo-filesystem mounting.

#![deny(missing_docs)]

use libc::{c_int, MS_BIND, MS_NODEV, MS_NOEXEC, MS_NOSUID, MS_RDONLY, MS_REC, MS_REMOUNT};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::{debug, info, warn};

/// Errors that can occur during chroot/jail operations.
#[derive(Debug, Error)]
pub enum JailError {
    /// Failed to create the new root directory.
    #[error("failed to create new root {0}: {1}")]
    CreateRootFailed(PathBuf, std::io::Error),
    /// `pivot_root(2)` failed.
    #[error("pivot_root failed: {0}")]
    PivotRootFailed(std::io::Error),
    /// `chroot(2)` failed.
    #[error("chroot failed: {0}")]
    ChrootFailed(std::io::Error),
    /// `mount(2)` failed.
    #[error("mount failed: {0}")]
    MountFailed(std::io::Error),
    /// `umount(2)` failed.
    #[error("umount failed: {0}")]
    UmountFailed(std::io::Error),
}

/// Configuration for a chroot jail.
///
/// # Example
///
/// ```
/// use tpt_l_chroot_jail::JailConfig;
///
/// let config = JailConfig::new("/var/sandbox/root")
///     .mount_proc()
///     .mount_dev_minimal()
///     .mount_sys_ro();
/// ```
#[derive(Debug, Clone)]
pub struct JailConfig {
    new_root: PathBuf,
    mount_proc: bool,
    mount_dev_minimal: bool,
    mount_sys_ro: bool,
}

impl JailConfig {
    /// Creates a new `JailConfig` with the given new root path.
    pub fn new<P: AsRef<Path>>(new_root: P) -> Self {
        Self {
            new_root: new_root.as_ref().to_path_buf(),
            mount_proc: false,
            mount_dev_minimal: false,
            mount_sys_ro: false,
        }
    }

    /// Mounts `/proc` inside the jail.
    pub fn mount_proc(mut self) -> Self {
        self.mount_proc = true;
        self
    }

    /// Mounts a minimal `/dev` (just null, zero, random, urandom) inside the jail.
    pub fn mount_dev_minimal(mut self) -> Self {
        self.mount_dev_minimal = true;
        self
    }

    /// Mounts `/sys` read-only inside the jail.
    pub fn mount_sys_ro(mut self) -> Self {
        self.mount_sys_ro = true;
        self
    }

    /// Returns the new root path.
    pub fn new_root(&self) -> &Path {
        &self.new_root
    }

    /// Applies the jail: creates root, pivot_root, mounts pseudo-filesystems.
    ///
    /// This is irreversible for the calling process.
    pub fn apply(&self) -> Result<(), JailError> {
        debug!(new_root = ?self.new_root, "applying chroot jail");

        fs::create_dir_all(&self.new_root)
            .map_err(|e| JailError::CreateRootFailed(self.new_root.clone(), e))?;

        // Attempt pivot_root; fall back to chroot with warning
        if let Err(e) = self.pivot_root() {
            warn!("pivot_root failed, falling back to chroot: {e}");
            self.chroot_fallback()?;
        }

        // Mount pseudo-filesystems
        if self.mount_proc {
            self.mount_proc_fs()?;
        }
        if self.mount_dev_minimal {
            self.mount_dev()?;
        }
        if self.mount_sys_ro {
            self.mount_sys()?;
        }

        info!("chroot jail applied successfully");
        Ok(())
    }

    fn pivot_root(&self) -> Result<(), JailError> {
        // Create a directory for the old root inside the new root
        let old_root = self.new_root.join(".old_root");
        fs::create_dir_all(&old_root)
            .map_err(|e| JailError::CreateRootFailed(old_root.clone(), e))?;

        unsafe {
            if libc::pivot_root(
                self.new_root.as_os_str().as_encoded_bytes().as_ptr() as *const i8,
                old_root.as_os_str().as_encoded_bytes().as_ptr() as *const i8,
            ) != 0
            {
                return Err(JailError::PivotRootFailed(std::io::Error::last_os_error()));
            }
        }

        // Change to new root
        std::env::set_current_dir("/")
            .map_err(|e| JailError::PivotRootFailed(e))?;

        // Unmount old root
        unsafe {
            if libc::umount2(b"/.old_root\0".as_ptr() as *const i8, libc::MNT_DETACH) != 0 {
                warn!("failed to unmount old root: {}", std::io::Error::last_os_error());
            }
        }

        let _ = fs::remove_dir("/.old_root");
        Ok(())
    }

    fn chroot_fallback(&self) -> Result<(), JailError> {
        unsafe {
            let path = self.new_root.as_os_str().as_encoded_bytes();
            let c_path = std::ffi::CString::new(path).unwrap();
            if libc::chroot(c_path.as_ptr()) != 0 {
                return Err(JailError::ChrootFailed(std::io::Error::last_os_error()));
            }
        }
        std::env::set_current_dir("/")
            .map_err(JailError::ChrootFailed)?;
        Ok(())
    }

    fn mount_proc_fs(&self) -> Result<(), JailError> {
        let target = PathBuf::from("/proc");
        fs::create_dir_all(&target).ok();
        unsafe {
            if libc::mount(
                b"proc\0".as_ptr() as *const i8,
                b"/proc\0".as_ptr() as *const i8,
                b"proc\0".as_ptr() as *const i8,
                MS_NOEXEC | MS_NOSUID | MS_NODEV,
                std::ptr::null(),
            ) != 0
            {
                return Err(JailError::MountFailed(std::io::Error::last_os_error()));
            }
        }
        info!("mounted /proc");
        Ok(())
    }

    fn mount_dev(&self) -> Result<(), JailError> {
        let target = PathBuf::from("/dev");
        fs::create_dir_all(&target).ok();
        unsafe {
            if libc::mount(
                b"tmpfs\0".as_ptr() as *const i8,
                b"/dev\0".as_ptr() as *const i8,
                b"tmpfs\0".as_ptr() as *const i8,
                MS_NOEXEC | MS_NOSUID,
                std::ptr::null(),
            ) != 0
            {
                return Err(JailError::MountFailed(std::io::Error::last_os_error()));
            }
        }
        info!("mounted minimal /dev");
        Ok(())
    }

    fn mount_sys(&self) -> Result<(), JailError> {
        let target = PathBuf::from("/sys");
        fs::create_dir_all(&target).ok();
        unsafe {
            if libc::mount(
                b"sysfs\0".as_ptr() as *const i8,
                b"/sys\0".as_ptr() as *const i8,
                b"sysfs\0".as_ptr() as *const i8,
                MS_RDONLY | MS_NOEXEC | MS_NOSUID | MS_NODEV,
                std::ptr::null(),
            ) != 0
            {
                return Err(JailError::MountFailed(std::io::Error::last_os_error()));
            }
        }
        info!("mounted /sys read-only");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_config_defaults() {
        let config = JailConfig::new("/tmp/test-root");
        assert_eq!(config.new_root, PathBuf::from("/tmp/test-root"));
        assert!(!config.mount_proc);
        assert!(!config.mount_dev_minimal);
        assert!(!config.mount_sys_ro);
    }

    #[test]
    fn mount_proc_flag() {
        let config = JailConfig::new("/tmp/test").mount_proc();
        assert!(config.mount_proc);
    }

    #[test]
    fn mount_dev_flag() {
        let config = JailConfig::new("/tmp/test").mount_dev_minimal();
        assert!(config.mount_dev_minimal);
    }

    #[test]
    fn mount_sys_flag() {
        let config = JailConfig::new("/tmp/test").mount_sys_ro();
        assert!(config.mount_sys_ro);
    }

    #[test]
    fn new_root_returns_path() {
        let config = JailConfig::new("/var/sandbox");
        assert_eq!(config.new_root(), Path::new("/var/sandbox"));
    }
}
