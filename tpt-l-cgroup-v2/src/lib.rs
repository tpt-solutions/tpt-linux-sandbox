//! Manages cgroup v2 hierarchies for CPU/memory/I/O limits.

#![deny(missing_docs)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]

use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::{debug, info};

/// Errors that can occur when managing cgroups.
#[derive(Debug, Error)]
pub enum CgroupError {
    /// Failed to create the cgroup directory.
    #[error("failed to create cgroup directory {0}: {1}")]
    CreateFailed(PathBuf, std::io::Error),
    /// Failed to write a cgroup control file.
    #[error("failed to write {0}: {1}")]
    WriteFailed(String, std::io::Error),
    /// Failed to read a cgroup control file.
    #[error("failed to read {0}: {1}")]
    ReadFailed(String, std::io::Error),
    /// The cgroup path does not exist.
    #[error("cgroup path does not exist: {0}")]
    NotFound(PathBuf),
}

/// Configuration for a cgroup v2 hierarchy.
///
/// # Example
///
/// ```
/// use tpt_l_cgroup_v2::CgroupConfig;
///
/// let config = CgroupConfig::new("my-sandbox")
///     .cpu_quota(50000, 100000)
///     .memory_limit(256 * 1024 * 1024)
///     .io_weight(100);
/// ```
#[derive(Debug, Clone)]
pub struct CgroupConfig {
    name: PathBuf,
    cpu_quota: Option<(u64, u64)>,
    memory_limit: Option<u64>,
    io_weight: Option<u32>,
}

impl CgroupConfig {
    /// Creates a new `CgroupConfig` with the given cgroup name.
    pub fn new<P: AsRef<Path>>(name: P) -> Self {
        Self {
            name: name.as_ref().to_path_buf(),
            cpu_quota: None,
            memory_limit: None,
            io_weight: None,
        }
    }

    /// Sets the CPU quota: `(quota_us, period_us)`.
    ///
    /// The process can run for `quota_us` microseconds every `period_us` microseconds.
    pub fn cpu_quota(mut self, quota_us: u64, period_us: u64) -> Self {
        self.cpu_quota = Some((quota_us, period_us));
        self
    }

    /// Sets the memory limit in bytes.
    pub fn memory_limit(mut self, bytes: u64) -> Self {
        self.memory_limit = Some(bytes);
        self
    }

    /// Sets the I/O weight (10-10000, default 100).
    pub fn io_weight(mut self, weight: u32) -> Self {
        self.io_weight = Some(weight);
        self
    }

    /// Returns the cgroup path under `/sys/fs/cgroup/`.
    pub fn cgroup_path(&self) -> PathBuf {
        PathBuf::from("/sys/fs/cgroup").join(&self.name)
    }

    /// Creates the cgroup hierarchy and applies resource limits.
    ///
    /// # Errors
    ///
    /// Returns `CgroupError::CreateFailed` if the cgroup directory cannot be
    /// created, or `CgroupError::WriteFailed` if a control file cannot be written.
    pub fn create(&self) -> Result<(), CgroupError> {
        let path = self.cgroup_path();
        debug!(path = ?path, "creating cgroup");

        fs::create_dir_all(&path)
            .map_err(|e| CgroupError::CreateFailed(path.clone(), e))?;

        if let Some((quota, period)) = self.cpu_quota {
            self.write_control("cpu.max", &format!("{quota} {period}"))?;
        }

        if let Some(limit) = self.memory_limit {
            self.write_control("memory.max", &limit.to_string())?;
        }

        if let Some(weight) = self.io_weight {
            self.write_control("io.weight", &format!("default {weight}"))?;
        }

        info!(path = ?path, "cgroup created successfully");
        Ok(())
    }

    /// Enters the cgroup by writing the current PID to `cgroup.procs`.
    ///
    /// # Errors
    ///
    /// Returns `CgroupError::WriteFailed` if `cgroup.procs` cannot be written.
    pub fn enter(&self) -> Result<(), CgroupError> {
        let pid = std::process::id();
        self.write_control("cgroup.procs", &pid.to_string())?;
        debug!(pid, "entered cgroup");
        Ok(())
    }

    /// Enters the cgroup by writing a specific PID to `cgroup.procs`.
    ///
    /// # Errors
    ///
    /// Returns `CgroupError::WriteFailed` if `cgroup.procs` cannot be written.
    pub fn enter_pid(&self, pid: u32) -> Result<(), CgroupError> {
        self.write_control("cgroup.procs", &pid.to_string())?;
        debug!(pid, "PID entered cgroup");
        Ok(())
    }

    /// Destroys the cgroup by removing its directory.
    ///
    /// # Errors
    ///
    /// Returns `CgroupError::WriteFailed` if the cgroup directory cannot be removed.
    pub fn destroy(&self) -> Result<(), CgroupError> {
        let path = self.cgroup_path();
        fs::remove_dir(&path)
            .map_err(|e| CgroupError::WriteFailed(path.display().to_string(), e))?;
        info!(path = ?path, "cgroup destroyed");
        Ok(())
    }

    fn write_control(&self, file: &str, value: &str) -> Result<(), CgroupError> {
        let path = self.cgroup_path().join(file);
        fs::write(&path, value)
            .map_err(|e| CgroupError::WriteFailed(path.display().to_string(), e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_config_has_no_limits() {
        let config = CgroupConfig::new("test");
        assert!(config.cpu_quota.is_none());
        assert!(config.memory_limit.is_none());
        assert!(config.io_weight.is_none());
    }

    #[test]
    fn cpu_quota_stored() {
        let config = CgroupConfig::new("test").cpu_quota(50000, 100000);
        assert_eq!(config.cpu_quota, Some((50000, 100000)));
    }

    #[test]
    fn memory_limit_stored() {
        let config = CgroupConfig::new("test").memory_limit(256 * 1024 * 1024);
        assert_eq!(config.memory_limit, Some(256 * 1024 * 1024));
    }

    #[test]
    fn io_weight_stored() {
        let config = CgroupConfig::new("test").io_weight(500);
        assert_eq!(config.io_weight, Some(500));
    }

    #[test]
    fn cgroup_path_constructed() {
        let config = CgroupConfig::new("my-sandbox");
        assert_eq!(
            config.cgroup_path(),
            PathBuf::from("/sys/fs/cgroup/my-sandbox")
        );
    }
}
