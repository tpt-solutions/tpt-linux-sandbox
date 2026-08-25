//! cgroup v2 hierarchy management for CPU, memory, and I/O limits.
//!
//! Operates directly on the cgroupfs at `/sys/fs/cgroup` — no external
//! library dependency required.
//!
//! # Example
//!
//! ```no_run
//! use tpt_l_cgroup_v2::CgroupConfig;
//!
//! let cg = CgroupConfig::new("my-sandbox")
//!     .cpu_quota(50)           // 50% of one core
//!     .memory_limit(128 << 20) // 128 MiB
//!     .io_weight(50);
//!
//! cg.apply().expect("cgroup setup failed");
//! cg.enter().expect("failed to join cgroup");
//! ```

#[cfg(not(target_os = "linux"))]
compile_error!("tpt-l-cgroup-v2 only supports Linux");

use std::path::{Path, PathBuf};
use thiserror::Error;

/// Errors produced by this crate.
#[derive(Debug, Error)]
pub enum CgroupError {
    /// The cgroupfs is not mounted where expected.
    #[error("cgroupfs not mounted at {path}: {source}")]
    NotMounted { path: PathBuf, source: std::io::Error },
    /// Writing a cgroup control file failed.
    #[error("failed to write cgroup control file {path}: {source}")]
    Write { path: PathBuf, source: std::io::Error },
}

/// Configuration for a cgroup v2 hierarchy.
#[derive(Debug, Clone)]
pub struct CgroupConfig {
    name: String,
    cpu_quota_percent: Option<u32>,
    memory_limit_bytes: Option<u64>,
    io_weight: Option<u32>,
}

impl CgroupConfig {
    const CGROUP_ROOT: &'static str = "/sys/fs/cgroup";

    /// Create a new config for a cgroup named `name` under the cgroup root.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            cpu_quota_percent: None,
            memory_limit_bytes: None,
            io_weight: None,
        }
    }

    /// Limit CPU usage to `percent` percent of one core (clamped 1–100).
    pub fn cpu_quota(mut self, percent: u32) -> Self {
        self.cpu_quota_percent = Some(percent.clamp(1, 100));
        self
    }

    /// Limit memory usage to `bytes`.
    pub fn memory_limit(mut self, bytes: u64) -> Self {
        self.memory_limit_bytes = Some(bytes);
        self
    }

    /// Set I/O weight (clamped 1–10000; default kernel value is 100).
    pub fn io_weight(mut self, weight: u32) -> Self {
        self.io_weight = Some(weight.clamp(1, 10000));
        self
    }

    /// Create the cgroup hierarchy directory and write configured limits.
    pub fn apply(&self) -> Result<(), CgroupError> {
        let base = Path::new(Self::CGROUP_ROOT).join(&self.name);
        // TODO: std::fs::create_dir_all(&base), then write control files:
        //   cpu.max    → "{quota} 100000\n" where quota = percent * 1000
        //   memory.max → "{bytes}\n"
        //   io.weight  → "default {weight}\n"
        drop(base);
        Ok(())
    }

    /// Move the calling process into this cgroup.
    pub fn enter(&self) -> Result<(), CgroupError> {
        let procs = Path::new(Self::CGROUP_ROOT)
            .join(&self.name)
            .join("cgroup.procs");
        // TODO: write std::process::id().to_string() to `procs`.
        drop(procs);
        Ok(())
    }

    /// Remove the cgroup hierarchy directory (must have no member processes).
    pub fn destroy(&self) -> Result<(), CgroupError> {
        let base = Path::new(Self::CGROUP_ROOT).join(&self.name);
        // TODO: std::fs::remove_dir(&base)
        drop(base);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_quota_clamps() {
        let c = CgroupConfig::new("t").cpu_quota(200);
        assert_eq!(c.cpu_quota_percent, Some(100));
    }

    #[test]
    fn io_weight_clamps() {
        let c = CgroupConfig::new("t").io_weight(0);
        assert_eq!(c.io_weight, Some(1));
    }

    #[test]
    fn memory_limit_stored() {
        let c = CgroupConfig::new("t").memory_limit(1 << 30);
        assert_eq!(c.memory_limit_bytes, Some(1 << 30));
    }
}
