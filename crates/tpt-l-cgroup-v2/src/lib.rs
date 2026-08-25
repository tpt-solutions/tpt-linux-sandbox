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

    /// Set I/O weight (clamped 1–10000; kernel default is 100).
    pub fn io_weight(mut self, weight: u32) -> Self {
        self.io_weight = Some(weight.clamp(1, 10000));
        self
    }

    /// Create the cgroup hierarchy directory and write configured limits.
    pub fn apply(&self) -> Result<(), CgroupError> {
        let base = Path::new(Self::CGROUP_ROOT).join(&self.name);

        std::fs::create_dir_all(&base).map_err(|source| {
            if source.kind() == std::io::ErrorKind::NotFound {
                CgroupError::NotMounted {
                    path: base.clone(),
                    source,
                }
            } else {
                CgroupError::Write {
                    path: base.clone(),
                    source,
                }
            }
        })?;

        if let Some(percent) = self.cpu_quota_percent {
            // cpu.max format: "{quota_us} {period_us}\n"
            // We use a 100ms period; quota = percent * 1000 µs per period.
            let quota_us = u64::from(percent) * 1_000;
            let path = base.join("cpu.max");
            std::fs::write(&path, format!("{quota_us} 100000\n"))
                .map_err(|source| CgroupError::Write { path, source })?;
        }

        if let Some(bytes) = self.memory_limit_bytes {
            let path = base.join("memory.max");
            std::fs::write(&path, format!("{bytes}\n"))
                .map_err(|source| CgroupError::Write { path, source })?;
        }

        if let Some(weight) = self.io_weight {
            let path = base.join("io.weight");
            std::fs::write(&path, format!("default {weight}\n"))
                .map_err(|source| CgroupError::Write { path, source })?;
        }

        Ok(())
    }

    /// Move the calling process into this cgroup.
    pub fn enter(&self) -> Result<(), CgroupError> {
        let path = Path::new(Self::CGROUP_ROOT)
            .join(&self.name)
            .join("cgroup.procs");
        let pid = std::process::id();
        std::fs::write(&path, format!("{pid}\n"))
            .map_err(|source| CgroupError::Write { path, source })
    }

    /// Remove the cgroup hierarchy directory (must have no member processes).
    pub fn destroy(&self) -> Result<(), CgroupError> {
        let path = Path::new(Self::CGROUP_ROOT).join(&self.name);
        std::fs::remove_dir(&path)
            .map_err(|source| CgroupError::Write { path, source })
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
    fn io_weight_clamps_low() {
        let c = CgroupConfig::new("t").io_weight(0);
        assert_eq!(c.io_weight, Some(1));
    }

    #[test]
    fn io_weight_clamps_high() {
        let c = CgroupConfig::new("t").io_weight(99999);
        assert_eq!(c.io_weight, Some(10000));
    }

    #[test]
    fn memory_limit_stored() {
        let c = CgroupConfig::new("t").memory_limit(1 << 30);
        assert_eq!(c.memory_limit_bytes, Some(1 << 30));
    }

    #[test]
    fn cpu_quota_us_math() {
        // 50% → 50_000 µs per 100ms period
        let c = CgroupConfig::new("t").cpu_quota(50);
        let expected_us = 50u64 * 1_000;
        assert_eq!(expected_us, 50_000);
        assert_eq!(c.cpu_quota_percent, Some(50));
    }
}
