//! cgroup v2 hierarchy management for CPU, memory, I/O and process-count limits.
//!
//! Operates directly on the cgroupfs at `/sys/fs/cgroup` — no external
//! library dependency required.
//!
//! The directory is created with `mkdir` (not `mkdir -p`), so a stale
//! directory from an earlier run is reported instead of being silently reused
//! with old limits.
//!
//! # Example
//!
//! ```no_run
//! use tpt_l_cgroup_v2::CgroupConfig;
//!
//! let cg = CgroupConfig::new("my-sandbox")
//!     .cpu_quota(50)           // 50% of one core
//!     .memory_limit(128 << 20) // 128 MiB
//!     .pids_limit(64)
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
    NotMounted {
        /// The directory that was expected to exist.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// Writing a cgroup control file failed.
    #[error("failed to write cgroup control file {path}: {source}")]
    Write {
        /// The control file that could not be written.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// The cgroup name is not a single, plain path component.
    #[error("invalid cgroup name {0:?}: must be a single non-empty component without '/' or '..'")]
    InvalidName(String),
    /// A cgroup with this name already exists (possibly stale from an earlier run).
    #[error("cgroup {0} already exists; refusing to reuse it")]
    AlreadyExists(PathBuf),
}

/// Configuration for a cgroup v2 hierarchy.
#[derive(Debug, Clone)]
pub struct CgroupConfig {
    name: String,
    cpu_quota_percent: Option<u32>,
    memory_limit_bytes: Option<u64>,
    io_weight: Option<u32>,
    pids_max: Option<u32>,
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
            pids_max: None,
        }
    }

    /// The cgroup's name (its directory name under `/sys/fs/cgroup`).
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Limit CPU usage to `percent` percent of one core (clamped 1–100).
    pub fn cpu_quota(mut self, percent: u32) -> Self {
        self.cpu_quota_percent = Some(percent.clamp(1, 100));
        self
    }

    /// Limit memory usage to `bytes`. Swap is disabled for the cgroup so the
    /// limit cannot be bypassed by swapping.
    pub fn memory_limit(mut self, bytes: u64) -> Self {
        self.memory_limit_bytes = Some(bytes);
        self
    }

    /// Limit the number of processes and threads (`pids.max`), which bounds
    /// fork bombs.
    pub fn pids_limit(mut self, max: u32) -> Self {
        self.pids_max = Some(max);
        self
    }

    /// Set I/O weight (clamped 1–10000; kernel default is 100).
    pub fn io_weight(mut self, weight: u32) -> Self {
        self.io_weight = Some(weight.clamp(1, 10000));
        self
    }

    /// Resolve the cgroup directory, rejecting names that could escape the root.
    fn path(&self) -> Result<PathBuf, CgroupError> {
        let name = &self.name;
        let valid = !name.is_empty()
            && name != "."
            && name != ".."
            && !name.contains('/')
            && !name.contains('\0');
        if !valid {
            return Err(CgroupError::InvalidName(name.clone()));
        }
        Ok(Path::new(Self::CGROUP_ROOT).join(name))
    }

    /// Controllers this configuration needs enabled in the parent's
    /// `cgroup.subtree_control`.
    fn required_controllers(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.cpu_quota_percent.is_some() {
            out.push("cpu");
        }
        if self.memory_limit_bytes.is_some() {
            out.push("memory");
        }
        if self.io_weight.is_some() {
            out.push("io");
        }
        if self.pids_max.is_some() {
            out.push("pids");
        }
        out
    }

    /// Create the cgroup hierarchy directory and write configured limits.
    ///
    /// # Errors
    ///
    /// Fails with [`CgroupError::AlreadyExists`] if the directory is present,
    /// and with [`CgroupError::Write`] if a controller cannot be enabled or a
    /// limit cannot be written (typically a permissions or delegation problem).
    pub fn apply(&self) -> Result<(), CgroupError> {
        let base = self.path()?;

        // Enable only the controllers the parent does not already delegate.
        // Rewriting an enabled controller is unnecessary, and in a cgroup that
        // holds processes the write can fail with EBUSY.
        let control = Path::new(Self::CGROUP_ROOT).join("cgroup.subtree_control");
        let enabled = std::fs::read_to_string(&control).unwrap_or_default();
        let missing: Vec<String> = self
            .required_controllers()
            .into_iter()
            .filter(|c| !enabled.split_whitespace().any(|e| e == *c))
            .map(|c| format!("+{c}"))
            .collect();
        if !missing.is_empty() {
            std::fs::write(&control, format!("{}\n", missing.join(" "))).map_err(|source| {
                CgroupError::Write {
                    path: control,
                    source,
                }
            })?;
        }

        std::fs::create_dir(&base).map_err(|source| match source.kind() {
            std::io::ErrorKind::AlreadyExists => CgroupError::AlreadyExists(base.clone()),
            std::io::ErrorKind::NotFound => CgroupError::NotMounted {
                path: base.clone(),
                source,
            },
            _ => CgroupError::Write {
                path: base.clone(),
                source,
            },
        })?;

        if let Some(percent) = self.cpu_quota_percent {
            // cpu.max format: "{quota_us} {period_us}\n"
            // We use a 100ms period; quota = percent * 1000 µs per period.
            let quota_us = u64::from(percent) * 1_000;
            Self::write_control(&base, "cpu.max", &format!("{quota_us} 100000\n"))?;
        }

        if let Some(bytes) = self.memory_limit_bytes {
            Self::write_control(&base, "memory.max", &format!("{bytes}\n"))?;
            Self::write_control(&base, "memory.swap.max", "0\n")?;
        }

        if let Some(weight) = self.io_weight {
            Self::write_control(&base, "io.weight", &format!("default {weight}\n"))?;
        }

        if let Some(max) = self.pids_max {
            Self::write_control(&base, "pids.max", &format!("{max}\n"))?;
        }

        Ok(())
    }

    /// Write one control file below `base`.
    fn write_control(base: &Path, file: &str, contents: &str) -> Result<(), CgroupError> {
        let path = base.join(file);
        std::fs::write(&path, contents).map_err(|source| CgroupError::Write { path, source })
    }

    /// Move the calling process into this cgroup.
    pub fn enter(&self) -> Result<(), CgroupError> {
        let path = self.path()?.join("cgroup.procs");
        let pid = std::process::id();
        std::fs::write(&path, format!("{pid}\n"))
            .map_err(|source| CgroupError::Write { path, source })
    }

    /// Remove the cgroup hierarchy directory (must have no member processes).
    pub fn destroy(&self) -> Result<(), CgroupError> {
        let path = self.path()?;
        std::fs::remove_dir(&path).map_err(|source| CgroupError::Write { path, source })
    }

    /// Move the calling process back to the cgroup root and remove this
    /// cgroup. Used to roll back when a later sandbox stage fails.
    pub fn release(&self) -> Result<(), CgroupError> {
        let root_procs = Path::new(Self::CGROUP_ROOT).join("cgroup.procs");
        let pid = std::process::id();
        std::fs::write(&root_procs, format!("{pid}\n")).map_err(|source| CgroupError::Write {
            path: root_procs,
            source,
        })?;
        self.destroy()
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

    #[test]
    fn rejects_traversal_names() {
        for bad in ["", ".", "..", "../x", "/etc", "a/b", "x\0y"] {
            let c = CgroupConfig::new(bad);
            assert!(
                matches!(c.path(), Err(CgroupError::InvalidName(_))),
                "name {bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn accepts_plain_name() {
        let c = CgroupConfig::new("tpt-sandbox-42");
        assert_eq!(
            c.path().unwrap(),
            Path::new("/sys/fs/cgroup/tpt-sandbox-42")
        );
    }

    /// Create, join and remove a cgroup from a forked child. The child is the
    /// one that joins, so the test process is not moved. Skips when this user
    /// cannot create cgroups under `/sys/fs/cgroup`.
    #[test]
    #[ignore = "creates a cgroup under /sys/fs/cgroup; run with --include-ignored"]
    fn enter_and_release_in_forked_child() {
        let name = format!("tpt-cgroup-test-{}", std::process::id());
        // SAFETY: the child is single-threaded; it only manipulates cgroups and
        // `_exit`s.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let cg = CgroupConfig::new(name);
            let code = match cg.apply() {
                Err(CgroupError::NotMounted { .. } | CgroupError::Write { .. }) => 3,
                Err(_) => 4,
                Ok(()) => match cg.enter().and_then(|()| cg.release()) {
                    Ok(()) => 0,
                    Err(_) => 5,
                },
            };
            // SAFETY: _exit skips destructors, which must not run in a forked child.
            unsafe { libc::_exit(code) };
        }

        let mut status: libc::c_int = 0;
        // SAFETY: `status` is a valid out-pointer.
        unsafe { libc::waitpid(pid, &raw mut status, 0) };
        assert!(libc::WIFEXITED(status), "child was killed");
        match libc::WEXITSTATUS(status) {
            0 => {}
            3 => eprintln!("skipping: this user cannot create cgroups"),
            code => panic!("cgroup enter/release failed with code {code}"),
        }
    }

    #[test]
    fn required_controllers_follow_config() {
        assert_eq!(CgroupConfig::new("t").required_controllers().len(), 0);
        let c = CgroupConfig::new("t").memory_limit(1).pids_limit(8);
        assert_eq!(c.required_controllers(), vec!["memory", "pids"]);
    }

    #[test]
    fn pids_limit_stored() {
        let c = CgroupConfig::new("t").pids_limit(64);
        assert_eq!(c.pids_max, Some(64));
    }
}
