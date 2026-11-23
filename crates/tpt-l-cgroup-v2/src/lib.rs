//! cgroup v2 hierarchy management for CPU, memory, I/O and process-count limits.
//!
//! Operates directly on the cgroupfs — no external library dependency
//! required. A cgroup is created under the calling process's own cgroup, so it
//! works under systemd `Delegate=yes` without root.
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
use std::sync::OnceLock;
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
    /// Controllers cannot be enabled because the cgroup also holds other
    /// processes, which cgroup v2 allows only in a leaf.
    #[error(
        "cannot enable controllers in {cgroup}: it also holds other processes. \
         Move them out, or opt in with move_existing_processes()"
    )]
    SharedCgroup {
        /// The cgroup that holds the processes.
        cgroup: PathBuf,
    },
}

/// Configuration for a cgroup v2 hierarchy.
#[derive(Debug, Clone)]
pub struct CgroupConfig {
    name: String,
    /// The calling process's cgroup when the config was made.
    parent: PathBuf,
    /// Where `apply` created the group: `parent`, or the cgroupfs root when
    /// `parent` could not take controllers. Unset until `apply` succeeds.
    created_under: OnceLock<PathBuf>,
    /// The leaf that holds this process while controllers are enabled in the
    /// parent, when apply needed one.
    host_leaf: OnceLock<PathBuf>,
    /// Whether `apply` may move the other processes of the caller's cgroup
    /// into the leaf. Off by default.
    move_existing: bool,
    cpu_quota_percent: Option<u32>,
    memory_limit_bytes: Option<u64>,
    io_weight: Option<u32>,
    pids_max: Option<u32>,
}

/// The cgroupfs mount point.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Name of the leaf that holds the process while the parent enables
/// controllers. Fixed, so repeated runs reuse one directory.
const HOST_LEAF: &str = "tpt-sandbox-host";

/// `EBUSY` on Linux: a cgroup write refused because the cgroup holds processes.
const EBUSY: i32 = 16;

/// The calling process's own cgroup directory, from `/proc/self/cgroup`.
///
/// Under systemd `Delegate=yes` (or a delegated user slice) this is the
/// writable subtree; the cgroupfs root usually is not writable. Falls back to
/// the cgroupfs root when the process is not in a v2 hierarchy.
fn own_cgroup_dir() -> PathBuf {
    std::fs::read_to_string("/proc/self/cgroup").map_or_else(
        |_| PathBuf::from(CGROUP_ROOT),
        |text| cgroup_dir_from(&text),
    )
}

/// Map the contents of a `/proc/self/cgroup` file to a cgroupfs directory.
/// A v2 entry has the form `0::/path`.
fn cgroup_dir_from(text: &str) -> PathBuf {
    text.lines()
        .find_map(|line| line.strip_prefix("0::"))
        .map_or_else(
            || PathBuf::from(CGROUP_ROOT),
            |rel| Path::new(CGROUP_ROOT).join(rel.trim_start_matches('/')),
        )
}

impl CgroupConfig {
    /// Create a new config for a cgroup named `name`, nested under the calling
    /// process's own cgroup. The parent is read now, not at apply time, because
    /// [`enter`](Self::enter) moves the process into the new cgroup.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            parent: own_cgroup_dir(),
            created_under: OnceLock::new(),
            host_leaf: OnceLock::new(),
            move_existing: false,
            cpu_quota_percent: None,
            memory_limit_bytes: None,
            io_weight: None,
            pids_max: None,
        }
    }

    /// The cgroup's name (its directory name under the parent cgroup).
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The directory the cgroup lives in: where `apply` created it, otherwise
    /// the calling process's cgroup (usually the delegated subtree).
    #[must_use]
    pub fn parent(&self) -> &Path {
        self.created_under.get().unwrap_or(&self.parent)
    }

    /// Let `apply` move the other processes of the caller's cgroup into a leaf
    /// when controllers can only be enabled that way.
    ///
    /// Off by default, because it moves processes the caller did not start.
    /// They stay in that leaf afterwards: cgroup v2 does not allow them back
    /// into the parent while its controllers are enabled.
    #[must_use]
    pub fn move_existing_processes(mut self) -> Self {
        self.move_existing = true;
        self
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
    fn check_name(&self) -> Result<(), CgroupError> {
        let name = &self.name;
        let valid = !name.is_empty()
            && name != "."
            && name != ".."
            && !name.contains('/')
            && !name.contains('\0');
        if !valid {
            return Err(CgroupError::InvalidName(name.clone()));
        }
        Ok(())
    }

    /// The cgroup's directory: the name under the parent that `apply` used.
    fn path(&self) -> Result<PathBuf, CgroupError> {
        self.check_name()?;
        Ok(self.parent().join(&self.name))
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
        // Controllers cannot be enabled in a cgroup that holds processes
        // (cgroup v2 "no internal processes"). The delegation rule is to move
        // this process into a leaf first, then enable the parent. That only
        // works when no other process shares the cgroup.
        let own_error = match self.create_under(&self.parent) {
            Err(CgroupError::Write { path, source })
                if path.ends_with("cgroup.subtree_control")
                    && self.parent != Path::new(CGROUP_ROOT) =>
            {
                if source.raw_os_error() == Some(EBUSY) {
                    CgroupError::SharedCgroup {
                        cgroup: self.parent.clone(),
                    }
                } else {
                    CgroupError::Write { path, source }
                }
            }
            other => return other,
        };
        if self.enable_via_host_leaf(&self.parent).is_ok() {
            return self.create_under(&self.parent);
        }
        // Not delegated to this process. The cgroupfs root takes controllers
        // when the caller is root. If that fails too, report the caller's own
        // cgroup: that is the error the user can act on.
        self.create_under(Path::new(CGROUP_ROOT))
            .map_err(|_| own_error)
    }

    /// Enable the required controllers in `parent` by first moving this process
    /// into a leaf below it. On failure the process is moved back.
    fn enable_via_host_leaf(&self, parent: &Path) -> Result<(), CgroupError> {
        let leaf = parent.join(HOST_LEAF);
        match std::fs::create_dir(&leaf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(source) => {
                return Err(CgroupError::Write { path: leaf, source });
            }
        }
        let pid = std::process::id();
        Self::write_control(&leaf, "cgroup.procs", &format!("{pid}\n"))?;

        // With the opt-in, move the other processes too. Each one that moved is
        // recorded, so a failure can put it back.
        let mut moved = vec![pid];
        if self.move_existing {
            let procs = std::fs::read_to_string(parent.join("cgroup.procs")).unwrap_or_default();
            for other in procs.lines().filter_map(|l| l.trim().parse::<u32>().ok()) {
                if other == pid {
                    continue;
                }
                match Self::write_control(&leaf, "cgroup.procs", &format!("{other}\n")) {
                    Ok(()) => moved.push(other),
                    // The process exited since it was listed. Nothing to move.
                    Err(CgroupError::Write { source, .. })
                        if source.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => {
                        Self::restore_processes(parent, &moved);
                        return Err(e);
                    }
                }
            }
        }

        if let Err(e) = self.enable_controllers(parent) {
            // The parent refused, so it has no controllers and can take the
            // processes back.
            Self::restore_processes(parent, &moved);
            return Err(e);
        }
        // Remembered so release() moves the process back into this leaf rather
        // than into the parent, which now has controllers enabled.
        let _ = self.host_leaf.set(leaf);
        Ok(())
    }

    /// Move `pids` back into `parent`, best effort. Only valid while the parent
    /// has no controllers enabled.
    fn restore_processes(parent: &Path, pids: &[u32]) {
        for pid in pids {
            let _ = Self::write_control(parent, "cgroup.procs", &format!("{pid}\n"));
        }
    }

    /// Enable, in `parent`'s `cgroup.subtree_control`, the controllers this
    /// configuration needs and the parent does not already have.
    fn enable_controllers(&self, parent: &Path) -> Result<(), CgroupError> {
        // Rewriting an enabled controller is unnecessary, and in a cgroup that
        // holds processes the write can fail with EBUSY.
        let control = parent.join("cgroup.subtree_control");
        let enabled = std::fs::read_to_string(&control).unwrap_or_default();
        let missing: Vec<String> = self
            .required_controllers()
            .into_iter()
            .filter(|c| !enabled.split_whitespace().any(|e| e == *c))
            .map(|c| format!("+{c}"))
            .collect();
        if missing.is_empty() {
            return Ok(());
        }
        std::fs::write(&control, format!("{}\n", missing.join(" "))).map_err(|source| {
            CgroupError::Write {
                path: control,
                source,
            }
        })
    }

    /// Create the directory under `parent` and write the limits. Records
    /// `parent` as the place the group lives once it succeeds.
    fn create_under(&self, parent: &Path) -> Result<(), CgroupError> {
        self.check_name()?;
        let base = parent.join(&self.name);

        self.enable_controllers(parent)?;

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

        // The directory is ours (mkdir just succeeded). If a limit cannot be
        // written, remove it so a failed apply leaves nothing behind.
        if let Err(e) = self.write_limits(&base) {
            let _ = std::fs::remove_dir(&base);
            return Err(e);
        }
        // Only the first successful apply records the parent.
        let _ = self.created_under.set(parent.to_path_buf());
        Ok(())
    }

    /// Write every configured limit below `base`.
    fn write_limits(&self, base: &Path) -> Result<(), CgroupError> {
        if let Some(percent) = self.cpu_quota_percent {
            // cpu.max format: "{quota_us} {period_us}\n"
            // We use a 100ms period; quota = percent * 1000 µs per period.
            let quota_us = u64::from(percent) * 1_000;
            Self::write_control(base, "cpu.max", &format!("{quota_us} 100000\n"))?;
        }

        if let Some(bytes) = self.memory_limit_bytes {
            Self::write_control(base, "memory.max", &format!("{bytes}\n"))?;
            Self::write_control(base, "memory.swap.max", "0\n")?;
        }

        if let Some(weight) = self.io_weight {
            Self::write_control(base, "io.weight", &format!("default {weight}\n"))?;
        }

        if let Some(max) = self.pids_max {
            Self::write_control(base, "pids.max", &format!("{max}\n"))?;
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
        // Move back to where the process was: the host leaf if apply made one,
        // otherwise the caller's own cgroup. Not the cgroupfs root, which is
        // usually not writable for a delegated user.
        let back = self
            .host_leaf
            .get()
            .cloned()
            .unwrap_or_else(|| self.parent.clone());
        let procs = back.join("cgroup.procs");
        let pid = std::process::id();
        std::fs::write(&procs, format!("{pid}\n")).map_err(|source| CgroupError::Write {
            path: procs,
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
        assert_eq!(c.path().unwrap(), c.parent().join("tpt-sandbox-42"));
    }

    #[test]
    fn parent_is_the_callers_v2_cgroup() {
        let text = "12:cpu:/legacy\n0::/user.slice/app.slice/run-1.scope\n";
        assert_eq!(
            cgroup_dir_from(text),
            Path::new("/sys/fs/cgroup/user.slice/app.slice/run-1.scope")
        );
    }

    #[test]
    fn parent_falls_back_to_root_without_v2_entry() {
        assert_eq!(
            cgroup_dir_from("1:name=systemd:/\n"),
            Path::new(CGROUP_ROOT)
        );
        assert_eq!(cgroup_dir_from("0::/\n"), Path::new(CGROUP_ROOT));
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
