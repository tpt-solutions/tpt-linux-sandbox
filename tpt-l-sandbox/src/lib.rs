//! Composable sandbox orchestrator: Landlock + seccomp + namespaces + cgroups.
//!
//! Implements a 7-stage state machine with full validation before any
//! irreversible stage begins.

#![deny(missing_docs)]

use std::path::PathBuf;
use thiserror::Error;
use tracing::{debug, info, warn};

pub use tpt_l_caps_drop::{CapsError, CapsPolicy};
pub use tpt_l_cgroup_v2::{CgroupConfig, CgroupError};
pub use tpt_l_chroot_jail::{JailConfig, JailError};
pub use tpt_l_landlock_highlevel::{BuiltRuleset, LandlockError, RulesetBuilder};
pub use tpt_l_namespaces_rs::{NamespaceError, NamespaceFlags, NamespaceSet};
pub use tpt_l_seccomp_builder::{BuiltSeccompPolicy, SeccompError, SeccompPolicy};

/// Errors that can occur during sandbox construction or application.
#[derive(Debug, Error)]
pub enum SandboxError {
    /// Validation failed before any kernel calls.
    #[error("validation failed: {0}")]
    Validation(String),
    /// Landlock error.
    #[error("landlock: {0}")]
    Landlock(#[from] LandlockError),
    /// Seccomp error.
    #[error("seccomp: {0}")]
    Seccomp(#[from] SeccompError),
    /// Namespace error.
    #[error("namespaces: {0}")]
    Namespaces(#[from] NamespaceError),
    /// Cgroup error.
    #[error("cgroup: {0}")]
    Cgroup(#[from] CgroupError),
    /// Capability error.
    #[error("caps: {0}")]
    Caps(#[from] CapsError),
    /// Chroot/jail error.
    #[error("jail: {0}")]
    Jail(#[from] JailError),
    /// No command specified for execution.
    #[error("no command specified")]
    NoCommand,
}

/// The top-level sandbox builder.
///
/// # Example
///
/// ```
/// use tpt_l_sandbox::Sandbox;
///
/// let sandbox = Sandbox::new()
///     .allow_read("/etc")
///     .allow_write("/tmp")
///     .no_network()
///     .memory_limit(256 * 1024 * 1024);
/// ```
#[derive(Debug)]
pub struct Sandbox {
    landlock: Option<RulesetBuilder>,
    seccomp: Option<SeccompPolicy>,
    namespaces: Option<NamespaceSet>,
    cgroup: Option<CgroupConfig>,
    caps: Option<CapsPolicy>,
    jail: Option<JailConfig>,
    command: Option<Vec<String>>,
}

impl Sandbox {
    /// Creates a new `Sandbox` builder with default settings.
    pub fn new() -> Self {
        Self {
            landlock: None,
            seccomp: None,
            namespaces: None,
            cgroup: None,
            caps: None,
            jail: None,
            command: None,
        }
    }

    /// Adds a path that the sandboxed process may read.
    pub fn allow_read<P: Into<PathBuf>>(mut self, path: P) -> Self {
        let builder = self.landlock.take().unwrap_or_default();
        self.landlock = Some(builder.allow_read(path.into()));
        self
    }

    /// Adds a path that the sandboxed process may write to.
    pub fn allow_write<P: Into<PathBuf>>(mut self, path: P) -> Self {
        let builder = self.landlock.take().unwrap_or_default();
        self.landlock = Some(builder.allow_write(path.into()));
        self
    }

    /// Adds a path that the sandboxed process may execute.
    pub fn allow_exec<P: Into<PathBuf>>(mut self, path: P) -> Self {
        let builder = self.landlock.take().unwrap_or_default();
        self.landlock = Some(builder.allow_exec(path.into()));
        self
    }

    /// Sets the seccomp policy.
    pub fn seccomp_policy(mut self, policy: SeccompPolicy) -> Self {
        self.seccomp = Some(policy);
        self
    }

    /// Adds a syscall to the seccomp allowlist.
    pub fn allow_syscall(mut self, name: &str) -> Self {
        let policy = self.seccomp.take().unwrap_or_default();
        self.seccomp = Some(policy.allow_syscall(name));
        self
    }

    /// Configures namespace isolation.
    pub fn namespaces(mut self, ns: NamespaceSet) -> Self {
        self.namespaces = Some(ns);
        self
    }

    /// Disables network access by adding the network namespace.
    pub fn no_network(mut self) -> Self {
        let ns = self.namespaces.take().unwrap_or_default();
        self.namespaces = Some(ns.network());
        self
    }

    /// Sets the cgroup configuration.
    pub fn cgroup(mut self, config: CgroupConfig) -> Self {
        self.cgroup = Some(config);
        self
    }

    /// Sets a memory limit in bytes.
    pub fn memory_limit(mut self, bytes: u64) -> Self {
        let config = self.cgroup.take().unwrap_or_else(|| CgroupConfig::new("tpt-sandbox"));
        self.cgroup = Some(config.memory_limit(bytes));
        self
    }

    /// Sets the CPU quota: `(quota_us, period_us)`.
    pub fn cpu_quota(mut self, quota_us: u64, period_us: u64) -> Self {
        let config = self.cgroup.take().unwrap_or_else(|| CgroupConfig::new("tpt-sandbox"));
        self.cgroup = Some(config.cpu_quota(quota_us, period_us));
        self
    }

    /// Sets the capability dropping policy.
    pub fn caps_policy(mut self, policy: CapsPolicy) -> Self {
        self.caps = Some(policy);
        self
    }

    /// Drops all capabilities.
    pub fn drop_all_caps(mut self) -> Self {
        let policy = self.caps.take().unwrap_or_default();
        self.caps = Some(policy.drop_all());
        self
    }

    /// Sets the chroot jail configuration.
    pub fn jail(mut self, config: JailConfig) -> Self {
        self.jail = Some(config);
        self
    }

    /// Sets the command to execute after applying the sandbox.
    pub fn command(mut self, args: &[&str]) -> Self {
        self.command = Some(args.iter().map(|s| s.to_string()).collect());
        self
    }

    /// Validates the entire sandbox configuration before any kernel calls.
    ///
    /// Returns `Ok(())` if the configuration is valid, or an error describing
    /// the first invalid combination found.
    pub fn validate(&self) -> Result<(), SandboxError> {
        // Validate that we have at least some restriction
        if self.landlock.is_none()
            && self.seccomp.is_none()
            && self.namespaces.is_none()
            && self.cgroup.is_none()
            && self.caps.is_none()
            && self.jail.is_none()
        {
            return Err(SandboxError::Validation(
                "no sandbox restrictions specified".into(),
            ));
        }

        // Validate seccomp syscall names are resolvable
        if let Some(ref policy) = self.seccomp {
            for name in policy.allowed_syscalls() {
                if seccompiler::Syscall::from_name(name).is_none() {
                    return Err(SandboxError::Validation(format!(
                        "unknown syscall: {name}"
                    )));
                }
            }
        }

        // Validate landlock has at least one access path
        if let Some(ref builder) = self.landlock {
            if builder.read_paths().is_empty()
                && builder.write_paths().is_empty()
                && builder.exec_paths().is_empty()
            {
                return Err(SandboxError::Validation(
                    "landlock ruleset has no paths".into(),
                ));
            }
        }

        // Validate caps policy if present
        if let Some(ref policy) = self.caps {
            policy.validate().map_err(SandboxError::Caps)?;
        }

        info!("sandbox configuration validated successfully");
        Ok(())
    }

    /// Applies the sandbox using the 7-stage state machine.
    ///
    /// Stages:
    /// 1. Validation (no kernel calls)
    /// 2. Cgroup setup + enter
    /// 3. Namespace creation
    /// 4. Filesystem jail (pivot_root / chroot + pseudo-fs)
    /// 5. Capability dropping
    /// 6. Seccomp enforcement (irreversible)
    /// 7. Landlock enforcement (irreversible, last)
    pub fn apply(self) -> Result<AppliedSandbox, SandboxError> {
        // Stage 1: Validation
        info!("Stage 1: validating sandbox configuration");
        self.validate()?;

        // Stage 2: Cgroup setup + enter
        if let Some(ref cgroup) = self.cgroup {
            info!("Stage 2: setting up cgroup");
            cgroup.create()?;
            cgroup.enter()?;
        }

        // Stage 3: Namespace creation
        if let Some(ref namespaces) = self.namespaces {
            info!("Stage 3: creating namespaces");
            namespaces.apply()?;
        }

        // Stage 4: Filesystem jail
        if let Some(ref jail) = self.jail {
            info!("Stage 4: setting up filesystem jail");
            jail.apply()?;
        }

        // Stage 5: Capability dropping
        if let Some(ref caps) = self.caps {
            info!("Stage 5: dropping capabilities");
            caps.clone().apply()?;
        }

        // Stage 6: Seccomp enforcement (irreversible)
        if let Some(ref seccomp) = self.seccomp {
            info!("Stage 6: applying seccomp (irreversible)");
            seccomp.clone().build()?.apply()?;
        }

        // Stage 7: Landlock enforcement (irreversible, last)
        if let Some(ref landlock) = self.landlock {
            info!("Stage 7: applying landlock (irreversible, last)");
            landlock.clone().build()?.apply()?;
        }

        info!("sandbox applied successfully");
        Ok(AppliedSandbox {
            command: self.command,
        })
    }
}

impl Default for Sandbox {
    fn default() -> Self {
        Self::new()
    }
}

/// An applied sandbox ready to execute a command.
#[derive(Debug)]
pub struct AppliedSandbox {
    command: Option<Vec<String>>,
}

impl AppliedSandbox {
    /// Executes the configured command within the applied sandbox.
    pub fn exec(&self) -> Result<(), SandboxError> {
        let command = self.command.as_ref().ok_or(SandboxError::NoCommand)?;

        if command.is_empty() {
            return Err(SandboxError::NoCommand);
        }

        let program = &command[0];
        let args: Vec<&str> = command.iter().map(|s| s.as_str()).collect();

        debug!(program = program, args = ?args, "executing command in sandbox");

        let err = execvp(program, &args);
        return Err(SandboxError::Validation(format!("execvp failed: {err}")));
    }
}

fn execvp(program: &str, args: &[&str]) -> std::io::Error {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_program = CString::new(program.as_bytes()).unwrap();
    let c_args: Vec<CString> = args.iter().map(|a| CString::new(a.as_bytes()).unwrap()).collect();
    let c_args_ptrs: Vec<*const i8> = c_args.iter().map(|a| a.as_ptr()).collect();

    unsafe {
        libc::execvp(c_program.as_ptr(), c_args_ptrs.as_ptr());
    }
    std::io::Error::last_os_error()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_sandbox_is_empty() {
        let sandbox = Sandbox::new();
        assert!(sandbox.landlock.is_none());
        assert!(sandbox.seccomp.is_none());
    }

    #[test]
    fn allow_read_sets_landlock() {
        let sandbox = Sandbox::new().allow_read("/etc");
        assert!(sandbox.landlock.is_some());
    }

    #[test]
    fn allow_write_sets_landlock() {
        let sandbox = Sandbox::new().allow_write("/tmp");
        assert!(sandbox.landlock.is_some());
    }

    #[test]
    fn no_network_sets_namespace() {
        let sandbox = Sandbox::new().no_network();
        assert!(sandbox.namespaces.is_some());
    }

    #[test]
    fn memory_limit_sets_cgroup() {
        let sandbox = Sandbox::new().memory_limit(1024 * 1024);
        assert!(sandbox.cgroup.is_some());
    }

    #[test]
    fn drop_all_caps_sets_policy() {
        let sandbox = Sandbox::new().drop_all_caps();
        assert!(sandbox.caps.is_some());
    }

    #[test]
    fn validate_empty_sandbox_fails() {
        let sandbox = Sandbox::new();
        assert!(matches!(sandbox.validate(), Err(SandboxError::Validation(_))));
    }

    #[test]
    fn validate_with_restrictions_passes() {
        let sandbox = Sandbox::new().allow_read("/etc");
        assert!(sandbox.validate().is_ok());
    }

    #[test]
    fn command_stored() {
        let sandbox = Sandbox::new().command(&["cat", "/etc/hostname"]);
        assert_eq!(sandbox.command, Some(vec!["cat".to_string(), "/etc/hostname".to_string()]));
    }

    #[test]
    fn exec_without_command_fails() {
        let applied = AppliedSandbox { command: None };
        assert!(matches!(applied.exec(), Err(SandboxError::NoCommand)));
    }
}
