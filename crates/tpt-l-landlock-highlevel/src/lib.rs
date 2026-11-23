//! Declarative builder API for Linux Landlock restrictions.
//!
//! Wraps the [`landlock`] crate with an ergonomic, composable builder that
//! integrates with the `tpt-l-sandbox` 7-stage state machine.
//!
//! # Kernel support
//!
//! Filesystem rules request Landlock ABI v3 rights (Linux 6.2+, which adds
//! `Refer` and `Truncate`). TCP port rules need ABI v4 (Linux 6.7+). Abstract
//! socket and signal isolation needs ABI v6 (Linux 6.12+). The `landlock`
//! crate uses best-effort compatibility, so on older kernels the unsupported
//! rights are dropped and the ruleset is only *partially* enforced. Use
//! [`RulesetBuilder::require_full_enforcement`] to turn that into an error.
//!
//! Network rules are only handled once a port is allowed. A ruleset with no
//! port rules leaves TCP alone, so `--no-network` still needs the network
//! namespace.
//!
//! # Example
//!
//! ```no_run
//! use tpt_l_landlock_highlevel::RulesetBuilder;
//!
//! RulesetBuilder::new()
//!     .allow_read("/etc")
//!     .allow_read("/usr")
//!     .allow_exec("/usr/bin")
//!     .allow_tcp_connect(443)
//!     .build()
//!     .expect("invalid policy")
//!     .apply()
//!     .expect("landlock enforcement failed");
//! ```

#[cfg(not(target_os = "linux"))]
compile_error!("tpt-l-landlock-highlevel only supports Linux");

use std::path::{Path, PathBuf};
use thiserror::Error;

/// Errors produced by this crate.
#[derive(Debug, Error)]
pub enum LandlockError {
    /// The running kernel's Landlock ABI version is below the required minimum.
    #[error("kernel Landlock ABI version {found} is below required {required}")]
    KernelTooOld {
        /// The ABI version reported by the running kernel.
        found: u32,
        /// The minimum ABI version this crate requires.
        required: u32,
    },
    /// A path could not be opened for use in a Landlock rule.
    #[error("cannot open path for Landlock rule {path:?}: {source}")]
    PathOpen {
        /// The path that could not be opened.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// Ruleset creation or restriction failed.
    #[error("landlock operation failed: {0}")]
    Operation(String),
    /// Only part of the requested ruleset is enforced by this kernel, and the
    /// caller asked for full enforcement.
    #[error("Landlock partially enforced by this kernel and full enforcement was required")]
    PartiallyEnforced,
}

/// Builder for a Landlock restriction policy.
///
/// Paths added here become the **allowlist** — all other filesystem access is
/// denied once [`ValidatedRuleset::apply`] is called. Ports added with
/// [`allow_tcp_bind`](Self::allow_tcp_bind) and
/// [`allow_tcp_connect`](Self::allow_tcp_connect) work the same way for TCP.
///
/// Call [`build`](Self::build) to validate the full configuration, then
/// [`apply`](ValidatedRuleset::apply) to enforce it. Enforcement is
/// **irreversible** for the lifetime of the process.
#[derive(Debug, Default, Clone)]
pub struct RulesetBuilder {
    read_paths: Vec<PathBuf>,
    write_paths: Vec<PathBuf>,
    exec_paths: Vec<PathBuf>,
    tcp_bind: Vec<u16>,
    tcp_connect: Vec<u16>,
    isolate_ipc: bool,
    strict: bool,
}

impl RulesetBuilder {
    /// Create a new, empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Permit read access to `path` and everything beneath it.
    pub fn allow_read(mut self, path: impl AsRef<Path>) -> Self {
        self.read_paths.push(path.as_ref().to_owned());
        self
    }

    /// Permit write access to `path` and everything beneath it.
    pub fn allow_write(mut self, path: impl AsRef<Path>) -> Self {
        self.write_paths.push(path.as_ref().to_owned());
        self
    }

    /// Permit execute access to `path` and everything beneath it.
    pub fn allow_exec(mut self, path: impl AsRef<Path>) -> Self {
        self.exec_paths.push(path.as_ref().to_owned());
        self
    }

    /// Permit binding a TCP socket to `port`. Once any bind port is allowed,
    /// binding to every other port is denied (Linux 6.7+).
    pub fn allow_tcp_bind(mut self, port: u16) -> Self {
        self.tcp_bind.push(port);
        self
    }

    /// Permit connecting a TCP socket to `port`. Once any connect port is
    /// allowed, connecting to every other port is denied (Linux 6.7+).
    pub fn allow_tcp_connect(mut self, port: u16) -> Self {
        self.tcp_connect.push(port);
        self
    }

    /// Stop the process from connecting to abstract Unix sockets, or signalling
    /// processes, outside its own Landlock domain (Linux 6.12+). Without this,
    /// abstract sockets and signals are not restricted.
    pub fn isolate_abstract_sockets_and_signals(mut self) -> Self {
        self.isolate_ipc = true;
        self
    }

    /// Fail [`apply`](ValidatedRuleset::apply) unless the kernel enforces the
    /// whole ruleset, rather than silently dropping unsupported rights.
    ///
    /// Port rules do not need this: they fail at [`apply`](ValidatedRuleset::apply)
    /// on kernels before 6.7 instead of being silently dropped.
    pub fn require_full_enforcement(mut self) -> Self {
        self.strict = true;
        self
    }

    /// Validate the rule set. Every configured path is opened once to confirm
    /// it exists and can be referenced; no restriction is applied yet.
    ///
    /// # Errors
    ///
    /// Returns [`LandlockError::PathOpen`] for the first path that cannot be
    /// opened.
    pub fn build(self) -> Result<ValidatedRuleset, LandlockError> {
        for path in self
            .read_paths
            .iter()
            .chain(&self.write_paths)
            .chain(&self.exec_paths)
        {
            landlock::PathFd::new(path).map_err(|e| LandlockError::PathOpen {
                path: path.clone(),
                source: std::io::Error::other(e),
            })?;
        }
        Ok(ValidatedRuleset {
            read_paths: self.read_paths,
            write_paths: self.write_paths,
            exec_paths: self.exec_paths,
            tcp_bind: self.tcp_bind,
            tcp_connect: self.tcp_connect,
            isolate_ipc: self.isolate_ipc,
            strict: self.strict,
        })
    }
}

/// A fully validated Landlock ruleset, ready to apply.
///
/// Obtained from [`RulesetBuilder::build`]. Consuming [`apply`](Self::apply)
/// enforces the policy — this is **irreversible**.
#[derive(Debug)]
pub struct ValidatedRuleset {
    read_paths: Vec<PathBuf>,
    write_paths: Vec<PathBuf>,
    exec_paths: Vec<PathBuf>,
    tcp_bind: Vec<u16>,
    tcp_connect: Vec<u16>,
    isolate_ipc: bool,
    strict: bool,
}

fn op_err(e: impl std::fmt::Display) -> LandlockError {
    LandlockError::Operation(e.to_string())
}

fn tcp_unsupported(direction: &str, e: impl std::fmt::Display) -> LandlockError {
    LandlockError::Operation(format!(
        "TCP {direction} port rules need Landlock ABI 4 (Linux 6.7+), which this kernel \
         does not provide: {e}"
    ))
}

impl ValidatedRuleset {
    /// Apply the ruleset to the calling process. **Irreversible.**
    ///
    /// After this call the process and all children it forks are restricted to
    /// the declared filesystem paths, ports and (if requested) IPC scopes.
    ///
    /// # Errors
    ///
    /// Returns [`LandlockError::Operation`] if Landlock is not enforced at all,
    /// and [`LandlockError::PartiallyEnforced`] for partial enforcement when the
    /// builder required full enforcement.
    pub fn apply(self) -> Result<(), LandlockError> {
        use landlock::{
            ABI, Access, AccessFs, AccessNet, CompatLevel, Compatible, NetPort, PathBeneath,
            PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus, Scope,
        };

        // Request ABI v3 filesystem rights (Refer, Truncate). The landlock
        // crate's default best-effort mode drops rights the kernel does not know.
        let abi = ABI::V3;

        let read_access = AccessFs::ReadFile | AccessFs::ReadDir;
        let write_access = AccessFs::WriteFile
            | AccessFs::RemoveFile
            | AccessFs::RemoveDir
            | AccessFs::Truncate
            | AccessFs::Refer
            | AccessFs::MakeDir
            | AccessFs::MakeReg
            | AccessFs::MakeSock
            | AccessFs::MakeFifo
            | AccessFs::MakeBlock
            | AccessFs::MakeChar
            | AccessFs::MakeSym;
        let exec_access = AccessFs::Execute;

        // Handle only the rights this ruleset uses. Unhandled network or scope
        // rights stay unrestricted.
        let mut attr = Ruleset::default()
            .handle_access(AccessFs::from_all(abi))
            .map_err(op_err)?;
        // Port rules are an explicit request, so the kernel must support them:
        // a hard requirement turns "not supported" into an error. The IPC scope
        // below stays best-effort, because it is on by default.
        if !self.tcp_bind.is_empty() {
            attr = attr
                .set_compatibility(CompatLevel::HardRequirement)
                .handle_access(AccessNet::BindTcp)
                .map_err(|e| tcp_unsupported("bind", e))?
                .set_compatibility(CompatLevel::BestEffort);
        }
        if !self.tcp_connect.is_empty() {
            attr = attr
                .set_compatibility(CompatLevel::HardRequirement)
                .handle_access(AccessNet::ConnectTcp)
                .map_err(|e| tcp_unsupported("connect", e))?
                .set_compatibility(CompatLevel::BestEffort);
        }
        if self.isolate_ipc {
            attr = attr
                .scope(Scope::AbstractUnixSocket | Scope::Signal)
                .map_err(op_err)?;
        }
        let mut ruleset = attr.create().map_err(op_err)?;

        for path in &self.read_paths {
            let fd = PathFd::new(path).map_err(|e| LandlockError::PathOpen {
                path: path.clone(),
                source: std::io::Error::other(e),
            })?;
            ruleset = ruleset
                .add_rule(PathBeneath::new(fd, read_access))
                .map_err(op_err)?;
        }

        for path in &self.write_paths {
            let fd = PathFd::new(path).map_err(|e| LandlockError::PathOpen {
                path: path.clone(),
                source: std::io::Error::other(e),
            })?;
            ruleset = ruleset
                .add_rule(PathBeneath::new(fd, read_access | write_access))
                .map_err(op_err)?;
        }

        for path in &self.exec_paths {
            let fd = PathFd::new(path).map_err(|e| LandlockError::PathOpen {
                path: path.clone(),
                source: std::io::Error::other(e),
            })?;
            ruleset = ruleset
                .add_rule(PathBeneath::new(fd, read_access | exec_access))
                .map_err(op_err)?;
        }

        for &port in &self.tcp_bind {
            ruleset = ruleset
                .add_rule(NetPort::new(port, AccessNet::BindTcp))
                .map_err(op_err)?;
        }
        for &port in &self.tcp_connect {
            ruleset = ruleset
                .add_rule(NetPort::new(port, AccessNet::ConnectTcp))
                .map_err(op_err)?;
        }

        let status = ruleset.restrict_self().map_err(op_err)?;

        // The landlock crate reports an unsupported kernel as `Ok` with
        // `NotEnforced` rather than as an error. Treat that as a failure so
        // callers never believe a restriction is active when it is not.
        match status.ruleset {
            RulesetStatus::NotEnforced => Err(LandlockError::Operation(
                "Landlock is not enforced by this kernel; the ruleset was not applied".to_owned(),
            )),
            RulesetStatus::PartiallyEnforced if self.strict => {
                Err(LandlockError::PartiallyEnforced)
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_accumulates_paths() {
        let b = RulesetBuilder::new()
            .allow_read("/etc")
            .allow_read("/usr")
            .allow_write("/tmp")
            .allow_exec("/usr/bin");
        assert_eq!(b.read_paths.len(), 2);
        assert_eq!(b.write_paths.len(), 1);
        assert_eq!(b.exec_paths.len(), 1);
    }

    #[test]
    fn build_succeeds_with_empty_ruleset() {
        RulesetBuilder::new().build().unwrap();
    }

    #[test]
    fn build_rejects_missing_path() {
        let err = RulesetBuilder::new()
            .allow_read("/definitely/not/a/real/path/tpt")
            .build()
            .unwrap_err();
        assert!(matches!(err, LandlockError::PathOpen { .. }));
    }

    #[test]
    fn strict_flag_is_carried_into_build() {
        let v = RulesetBuilder::new()
            .require_full_enforcement()
            .build()
            .unwrap();
        assert!(v.strict);
    }

    #[test]
    fn network_and_ipc_options_are_carried_into_build() {
        let v = RulesetBuilder::new()
            .allow_tcp_bind(8080)
            .allow_tcp_connect(443)
            .allow_tcp_connect(80)
            .isolate_abstract_sockets_and_signals()
            .build()
            .unwrap();
        assert_eq!(v.tcp_bind, vec![8080]);
        assert_eq!(v.tcp_connect, vec![443, 80]);
        assert!(v.isolate_ipc);
    }

    #[test]
    fn defaults_leave_network_and_ipc_alone() {
        let v = RulesetBuilder::new().build().unwrap();
        assert!(v.tcp_bind.is_empty() && v.tcp_connect.is_empty() && !v.isolate_ipc);
    }

    /// Regression test: a forked child applies a filesystem allowlist and must
    /// be denied outside it. Runs in a fork so the restriction stays in the
    /// child. Needs a kernel with Landlock enabled.
    #[test]
    #[ignore = "restricts the calling process; run with --include-ignored"]
    fn filesystem_allowlist_holds_in_forked_child() {
        // SAFETY: the child only applies the ruleset, reads files and `_exit`s.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let code = match RulesetBuilder::new().allow_read("/etc").build() {
                Ok(v) => match v.apply() {
                    Ok(()) => {
                        let allowed = std::fs::read_to_string("/etc/hostname").is_ok()
                            || std::fs::read_dir("/etc").is_ok();
                        let denied = std::fs::read_dir("/proc/self").is_err();
                        match (allowed, denied) {
                            (true, true) => 0,
                            _ => 2,
                        }
                    }
                    Err(_) => 1,
                },
                Err(_) => 1,
            };
            // SAFETY: _exit skips destructors, which must not run in a forked child.
            unsafe { libc::_exit(code) };
        }

        let mut status: libc::c_int = 0;
        // SAFETY: `status` is a valid out-pointer.
        unsafe { libc::waitpid(pid, &raw mut status, 0) };
        assert!(libc::WIFEXITED(status), "child was killed");
        assert_eq!(libc::WEXITSTATUS(status), 0, "allowlist was not enforced");
    }
}
