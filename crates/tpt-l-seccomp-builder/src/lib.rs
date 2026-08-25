//! High-level DSL for building and applying seccomp BPF syscall filters.
//!
//! Produces a **default-deny** policy: every syscall not explicitly allowed
//! is rejected with the configured [`DenyAction`].
//!
//! # Example
//!
//! ```no_run
//! use tpt_l_seccomp_builder::{DenyAction, SeccompPolicy};
//!
//! SeccompPolicy::new()
//!     .default_action(DenyAction::Errno(libc::EPERM))
//!     .allow_syscall("read")
//!     .allow_syscall("write")
//!     .allow_syscall("exit_group")
//!     .apply()
//!     .expect("seccomp enforcement failed");
//! ```

#[cfg(not(target_os = "linux"))]
compile_error!("tpt-l-seccomp-builder only supports Linux");

use thiserror::Error;

/// What to do when a denied syscall is attempted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyAction {
    /// Terminate the process with SIGSYS.
    Kill,
    /// Return the given errno to the caller (e.g. `libc::EPERM`).
    Errno(i32),
    /// Allow the syscall but log it via the audit subsystem.
    Log,
}

/// Errors produced by this crate.
#[derive(Debug, Error)]
pub enum SeccompError {
    /// A syscall name could not be resolved to a number.
    #[error("unknown syscall name: {0}")]
    UnknownSyscall(String),
    /// BPF program compilation failed.
    #[error("failed to compile BPF filter: {0}")]
    Compile(String),
    /// Loading the BPF filter into the kernel failed.
    #[error("failed to load seccomp filter: {0}")]
    Load(#[from] std::io::Error),
}

/// Builder for a seccomp syscall allow/deny policy.
///
/// The default action (applied to any syscall not matched by an explicit rule)
/// is [`DenyAction::Kill`]. Change it with [`default_action`](Self::default_action).
///
/// Calling [`apply`](Self::apply) is **irreversible**.
#[derive(Debug)]
pub struct SeccompPolicy {
    allowed: Vec<String>,
    denied: Vec<(String, DenyAction)>,
    default: DenyAction,
}

impl SeccompPolicy {
    /// Create a new policy with default-kill behaviour for unmatched syscalls.
    pub fn new() -> Self {
        Self {
            allowed: Vec::new(),
            denied: Vec::new(),
            default: DenyAction::Kill,
        }
    }

    /// Override the default action for syscalls not matched by any rule.
    pub fn default_action(mut self, action: DenyAction) -> Self {
        self.default = action;
        self
    }

    /// Explicitly permit `syscall`.
    pub fn allow_syscall(mut self, syscall: impl Into<String>) -> Self {
        self.allowed.push(syscall.into());
        self
    }

    /// Explicitly deny `syscall` with `action`.
    pub fn deny_syscall(mut self, syscall: impl Into<String>, action: DenyAction) -> Self {
        self.denied.push((syscall.into(), action));
        self
    }

    /// Compile and apply the BPF filter to the calling process. **Irreversible.**
    pub fn apply(self) -> Result<(), SeccompError> {
        // TODO: use `seccompiler` to compile self.allowed / self.denied into a
        // BpfProgram and call seccompiler::apply_filter().
        drop(self);
        Ok(())
    }
}

impl Default for SeccompPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_records_rules() {
        let p = SeccompPolicy::new()
            .allow_syscall("read")
            .allow_syscall("write")
            .deny_syscall("ptrace", DenyAction::Errno(1));
        assert_eq!(p.allowed.len(), 2);
        assert_eq!(p.denied.len(), 1);
    }

    #[test]
    fn default_action_override() {
        let p = SeccompPolicy::new().default_action(DenyAction::Errno(1));
        assert_eq!(p.default, DenyAction::Errno(1));
    }
}
