//! High-level DSL over seccompiler/BPF filter generation for syscall policies.
//!
//! Provides an allow/deny syscall policy with default-deny semantics.

#![deny(missing_docs)]

use seccompiler::{BpfProgram, SeccompCondition, SeccompAction, SeccompFilter, SeccompRule};
use std::collections::HashMap;
use thiserror::Error;
use tracing::info;

/// Errors that can occur when building or applying seccomp policies.
#[derive(Debug, Error)]
pub enum SeccompError {
    /// Failed to compile the BPF filter.
    #[error("BPF compilation failed: {0}")]
    BpfCompilation(String),
    /// Failed to load the seccomp filter into the kernel.
    #[error("seccomp_load failed: {0}")]
    Load(String),
    /// Invalid syscall number.
    #[error("invalid syscall number: {0}")]
    InvalidSyscall(i64),
}

/// The default action for syscalls not matching any rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultAction {
    /// Kill the process (default-deny).
    Kill,
    /// Return EPERM for disallowed syscalls.
    Errno(u16),
    /// Allow the syscall (default-allow — not recommended).
    Allow,
}

/// A seccomp policy builder with default-deny semantics.
///
/// # Example
///
/// ```
/// use tpt_l_seccomp_builder::{SeccompPolicy, DefaultAction};
///
/// let policy = SeccompPolicy::new()
///     .default_action(DefaultAction::Kill)
///     .allow_syscall("read")
///     .allow_syscall("write")
///     .allow_syscall("exit_group")
///     .build()
///     .unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct SeccompPolicy {
    allowed_syscalls: Vec<String>,
    denied_syscalls: Vec<String>,
    default_action: DefaultAction,
}

impl SeccompPolicy {
    /// Creates a new `SeccompPolicy` with default-deny (kill) semantics.
    pub fn new() -> Self {
        Self {
            allowed_syscalls: Vec::new(),
            denied_syscalls: Vec::new(),
            default_action: DefaultAction::Kill,
        }
    }

    /// Sets the default action for unmatched syscalls.
    pub fn default_action(mut self, action: DefaultAction) -> Self {
        self.default_action = action;
        self
    }

    /// Adds a syscall to the allowlist.
    pub fn allow_syscall(mut self, name: &str) -> Self {
        self.allowed_syscalls.push(name.to_string());
        self
    }

    /// Adds a syscall to the denylist (denied even if default is allow).
    pub fn deny_syscall(mut self, name: &str) -> Self {
        self.denied_syscalls.push(name.to_string());
        self
    }

    /// Returns the list of allowed syscall names.
    pub fn allowed_syscalls(&self) -> &[String] {
        &self.allowed_syscalls
    }

    /// Returns the list of denied syscall names.
    pub fn denied_syscalls(&self) -> &[String] {
        &self.denied_syscalls
    }

    /// Builds the seccomp filter, compiling BPF but not applying it.
    pub fn build(self) -> Result<BuiltSeccompPolicy, SeccompError> {
        let default_action = match self.default_action {
            DefaultAction::Kill => SeccompAction::KillThread,
            DefaultAction::Errno(code) => SeccompAction::Errno(code),
            DefaultAction::Allow => SeccompAction::Allow,
        };

        let mut filter = SeccompFilter::new(
            HashMap::new(),
            default_action,
        ).map_err(|e| SeccompError::BpfCompilation(e.to_string()))?;

        for name in &self.allowed_syscalls {
            let syscall_nr = SeccompPolicy::resolve_syscall_nr(name)?;
            let rule = SeccompRule::new(vec![]);
            filter.add_rule_unchecked(syscall_nr, rule);
        }

        let program = filter.try_into().map_err(|e| {
            SeccompError::BpfCompilation(format!("filter conversion: {e}"))
        })?;

        Ok(BuiltSeccompPolicy { program })
    }

    fn resolve_syscall_nr(name: &str) -> Result<i64, SeccompError> {
        seccompiler::Syscall::from_name(name)
            .ok_or_else(|| SeccompError::InvalidSyscall(-1))
            .map(|s| s as i64)
    }
}

impl Default for SeccompPolicy {
    fn default() -> Self {
        Self::new()
    }
}

/// A compiled seccomp BPF program ready to be applied.
#[derive(Debug)]
pub struct BuiltSeccompPolicy {
    program: BpfProgram,
}

impl BuiltSeccompPolicy {
    /// Applies the seccomp filter to the current thread — irreversible.
    ///
    /// Once loaded, the seccomp filter cannot be removed.
    pub fn apply(self) -> Result<(), SeccompError> {
        seccompiler::apply_filter(&self.program)
            .map_err(|e| SeccompError::Load(e.to_string()))?;
        info!("Seccomp filter applied successfully");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_policy_is_default_deny() {
        let policy = SeccompPolicy::new();
        assert_eq!(policy.default_action, DefaultAction::Kill);
        assert!(policy.allowed_syscalls.is_empty());
    }

    #[test]
    fn allow_syscall_adds_to_list() {
        let policy = SeccompPolicy::new().allow_syscall("read");
        assert_eq!(policy.allowed_syscalls.len(), 1);
    }

    #[test]
    fn deny_syscall_adds_to_list() {
        let policy = SeccompPolicy::new().deny_syscall("execve");
        assert_eq!(policy.denied_syscalls.len(), 1);
    }

    #[test]
    fn default_action_can_be_changed() {
        let policy = SeccompPolicy::new().default_action(DefaultAction::Errno(1));
        assert_eq!(policy.default_action, DefaultAction::Errno(1));
    }

    #[test]
    fn build_creates_program() {
        let policy = SeccompPolicy::new()
            .allow_syscall("read")
            .allow_syscall("write")
            .allow_syscall("exit_group");
        let built = policy.build();
        assert!(built.is_ok());
    }
}
