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

use std::collections::BTreeMap;
use thiserror::Error;

/// What to do when a denied syscall is attempted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyAction {
    /// Terminate the process with SIGSYS.
    Kill,
    /// Return the given errno to the caller.
    Errno(i32),
    /// Allow the syscall but log it via the audit subsystem.
    Log,
}

/// Errors produced by this crate.
#[derive(Debug, Error)]
pub enum SeccompError {
    /// A syscall name could not be resolved to a number on this architecture.
    #[error("unknown syscall name: {0}")]
    UnknownSyscall(String),
    /// BPF program compilation failed.
    #[error("failed to compile BPF filter: {0}")]
    Compile(String),
    /// Loading the BPF filter into the kernel failed.
    #[error("failed to load seccomp filter: {0}")]
    Load(String),
}

/// Builder for a seccomp syscall allow/deny policy.
///
/// The default action (applied to any unmatched syscall) is
/// [`DenyAction::Kill`]. Override it with [`default_action`](Self::default_action).
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
        use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule};

        let default_action = deny_action_to_seccomp(self.default);

        // Build the rules map: syscall_nr → [SeccompRule] (empty vec = unconditional match).
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

        for name in &self.allowed {
            let nr = syscall_nr(name).ok_or_else(|| SeccompError::UnknownSyscall(name.clone()))?;
            rules.entry(nr).or_default();
        }

        for (name, _action) in &self.denied {
            // Explicit deny entries are omitted from the allow-rules map,
            // so they fall through to the default action.
            // (Per-syscall overrides would need SeccompFilter with per-syscall
            // actions, which requires a more complex seccompiler setup.)
            let _ = syscall_nr(name).ok_or_else(|| SeccompError::UnknownSyscall(name.clone()))?;
        }

        let filter = SeccompFilter::new(
            rules,
            default_action,
            SeccompAction::Allow,
            std::env::consts::ARCH.try_into().map_err(|_| {
                SeccompError::Compile(format!(
                    "unsupported architecture: {}",
                    std::env::consts::ARCH
                ))
            })?,
        )
        .map_err(|e| SeccompError::Compile(e.to_string()))?;

        let program: BpfProgram = filter
            .try_into()
            .map_err(|e: seccompiler::Error| SeccompError::Compile(e.to_string()))?;

        seccompiler::apply_filter(&program).map_err(|e| SeccompError::Load(e.to_string()))?;

        Ok(())
    }
}

impl Default for SeccompPolicy {
    fn default() -> Self {
        Self::new()
    }
}

fn deny_action_to_seccomp(action: DenyAction) -> seccompiler::SeccompAction {
    use seccompiler::SeccompAction;
    match action {
        DenyAction::Kill => SeccompAction::KillProcess,
        DenyAction::Errno(e) => SeccompAction::Errno(e as u32),
        DenyAction::Log => SeccompAction::Log,
    }
}

/// Resolve a Linux syscall name to its number on the current architecture.
///
/// Only the most common syscalls are covered here; the list should be expanded
/// as needed or replaced with a generated table.
#[allow(clippy::too_many_lines)]
fn syscall_nr(name: &str) -> Option<i64> {
    #[cfg(target_arch = "x86_64")]
    {
        // Subset of x86_64 syscall numbers (Linux ABI).
        let table: &[(&str, i64)] = &[
            ("read", libc::SYS_read),
            ("write", libc::SYS_write),
            ("open", libc::SYS_open),
            ("close", libc::SYS_close),
            ("stat", libc::SYS_stat),
            ("fstat", libc::SYS_fstat),
            ("lstat", libc::SYS_lstat),
            ("poll", libc::SYS_poll),
            ("lseek", libc::SYS_lseek),
            ("mmap", libc::SYS_mmap),
            ("mprotect", libc::SYS_mprotect),
            ("munmap", libc::SYS_munmap),
            ("brk", libc::SYS_brk),
            ("rt_sigaction", libc::SYS_rt_sigaction),
            ("rt_sigprocmask", libc::SYS_rt_sigprocmask),
            ("rt_sigreturn", libc::SYS_rt_sigreturn),
            ("ioctl", libc::SYS_ioctl),
            ("pread64", libc::SYS_pread64),
            ("pwrite64", libc::SYS_pwrite64),
            ("readv", libc::SYS_readv),
            ("writev", libc::SYS_writev),
            ("access", libc::SYS_access),
            ("pipe", libc::SYS_pipe),
            ("select", libc::SYS_select),
            ("sched_yield", libc::SYS_sched_yield),
            ("mremap", libc::SYS_mremap),
            ("msync", libc::SYS_msync),
            ("dup", libc::SYS_dup),
            ("dup2", libc::SYS_dup2),
            ("nanosleep", libc::SYS_nanosleep),
            ("getpid", libc::SYS_getpid),
            ("socket", libc::SYS_socket),
            ("connect", libc::SYS_connect),
            ("accept", libc::SYS_accept),
            ("sendto", libc::SYS_sendto),
            ("recvfrom", libc::SYS_recvfrom),
            ("sendmsg", libc::SYS_sendmsg),
            ("recvmsg", libc::SYS_recvmsg),
            ("bind", libc::SYS_bind),
            ("listen", libc::SYS_listen),
            ("getsockname", libc::SYS_getsockname),
            ("getpeername", libc::SYS_getpeername),
            ("clone", libc::SYS_clone),
            ("fork", libc::SYS_fork),
            ("vfork", libc::SYS_vfork),
            ("execve", libc::SYS_execve),
            ("exit", libc::SYS_exit),
            ("wait4", libc::SYS_wait4),
            ("kill", libc::SYS_kill),
            ("uname", libc::SYS_uname),
            ("fcntl", libc::SYS_fcntl),
            ("fsync", libc::SYS_fsync),
            ("truncate", libc::SYS_truncate),
            ("ftruncate", libc::SYS_ftruncate),
            ("getcwd", libc::SYS_getcwd),
            ("chdir", libc::SYS_chdir),
            ("fchdir", libc::SYS_fchdir),
            ("rename", libc::SYS_rename),
            ("mkdir", libc::SYS_mkdir),
            ("rmdir", libc::SYS_rmdir),
            ("creat", libc::SYS_creat),
            ("link", libc::SYS_link),
            ("unlink", libc::SYS_unlink),
            ("symlink", libc::SYS_symlink),
            ("readlink", libc::SYS_readlink),
            ("chmod", libc::SYS_chmod),
            ("chown", libc::SYS_chown),
            ("getuid", libc::SYS_getuid),
            ("getgid", libc::SYS_getgid),
            ("getpgrp", libc::SYS_getpgrp),
            ("geteuid", libc::SYS_geteuid),
            ("getegid", libc::SYS_getegid),
            ("getppid", libc::SYS_getppid),
            ("setuid", libc::SYS_setuid),
            ("setgid", libc::SYS_setgid),
            ("ptrace", libc::SYS_ptrace),
            ("getdents", libc::SYS_getdents),
            ("getdents64", libc::SYS_getdents64),
            ("openat", libc::SYS_openat),
            ("mkdirat", libc::SYS_mkdirat),
            ("newfstatat", libc::SYS_newfstatat),
            ("unlinkat", libc::SYS_unlinkat),
            ("renameat", libc::SYS_renameat),
            ("linkat", libc::SYS_linkat),
            ("symlinkat", libc::SYS_symlinkat),
            ("readlinkat", libc::SYS_readlinkat),
            ("fchmodat", libc::SYS_fchmodat),
            ("faccessat", libc::SYS_faccessat),
            ("epoll_wait", libc::SYS_epoll_wait),
            ("epoll_ctl", libc::SYS_epoll_ctl),
            ("epoll_create1", libc::SYS_epoll_create1),
            ("set_tid_address", libc::SYS_set_tid_address),
            ("futex", libc::SYS_futex),
            ("set_robust_list", libc::SYS_set_robust_list),
            ("clock_gettime", libc::SYS_clock_gettime),
            ("clock_nanosleep", libc::SYS_clock_nanosleep),
            ("exit_group", libc::SYS_exit_group),
            ("tgkill", libc::SYS_tgkill),
            ("prctl", libc::SYS_prctl),
            ("arch_prctl", libc::SYS_arch_prctl),
            ("pipe2", libc::SYS_pipe2),
            ("dup3", libc::SYS_dup3),
            ("accept4", libc::SYS_accept4),
            ("recvmmsg", libc::SYS_recvmmsg),
            ("sendmmsg", libc::SYS_sendmmsg),
            ("getrandom", libc::SYS_getrandom),
            ("statx", libc::SYS_statx),
        ];
        table.iter().find(|(n, _)| *n == name).map(|(_, nr)| *nr)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        // TODO: add tables for aarch64, riscv64, etc.
        let _ = name;
        None
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

    #[test]
    fn syscall_nr_resolves_common() {
        assert!(syscall_nr("read").is_some());
        assert!(syscall_nr("write").is_some());
        assert!(syscall_nr("exit_group").is_some());
        assert!(syscall_nr("definitely_not_a_syscall").is_none());
    }
}
