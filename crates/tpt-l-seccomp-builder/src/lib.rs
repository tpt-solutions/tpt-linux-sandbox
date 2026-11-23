//! High-level DSL for building and applying seccomp BPF syscall filters.
//!
//! Produces a **default-deny** policy: every syscall not explicitly allowed
//! is rejected with the configured [`DenyAction`].
//!
//! Explicit deny rules are enforced with their own action. They are compiled
//! into separate filters that are loaded before the allowlist filter; seccomp
//! applies the most restrictive result, so a denied syscall stays denied even
//! if it is also allowed.
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
    /// Return the given errno to the caller. Must be in `1..4096`.
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
    /// An errno value is outside the range the kernel accepts (1..4096).
    #[error("invalid errno {0}: must be between 1 and 4095")]
    InvalidErrno(i32),
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
#[derive(Debug, Clone)]
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

    /// A conservative general-purpose allowlist for ordinary dynamically
    /// linked programs (file I/O, memory management, threads, sockets, time).
    ///
    /// Excludes process-tracing and signal-sending syscalls (`ptrace`, `kill`,
    /// `tgkill`) and credential changes (`setuid`, `setgid`). `setresuid` and
    /// `setresgid` are allowed because GNU make calls them at startup; the
    /// sandbox's user namespace maps only the caller's own ids, so they can
    /// only keep the current ones. Unlisted calls return `EPERM`.
    ///
    /// Note: `clone` and `clone3` are allowed without filtering their flags,
    /// so this profile does not by itself prevent creating new namespaces.
    pub fn base_profile() -> Self {
        let mut policy = Self::new().default_action(DenyAction::Errno(libc::EPERM));
        for name in BASE_ALLOW
            .iter()
            .chain(BASE_ALLOW_LEGACY)
            .chain(BASE_ALLOW_RENAMEAT)
        {
            policy = policy.allow_syscall(*name);
        }
        policy
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

    /// Explicitly deny `syscall` with `action`. Enforced even when the same
    /// syscall is also allowed.
    pub fn deny_syscall(mut self, syscall: impl Into<String>, action: DenyAction) -> Self {
        self.denied.push((syscall.into(), action));
        self
    }

    /// Check every syscall name and errno without touching the kernel.
    ///
    /// # Errors
    ///
    /// [`SeccompError::UnknownSyscall`] for names missing from the table on
    /// this architecture, and [`SeccompError::InvalidErrno`] for out-of-range
    /// errno values.
    pub fn validate(&self) -> Result<(), SeccompError> {
        for name in &self.allowed {
            resolve(name)?;
        }
        for (name, action) in &self.denied {
            resolve(name)?;
            deny_action_to_seccomp(*action)?;
        }
        deny_action_to_seccomp(self.default)?;
        Ok(())
    }

    /// Compile and apply the BPF filters to the calling process. **Irreversible.**
    pub fn apply(self) -> Result<(), SeccompError> {
        use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch};

        self.validate()?;

        let arch: TargetArch = std::env::consts::ARCH.try_into().map_err(|_| {
            SeccompError::Compile(format!(
                "unsupported architecture: {}",
                std::env::consts::ARCH
            ))
        })?;

        let mut programs: Vec<BpfProgram> = Vec::new();

        // Deny filters go first. Each allows everything except the syscalls in
        // its group, which get that group's action. Loading them first means
        // the later `seccomp(2)` calls are not blocked by the allowlist.
        let mut groups: Vec<(DenyAction, BTreeMap<i64, Vec<SeccompRule>>)> = Vec::new();
        for (name, action) in &self.denied {
            let nr = resolve(name)?;
            if let Some((_, map)) = groups.iter_mut().find(|(a, _)| a == action) {
                map.entry(nr).or_default();
            } else {
                let mut map = BTreeMap::new();
                map.insert(nr, Vec::new());
                groups.push((*action, map));
            }
        }
        for (action, rules) in groups {
            let filter = SeccompFilter::new(
                rules,
                SeccompAction::Allow,
                deny_action_to_seccomp(action)?,
                arch,
            )
            .map_err(|e| SeccompError::Compile(e.to_string()))?;
            programs.push(to_program(filter)?);
        }

        // The allowlist filter goes last. Loading it makes every syscall not
        // on the list follow the default action.
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
        for name in &self.allowed {
            rules.entry(resolve(name)?).or_default();
        }
        let main = SeccompFilter::new(
            rules,
            deny_action_to_seccomp(self.default)?,
            SeccompAction::Allow,
            arch,
        )
        .map_err(|e| SeccompError::Compile(e.to_string()))?;
        programs.push(to_program(main)?);

        for program in &programs {
            seccompiler::apply_filter(program).map_err(|e| SeccompError::Load(e.to_string()))?;
        }

        Ok(())
    }
}

impl Default for SeccompPolicy {
    fn default() -> Self {
        Self::new()
    }
}

fn to_program(filter: seccompiler::SeccompFilter) -> Result<seccompiler::BpfProgram, SeccompError> {
    filter
        .try_into()
        .map_err(|e: seccompiler::BackendError| SeccompError::Compile(e.to_string()))
}

fn deny_action_to_seccomp(action: DenyAction) -> Result<seccompiler::SeccompAction, SeccompError> {
    use seccompiler::SeccompAction;
    match action {
        DenyAction::Kill => Ok(SeccompAction::KillProcess),
        DenyAction::Errno(e) if (1..4096).contains(&e) => {
            // The range check above guarantees a positive value.
            #[allow(clippy::cast_sign_loss)]
            Ok(SeccompAction::Errno(e as u32))
        }
        DenyAction::Errno(e) => Err(SeccompError::InvalidErrno(e)),
        DenyAction::Log => Ok(SeccompAction::Log),
    }
}

fn resolve(name: &str) -> Result<i64, SeccompError> {
    syscall_nr(name).ok_or_else(|| SeccompError::UnknownSyscall(name.to_owned()))
}

/// Syscalls allowed by [`SeccompPolicy::base_profile`].
const BASE_ALLOW: &[&str] = &[
    "read",
    "write",
    "close",
    "fstat",
    "newfstatat",
    "statx",
    "lseek",
    "pread64",
    "pwrite64",
    "readv",
    "writev",
    "openat",
    "getdents64",
    "readlinkat",
    "faccessat",
    // glibc's eaccess() (used by GNU make to search PATH) calls this. Without
    // it the call fails with EPERM and make reports "Operation not permitted".
    // It only reads access rights; Landlock still decides what is reachable.
    "faccessat2",
    "fchmodat",
    "mkdirat",
    "unlinkat",
    "renameat2",
    "linkat",
    "symlinkat",
    "fsync",
    "fdatasync",
    "ftruncate",
    "getcwd",
    "chdir",
    "fchdir",
    "fcntl",
    "dup",
    "dup3",
    "pipe2",
    "ioctl",
    "mmap",
    "mprotect",
    "munmap",
    "mremap",
    "msync",
    "madvise",
    "brk",
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigreturn",
    "sigaltstack",
    "nanosleep",
    "clock_gettime",
    "clock_nanosleep",
    "sched_yield",
    "sched_getaffinity",
    "sched_getparam",
    "getpid",
    "getppid",
    "gettid",
    "getuid",
    "geteuid",
    "getgid",
    "getegid",
    "getgroups",
    "getpgid",
    "setpgid",
    "uname",
    "sysinfo",
    "prlimit64",
    "getrlimit",
    // Read-only resource accounting; GNU make calls it after each job.
    "getrusage",
    // GNU make calls these at startup. Only the caller's own ids are mapped
    // into the user namespace, so the calls cannot change identity.
    "setresuid",
    "setresgid",
    "umask",
    "prctl",
    "set_tid_address",
    "set_robust_list",
    "rseq",
    "futex",
    "getrandom",
    "memfd_create",
    "eventfd2",
    "epoll_create1",
    "epoll_ctl",
    "epoll_pwait",
    "ppoll",
    "pselect6",
    "socket",
    "connect",
    "accept4",
    "bind",
    "listen",
    "sendto",
    "recvfrom",
    "sendmsg",
    "recvmsg",
    "getsockname",
    "getpeername",
    "clone",
    "clone3",
    "wait4",
    "exit",
    "exit_group",
    "execve",
    "execveat",
    "close_range",
    "flock",
    "fchmod",
    "fchown",
    "utimensat",
];

/// Legacy x86_64-only syscalls that glibc and common runtimes still use
/// (`arch_prctl` is required for TLS setup on x86_64).
#[cfg(target_arch = "x86_64")]
const BASE_ALLOW_LEGACY: &[&str] = &[
    "open",
    "stat",
    "lstat",
    "access",
    "pipe",
    "dup2",
    "poll",
    "select",
    "readlink",
    "mkdir",
    "rmdir",
    "rename",
    "unlink",
    "link",
    "symlink",
    "chmod",
    "chown",
    "creat",
    "getdents",
    "getpgrp",
    "epoll_wait",
    "fork",
    "vfork",
    "arch_prctl",
];

#[cfg(not(target_arch = "x86_64"))]
const BASE_ALLOW_LEGACY: &[&str] = &[];

/// `renameat` exists on x86_64 and aarch64 but not on riscv64, which only has
/// `renameat2` (already in the base list).
#[cfg(not(target_arch = "riscv64"))]
const BASE_ALLOW_RENAMEAT: &[&str] = &["renameat"];

#[cfg(target_arch = "riscv64")]
const BASE_ALLOW_RENAMEAT: &[&str] = &[];

/// Resolve a Linux syscall name to its number on the current architecture.
///
/// Covers the syscalls a typical dynamically linked program uses. Entries
/// marked as x86_64-only are legacy calls that aarch64 does not provide.
fn syscall_nr(name: &str) -> Option<i64> {
    syscall_table()
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, nr)| *nr)
}

/// The name → number table for the current architecture.
#[allow(clippy::too_many_lines)]
fn syscall_table() -> Vec<(&'static str, i64)> {
    // Entries that exist on every supported architecture.
    // riscv64 has no extra entries below, so `mut` is unused there only.
    #[cfg_attr(target_arch = "riscv64", allow(unused_mut))]
    let mut table: Vec<(&'static str, i64)> = vec![
        ("read", libc::SYS_read),
        ("write", libc::SYS_write),
        ("close", libc::SYS_close),
        ("fstat", libc::SYS_fstat),
        ("newfstatat", libc::SYS_newfstatat),
        ("statx", libc::SYS_statx),
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
        ("sched_yield", libc::SYS_sched_yield),
        ("mremap", libc::SYS_mremap),
        ("msync", libc::SYS_msync),
        ("madvise", libc::SYS_madvise),
        ("dup", libc::SYS_dup),
        ("dup3", libc::SYS_dup3),
        ("nanosleep", libc::SYS_nanosleep),
        ("getpid", libc::SYS_getpid),
        ("getppid", libc::SYS_getppid),
        ("gettid", libc::SYS_gettid),
        ("socket", libc::SYS_socket),
        ("connect", libc::SYS_connect),
        ("accept4", libc::SYS_accept4),
        ("sendto", libc::SYS_sendto),
        ("recvfrom", libc::SYS_recvfrom),
        ("sendmsg", libc::SYS_sendmsg),
        ("recvmsg", libc::SYS_recvmsg),
        ("bind", libc::SYS_bind),
        ("listen", libc::SYS_listen),
        ("getsockname", libc::SYS_getsockname),
        ("getpeername", libc::SYS_getpeername),
        ("clone", libc::SYS_clone),
        ("clone3", libc::SYS_clone3),
        ("execve", libc::SYS_execve),
        ("execveat", libc::SYS_execveat),
        ("exit", libc::SYS_exit),
        ("exit_group", libc::SYS_exit_group),
        ("wait4", libc::SYS_wait4),
        ("kill", libc::SYS_kill),
        ("uname", libc::SYS_uname),
        ("fcntl", libc::SYS_fcntl),
        ("fsync", libc::SYS_fsync),
        ("fdatasync", libc::SYS_fdatasync),
        ("ftruncate", libc::SYS_ftruncate),
        ("getcwd", libc::SYS_getcwd),
        ("chdir", libc::SYS_chdir),
        ("fchdir", libc::SYS_fchdir),
        ("renameat2", libc::SYS_renameat2),
        ("unlinkat", libc::SYS_unlinkat),
        ("mkdirat", libc::SYS_mkdirat),
        ("linkat", libc::SYS_linkat),
        ("symlinkat", libc::SYS_symlinkat),
        ("readlinkat", libc::SYS_readlinkat),
        ("fchmodat", libc::SYS_fchmodat),
        ("faccessat", libc::SYS_faccessat),
        ("faccessat2", libc::SYS_faccessat2),
        ("fchmod", libc::SYS_fchmod),
        ("fchown", libc::SYS_fchown),
        ("flock", libc::SYS_flock),
        ("utimensat", libc::SYS_utimensat),
        ("umask", libc::SYS_umask),
        ("getuid", libc::SYS_getuid),
        ("getgid", libc::SYS_getgid),
        ("geteuid", libc::SYS_geteuid),
        ("getegid", libc::SYS_getegid),
        ("getgroups", libc::SYS_getgroups),
        ("getpgid", libc::SYS_getpgid),
        ("setpgid", libc::SYS_setpgid),
        ("setsid", libc::SYS_setsid),
        ("setuid", libc::SYS_setuid),
        ("setgid", libc::SYS_setgid),
        ("ptrace", libc::SYS_ptrace),
        ("tgkill", libc::SYS_tgkill),
        ("getdents64", libc::SYS_getdents64),
        ("openat", libc::SYS_openat),
        ("epoll_ctl", libc::SYS_epoll_ctl),
        ("epoll_pwait", libc::SYS_epoll_pwait),
        ("epoll_create1", libc::SYS_epoll_create1),
        ("eventfd2", libc::SYS_eventfd2),
        ("set_tid_address", libc::SYS_set_tid_address),
        ("set_robust_list", libc::SYS_set_robust_list),
        ("futex", libc::SYS_futex),
        ("clock_gettime", libc::SYS_clock_gettime),
        ("clock_nanosleep", libc::SYS_clock_nanosleep),
        ("prctl", libc::SYS_prctl),
        ("pipe2", libc::SYS_pipe2),
        ("recvmmsg", libc::SYS_recvmmsg),
        ("sendmmsg", libc::SYS_sendmmsg),
        ("getrandom", libc::SYS_getrandom),
        ("memfd_create", libc::SYS_memfd_create),
        ("sigaltstack", libc::SYS_sigaltstack),
        ("rseq", libc::SYS_rseq),
        ("prlimit64", libc::SYS_prlimit64),
        ("getrlimit", libc::SYS_getrlimit),
        ("getrusage", libc::SYS_getrusage),
        ("setresuid", libc::SYS_setresuid),
        ("setresgid", libc::SYS_setresgid),
        ("sched_getaffinity", libc::SYS_sched_getaffinity),
        ("sched_getparam", libc::SYS_sched_getparam),
        ("ppoll", libc::SYS_ppoll),
        ("pselect6", libc::SYS_pselect6),
        ("sysinfo", libc::SYS_sysinfo),
        ("close_range", libc::SYS_close_range),
        ("landlock_create_ruleset", libc::SYS_landlock_create_ruleset),
        ("landlock_add_rule", libc::SYS_landlock_add_rule),
        ("landlock_restrict_self", libc::SYS_landlock_restrict_self),
    ];

    // `renameat` is missing on riscv64 (see BASE_ALLOW_RENAMEAT).
    #[cfg(not(target_arch = "riscv64"))]
    table.push(("renameat", libc::SYS_renameat));

    // Legacy calls that only exist on x86_64 (aarch64 uses the *at variants).
    #[cfg(target_arch = "x86_64")]
    table.extend_from_slice(&[
        ("open", libc::SYS_open),
        ("stat", libc::SYS_stat),
        ("lstat", libc::SYS_lstat),
        ("poll", libc::SYS_poll),
        ("select", libc::SYS_select),
        ("access", libc::SYS_access),
        ("pipe", libc::SYS_pipe),
        ("dup2", libc::SYS_dup2),
        ("fork", libc::SYS_fork),
        ("vfork", libc::SYS_vfork),
        ("creat", libc::SYS_creat),
        ("link", libc::SYS_link),
        ("unlink", libc::SYS_unlink),
        ("symlink", libc::SYS_symlink),
        ("readlink", libc::SYS_readlink),
        ("mkdir", libc::SYS_mkdir),
        ("rmdir", libc::SYS_rmdir),
        ("rename", libc::SYS_rename),
        ("chmod", libc::SYS_chmod),
        ("chown", libc::SYS_chown),
        ("getdents", libc::SYS_getdents),
        ("getpgrp", libc::SYS_getpgrp),
        ("epoll_wait", libc::SYS_epoll_wait),
        ("arch_prctl", libc::SYS_arch_prctl),
    ]);

    table
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

    #[test]
    fn table_names_are_unique() {
        let table = syscall_table();
        let mut names: Vec<&str> = table.iter().map(|(n, _)| *n).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "duplicate syscall names in table");
    }

    #[test]
    fn base_profile_names_all_resolve() {
        for name in BASE_ALLOW {
            assert!(syscall_nr(name).is_some(), "{name} missing from table");
        }
        SeccompPolicy::base_profile().validate().unwrap();
    }

    #[test]
    fn errno_range_is_validated() {
        assert!(
            SeccompPolicy::new()
                .default_action(DenyAction::Errno(0))
                .validate()
                .is_err()
        );
        assert!(
            SeccompPolicy::new()
                .default_action(DenyAction::Errno(-1))
                .validate()
                .is_err()
        );
        assert!(
            SeccompPolicy::new()
                .default_action(DenyAction::Errno(4096))
                .validate()
                .is_err()
        );
        assert!(
            SeccompPolicy::new()
                .default_action(DenyAction::Errno(1))
                .validate()
                .is_ok()
        );
    }

    /// Regression test: the base profile lets ordinary calls through and returns
    /// EPERM for `ptrace`. Runs in a forked child, since the filter is
    /// irreversible for that process.
    #[test]
    #[ignore = "installs a seccomp filter; run with --include-ignored"]
    fn base_profile_blocks_ptrace_in_forked_child() {
        // SAFETY: the child only issues syscalls, reads errno and `_exit`s.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let code = match SeccompPolicy::base_profile().apply() {
                Ok(()) => {
                    // SAFETY: getpid takes no arguments.
                    let pid_now = unsafe { libc::getpid() };
                    // SAFETY: a PTRACE_TRACEME request with no pointers; the
                    // filter should reject it before the kernel acts on it.
                    let r = unsafe {
                        libc::syscall(
                            libc::SYS_ptrace,
                            0 as libc::c_long,
                            0 as libc::c_long,
                            0 as libc::c_long,
                            0 as libc::c_long,
                        )
                    };
                    let errno = std::io::Error::last_os_error().raw_os_error();
                    if pid_now > 0 && r == -1 && errno == Some(libc::EPERM) {
                        0
                    } else {
                        2
                    }
                }
                Err(_) => 1,
            };
            // SAFETY: _exit skips destructors, which must not run in a forked child.
            unsafe { libc::_exit(code) };
        }

        let mut status: libc::c_int = 0;
        // SAFETY: `status` is a valid out-pointer.
        unsafe { libc::waitpid(pid, &raw mut status, 0) };
        assert!(
            libc::WIFEXITED(status),
            "child was killed, probably by the filter"
        );
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn unknown_names_fail_validation() {
        assert!(
            SeccompPolicy::new()
                .allow_syscall("nope")
                .validate()
                .is_err()
        );
        assert!(
            SeccompPolicy::new()
                .deny_syscall("nope", DenyAction::Kill)
                .validate()
                .is_err()
        );
    }
}
