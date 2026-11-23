//! `tpt-sandbox` — run a command inside a composable Linux sandbox.
//!
//! Pure-Rust alternative to bwrap (Bubblewrap) and firejail.
//!
//! # Process model
//!
//! The CLI forks before any restriction is applied. The child applies the
//! sandbox and `exec`s the command. The parent is never restricted, waits for
//! the child, removes the child's cgroup, and reports how it exited.

#[cfg(not(target_os = "linux"))]
compile_error!("tpt-l-sandbox-cli only supports Linux");

mod policy;
mod tools;

use std::io;
use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

use anyhow::{Context as _, bail};
use clap::{ArgAction, Parser};
use policy::Policy;
use tpt_l_sandbox::{
    CapsPolicy, CgroupConfig, DenyAction, JailConfig, NamespaceSet, RulesetBuilder, Sandbox,
    SeccompPolicy,
};

const SIGKILL: i32 = 9;
const SIGSYS: i32 = 31;

/// Standard system directories granted read and exec when `system_paths` is on.
/// Entries that do not exist on this system are skipped.
const SYSTEM_PATHS: &[&str] = &["/usr", "/bin", "/sbin", "/lib", "/lib64"];

/// Run a command inside a composable Linux sandbox.
///
/// All restrictions are validated before any irreversible kernel state change.
#[derive(Parser, Debug)]
#[command(name = "tpt-sandbox", version, about, long_about = None)]
struct Args {
    /// Start from a built-in profile (see --print-profile). Other flags extend it.
    #[arg(long, value_name = "NAME")]
    profile: Option<String>,

    /// Load a policy file (TOML, same schema as profiles).
    #[arg(long, value_name = "FILE")]
    policy: Option<PathBuf>,

    /// Import the file rules of an AppArmor profile.
    #[arg(long, value_name = "FILE")]
    from_apparmor: Option<PathBuf>,

    /// Permit read access to PATH (repeatable).
    #[arg(long, value_name = "PATH", action = ArgAction::Append)]
    allow_read: Vec<PathBuf>,

    /// Permit write access to PATH (repeatable).
    #[arg(long, value_name = "PATH", action = ArgAction::Append)]
    allow_write: Vec<PathBuf>,

    /// Permit executing files under PATH (repeatable).
    #[arg(long, value_name = "PATH", action = ArgAction::Append)]
    allow_exec: Vec<PathBuf>,

    /// Do not grant read and exec on the standard system directories.
    #[arg(long)]
    no_system_paths: bool,

    /// Isolate the network namespace (sandbox gets no external network access).
    #[arg(long)]
    no_network: bool,

    /// Memory limit in bytes (must be greater than 0).
    #[arg(long, value_name = "BYTES")]
    memory_limit: Option<u64>,

    /// CPU quota as a percentage of one core (1–100).
    #[arg(long, value_name = "PERCENT")]
    cpu_quota: Option<u32>,

    /// Maximum number of processes and threads.
    #[arg(long, value_name = "N")]
    pids_limit: Option<u32>,

    /// Use PATH as the new filesystem root (pivot_root / chroot).
    #[arg(long, value_name = "PATH")]
    new_root: Option<PathBuf>,

    /// Working directory for the command (default /).
    #[arg(long, value_name = "PATH")]
    cwd: Option<PathBuf>,

    /// Drop all Linux capabilities before exec.
    #[arg(long)]
    drop_caps: bool,

    /// Seccomp mode: enforce (default allowlist), log (log only), off.
    #[arg(long, value_name = "MODE", value_parser = ["enforce", "log", "off"])]
    seccomp: Option<String>,

    /// Pass this environment variable through (repeatable). The default
    /// environment keeps only PATH, TERM, LANG, LC_ALL and LC_CTYPE.
    #[arg(long, value_name = "NAME", action = ArgAction::Append)]
    pass_env: Vec<String>,

    /// Permit binding a TCP socket to PORT (repeatable; Linux 6.7+).
    #[arg(long, value_name = "PORT", action = ArgAction::Append)]
    allow_tcp_bind: Vec<u16>,

    /// Permit connecting a TCP socket to PORT (repeatable; Linux 6.7+).
    #[arg(long, value_name = "PORT", action = ArgAction::Append)]
    allow_tcp_connect: Vec<u16>,

    /// Share the host PID namespace (the command can see and signal host processes).
    #[arg(long)]
    share_pids: bool,

    /// Share host abstract Unix sockets and signalling (no IPC isolation).
    #[arg(long)]
    share_ipc: bool,

    /// Print a JSON exit event to stderr.
    #[arg(long)]
    json: bool,

    /// Show the effective policy and exit without applying it.
    #[arg(long, alias = "explain")]
    dry_run: bool,

    /// Run the command unsandboxed under strace and print a starter policy.
    #[arg(long)]
    learn: bool,

    /// Check whether this machine can run the sandbox, and exit.
    #[arg(long)]
    doctor: bool,

    /// Print a built-in profile's TOML and exit.
    #[arg(long, value_name = "NAME")]
    print_profile: Option<String>,

    /// The command to run, followed by its arguments.
    #[arg(trailing_var_arg = true, value_name = "COMMAND")]
    command: Vec<String>,
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(&args) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("tpt-sandbox: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &Args) -> anyhow::Result<u8> {
    if let Some(name) = &args.print_profile {
        let text = policy::preset_text(name).with_context(|| {
            format!(
                "unknown profile {name:?}; available: {}",
                policy::PRESET_NAMES.join(", ")
            )
        })?;
        print!("{text}");
        return Ok(0);
    }

    if args.doctor {
        tools::doctor();
        return Ok(0);
    }

    if args.learn {
        if args.command.is_empty() {
            bail!("--learn needs a command after --");
        }
        return tools::learn(&args.command);
    }

    let policy = build_policy(args)?;
    policy.validate()?;

    if args.dry_run {
        tools::explain(&policy, &args.command);
        return Ok(0);
    }

    if args.command.is_empty() {
        bail!("no command given; usage: tpt-sandbox [OPTIONS] -- COMMAND [ARGS...]");
    }

    supervise(&policy, &args.command, args.json)
}

/// Combine the policy sources in order: profile, policy file, AppArmor
/// profile, then command-line flags. Relative paths resolve against the
/// current directory.
fn build_policy(args: &Args) -> anyhow::Result<Policy> {
    let mut policy = Policy::default();
    if let Some(name) = &args.profile {
        policy.merge(Policy::from_preset(name)?);
    }
    if let Some(path) = &args.policy {
        policy.merge(Policy::from_file(path)?);
    }
    if let Some(path) = &args.from_apparmor {
        policy.merge(Policy::from_apparmor(path)?);
    }
    policy.merge(flags_policy(args));

    let base = std::env::current_dir().context("cannot read current directory")?;
    policy.resolve_paths(&base);
    Ok(policy)
}

fn flags_policy(args: &Args) -> Policy {
    Policy {
        allow_read: args.allow_read.clone(),
        allow_write: args.allow_write.clone(),
        allow_exec: args.allow_exec.clone(),
        system_paths: args.no_system_paths.then_some(false),
        no_network: args.no_network,
        drop_caps: args.drop_caps,
        memory_limit: args.memory_limit,
        cpu_quota: args.cpu_quota,
        pids_limit: args.pids_limit,
        new_root: args.new_root.clone(),
        cwd: args.cwd.clone(),
        seccomp: args.seccomp.clone(),
        pass_env: args.pass_env.clone(),
        pid_namespace: args.share_pids.then_some(false),
        isolate_ipc: args.share_ipc.then_some(false),
        allow_tcp_bind: args.allow_tcp_bind.clone(),
        allow_tcp_connect: args.allow_tcp_connect.clone(),
    }
}

/// Build the sandbox from a validated policy. Does not change kernel state.
fn build_sandbox(policy: &Policy) -> Sandbox {
    let mut ns = NamespaceSet::new().user().mount();
    if policy.pid_namespace() {
        ns = ns.pid();
    }
    if policy.no_network {
        ns = ns.network();
    }
    let mut sandbox = Sandbox::new().namespaces(ns);

    if let Some(cg) = build_cgroup(policy) {
        sandbox = sandbox.cgroup(cg);
    }

    if let Some(root) = &policy.new_root {
        sandbox = sandbox.jail(JailConfig::new(root).mount_proc().mount_dev_minimal());
    }

    if policy.drop_caps {
        sandbox = sandbox.caps(CapsPolicy::new().drop_all());
    }

    match policy.seccomp.as_deref().unwrap_or("enforce") {
        "enforce" => sandbox = sandbox.seccomp(SeccompPolicy::base_profile()),
        "log" => sandbox = sandbox.seccomp(SeccompPolicy::new().default_action(DenyAction::Log)),
        _ => {}
    }

    let mut ruleset = RulesetBuilder::new();
    if policy.system_paths() {
        for dir in SYSTEM_PATHS
            .iter()
            .filter(|p| std::path::Path::new(p).exists())
        {
            ruleset = ruleset.allow_read(dir).allow_exec(dir);
        }
    }
    for path in &policy.allow_read {
        ruleset = ruleset.allow_read(path);
    }
    for path in &policy.allow_write {
        ruleset = ruleset.allow_write(path);
    }
    for path in &policy.allow_exec {
        ruleset = ruleset.allow_exec(path);
    }
    for &port in &policy.allow_tcp_bind {
        ruleset = ruleset.allow_tcp_bind(port);
    }
    for &port in &policy.allow_tcp_connect {
        ruleset = ruleset.allow_tcp_connect(port);
    }
    if policy.isolate_ipc() {
        ruleset = ruleset.isolate_abstract_sockets_and_signals();
    }
    sandbox.landlock(ruleset)
}

/// cgroup limits for the child, named after this (the supervising) process.
fn build_cgroup(policy: &Policy) -> Option<CgroupConfig> {
    if policy.memory_limit.is_none() && policy.cpu_quota.is_none() && policy.pids_limit.is_none() {
        return None;
    }
    let mut cg = CgroupConfig::new(format!("tpt-sandbox-{}", std::process::id()));
    if let Some(bytes) = policy.memory_limit {
        cg = cg.memory_limit(bytes);
    }
    if let Some(quota) = policy.cpu_quota {
        cg = cg.cpu_quota(quota);
    }
    if let Some(max) = policy.pids_limit {
        cg = cg.pids_limit(max);
    }
    Some(cg)
}

/// Fork, sandbox and exec the command in the child, then wait for it.
fn supervise(policy: &Policy, command: &[String], json: bool) -> anyhow::Result<u8> {
    let sandbox = build_sandbox(policy);
    sandbox.validate().context("policy validation failed")?;
    let cgroup = build_cgroup(policy);

    // SAFETY: called before this process starts any threads, so the child is
    // single-threaded and may safely run the setup code below.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error()).context("fork failed");
    }
    if pid == 0 {
        child_main(policy, &sandbox, command);
    }

    let status = wait_child(pid).context("waiting for the sandboxed command failed")?;
    if let Some(cg) = &cgroup {
        // The child has exited, so the cgroup is empty and can be removed.
        // Ignore failures: the directory may never have been created.
        let _ = cg.destroy();
    }
    Ok(report_exit(status, json))
}

/// Runs in the forked child. Never returns.
fn child_main(policy: &Policy, sandbox: &Sandbox, command: &[String]) -> ! {
    // Detach from the controlling terminal so keystrokes cannot be injected
    // into it (TIOCSTI).
    // SAFETY: setsid has no memory-safety preconditions.
    unsafe { libc::setsid() };
    close_inherited_fds();

    if let Err(e) = sandbox.clone().apply() {
        child_fail(126, &format!("sandbox setup failed: {e}"));
    }

    // With a PID namespace, the process that created it is not PID 1. Fork
    // once more so the command is PID 1; this process only relays its status.
    if policy.pid_namespace() {
        // SAFETY: the child is still single-threaded, which fork requires.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            child_fail(126, "cannot fork into the PID namespace");
        }
        if pid > 0 {
            relay_command_status(pid);
        }
    }

    let cwd = policy.cwd.clone().unwrap_or_else(|| PathBuf::from("/"));
    if let Err(e) = std::env::set_current_dir(&cwd) {
        child_fail(126, &format!("cannot enter {}: {e}", cwd.display()));
    }

    let Some((program, args)) = command.split_first() else {
        child_fail(127, "no command given");
    };
    let err = Command::new(program)
        .args(args)
        .env_clear()
        .envs(passthrough_env(&policy.pass_env))
        .exec();
    child_fail(127, &format!("cannot execute {program}: {err}"))
}

/// Wait for the command (the PID 1 of the namespace) and exit with its
/// status. A signal death is explained here, because this process cannot
/// re-raise the signal: the seccomp allowlist excludes `tgkill`. Never returns.
fn relay_command_status(pid: libc::pid_t) -> ! {
    let status = match wait_child(pid) {
        Ok(status) => status,
        Err(e) => child_fail(126, &format!("waiting for the command failed: {e}")),
    };
    if libc::WIFSIGNALED(status) {
        let sig = libc::WTERMSIG(status);
        eprintln!("tpt-sandbox: {}", signal_reason(sig));
        // SAFETY: _exit skips destructors, which must not run in a forked child.
        unsafe { libc::_exit(128 + sig) }
    }
    // SAFETY: as above.
    unsafe { libc::_exit(libc::WEXITSTATUS(status)) }
}

/// A short explanation for a signal that ended the command.
fn signal_reason(sig: i32) -> &'static str {
    match sig {
        SIGSYS => "terminated by seccomp: the policy does not allow a system call it made",
        SIGKILL => "killed with SIGKILL; possibly the --memory-limit cgroup",
        _ => "terminated by a signal",
    }
}

fn child_fail(code: i32, message: &str) -> ! {
    eprintln!("tpt-sandbox: {message}");
    // SAFETY: _exit skips atexit handlers and destructors, which must not run
    // in a forked child of a multi-threaded parent.
    unsafe { libc::_exit(code) }
}

/// Close every descriptor from 3 upward, so nothing inherited from the caller
/// bypasses the sandbox.
fn close_inherited_fds() {
    // SAFETY: close_range takes plain integers and only closes descriptors.
    // The arguments are passed as c_long to match the variadic ABI.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3 as libc::c_long,
            libc::c_long::from(u32::MAX),
            0 as libc::c_long,
        )
    };
    if ret != 0 {
        // Kernels without close_range: close the usual range one by one.
        for fd in 3..4096 {
            // SAFETY: closing an arbitrary descriptor number is always memory-safe.
            unsafe { libc::close(fd) };
        }
    }
}

/// The environment the command receives: the defaults plus any `--pass-env`
/// names that are set in the caller's environment.
fn passthrough_env(extra: &[String]) -> Vec<(String, String)> {
    const DEFAULT: &[&str] = &["PATH", "TERM", "LANG", "LC_ALL", "LC_CTYPE"];
    DEFAULT
        .iter()
        .map(|s| (*s).to_owned())
        .chain(extra.iter().cloned())
        .filter_map(|name| std::env::var(&name).ok().map(|value| (name, value)))
        .collect()
}

fn wait_child(pid: libc::pid_t) -> io::Result<libc::c_int> {
    let mut status: libc::c_int = 0;
    loop {
        // SAFETY: `status` is a valid out-pointer for the duration of the call.
        let ret = unsafe { libc::waitpid(pid, &raw mut status, 0) };
        if ret == pid {
            return Ok(status);
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

/// Report how the child ended and return the exit code to pass on.
fn report_exit(status: libc::c_int, json: bool) -> u8 {
    let (code, signal) = if libc::WIFEXITED(status) {
        (libc::WEXITSTATUS(status), None)
    } else if libc::WIFSIGNALED(status) {
        let sig = libc::WTERMSIG(status);
        (128 + sig, Some(sig))
    } else {
        (1, None)
    };

    let reason = signal.map(signal_reason);

    if json {
        let sig = signal.map_or_else(|| "null".to_owned(), |s| s.to_string());
        let reason_json = reason.map_or_else(|| "null".to_owned(), |r| format!("\"{r}\""));
        eprintln!(r#"{{"event":"exit","exit_code":{code},"signal":{sig},"reason":{reason_json}}}"#);
    } else if let Some(r) = reason {
        eprintln!("tpt-sandbox: {r}");
    }

    u8::try_from(code.clamp(0, 255)).unwrap_or(1)
}
