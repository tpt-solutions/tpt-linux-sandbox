//! `tpt-sandbox` — run a command inside a composable Linux sandbox.
//!
//! Pure-Rust alternative to bwrap (Bubblewrap) and firejail.

#[cfg(not(target_os = "linux"))]
compile_error!("tpt-l-sandbox-cli only supports Linux");

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Context as _;
use clap::Parser;
use tpt_l_sandbox::{
    CapsPolicy, CgroupConfig, DenyAction, JailConfig, NamespaceSet, RulesetBuilder, Sandbox,
    SeccompPolicy,
};

/// Run a command inside a composable Linux sandbox.
///
/// All restrictions are validated before any irreversible kernel state change.
#[derive(Parser, Debug)]
#[command(name = "tpt-sandbox", version, about, long_about = None)]
struct Args {
    /// Permit read access to PATH (repeatable).
    #[arg(long, value_name = "PATH", action = clap::ArgAction::Append)]
    allow_read: Vec<PathBuf>,

    /// Permit write access to PATH (repeatable).
    #[arg(long, value_name = "PATH", action = clap::ArgAction::Append)]
    allow_write: Vec<PathBuf>,

    /// Isolate the network namespace (sandbox gets no external network access).
    #[arg(long)]
    no_network: bool,

    /// Memory limit in bytes.
    #[arg(long, value_name = "BYTES")]
    memory_limit: Option<u64>,

    /// CPU quota as a percentage of one core (1–100).
    #[arg(long, value_name = "PERCENT")]
    cpu_quota: Option<u32>,

    /// Use PATH as the new filesystem root (pivot_root / chroot).
    #[arg(long, value_name = "PATH")]
    new_root: Option<PathBuf>,

    /// Drop all Linux capabilities before exec.
    #[arg(long)]
    drop_caps: bool,

    /// The command to run, followed by its arguments.
    #[arg(trailing_var_arg = true, required = true, value_name = "COMMAND")]
    command: Vec<String>,
}

fn main() -> ExitCode {
    let args = Args::parse();
    if let Err(e) = run(args) {
        eprintln!("tpt-sandbox: {e:#}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn run(args: Args) -> anyhow::Result<()> {
    let mut sandbox = Sandbox::new();

    // Namespaces — always unshare user + mount; optionally network.
    let mut ns = NamespaceSet::new().user().mount();
    if args.no_network {
        ns = ns.network();
    }
    sandbox = sandbox.namespaces(ns);

    // cgroup resource limits.
    if args.memory_limit.is_some() || args.cpu_quota.is_some() {
        let mut cg = CgroupConfig::new(format!("tpt-sandbox-{}", std::process::id()));
        if let Some(limit) = args.memory_limit {
            cg = cg.memory_limit(limit);
        }
        if let Some(quota) = args.cpu_quota {
            cg = cg.cpu_quota(quota);
        }
        sandbox = sandbox.cgroup(cg);
    }

    // Filesystem jail.
    if let Some(root) = args.new_root {
        sandbox = sandbox.jail(JailConfig::new(root).mount_proc().mount_dev_minimal());
    }

    // Capability dropping.
    if args.drop_caps {
        sandbox = sandbox.caps(CapsPolicy::new().drop_all());
    }

    // Seccomp — log-only default until per-command profiles are implemented.
    sandbox = sandbox.seccomp(SeccompPolicy::new().default_action(DenyAction::Log));

    // Landlock filesystem allowlist.
    let mut ruleset = RulesetBuilder::new();
    for path in &args.allow_read {
        ruleset = ruleset.allow_read(path);
    }
    for path in &args.allow_write {
        ruleset = ruleset.allow_write(path);
    }
    sandbox = sandbox.landlock(ruleset);

    // Apply all restrictions (irreversible from seccomp onward).
    sandbox.apply().context("failed to apply sandbox policy")?;

    // exec(2) replaces the current process image — if this returns we have an error.
    let err = exec_command(&args.command[0], &args.command[1..]);
    Err(err).context(format!("exec failed: {}", args.command[0]))
}

fn exec_command(cmd: &str, cmd_args: &[String]) -> std::io::Error {
    use std::os::unix::process::CommandExt as _;
    std::process::Command::new(cmd).args(cmd_args).exec()
}
