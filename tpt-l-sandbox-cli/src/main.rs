//! CLI frontend for tpt-l-sandbox — a pure-Rust alternative to bwrap/firejail.

#![deny(missing_docs)]

use clap::Parser;
use std::path::PathBuf;
use tpt_l_sandbox::Sandbox;

/// Command-line arguments for the sandbox.
#[derive(Parser, Debug)]
#[command(
    name = "tpt-sandbox",
    about = "Run a command in a composable Linux sandbox",
    version
)]
pub struct Args {
    /// Paths the sandboxed process may read.
    #[arg(long = "allow-read", value_name = "PATH")]
    pub allow_read: Vec<PathBuf>,

    /// Paths the sandboxed process may write to.
    #[arg(long = "allow-write", value_name = "PATH")]
    pub allow_write: Vec<PathBuf>,

    /// Paths the sandboxed process may execute.
    #[arg(long = "allow-exec", value_name = "PATH")]
    pub allow_exec: Vec<PathBuf>,

    /// Disable network access.
    #[arg(long = "no-network")]
    pub no_network: bool,

    /// Memory limit in bytes.
    #[arg(long = "memory-limit", value_name = "BYTES")]
    pub memory_limit: Option<u64>,

    /// CPU quota in microseconds per period.
    #[arg(long = "cpu-quota", value_name = "QUOTA:PERIOD")]
    pub cpu_quota: Option<String>,

    /// New root directory for chroot jail.
    #[arg(long = "new-root", value_name = "PATH")]
    pub new_root: Option<PathBuf>,

    /// Drop all capabilities.
    #[arg(long = "drop-caps")]
    pub drop_caps: bool,

    /// Syscalls to allow (seccomp).
    #[arg(long = "allow-syscall", value_name = "NAME")]
    pub allow_syscall: Vec<String>,

    /// The command to run inside the sandbox.
    #[arg(required = true, last = true)]
    pub command: Vec<String>,
}

impl Args {
    /// Maps CLI arguments to a `Sandbox` builder.
    pub fn to_sandbox(&self) -> Sandbox {
        let mut sandbox = Sandbox::new();

        for path in &self.allow_read {
            sandbox = sandbox.allow_read(path.clone());
        }
        for path in &self.allow_write {
            sandbox = sandbox.allow_write(path.clone());
        }
        for path in &self.allow_exec {
            sandbox = sandbox.allow_exec(path.clone());
        }

        if self.no_network {
            sandbox = sandbox.no_network();
        }

        if let Some(limit) = self.memory_limit {
            sandbox = sandbox.memory_limit(limit);
        }

        if let Some(ref quota_str) = self.cpu_quota {
            if let Some((quota, period)) = Self::parse_cpu_quota(quota_str) {
                sandbox = sandbox.cpu_quota(quota, period);
            } else {
                eprintln!("Invalid --cpu-quota format: expected QUOTA:PERIOD");
                std::process::exit(1);
            }
        }

        if let Some(ref root) = self.new_root {
            let jail = tpt_l_chroot_jail::JailConfig::new(root)
                .mount_proc()
                .mount_dev_minimal()
                .mount_sys_ro();
            sandbox = sandbox.jail(jail);
        }

        if self.drop_caps {
            sandbox = sandbox.drop_all_caps();
        }

        for syscall in &self.allow_syscall {
            sandbox = sandbox.allow_syscall(syscall);
        }

        sandbox.command(&self.command.iter().map(|s| s.as_str()).collect::<Vec<_>>());
        sandbox
    }

    fn parse_cpu_quota(s: &str) -> Option<(u64, u64)> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return None;
        }
        let quota = parts[0].parse().ok()?;
        let period = parts[1].parse().ok()?;
        Some((quota, period))
    }
}

fn main() {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let sandbox = args.to_sandbox();

    match sandbox.apply() {
        Ok(applied) => {
            if let Err(e) = applied.exec() {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Sandbox error: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cpu_quota_valid() {
        assert_eq!(Args::parse_cpu_quota("50000:100000"), Some((50000, 100000)));
    }

    #[test]
    fn parse_cpu_quota_invalid() {
        assert_eq!(Args::parse_cpu_quota("invalid"), None);
    }

    #[test]
    fn parse_cpu_quota_missing_period() {
        assert_eq!(Args::parse_cpu_quota("50000"), None);
    }
}
