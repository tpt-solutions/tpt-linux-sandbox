//! Diagnostic modes: `--doctor`, `--dry-run` / `--explain`, and `--learn`.

use std::collections::BTreeSet;
use std::ffi::CString;
use std::path::Path;
use std::process::Command;

use anyhow::{Context as _, Result, bail};

use crate::policy::Policy;

/// Print a report on whether this machine can run the sandbox, and what will
/// degrade if it cannot.
///
/// Returns the exit code: 1 if any check is a warning, so the report can gate
/// a script. Informational lines do not fail.
pub fn doctor() -> u8 {
    let kernel = read_trim("/proc/sys/kernel/osrelease").unwrap_or_default();
    let checks = [
        check_kernel(),
        check_landlock_features(&kernel),
        check_wsl(),
        check_userns(),
        check_apparmor_userns(),
        check_landlock(),
        check_seccomp(),
        check_cgroup(),
        check_selinux(),
        check_strace(),
    ];
    let mut code = 0;
    for (level, name, detail) in checks {
        if level == "warn" {
            code = 1;
        }
        println!("[{level}] {name}: {detail}");
    }
    code
}

/// Whether the `strace` binary used by `--learn` can run.
fn check_strace() -> Check {
    match Command::new("strace").arg("-V").output() {
        Ok(out) if out.status.success() => ("ok", "strace", "found (used by --learn)".into()),
        _ => ("info", "strace", "not found; --learn needs it".into()),
    }
}

/// Landlock features the CLI uses, by the kernel release that added them.
/// Matches the ABI table in docs/kernel-matrix.md.
fn check_landlock_features(release: &str) -> Check {
    let mut parts = release.split(|c: char| !c.is_ascii_digit());
    let major: u32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor: u32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let at_least = |maj: u32, min: u32| (major, minor) >= (maj, min);
    if release.is_empty() {
        return ("warn", "landlock features", "kernel release unknown".into());
    }
    let mut missing = Vec::new();
    if !at_least(5, 19) {
        missing.push("Refer (5.19)");
    }
    if !at_least(6, 2) {
        missing.push("Truncate (6.2)");
    }
    if !at_least(6, 7) {
        missing.push("TCP port rules (6.7)");
    }
    if !at_least(6, 12) {
        missing.push("IPC scoping (6.12)");
    }
    if missing.is_empty() {
        (
            "ok",
            "landlock features",
            "all used features available".into(),
        )
    } else {
        (
            "info",
            "landlock features",
            format!("not available on {release}: {}", missing.join(", ")),
        )
    }
}

type Check = (&'static str, &'static str, String);

fn read_trim(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_owned())
}

fn check_kernel() -> Check {
    let Some(release) = read_trim("/proc/sys/kernel/osrelease") else {
        return (
            "warn",
            "kernel",
            "cannot read /proc/sys/kernel/osrelease".into(),
        );
    };
    // Landlock needs 5.13; the crate's features need 6.2 for full coverage.
    let mut parts = release.split(|c: char| !c.is_ascii_digit());
    let major: u32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor: u32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    if (major, minor) < (5, 13) {
        (
            "warn",
            "kernel",
            format!("{release}; Landlock needs 5.13 or newer"),
        )
    } else if (major, minor) < (6, 12) {
        (
            "info",
            "kernel",
            format!("{release}; Landlock works; some features are missing (see landlock features)"),
        )
    } else {
        ("ok", "kernel", release)
    }
}

fn check_wsl() -> Check {
    match read_trim("/proc/version") {
        Some(v) if v.to_ascii_lowercase().contains("microsoft") => (
            "warn",
            "wsl",
            "WSL detected; UID mapping and cgroup delegation can fail (see docs/troubleshooting.md)"
                .into(),
        ),
        _ => ("ok", "wsl", "not running under WSL".into()),
    }
}

fn check_userns() -> Check {
    match read_trim("/proc/sys/user/max_user_namespaces").as_deref() {
        Some("0") => (
            "warn",
            "user namespaces",
            "disabled (max_user_namespaces = 0)".into(),
        ),
        Some(n) => ("ok", "user namespaces", format!("enabled (max {n})")),
        None => (
            "warn",
            "user namespaces",
            "cannot read max_user_namespaces".into(),
        ),
    }
}

fn check_apparmor_userns() -> Check {
    match read_trim("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").as_deref() {
        Some("1") => (
            "warn",
            "AppArmor userns restriction",
            "unprivileged user namespaces are restricted; see docs/troubleshooting.md".into(),
        ),
        Some(_) => ("ok", "AppArmor userns restriction", "not restricted".into()),
        None => ("info", "AppArmor userns restriction", "not present".into()),
    }
}

fn check_landlock() -> Check {
    match read_trim("/sys/kernel/security/lsm") {
        Some(lsms) if lsms.split(',').any(|l| l == "landlock") => {
            ("ok", "landlock", "active in the LSM list".into())
        }
        Some(_) => (
            "warn",
            "landlock",
            "not in the active LSM list; filesystem rules will fail".into(),
        ),
        None => (
            "warn",
            "landlock",
            "cannot read /sys/kernel/security/lsm".into(),
        ),
    }
}

fn check_seccomp() -> Check {
    match read_trim("/proc/sys/kernel/seccomp/actions_avail") {
        Some(actions) => ("ok", "seccomp", format!("actions: {actions}")),
        None => (
            "warn",
            "seccomp",
            "actions_avail not found; seccomp filters may be unsupported".into(),
        ),
    }
}

/// The calling process's cgroup directory, from `/proc/self/cgroup`. The
/// sandbox creates its cgroup here, so this is what the check must test.
fn own_cgroup_dir() -> std::path::PathBuf {
    let rel = std::fs::read_to_string("/proc/self/cgroup")
        .ok()
        .and_then(|text| {
            text.lines()
                .find_map(|l| l.strip_prefix("0::").map(str::to_owned))
        })
        .unwrap_or_else(|| "/".into());
    Path::new("/sys/fs/cgroup").join(rel.trim_start_matches('/'))
}

fn check_cgroup() -> Check {
    let own = own_cgroup_dir();
    let location = own.display().to_string();
    if !own.join("cgroup.controllers").exists() {
        return (
            "info",
            "cgroup v2",
            "not mounted; --memory-limit and --cpu-quota will fail".into(),
        );
    }
    // The controllers this process's cgroup offers. The sandbox enables them
    // there (moving the process into a leaf first if needed), so they must be
    // offered, not already enabled.
    let offered: Vec<String> = read_trim(&format!("{location}/cgroup.controllers"))
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    let missing: Vec<&str> = ["cpu", "memory", "pids"]
        .into_iter()
        .filter(|c| !offered.iter().any(|e| e.as_str() == *c))
        .collect();
    if !missing.is_empty() {
        return (
            "warn",
            "cgroup v2",
            format!(
                "controllers not available to {location}: {}; --cpu-quota, --memory-limit and --pids-limit will fail",
                missing.join(", ")
            ),
        );
    }
    if access_writable(&own) {
        (
            "ok",
            "cgroup v2",
            format!("writable at {location}; resource limits available"),
        )
    } else {
        (
            "warn",
            "cgroup v2",
            format!(
                "{location} is not writable by this user; limits need systemd delegation (Delegate=yes)"
            ),
        )
    }
}

fn check_selinux() -> Check {
    match tpt_l_selinux_context::SecurityContext::current_process() {
        Ok(ctx) => (
            "info",
            "selinux",
            format!("process context {}", ctx.to_canonical()),
        ),
        Err(tpt_l_selinux_context::SelinuxError::NotEnabled) => {
            ("info", "selinux", "not enabled".into())
        }
        // Systems without SELinux report a plain LSM label such as "kernel".
        Err(tpt_l_selinux_context::SelinuxError::InvalidFormat(_)) => (
            "info",
            "selinux",
            "not enabled (no SELinux context on this process)".into(),
        ),
        Err(e) => ("warn", "selinux", format!("cannot read context: {e}")),
    }
}

fn access_writable(path: &Path) -> bool {
    let Ok(c) = CString::new(path.as_os_str().as_encoded_bytes()) else {
        return false;
    };
    // SAFETY: `c` is a valid NUL-terminated path for the duration of the call.
    unsafe { libc::access(c.as_ptr(), libc::W_OK) == 0 }
}

/// Print the effective policy without applying anything.
pub fn explain(policy: &Policy, command: &[String]) {
    println!("Effective policy (dry run; nothing applied)");
    println!(
        "  namespaces : user, mount{}{}",
        if policy.pid_namespace() { ", pid" } else { "" },
        if policy.no_network {
            ", network (no external access)"
        } else {
            " (network shared with host)"
        }
    );
    println!(
        "  ipc        : {}",
        if policy.isolate_ipc() {
            "requested: abstract sockets and signals isolated (needs kernel 6.12+; best-effort)"
        } else {
            "shared with host"
        }
    );
    if !policy.allow_tcp_bind.is_empty() || !policy.allow_tcp_connect.is_empty() {
        println!(
            "  tcp        : bind {:?}, connect {:?} (other ports denied)",
            policy.allow_tcp_bind, policy.allow_tcp_connect
        );
    }
    let limits = [
        policy.memory_limit.map(|m| format!("memory {m} bytes")),
        policy.cpu_quota.map(|q| format!("cpu {q}%")),
        policy.pids_limit.map(|p| format!("pids {p}")),
    ];
    let limits: Vec<String> = limits.into_iter().flatten().collect();
    println!(
        "  cgroup     : {}",
        if limits.is_empty() {
            "none".to_owned()
        } else {
            limits.join(", ")
        }
    );
    println!(
        "  jail       : {}",
        policy.new_root.as_ref().map_or_else(
            || "none".to_owned(),
            |r| format!("new root {}", r.display())
        )
    );
    println!(
        "  caps       : {}",
        if policy.drop_caps {
            "all dropped"
        } else {
            "unchanged"
        }
    );
    println!(
        "  seccomp    : {}",
        policy.seccomp.as_deref().unwrap_or("enforce")
    );
    println!(
        "  landlock   : read {}, write {}, exec {}, system paths {}",
        policy.allow_read.len(),
        policy.allow_write.len(),
        policy.allow_exec.len(),
        if policy.system_paths() { "on" } else { "off" }
    );
    for p in &policy.allow_read {
        println!("               read  {}", p.display());
    }
    for p in &policy.allow_write {
        println!("               write {}", p.display());
    }
    for p in &policy.allow_exec {
        println!("               exec  {}", p.display());
    }
    println!(
        "  cwd        : {}",
        policy
            .cwd
            .as_deref()
            .map_or("/".into(), |p| p.display().to_string())
    );
    println!("  command    : {}", command.join(" "));

    if policy.seccomp.as_deref() == Some("off") {
        println!("warning: seccomp is off; syscalls are not filtered");
    }
    if policy.seccomp.as_deref() == Some("log") {
        println!(
            "warning: seccomp=log allows every syscall and only logs; this is not enforcement"
        );
    }
    if !policy.system_paths() && policy.allow_exec.is_empty() {
        println!("warning: no exec paths granted; the command may fail to start");
    }
}

/// Run the command under `strace` and print a starter policy built from the
/// paths it opened. The command runs **unsandboxed**.
pub fn learn(command: &[String]) -> Result<u8> {
    let (program, args) = command
        .split_first()
        .context("--learn needs a command after --")?;
    // A private directory for the log. `create_dir` fails if the path exists,
    // including as a symlink, so a file planted in the shared temp directory
    // cannot redirect strace's output.
    let dir = std::env::temp_dir().join(format!("tpt-sandbox-learn-{}", std::process::id()));
    std::fs::create_dir(&dir)
        .with_context(|| format!("cannot create private log directory {}", dir.display()))?;
    let log = dir.join("strace.log");

    let status = Command::new("strace")
        .args(["-f", "-q", "-e", "trace=file", "-o"])
        .arg(&log)
        .arg("--")
        .arg(program)
        .args(args)
        .status();
    let text = match &status {
        Ok(_) => std::fs::read_to_string(&log)
            .with_context(|| format!("strace produced no log at {}", log.display())),
        Err(_) => Ok(String::new()),
    };
    let _ = std::fs::remove_dir_all(&dir);
    let status = status.context("failed to run strace; install it to use --learn")?;
    let text = text?;

    let mut reads = BTreeSet::new();
    let mut writes = BTreeSet::new();
    for (path, is_write) in text.lines().filter_map(accessed_path) {
        if is_write {
            writes.insert(path);
        } else {
            reads.insert(path);
        }
    }

    println!(
        "# Generated by tpt-sandbox --learn for: {}",
        command.join(" ")
    );
    println!("# The command ran WITHOUT a sandbox. Review before use.");
    println!("allow_read = [");
    for p in &reads {
        println!("  {p:?},");
    }
    println!("]");
    println!("allow_write = [");
    for p in &writes {
        println!("  {p:?},");
    }
    println!("]");
    eprintln!(
        "tpt-sandbox: observed {} read and {} write paths; the command ran unsandboxed",
        reads.len(),
        writes.len()
    );

    if !status.success() {
        bail!("the learned command exited with {status}");
    }
    Ok(0)
}

/// Extract a successfully opened absolute path from one strace line, with
/// whether it was opened for writing. Kernel pseudo-filesystems are skipped:
/// they are noise for policy purposes.
fn accessed_path(line: &str) -> Option<(String, bool)> {
    let path = first_quoted(line)?;
    if !path.starts_with('/')
        || path.starts_with("/proc")
        || path.starts_with("/sys")
        || path.starts_with("/dev")
    {
        return None;
    }
    // The return value follows ") = "; failed calls return -1.
    let result = line.rsplit_once(") = ")?.1.trim();
    if result.starts_with('-') {
        return None;
    }
    // Only open flags say whether a path is written. Other calls (stat,
    // access, execve) are read-side for policy purposes.
    let flags = line.find('"').map_or("", |start| &line[start..]);
    let writes = ["O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC"]
        .iter()
        .any(|flag| flags.contains(flag));
    Some((path, writes))
}

/// The first double-quoted string in an strace line, with `\"` and `\\`
/// unescaped. strace escapes quotes and backslashes inside paths.
fn first_quoted(line: &str) -> Option<String> {
    let start = line.find('"')? + 1;
    let mut out = String::new();
    let mut chars = line[start..].chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Some(out),
            '\\' => out.push(chars.next()?),
            _ => out.push(c),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strace_success_line_yields_path() {
        let line = r#"openat(AT_FDCWD, "/etc/hostname", O_RDONLY|O_CLOEXEC) = 3"#;
        assert_eq!(
            accessed_path(line),
            Some(("/etc/hostname".to_owned(), false))
        );
    }

    #[test]
    fn strace_write_open_is_a_write() {
        let line = r#"openat(AT_FDCWD, "/work/out.txt", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 4"#;
        assert_eq!(
            accessed_path(line),
            Some(("/work/out.txt".to_owned(), true))
        );
    }

    #[test]
    fn strace_stat_is_a_read() {
        let line = r#"newfstatat(AT_FDCWD, "/work/x", {st_mode=S_IFREG}, 0) = 0"#;
        assert_eq!(accessed_path(line), Some(("/work/x".to_owned(), false)));
    }

    #[test]
    fn strace_escaped_quote_stays_in_path() {
        let line = r#"openat(AT_FDCWD, "/tmp/a\"b", O_RDONLY) = 3"#;
        assert_eq!(accessed_path(line), Some((r#"/tmp/a"b"#.to_owned(), false)));
    }

    #[test]
    fn strace_failed_line_is_skipped() {
        let line = r#"openat(AT_FDCWD, "/tmp/secret", O_RDONLY) = -1 EACCES (Permission denied)"#;
        assert!(accessed_path(line).is_none());
    }

    #[test]
    fn strace_noise_paths_are_skipped() {
        let line = r#"openat(AT_FDCWD, "/proc/self/maps", O_RDONLY) = 3"#;
        assert!(accessed_path(line).is_none());
    }

    #[test]
    fn strace_relative_paths_are_skipped() {
        let line = r#"openat(AT_FDCWD, "relative.txt", O_RDONLY) = 3"#;
        assert!(accessed_path(line).is_none());
    }
}
