//! Integration tests for tpt-l-sandbox-cli.
//!
//! These run the real binary and need Linux with unprivileged user namespaces,
//! Landlock and cgroup v2 delegation where the tests use those features.
//!
//! Negative tests assert two things: the command was blocked *and* the sandbox
//! was set up. Otherwise a setup failure would look like a successful block.

#![cfg(target_os = "linux")]

use std::process::{Command, Output};

/// Path to the compiled CLI binary.
fn cli_binary() -> String {
    env!("CARGO_BIN_EXE_tpt-sandbox").to_string()
}

fn run_cli(args: &[&str]) -> Output {
    Command::new(cli_binary())
        .args(args)
        .output()
        .expect("failed to execute CLI")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// True when the CLI failed to set up the sandbox at all.
fn setup_failed(out: &Output) -> bool {
    let err = stderr(out);
    err.contains("sandbox setup failed") || err.contains("policy validation failed")
}

#[test]
fn cli_allow_read_etc_hostname_succeeds() {
    let out = run_cli(&["--allow-read", "/etc", "--", "cat", "/etc/hostname"]);
    assert!(
        out.status.success(),
        "expected success, stderr: {}",
        stderr(&out)
    );
    assert!(!setup_failed(&out));

    let expected = std::fs::read_to_string("/etc/hostname").expect("read /etc/hostname");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), expected.trim());
}

#[test]
fn cli_blocks_read_outside_allowed_paths() {
    let secret = std::env::temp_dir().join(format!("tpt-sandbox-secret-{}", std::process::id()));
    std::fs::write(&secret, "classified\n").expect("write secret");
    let secret_str = secret.to_string_lossy().into_owned();

    let out = run_cli(&["--allow-read", "/etc", "--", "cat", &secret_str]);
    let _ = std::fs::remove_file(&secret);

    assert!(
        !out.status.success(),
        "reading outside the allowlist must fail"
    );
    assert!(
        !setup_failed(&out),
        "failure must come from Landlock, not setup"
    );
    assert!(
        stderr(&out).contains("Permission denied"),
        "expected EACCES from the kernel, stderr: {}",
        stderr(&out)
    );
    assert!(!String::from_utf8_lossy(&out.stdout).contains("classified"));
}

#[test]
fn cli_no_network_blocks_connect() {
    if Command::new("python3").arg("--version").output().is_err() {
        eprintln!("skipping: python3 not installed");
        return;
    }
    let out = run_cli(&[
        "--no-network",
        "--",
        "python3",
        "-c",
        "import socket; socket.create_connection(('192.0.2.1', 80), timeout=2)",
    ]);
    assert!(!out.status.success(), "connect must fail without a network");
    assert!(!setup_failed(&out), "stderr: {}", stderr(&out));
    let err = stderr(&out);
    assert!(
        err.contains("Network is unreachable") || err.contains("OSError"),
        "expected a network error, stderr: {err}"
    );
}

#[test]
fn cli_memory_limit_kills_allocation() {
    if Command::new("python3").arg("--version").output().is_err() {
        eprintln!("skipping: python3 not installed");
        return;
    }
    if !memory_controller_delegated() {
        eprintln!(
            "skipping: memory cgroup not usable (not delegated, or no write access to /sys/fs/cgroup)"
        );
        return;
    }
    // Python's own startup stays well under 64 MiB; the 256 MiB allocation does not.
    let out = run_cli(&[
        "--memory-limit",
        "67108864",
        "--allow-read",
        "/etc",
        "--",
        "python3",
        "-c",
        "b = b'x' * (256 * 1024 * 1024)",
    ]);
    assert!(!setup_failed(&out), "stderr: {}", stderr(&out));
    assert_eq!(
        out.status.code(),
        Some(137),
        "expected SIGKILL (137), stderr: {}",
        stderr(&out)
    );
    assert!(stderr(&out).contains("SIGKILL"));
}

#[test]
fn cli_drop_caps_blocks_mount() {
    // /usr/lib exists, so the only reason the mount can fail is the missing
    // capability (EPERM), not a bad target path.
    let out = run_cli(&[
        "--drop-caps",
        "--allow-read",
        "/etc",
        "--",
        "mount",
        "--bind",
        "/etc",
        "/usr/lib",
    ]);
    assert!(
        !out.status.success(),
        "mount must fail with capabilities dropped"
    );
    assert!(!setup_failed(&out), "stderr: {}", stderr(&out));
    // mount(8) prints "permission denied" for EPERM; accept the raw errno text too.
    let err = stderr(&out).to_lowercase();
    assert!(
        err.contains("permission denied") || err.contains("operation not permitted"),
        "expected a permission error from the dropped capability, stderr: {err}"
    );
}

/// The calling process's cgroup directory (cgroup v2 only), from /proc.
fn own_cgroup_dir() -> Option<std::path::PathBuf> {
    let text = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let rel = text.lines().find_map(|l| l.strip_prefix("0::"))?;
    Some(std::path::Path::new("/sys/fs/cgroup").join(rel.trim_start_matches('/')))
}

/// The memory controller must be enabled for the parent cgroup (delegation).
/// Without it the sandbox cannot set a limit, so the test is skipped.
/// True when the memory limit can actually be applied: the controller is
/// delegated, and this user may create a cgroup under `/sys/fs/cgroup`.
/// `subtree_control` is world-readable, so checking it alone is not enough;
/// on an unprivileged runner the controller is listed but cgroup creation
/// fails with EACCES.
fn memory_controller_delegated() -> bool {
    // The CLI works under the caller's own cgroup, so probe there. Enabling the
    // controller in a cgroup that also holds other processes is impossible
    // without moving them (cgroup v2 rule), so an unprivileged test only runs
    // when the controller is already enabled there. Root may use the cgroupfs
    // root instead.
    let Some(own) = own_cgroup_dir() else {
        return false;
    };
    // SAFETY: geteuid has no preconditions.
    let is_root = unsafe { libc::geteuid() } == 0;
    let enabled = std::fs::read_to_string(own.join("cgroup.subtree_control"))
        .is_ok_and(|s| s.split_whitespace().any(|c| c == "memory"));
    if !(enabled || is_root) {
        return false;
    }
    let probe = own.join(format!("tpt-test-probe-{}", std::process::id()));
    match std::fs::create_dir(&probe) {
        Ok(()) => {
            let _ = std::fs::remove_dir(&probe);
            true
        }
        Err(_) => false,
    }
}

#[test]
fn cli_environment_is_scrubbed() {
    let out = Command::new(cli_binary())
        .args([
            "--allow-read",
            "/etc",
            "--",
            "sh",
            "-c",
            "echo ${TPT_SECRET_VAR:-unset}",
        ])
        .env("TPT_SECRET_VAR", "leaked")
        .output()
        .expect("failed to execute CLI");
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "unset");
}

#[test]
fn cli_pass_env_forwards_named_variable() {
    let out = Command::new(cli_binary())
        .args([
            "--allow-read",
            "/etc",
            "--pass-env",
            "TPT_PASSED_VAR",
            "--",
            "sh",
            "-c",
            "echo ${TPT_PASSED_VAR:-unset}",
        ])
        .env("TPT_PASSED_VAR", "visible")
        .output()
        .expect("failed to execute CLI");
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "visible");
}

#[test]
fn cli_reports_exit_code_as_json() {
    let out = run_cli(&["--allow-read", "/etc", "--json", "--", "sh", "-c", "exit 3"]);
    assert_eq!(out.status.code(), Some(3), "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("\"exit_code\":3"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn cli_rejects_out_of_range_cpu_quota() {
    let out = run_cli(&["--cpu-quota", "0", "--", "true"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("between 1 and 100"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn cli_rejects_zero_memory_limit() {
    let out = run_cli(&["--memory-limit", "0", "--", "true"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("greater than 0"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn cli_dry_run_does_not_execute_command() {
    // If the command ran, the marker file would be created.
    let marker = std::env::temp_dir().join(format!("tpt-sandbox-dryrun-{}", std::process::id()));
    let _ = std::fs::remove_file(&marker);
    let marker_str = marker.to_string_lossy().into_owned();

    let out = run_cli(&[
        "--dry-run",
        "--allow-read",
        "/etc",
        "--",
        "touch",
        &marker_str,
    ]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(String::from_utf8_lossy(&out.stdout).contains("Effective policy"));
    assert!(!marker.exists(), "--dry-run must not run the command");
}

#[test]
fn cli_prints_builtin_profile() {
    let out = run_cli(&["--print-profile", "strict"]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("no_network = true"));
}

#[test]
fn cli_unknown_profile_fails() {
    let out = run_cli(&["--profile", "does-not-exist", "--", "true"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("unknown profile"));
}

#[test]
fn cli_runs_command_as_pid_one_by_default() {
    if Command::new("python3").arg("--version").output().is_err() {
        eprintln!("skipping: python3 not installed");
        return;
    }
    let out = run_cli(&[
        "--allow-read",
        "/etc",
        "--",
        "python3",
        "-c",
        "import os; print(os.getpid())",
    ]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(!setup_failed(&out));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "1");
}

#[test]
fn cli_share_pids_keeps_host_pid_space() {
    if Command::new("python3").arg("--version").output().is_err() {
        eprintln!("skipping: python3 not installed");
        return;
    }
    let out = run_cli(&[
        "--share-pids",
        "--allow-read",
        "/etc",
        "--",
        "python3",
        "-c",
        "import os; print(os.getpid())",
    ]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let pid: u32 = String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .expect("pid printed");
    assert!(pid > 1, "expected a host pid, got {pid}");
}

/// Landlock TCP rules need Linux 6.7 or newer. Returns false on older kernels.
fn kernel_has_landlock_tcp() -> bool {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    let mut parts = release.split(|c: char| !c.is_ascii_digit());
    let major: u32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor: u32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    (major, minor) >= (6, 7)
}

#[test]
fn cli_tcp_allowlist_denies_other_ports() {
    if !kernel_has_landlock_tcp() {
        eprintln!("skipping: Landlock TCP rules need Linux 6.7+");
        return;
    }
    if Command::new("python3").arg("--version").output().is_err() {
        eprintln!("skipping: python3 not installed");
        return;
    }
    // Only port 443 may be connected to; port 9 must be refused by Landlock.
    let out = run_cli(&[
        "--allow-read",
        "/etc",
        "--allow-tcp-connect",
        "443",
        "--",
        "python3",
        "-c",
        "import socket; socket.create_connection(('127.0.0.1', 9), timeout=2)",
    ]);
    assert!(!out.status.success(), "connect to port 9 must be denied");
    assert!(!setup_failed(&out), "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("Permission denied"),
        "expected EACCES from Landlock, stderr: {}",
        stderr(&out)
    );
}

#[test]
fn cli_command_starts_in_invoking_directory() {
    // The default working directory is the caller's, not `/`. `.` is granted so
    // the directory is readable; `pwd` prints where the command started.
    let out = run_cli(&["--allow-read", ".", "--", "pwd"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(!setup_failed(&out));

    let expected = std::env::current_dir().expect("current dir");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        expected.to_string_lossy()
    );
}

#[test]
fn cli_warns_about_unset_pass_env_name() {
    let out = run_cli(&["--pass-env", "TPT_TEST_NOT_SET_ANYWHERE", "--", "true"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("--pass-env TPT_TEST_NOT_SET_ANYWHERE is not set"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn cli_forwards_sigterm_to_the_command() {
    // The command sleeps for 30 s. A SIGTERM to the CLI must reach it, so the
    // CLI exits well before the sleep would finish. The default PID namespace
    // is in use, so this also covers the relay path.
    let mut child = Command::new(cli_binary())
        .args(["--", "sleep", "30"])
        .spawn()
        .expect("failed to spawn CLI");
    std::thread::sleep(std::time::Duration::from_millis(800));
    // SAFETY: kill takes plain integers; the pid is our own child.
    unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };

    let start = std::time::Instant::now();
    let status = child.wait().expect("wait for CLI");
    assert!(
        start.elapsed() < std::time::Duration::from_secs(20),
        "CLI did not stop after SIGTERM"
    );
    assert!(!status.success(), "a signalled run must not report success");
}

/// Write a policy file under the temp directory and return its path.
fn write_policy(name: &str, text: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("tpt-sandbox-{name}-{}.toml", std::process::id()));
    std::fs::write(&path, text).expect("write policy");
    path
}

#[test]
fn cli_check_policy_accepts_a_usable_policy() {
    let path = write_policy("check-ok", "allow_read = [\"/etc\"]\nno_network = true\n");
    let out = run_cli(&["--check-policy", &path.to_string_lossy()]);
    let _ = std::fs::remove_file(&path);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(String::from_utf8_lossy(&out.stdout).contains(": ok"));
}

#[test]
fn cli_check_policy_rejects_a_missing_path() {
    let path = write_policy(
        "check-missing",
        "allow_write = [\"/nonexistent-tpt-sandbox-path\"]\n",
    );
    let out = run_cli(&["--check-policy", &path.to_string_lossy()]);
    let _ = std::fs::remove_file(&path);
    assert!(!out.status.success(), "a missing path must fail the check");
    assert!(stderr(&out).contains("nonexistent-tpt-sandbox-path"));
}

#[test]
fn cli_new_root_without_system_directories_explains_itself() {
    // An empty new root has no /usr, which the default system paths need.
    let root = std::env::temp_dir().join(format!("tpt-sandbox-empty-root-{}", std::process::id()));
    std::fs::create_dir_all(&root).expect("create empty root");
    let root_str = root.to_string_lossy().into_owned();
    let out = run_cli(&["--dry-run", "--new-root", &root_str, "--", "true"]);
    let _ = std::fs::remove_dir(&root);
    assert!(!out.status.success(), "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("does not exist inside the new root"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn cli_doctor_json_is_one_object_with_matching_exit_code() {
    let out = run_cli(&["--doctor", "--json"]);
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 1, "expected one JSON line, got: {text}");
    let line = lines[0];
    assert!(line.starts_with(r#"{"checks":[{"level":"#), "got: {line}");
    assert!(line.ends_with('}'), "got: {line}");
    assert!(line.contains(r#""name":"kernel""#), "got: {line}");

    // The exit code is 1 when any check warns, and the object says the same.
    let expected = i32::from(line.contains(r#""level":"warn""#));
    assert!(
        line.contains(&format!(r#""exit_code":{expected}}}"#)),
        "got: {line}"
    );
    assert_eq!(out.status.code(), Some(expected), "stdout: {text}");
}

#[test]
fn cli_without_command_is_a_usage_error() {
    let out = run_cli(&["--allow-read", "/etc"]);
    assert_eq!(out.status.code(), Some(2), "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("no command given"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn cli_command_not_found_exits_127() {
    let out = run_cli(&["--allow-read", "/etc", "--", "/nonexistent-tpt-sandbox-cmd"]);
    assert_eq!(out.status.code(), Some(127), "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("cannot execute"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn cli_zero_pids_limit_is_rejected() {
    let out = run_cli(&["--allow-read", "/etc", "--pids-limit", "0", "--", "true"]);
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("process limit must be greater than 0"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn cli_seccomp_off_and_log_run_the_command() {
    for mode in ["off", "log"] {
        let out = run_cli(&["--allow-read", "/etc", "--seccomp", mode, "--", "true"]);
        assert!(
            out.status.success(),
            "--seccomp {mode}: expected success, stderr: {}",
            stderr(&out)
        );
    }
}

#[test]
fn cli_missing_policy_file_is_reported() {
    let out = run_cli(&[
        "--policy",
        "/nonexistent-tpt-sandbox-policy.toml",
        "--",
        "true",
    ]);
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("cannot read policy file"),
        "stderr: {}",
        stderr(&out)
    );
}
