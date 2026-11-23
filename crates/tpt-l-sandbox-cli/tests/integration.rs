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
        eprintln!("skipping: memory cgroup controller not delegated to /sys/fs/cgroup");
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

/// The memory controller must be enabled for the parent cgroup (delegation).
/// Without it the sandbox cannot set a limit, so the test is skipped.
fn memory_controller_delegated() -> bool {
    std::fs::read_to_string("/sys/fs/cgroup/cgroup.subtree_control")
        .is_ok_and(|s| s.split_whitespace().any(|c| c == "memory"))
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
