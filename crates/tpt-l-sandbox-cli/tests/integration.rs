//! Integration tests for tpt-l-sandbox-cli.
//!
//! These tests require Linux and are only compiled/runs on that platform.

#![cfg(target_os = "linux")]

use std::process::Command;

/// Path to the compiled CLI binary.
fn cli_binary() -> String {
    env!("CARGO_BIN_EXE_tpt-sandbox").to_string()
}

#[test]
fn cli_allow_read_etc_hostname_succeeds() {
    let output = Command::new(cli_binary())
        .args(["--allow-read", "/etc", "--", "cat", "/etc/hostname"])
        .output()
        .expect("failed to execute CLI");

    assert!(
        output.status.success(),
        "expected success, got stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn cli_allow_read_etc_blocks_tmp() {
    let output = Command::new(cli_binary())
        .args(["--allow-read", "/etc", "--", "cat", "/tmp/secret"])
        .output()
        .expect("failed to execute CLI");

    assert!(
        !output.status.success(),
        "expected failure when reading outside allowed paths"
    );
}

#[test]
fn cli_no_network_blocks_socket() {
    let output = Command::new(cli_binary())
        .args([
            "--allow-read", "/etc",
            "--no-network",
            "--",
            "python3", "-c", "import socket; socket.socket()",
        ])
        .output()
        .expect("failed to execute CLI");

    assert!(
        !output.status.success(),
        "expected failure when creating socket with --no-network"
    );
}

#[test]
fn cli_memory_limit_enforced() {
    let output = Command::new(cli_binary())
        .args([
            "--allow-read", "/etc",
            "--memory-limit", "1048576", // 1 MiB
            "--",
            "python3", "-c", "a = 'x' * 10 * 1024 * 1024", // try to alloc 10 MiB
        ])
        .output()
        .expect("failed to execute CLI");

    assert!(
        !output.status.success(),
        "expected OOM kill with 1MiB memory limit"
    );
}

#[test]
fn cli_drop_caps_blocks_mount() {
    let output = Command::new(cli_binary())
        .args([
            "--allow-read", "/etc",
            "--drop-caps",
            "--",
            "mount", "--bind", "/etc", "/tmp/mnt",
        ])
        .output()
        .expect("failed to execute CLI");

    assert!(
        !output.status.success(),
        "expected mount to fail with caps dropped"
    );
}
