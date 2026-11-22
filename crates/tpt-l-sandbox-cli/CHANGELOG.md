# Changelog

All notable changes to `tpt-l-sandbox-cli` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `tpt-sandbox` binary running a command inside `tpt-l-sandbox`.
- Options: `--allow-read`, `--allow-write`, `--no-network`, `--memory-limit`,
  `--cpu-quota`, `--new-root`, and `--drop-caps`.
- Integration tests in `tests/integration.rs` for read allow-lists, capability
  dropping, network isolation, and memory limits.

### Known issues

- Seccomp is installed with a default action of `Log`, so denied syscalls are
  logged but not blocked.
- `cli_allow_read_etc_hostname_succeeds` fails on WSL2 because user-namespace
  UID mapping is not permitted there.
