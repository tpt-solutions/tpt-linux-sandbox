# Changelog

All notable changes to `tpt-l-seccomp-builder` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `SeccompPolicy` builder with `allow_syscall`, `deny_syscall`, and
  `default_action`, defaulting to kill for non-allowed syscalls.
- `SeccompPolicy::base_profile`, a general-purpose allowlist for ordinary
  programs. Everything else returns `EPERM`.
- `SeccompPolicy::validate`, which checks names and errno values without
  loading a filter.
- `DenyAction` with `Kill`, `Errno`, and `Log`.
- BPF compilation via `seccompiler` and loading via `apply`.
- Syscall-name tables for x86_64, aarch64 and riscv64.
- `SeccompError` for unknown names, invalid errnos, compile failures, and load
  failures.
- Unit tests for rule recording, default-action override, and syscall lookup.

### Changed

- `deny_syscall` is enforced. Each explicit deny compiles to its own filter,
  loaded before the allowlist, so a denied syscall stays denied even if it is
  also allowed. Previously the entry only checked the name.
- Names and errno values are checked before anything is loaded.
- `renameat2` is in the shared table on every architecture. `renameat` is added
  only where it exists (riscv64 has no `renameat`).

### Fixed

- Name `seccompiler::BackendError` explicitly in the BPF conversion, so the
  error type can be inferred against `seccompiler` 0.4.0.
- `base_profile` allows the calls GNU make and glibc need: `faccessat2`,
  `getrusage`, `setresuid` and `setresgid`. With `EPERM` as the default, make
  reported `cc: Operation not permitted`. `setresuid` and `setresgid` can only
  keep the caller's own ids in a user namespace.
- Builds for riscv64.
