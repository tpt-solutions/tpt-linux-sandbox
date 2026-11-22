# Changelog

All notable changes to `tpt-l-seccomp-builder` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `SeccompPolicy` builder with `allow_syscall`, `deny_syscall`, and
  `default_action`, defaulting to kill for non-allowed syscalls.
- `DenyAction` with `Kill`, `Errno`, and `Log`.
- BPF compilation via `seccompiler` and loading via `apply`.
- x86_64 syscall-name table.
- `SeccompError` for unknown names, compile failures, and load failures.
- Unit tests for rule recording, default-action override, and syscall lookup.

### Fixed

- Name `seccompiler::BackendError` explicitly in the BPF conversion, so the
  error type can be inferred against `seccompiler` 0.4.0.
