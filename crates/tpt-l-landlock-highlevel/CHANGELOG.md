# Changelog

All notable changes to `tpt-l-landlock-highlevel` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `allow_tcp_bind` and `allow_tcp_connect` port rules (Landlock ABI 4). Once a port is listed, other ports of that kind are denied. Applying port rules on a kernel without ABI 4 fails.
- `isolate_abstract_sockets_and_signals` (Landlock ABI 6), best-effort.
- A forked-child regression test for the filesystem allowlist.

- `RulesetBuilder` with `allow_read`, `allow_write`, and `allow_exec`.
- `build` for validation without kernel calls, returning `ValidatedRuleset`.
- `ValidatedRuleset::apply` for irreversible Landlock enforcement.
- `LandlockError` for path, validation, and kernel failures.
- Unit tests for builder accumulation and empty rulesets.

### Fixed

- `apply` now returns an error when the kernel does not enforce the ruleset.
  Previously the `landlock` crate's `Ok(NotEnforced)` status was ignored, so
  the process ran unrestricted without any signal.
- Use `AccessFs::Truncate`, the name in `landlock` 0.4.7; `TruncateFile` does
  not exist.
- Wrap `PathFdError` in `io::Error` for `LandlockError::PathOpen`, so the
  public variant keeps its `std::io::Error` source type.
